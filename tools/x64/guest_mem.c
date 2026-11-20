#include "guest_mem.h"

#include <stdlib.h>
#include <string.h>

enum { GUEST_MAX_SPANS = 8 };

typedef struct Span {
    uint64_t lo;
    uint64_t hi;
    int perms;
    int logical_execute;
} Span;

typedef struct Page {
    uint64_t base;
    Span spans[GUEST_MAX_SPANS];
    int nspans;
    uint8_t data[GUEST_PAGE_SIZE];
    struct Page *next;
} Page;

struct GuestMem {
    Page *pages;
    Page *index[GUEST_MAX_PAGES];
    int count;
    int sealed;
};

static int g_fail_after = -1;
static uint64_t g_lookups;
static uint64_t g_span_visits;

void guest_reset_counters(void) {
    g_lookups = 0;
    g_span_visits = 0;
}

uint64_t guest_lookup_count(void) { return g_lookups; }
uint64_t guest_span_visit_count(void) { return g_span_visits; }

void guest_seal(GuestMem *mem) {
    if (mem != NULL)
        mem->sealed = 1;
}

int guest_is_sealed(const GuestMem *mem) {
    return mem != NULL && mem->sealed;
}

static uint64_t page_base(uint64_t addr) {
    return addr & ~((uint64_t)GUEST_PAGE_SIZE - 1);
}

static void *guest_alloc(size_t bytes) {
    if (g_fail_after == 0)
        return NULL;
    if (g_fail_after > 0)
        g_fail_after--;
    return calloc(1, bytes);
}

void guest_test_fail_allocs_after(int n) {
    g_fail_after = n;
}

static int page_slot(uint64_t addr, uint64_t *slot) {
    if (addr >= (uint64_t)GUEST_MAX_PAGES * (uint64_t)GUEST_PAGE_SIZE)
        return 0;
    *slot = addr >> 12;
    return 1;
}

static Page *find_page(const GuestMem *mem, uint64_t addr) {
    uint64_t slot;
    g_lookups++;
    if (!page_slot(page_base(addr), &slot))
        return NULL;
    return mem->index[slot];
}

/* first and last are inclusive page bases. Rejects a cursor that would wrap. */
static int page_bounds(uint64_t addr, uint64_t end, uint64_t *first, uint64_t *last) {
    if (end == 0 || end <= addr)
        return GUEST_ERR_RANGE;
    *first = page_base(addr);
    *last = page_base(end - 1);
    if (*last < *first)
        return GUEST_ERR_RANGE;
    if (*first >= (uint64_t)GUEST_MAX_PAGES * (uint64_t)GUEST_PAGE_SIZE ||
        *last >= (uint64_t)GUEST_MAX_PAGES * (uint64_t)GUEST_PAGE_SIZE)
        return GUEST_ERR_RANGE;
    return GUEST_OK;
}

static Span *span_at(Page *page, uint64_t addr) {
    int i;
    for (i = 0; i < page->nspans; i++) {
        if (addr >= page->spans[i].lo && addr < page->spans[i].hi)
            return &page->spans[i];
    }
    return NULL;
}

GuestMem *guest_create(void) {
    return guest_alloc(sizeof(GuestMem));
}

void guest_destroy(GuestMem *mem) {
    Page *page;
    if (mem == NULL)
        return;
    page = mem->pages;
    while (page != NULL) {
        Page *next = page->next;
        free(page);
        page = next;
    }
    free(mem);
}

int guest_host_executable(const GuestMem *mem) {
    (void)mem;
    return 0;
}

int guest_page_count(const GuestMem *mem) {
    if (mem == NULL)
        return 0;
    return mem->count;
}

static int range_overlaps(Page *page, uint64_t lo, uint64_t hi) {
    int i;
    for (i = 0; i < page->nspans; i++) {
        if (lo < page->spans[i].hi && hi > page->spans[i].lo)
            return 1;
    }
    return 0;
}

int guest_map(GuestMem *mem, uint64_t addr, size_t size, int perms,
              const uint8_t *file_bytes, size_t file_len) {
    uint64_t cursor, end;
    int need_new = 0;
    Page *fresh = NULL;
    Page *page;
    if (mem == NULL || size == 0 || addr + size < addr)
        return GUEST_ERR_RANGE;
    if (perms & GUEST_PERM_EXECUTE)
        return GUEST_ERR_EXEC;
    if ((perms & (GUEST_PERM_READ | GUEST_PERM_WRITE)) == 0)
        return GUEST_ERR_PERM;
    if (file_len > size || (file_bytes == NULL && file_len != 0))
        return GUEST_ERR_RANGE;
    end = addr + size;
    {
        uint64_t first, last, bounds_rc;
        bounds_rc = page_bounds(addr, end, &first, &last);
        if (bounds_rc != GUEST_OK)
            return (int)bounds_rc;
        for (cursor = first; ; ) {
            uint64_t lo = cursor < addr ? addr : cursor;
            uint64_t hi = end < cursor + GUEST_PAGE_SIZE ? end : cursor + GUEST_PAGE_SIZE;
            page = find_page(mem, cursor);
            if (page == NULL)
                need_new++;
            else if (range_overlaps(page, lo, hi) || page->nspans >= GUEST_MAX_SPANS)
                return GUEST_ERR_RANGE;
            if (cursor == last)
                break;
            if (cursor > UINT64_MAX - (uint64_t)GUEST_PAGE_SIZE)
                return GUEST_ERR_RANGE;
            cursor += GUEST_PAGE_SIZE;
        }
    }
    if (mem->count + need_new > GUEST_MAX_PAGES)
        return GUEST_ERR_NOMEM;
    for (cursor = 0; cursor < (uint64_t)need_new; cursor++) {
        Page *created = guest_alloc(sizeof *created);
        if (created == NULL) {
            while (fresh != NULL) {
                Page *next = fresh->next;
                free(fresh);
                fresh = next;
            }
            return GUEST_ERR_NOMEM;
        }
        created->next = fresh;
        fresh = created;
    }
    {
        uint64_t first, last;
        page_bounds(addr, end, &first, &last);
        for (cursor = first; ; ) {
            uint64_t lo = cursor < addr ? addr : cursor;
            uint64_t hi = end < cursor + GUEST_PAGE_SIZE ? end : cursor + GUEST_PAGE_SIZE;
            uint64_t copy_lo, copy_hi, slot;
            Span *span;
            page = find_page(mem, cursor);
            if (page == NULL) {
                page = fresh;
                fresh = fresh->next;
                page->base = cursor;
                page->next = mem->pages;
                mem->pages = page;
                mem->count++;
                page_slot(cursor, &slot);
                mem->index[slot] = page;
            }
            span = &page->spans[page->nspans++];
            span->lo = lo;
            span->hi = hi;
            span->perms = perms;
            span->logical_execute = 0;
            copy_lo = lo > addr ? lo : addr;
            copy_hi = hi < addr + file_len ? hi : addr + file_len;
            if (file_len != 0 && copy_lo < copy_hi) {
                memcpy(page->data + (size_t)(copy_lo - page->base),
                       file_bytes + (size_t)(copy_lo - addr),
                       (size_t)(copy_hi - copy_lo));
            }
            if (cursor == last)
                break;
            cursor += GUEST_PAGE_SIZE;
        }
    }
    return GUEST_OK;
}

static int access_bytes(GuestMem *mem, uint64_t addr, uint8_t *buf, size_t n, int write) {
    size_t i;
    if (mem == NULL || n == 0 || addr + n < addr)
        return GUEST_ERR_RANGE;
    for (i = 0; i < n; i++) {
        Page *page = find_page(mem, addr + i);
        Span *span = page == NULL ? NULL : span_at(page, addr + i);
        int need = write ? GUEST_PERM_WRITE : GUEST_PERM_READ;
        if (span == NULL)
            return GUEST_ERR_UNMAPPED;
        if ((span->perms & need) == 0)
            return GUEST_ERR_PERM;
    }
    for (i = 0; i < n; i++) {
        Page *page = find_page(mem, addr + i);
        size_t off = (size_t)((addr + i) - page->base);
        if (write)
            page->data[off] = buf[i];
        else
            buf[i] = page->data[off];
    }
    return GUEST_OK;
}

int guest_read(GuestMem *mem, uint64_t addr, void *dst, size_t n) {
    return access_bytes(mem, addr, dst, n, 0);
}

int guest_write(GuestMem *mem, uint64_t addr, const void *src, size_t n) {
    return access_bytes(mem, addr, (uint8_t *)src, n, 1);
}

static uint32_t ru32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t ru16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int qword_access(GuestMem *mem, uint64_t target, int need) {
    size_t i;
    if (target + 8 < target)
        return GUEST_ERR_RELOC;
    for (i = 0; i < 8; i++) {
        Page *page = find_page(mem, target + i);
        Span *span = page == NULL ? NULL : span_at(page, target + i);
        if (span == NULL)
            return GUEST_ERR_UNMAPPED;
        if (need != 0 && (span->perms & need) != need)
            return GUEST_ERR_PERM;
    }
    return GUEST_OK;
}

static int read_qword_raw(GuestMem *mem, uint64_t target, uint8_t raw[8]) {
    size_t i;
    for (i = 0; i < 8; i++) {
        Page *page = find_page(mem, target + i);
        if (page == NULL)
            return GUEST_ERR_UNMAPPED;
        raw[i] = page->data[(size_t)((target + i) - page->base)];
    }
    return GUEST_OK;
}

static int write_qword_raw(GuestMem *mem, uint64_t target, const uint8_t raw[8]) {
    size_t i;
    for (i = 0; i < 8; i++) {
        Page *page = find_page(mem, target + i);
        if (page == NULL)
            return GUEST_ERR_UNMAPPED;
        page->data[(size_t)((target + i) - page->base)] = raw[i];
    }
    return GUEST_OK;
}

static int commit_dir64(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta, int public_api) {
    size_t cursor = 0, count = 0, n = 0, i;
    typedef struct { uint64_t addr; uint8_t old[8]; } Snap;
    Snap *snaps;
    while (cursor + 8 <= reloc_len) {
        uint32_t block_size = ru32(reloc + cursor + 4);
        size_t at;
        for (at = cursor + 8; at + 2 <= cursor + block_size; at += 2) {
            if ((ru16(reloc + at) >> 12) == 10)
                count++;
        }
        cursor += block_size;
    }
    if (count == 0)
        return GUEST_OK;
    if (count > (1u << 20))
        return GUEST_ERR_NOMEM;
    snaps = malloc(count * sizeof *snaps);
    if (snaps == NULL)
        return GUEST_ERR_NOMEM;
    cursor = 0;
    while (cursor + 8 <= reloc_len) {
        uint32_t block_va = ru32(reloc + cursor);
        uint32_t block_size = ru32(reloc + cursor + 4);
        size_t at;
        for (at = cursor + 8; at + 2 <= cursor + block_size; at += 2) {
            uint64_t target;
            int rc;
            if ((ru16(reloc + at) >> 12) != 10)
                continue;
            target = (uint64_t)block_va + (ru16(reloc + at) & 0xFFF);
            snaps[n].addr = target;
            rc = read_qword_raw(mem, target, snaps[n].old);
            if (rc != GUEST_OK) {
                free(snaps);
                return rc;
            }
            if (public_api) {
                uint8_t check[8];
                rc = guest_read(mem, target, check, 8);
                if (rc != GUEST_OK || memcmp(check, snaps[n].old, 8) != 0) {
                    free(snaps);
                    return rc != GUEST_OK ? rc : GUEST_ERR_PERM;
                }
            }
            n++;
        }
        cursor += block_size;
    }
    for (i = 0; i < n; i++) {
        uint8_t raw[8];
        uint64_t value = 0;
        int b, rc;
        for (b = 0; b < 8; b++)
            value |= (uint64_t)snaps[i].old[b] << (8 * b);
        value = (value + delta) & 0xFFFFFFFFFFFFFFFFULL;
        for (b = 0; b < 8; b++)
            raw[b] = (uint8_t)(value >> (8 * b));
        rc = public_api ? guest_write(mem, snaps[i].addr, raw, 8) : write_qword_raw(mem, snaps[i].addr, raw);
        if (rc != GUEST_OK) {
            size_t back;
            for (back = 0; back < i; back++)
                write_qword_raw(mem, snaps[back].addr, snaps[back].old);
            free(snaps);
            return rc;
        }
    }
    free(snaps);
    return GUEST_OK;
}

int guest_apply_dir64(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta) {
    size_t cursor = 0;
    if (mem == NULL || reloc == NULL)
        return GUEST_ERR_RELOC;
    while (cursor + 8 <= reloc_len) {
        uint32_t block_size = ru32(reloc + cursor + 4);
        size_t at;
        if (block_size < 8 || cursor + block_size > reloc_len)
            return GUEST_ERR_RELOC;
        for (at = cursor + 8; at + 2 <= cursor + block_size; at += 2) {
            unsigned type = ru16(reloc + at) >> 12;
            uint64_t target;
            int access;
            if (type == 0)
                continue;
            if (type != 10)
                return GUEST_ERR_RELOC;
            target = (uint64_t)ru32(reloc + cursor) + (ru16(reloc + at) & 0xFFF);
            access = qword_access(mem, target, GUEST_PERM_READ | GUEST_PERM_WRITE);
            if (access != GUEST_OK)
                return access == GUEST_ERR_PERM ? GUEST_ERR_PERM : GUEST_ERR_RELOC;
        }
        cursor += block_size;
    }
    if (cursor != reloc_len)
        return GUEST_ERR_RELOC;
    return commit_dir64(mem, reloc, reloc_len, delta, 1);
}

int guest_loader_store(GuestMem *mem, uint64_t addr, const void *src, size_t n) {
    const uint8_t *bytes = src;
    size_t i;
    if (mem == NULL || mem->sealed || src == NULL || n == 0 || addr + n < addr)
        return GUEST_ERR_PERM;
    for (i = 0; i < n; i++) {
        Page *page = find_page(mem, addr + i);
        if (page == NULL || span_at(page, addr + i) == NULL)
            return GUEST_ERR_UNMAPPED;
    }
    for (i = 0; i < n; i++) {
        Page *page = find_page(mem, addr + i);
        page->data[(size_t)((addr + i) - page->base)] = bytes[i];
    }
    return GUEST_OK;
}

int guest_loader_reloc(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta) {
    size_t cursor = 0;
    if (mem == NULL || mem->sealed || reloc == NULL)
        return GUEST_ERR_PERM;
    while (cursor + 8 <= reloc_len) {
        uint32_t block_size = ru32(reloc + cursor + 4);
        size_t at;
        if (block_size < 8 || cursor + block_size > reloc_len)
            return GUEST_ERR_RELOC;
        for (at = cursor + 8; at + 2 <= cursor + block_size; at += 2) {
            unsigned type = ru16(reloc + at) >> 12;
            uint64_t target;
            int access;
            if (type == 0)
                continue;
            if (type != 10)
                return GUEST_ERR_RELOC;
            target = (uint64_t)ru32(reloc + cursor) + (ru16(reloc + at) & 0xFFF);
            access = qword_access(mem, target, 0);
            if (access != GUEST_OK)
                return GUEST_ERR_RELOC;
        }
        cursor += block_size;
    }
    if (cursor != reloc_len)
        return GUEST_ERR_RELOC;
    return commit_dir64(mem, reloc, reloc_len, delta, 0);
}

int guest_set_logical_execute(GuestMem *mem, uint64_t addr, size_t size, int enabled) {
    uint64_t cursor, end;
    int i;
    Page *page;
    if (mem == NULL || size == 0 || addr + size < addr)
        return GUEST_ERR_RANGE;
    end = addr + size;
    {
        uint64_t first, last, bounds_rc;
        bounds_rc = page_bounds(addr, end, &first, &last);
        if (bounds_rc != GUEST_OK)
            return (int)bounds_rc;
        for (cursor = first; ; ) {
            uint64_t slice_lo = cursor < addr ? addr : cursor;
            uint64_t slice_hi = end < cursor + GUEST_PAGE_SIZE ? end : cursor + GUEST_PAGE_SIZE;
            uint64_t cover = slice_lo;
            int guard = 0;
            page = mem->index[cursor >> 12];
            if (page == NULL)
                return GUEST_ERR_UNMAPPED;
            while (cover < slice_hi && guard++ <= GUEST_MAX_SPANS) {
                int s, advanced = 0;
                for (s = 0; s < page->nspans; s++) {
                    g_span_visits++;
                    if (page->spans[s].lo <= cover && cover < page->spans[s].hi) {
                        cover = page->spans[s].hi;
                        advanced = 1;
                        break;
                    }
                }
                if (!advanced)
                    return GUEST_ERR_UNMAPPED;
            }
            if (cover < slice_hi)
                return GUEST_ERR_UNMAPPED;
            if (cursor == last)
                break;
            if (cursor > UINT64_MAX - (uint64_t)GUEST_PAGE_SIZE)
                return GUEST_ERR_RANGE;
            cursor += GUEST_PAGE_SIZE;
        }
    }
    for (page = mem->pages; page != NULL; page = page->next) {
        int extra = 0;
        for (i = 0; i < page->nspans; i++) {
            Span *span = &page->spans[i];
            int cuts = 0;
            if (span->hi <= addr || span->lo >= end)
                continue;
            if (span->lo < addr)
                cuts++;
            if (span->hi > end)
                cuts++;
            extra += cuts;
        }
        if (page->nspans + extra > GUEST_MAX_SPANS)
            return GUEST_ERR_RANGE;
    }
    for (page = mem->pages; page != NULL; page = page->next) {
        int n = page->nspans;
        for (i = 0; i < n; i++) {
            Span *span = &page->spans[i];
            uint64_t lo = span->lo;
            uint64_t hi = span->hi;
            int perms = span->perms;
            int flag = span->logical_execute;
            uint64_t mid_lo = lo < addr ? addr : lo;
            uint64_t mid_hi = hi > end ? end : hi;
            if (hi <= addr || lo >= end)
                continue;
            if (lo < mid_lo) {
                span->hi = mid_lo;
                page->spans[page->nspans++] = (Span){mid_lo, mid_hi, perms, enabled ? 1 : 0};
            } else {
                span->lo = mid_lo;
                span->hi = mid_hi;
                span->logical_execute = enabled ? 1 : 0;
            }
            if (hi > mid_hi)
                page->spans[page->nspans++] = (Span){mid_hi, hi, perms, flag};
        }
    }
    return GUEST_OK;
}

int guest_logical_execute(const GuestMem *mem, uint64_t addr) {
    Page *page;
    int i;
    if (mem == NULL)
        return 0;
    page = find_page(mem, addr);
    if (page == NULL)
        return 0;
    for (i = 0; i < page->nspans; i++) {
        if (addr >= page->spans[i].lo && addr < page->spans[i].hi)
            return page->spans[i].logical_execute;
    }
    return 0;
}
