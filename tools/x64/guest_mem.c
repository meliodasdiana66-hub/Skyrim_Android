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
    int count;
};

static int g_fail_after = -1;

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

static Page *find_page(const GuestMem *mem, uint64_t addr) {
    uint64_t base = page_base(addr);
    Page *page;
    for (page = mem->pages; page != NULL; page = page->next) {
        if (page->base == base)
            return page;
    }
    return NULL;
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
    for (cursor = page_base(addr); cursor < end; cursor += GUEST_PAGE_SIZE) {
        uint64_t lo = cursor < addr ? addr : cursor;
        uint64_t hi = end < cursor + GUEST_PAGE_SIZE ? end : cursor + GUEST_PAGE_SIZE;
        page = find_page(mem, cursor);
        if (page == NULL)
            need_new++;
        else if (range_overlaps(page, lo, hi) || page->nspans >= GUEST_MAX_SPANS)
            return GUEST_ERR_RANGE;
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
    for (cursor = page_base(addr); cursor < end; cursor += GUEST_PAGE_SIZE) {
        uint64_t lo = cursor < addr ? addr : cursor;
        uint64_t hi = end < cursor + GUEST_PAGE_SIZE ? end : cursor + GUEST_PAGE_SIZE;
        Span *span;
        uint64_t at;
        page = find_page(mem, cursor);
        if (page == NULL) {
            page = fresh;
            fresh = fresh->next;
            page->base = cursor;
            page->next = mem->pages;
            mem->pages = page;
            mem->count++;
        }
        span = &page->spans[page->nspans++];
        span->lo = lo;
        span->hi = hi;
        span->perms = perms;
        span->logical_execute = 0;
        for (at = lo; at < hi; at++) {
            if (at - addr < file_len)
                page->data[at - page->base] = file_bytes[at - addr];
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

static int writable_qword(GuestMem *mem, uint64_t target) {
    size_t i;
    for (i = 0; i < 8; i++) {
        Page *page = find_page(mem, target + i);
        Span *span = page == NULL ? NULL : span_at(page, target + i);
        if (span == NULL)
            return GUEST_ERR_UNMAPPED;
        if ((span->perms & GUEST_PERM_WRITE) == 0)
            return GUEST_ERR_PERM;
    }
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
            if (target + 8 < target)
                return GUEST_ERR_RELOC;
            access = writable_qword(mem, target);
            if (access != GUEST_OK)
                return access == GUEST_ERR_PERM ? GUEST_ERR_PERM : GUEST_ERR_RELOC;
        }
        cursor += block_size;
    }
    if (cursor != reloc_len)
        return GUEST_ERR_RELOC;
    cursor = 0;
    while (cursor + 8 <= reloc_len) {
        uint32_t block_va = ru32(reloc + cursor);
        uint32_t block_size = ru32(reloc + cursor + 4);
        size_t at;
        for (at = cursor + 8; at + 2 <= cursor + block_size; at += 2) {
            uint16_t entry = ru16(reloc + at);
            uint64_t target, value;
            uint8_t raw[8];
            int i;
            if ((entry >> 12) != 10)
                continue;
            target = (uint64_t)block_va + (entry & 0xFFF);
            guest_read(mem, target, raw, 8);
            value = 0;
            for (i = 0; i < 8; i++)
                value |= (uint64_t)raw[i] << (8 * i);
            value = (value + delta) & 0xFFFFFFFFFFFFFFFFULL;
            for (i = 0; i < 8; i++)
                raw[i] = (uint8_t)(value >> (8 * i));
            guest_write(mem, target, raw, 8);
        }
        cursor += block_size;
    }
    return GUEST_OK;
}

int guest_set_logical_execute(GuestMem *mem, uint64_t addr, size_t size, int enabled) {
    uint64_t cursor, end;
    int i;
    Page *page;
    if (mem == NULL || size == 0 || addr + size < addr)
        return GUEST_ERR_RANGE;
    end = addr + size;
    for (cursor = addr; cursor < end; cursor++) {
        page = find_page(mem, cursor);
        if (page == NULL || span_at(page, cursor) == NULL)
            return GUEST_ERR_UNMAPPED;
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
