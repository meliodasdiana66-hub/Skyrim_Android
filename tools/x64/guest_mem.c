#include "guest_mem.h"

#include <stdlib.h>
#include <string.h>

enum { GUEST_PAGE = 4096, GUEST_MAX_PAGES = 64 };

typedef struct Page {
    uint64_t base;
    uint64_t lo;
    uint64_t hi;
    int perms;
    int logical_execute;
    uint8_t data[GUEST_PAGE];
    struct Page *next;
} Page;

struct GuestMem {
    Page *pages;
    int count;
    int host_executable;
};

static uint64_t page_base(uint64_t addr) {
    return addr & ~((uint64_t)GUEST_PAGE - 1);
}

static Page *find_page(GuestMem *mem, uint64_t addr) {
    uint64_t base = page_base(addr);
    Page *page;
    for (page = mem->pages; page != NULL; page = page->next) {
        if (page->base == base)
            return page;
    }
    return NULL;
}

GuestMem *guest_create(void) {
    GuestMem *mem = calloc(1, sizeof *mem);
    return mem;
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

int guest_map(GuestMem *mem, uint64_t addr, size_t size, int perms,
              const uint8_t *file_bytes, size_t file_len) {
    uint64_t cursor, end;
    if (mem == NULL || size == 0 || addr + size < addr)
        return GUEST_ERR_RANGE;
    if (perms & GUEST_PERM_EXECUTE)
        return GUEST_ERR_EXEC;
    if ((perms & (GUEST_PERM_READ | GUEST_PERM_WRITE)) == 0)
        return GUEST_ERR_PERM;
    if (file_len > size || (file_bytes == NULL && file_len != 0))
        return GUEST_ERR_RANGE;
    end = addr + size;
    for (cursor = page_base(addr); cursor < end; cursor += GUEST_PAGE) {
        if (find_page(mem, cursor) != NULL)
            return GUEST_ERR_RANGE;
        if (mem->count >= GUEST_MAX_PAGES)
            return GUEST_ERR_NOMEM;
    }
    for (cursor = page_base(addr); cursor < end; cursor += GUEST_PAGE) {
        Page *page = calloc(1, sizeof *page);
        size_t i;
        if (page == NULL)
            return GUEST_ERR_NOMEM;
        page->base = cursor;
        page->lo = cursor < addr ? addr : cursor;
        page->hi = end < cursor + GUEST_PAGE ? end : cursor + GUEST_PAGE;
        page->perms = perms;
        page->next = mem->pages;
        mem->pages = page;
        mem->count++;
        for (i = 0; i < GUEST_PAGE; i++) {
            uint64_t at = cursor + i;
            if (at < addr || at >= end)
                continue;
            if (at - addr < file_len)
                page->data[i] = file_bytes[at - addr];
        }
    }
    mem->host_executable = 0;
    return GUEST_OK;
}

static int access_bytes(GuestMem *mem, uint64_t addr, uint8_t *buf, size_t n, int write) {
    size_t i;
    if (mem == NULL || n == 0 || addr + n < addr)
        return GUEST_ERR_RANGE;
    for (i = 0; i < n; i++) {
        Page *page = find_page(mem, addr + i);
        int need = write ? GUEST_PERM_WRITE : GUEST_PERM_READ;
        if (page == NULL || addr + i < page->lo || addr + i >= page->hi)
            return GUEST_ERR_UNMAPPED;
        if ((page->perms & need) == 0)
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
            if (type != 0 && type != 10)
                return GUEST_ERR_RELOC;
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
            unsigned type = entry >> 12;
            uint64_t target;
            uint8_t raw[8];
            uint64_t value;
            int i;
            if (type == 0)
                continue;
            target = (uint64_t)block_va + (entry & 0xFFF);
            if (guest_read(mem, target, raw, 8) != GUEST_OK)
                return GUEST_ERR_RELOC;
            value = 0;
            for (i = 0; i < 8; i++)
                value |= (uint64_t)raw[i] << (8 * i);
            value = (value + delta) & 0xFFFFFFFFFFFFFFFFULL;
            for (i = 0; i < 8; i++)
                raw[i] = (uint8_t)(value >> (8 * i));
            if (guest_write(mem, target, raw, 8) != GUEST_OK)
                return GUEST_ERR_RELOC;
        }
        cursor += block_size;
    }
    return GUEST_OK;
}

int guest_set_logical_execute(GuestMem *mem, uint64_t addr, size_t size, int enabled) {
    uint64_t cursor, end;
    if (mem == NULL || size == 0 || addr + size < addr)
        return GUEST_ERR_RANGE;
    end = addr + size;
    for (cursor = addr; cursor < end; cursor++) {
        if (find_page(mem, cursor) == NULL)
            return GUEST_ERR_UNMAPPED;
    }
    for (cursor = page_base(addr); cursor < end; cursor += GUEST_PAGE) {
        Page *page = find_page(mem, cursor);
        if (page != NULL)
            page->logical_execute = enabled ? 1 : 0;
    }
    return GUEST_OK;
}

int guest_logical_execute(const GuestMem *mem, uint64_t addr) {
    Page *page;
    if (mem == NULL)
        return 0;
    for (page = mem->pages; page != NULL; page = page->next) {
        if (page->base == page_base(addr))
            return page->logical_execute;
    }
    return 0;
}
