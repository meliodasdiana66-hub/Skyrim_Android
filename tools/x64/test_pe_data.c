#include "pe_data.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

static void expect(int cond, const char *message) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", message);
        g_failures++;
    }
}

static void u16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void u32(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void u64(uint8_t *p, unsigned long long v) {
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void build(uint8_t *file) {
    int i;
    memset(file, 0, 0x800);
    file[0] = 'M'; file[1] = 'Z';
    u32(file + 0x3C, 0x80);
    memcpy(file + 0x80, "PE\0\0", 4);
    u16(file + 0x84, 0x8664);
    u16(file + 0x86, 2);
    u16(file + 0x94, 0xF0);
    u16(file + 0x98, 0x20B);
    u32(file + 0x98 + 16, 0x1000);
    u64(file + 0x98 + 24, 0x140000000ULL);
    u32(file + 0x98 + 56, 0x4000);
    u32(file + 0x98 + 108, 16);
    u32(file + 0x98 + 112 + 8, 0x2000);
    u32(file + 0x98 + 112 + 12, 40);
    u32(file + 0x98 + 112 + 40, 0x1100);
    u32(file + 0x98 + 112 + 44, 12);
    memcpy(file + 0x188, ".text", 5);
    u32(file + 0x188 + 8, 0x1000);
    u32(file + 0x188 + 12, 0x1000);
    u32(file + 0x188 + 16, 0x200);
    u32(file + 0x188 + 20, 0x400);
    u32(file + 0x188 + 36, 0x60000020);
    memcpy(file + 0x188 + 40, ".data", 5);
    u32(file + 0x188 + 40 + 8, 0x2000);
    u32(file + 0x188 + 40 + 12, 0x2000);
    u32(file + 0x188 + 40 + 16, 0x100);
    u32(file + 0x188 + 40 + 20, 0x600);
    u32(file + 0x188 + 40 + 36, 0xC0000040);
    file[0x400] = 0xCC;
    u32(file + 0x500, 0x2000);
    u32(file + 0x504, 12);
    u16(file + 0x508, 0xA000 | 0x0A0);
    u32(file + 0x600, 0x2060);
    u32(file + 0x60C, 0x2080);
    u32(file + 0x610, 0x20A0);
    u64(file + 0x660, 0x20C0);
    memcpy(file + 0x680, "KERNEL32.dll", 13);
    u64(file + 0x6A0, 0x1000);
    memcpy(file + 0x6C2, "GetProcessHeap", 15);
    (void)i;
}

int main(int argc, char **argv) {
    uint8_t file[0x800];
    uint8_t byte;
    PeImage *image = NULL;
    uint64_t relocated = 0x180000000ULL;
    uint64_t qword;
    uint8_t raw[8];
    int rc;
    build(file);
    if (argc > 1) {
        FILE *fp = fopen(argv[1], "wb");
        if (fp == NULL)
            return 1;
        if (fwrite(file, 1, sizeof file, fp) != sizeof file) {
            fclose(fp);
            return 1;
        }
        fclose(fp);
    }
    rc = pe_load_data(file, sizeof file, &relocated, 0, &image);
    expect(rc == PE_OK && image != NULL, "synthetic image loads");
    if (image != NULL) {
        expect(image->entry_called == 0, "entry was not called");
        expect(image->imports_bound == 0, "imports were not bound");
        expect(guest_host_executable(image->mem) == 0, "host pages are not executable");
        expect(guest_logical_execute(image->mem, 0x1000) == 1, "text is logically executable");
        expect(guest_logical_execute(image->mem, 0x2000) == 0, "data is not logically executable");
        expect(guest_read(image->mem, 0x1000, &byte, 1) == GUEST_OK && byte == 0xCC, "file byte mapped");
        expect(guest_read(image->mem, 0x2100, &byte, 1) == GUEST_OK && byte == 0, "virtual tail is zero");
        expect(guest_read(image->mem, 0x20A0, raw, 8) == GUEST_OK, "relocated iat readable");
        qword = 0;
        {
            int i;
            for (i = 0; i < 8; i++)
                qword |= (uint64_t)raw[i] << (8 * i);
        }
        expect(qword == 0x40001000ULL, "DIR64 delta applied");
        expect(image->import_count == 1 && image->imports[0].resolved == 0, "import stays unresolved");
        expect(strcmp(image->imports[0].dll, "KERNEL32.dll") == 0, "dll name");
        expect(strcmp(image->imports[0].name, "GetProcessHeap") == 0, "import name");
        expect(guest_write(image->mem, 0x1000, "Z", 1) == GUEST_ERR_PERM, "code span is not writable");
        pe_image_destroy(image);
    }
    image = NULL;
    expect(pe_load_data(file, sizeof file, NULL, 1, &image) == PE_OK, "read-only host map");
    if (image != NULL) {
        expect(image->relocations_applied == 0, "read-only map does not relocate");
        expect(guest_write(image->mem, 0x20A0, "Z", 1) == GUEST_ERR_PERM, "read-only data span rejects writes");
        expect(image->entry_called == 0 && guest_host_executable(image->mem) == 0, "still not executable");
        pe_image_destroy(image);
    }
    file[0x98 + 56] = 0x00;
    file[0x98 + 57] = 0x00;
    file[0x98 + 58] = 0x00;
    file[0x98 + 59] = 0x08; /* 128 MiB */
    image = (PeImage *)1;
    expect(pe_load_data(file, sizeof file, NULL, 1, &image) == PE_ERR_RANGE && image == NULL,
           "hostile SizeOfImage allocates nothing");
    build(file);
    u32(file + 0x188 + 40 + 16, 0x10000);
    image = (PeImage *)1;
    expect(pe_load_data(file, sizeof file, NULL, 1, &image) == PE_ERR_RANGE && image == NULL,
           "raw section past the file allocates nothing");
    if (g_failures) {
        fprintf(stderr, "%d pe_data checks failed\n", g_failures);
        return 1;
    }
    return 0;
}
