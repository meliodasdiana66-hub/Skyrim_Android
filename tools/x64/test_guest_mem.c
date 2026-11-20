#include "guest_mem.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

static void expect(int cond, const char *message) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", message);
        g_failures++;
    }
}

int main(void) {
    GuestMem *mem = guest_create();
    uint8_t file[0x100];
    uint8_t out[16];
    uint8_t qword[8];
    uint8_t reloc[12];
    uint8_t bad[12];
    size_t i;
    memset(file, 0xAB, sizeof file);
    expect(guest_host_executable(mem) == 0, "host executable is clear at create");
    expect(guest_map(mem, 0x2000, 0x1800, GUEST_PERM_READ | GUEST_PERM_EXECUTE, file, sizeof file) == GUEST_ERR_EXEC,
           "execute permission is refused");
    expect(guest_host_executable(mem) == 0, "refused execute did not create a host executable page");
    expect(guest_map(mem, 0x2000, 0x1800, GUEST_PERM_READ | GUEST_PERM_WRITE, file, sizeof file) == GUEST_OK,
           "map file bytes plus zero-fill");
    expect(guest_read(mem, 0x2000, out, 1) == GUEST_OK && out[0] == 0xAB, "file byte is visible");
    expect(guest_read(mem, 0x2100, out, 1) == GUEST_OK && out[0] == 0, "tail beyond the file is zero");
    expect(guest_read(mem, 0x37FF, out, 1) == GUEST_OK && out[0] == 0, "last mapped byte is zero");
    expect(guest_read(mem, 0x3800, out, 1) == GUEST_ERR_UNMAPPED, "read past the mapping fails");
    expect(guest_write(mem, 0x3000, "W", 1) == GUEST_OK, "write inside the mapping");
    expect(guest_read(mem, 0x3000, out, 1) == GUEST_OK && out[0] == 'W', "write is readable");
    expect(guest_set_logical_execute(mem, 0x2000, 0x1000, 1) == GUEST_OK, "logical execute flag");
    expect(guest_logical_execute(mem, 0x2000) == 1, "logical execute is recorded");
    expect(guest_host_executable(mem) == 0, "logical execute is not a host executable page");

    memset(qword, 0, sizeof qword);
    qword[0] = 0x00;
    qword[1] = 0x10; /* 0x1000 */
    expect(guest_map(mem, 0x10000, 0x1000, GUEST_PERM_READ | GUEST_PERM_WRITE, qword, 8) == GUEST_OK,
           "map relocation target");
    /* block VA 0x10000, size 12, one DIR64 at offset 0, one ABSOLUTE pad */
    reloc[0] = 0x00; reloc[1] = 0x00; reloc[2] = 0x01; reloc[3] = 0x00;
    reloc[4] = 12; reloc[5] = 0; reloc[6] = 0; reloc[7] = 0;
    reloc[8] = 0x00; reloc[9] = 0xA0; /* type 10, offset 0 */
    reloc[10] = 0; reloc[11] = 0;
    expect(guest_apply_dir64(mem, reloc, sizeof reloc, 0x20) == GUEST_OK, "DIR64 applies");
    expect(guest_read(mem, 0x10000, out, 8) == GUEST_OK, "read relocated qword");
    expect(out[0] == 0x20 && out[1] == 0x10 && out[2] == 0 && out[3] == 0, "delta was added");
    memcpy(bad, reloc, sizeof bad);
    bad[9] = 0x30; /* type 3 */
    expect(guest_apply_dir64(mem, bad, sizeof bad, 0x20) == GUEST_ERR_RELOC, "HIGHLOW is refused");
    expect(guest_read(mem, 0x10000, out, 8) == GUEST_OK && out[0] == 0x20, "failed reloc did not change the qword");

    expect(guest_map(mem, 0x8000, 0x1000, GUEST_PERM_READ, file, 4) == GUEST_OK, "read-only page");
    expect(guest_write(mem, 0x8000, "Z", 1) == GUEST_ERR_PERM, "write to a read-only page fails");
    expect(guest_read(mem, 0x8000, out, 1) == GUEST_OK && out[0] == 0xAB, "read-only byte is unchanged");

    /* cross a page boundary */
    {
        uint8_t span[8];
        uint8_t back[8];
        for (i = 0; i < 8; i++)
            span[i] = (uint8_t)(0x10 + i);
        expect(guest_write(mem, 0x2FFC, span, 8) == GUEST_OK, "write across a page boundary");
        expect(guest_read(mem, 0x2FFC, back, 8) == GUEST_OK && memcmp(span, back, 8) == 0,
               "cross-page read matches");
    }

    {
        uint8_t before[8], after[8];
        uint8_t two[24];
        GuestMem *fresh;
        expect(guest_read(mem, 0x10000, before, 8) == GUEST_OK, "snapshot relocated qword");
        memset(two, 0, sizeof two);
        two[0] = 0x00; two[1] = 0x00; two[2] = 0x01; two[3] = 0x00;
        two[4] = 12; two[8] = 0x00; two[9] = 0xA0;
        two[12] = 0x00; two[13] = 0x00; two[14] = 0x02; two[15] = 0x00;
        two[16] = 12; two[20] = 0x00; two[21] = 0xA0;
        expect(guest_apply_dir64(mem, two, sizeof two, 1) != GUEST_OK, "later unmapped DIR64 fails");
        expect(guest_read(mem, 0x10000, after, 8) == GUEST_OK && memcmp(before, after, 8) == 0,
               "unmapped DIR64 target rolls back earlier writes");
        expect(guest_map(mem, 0x9000, 8, GUEST_PERM_READ, before, 8) == GUEST_OK, "read-only reloc target");
        two[12] = 0x00; two[13] = 0x90; two[14] = 0x00; two[15] = 0x00;
        expect(guest_apply_dir64(mem, two, sizeof two, 1) == GUEST_ERR_PERM, "read-only DIR64 target fails");
        expect(guest_read(mem, 0x10000, after, 8) == GUEST_OK && memcmp(before, after, 8) == 0,
               "read-only DIR64 target leaves earlier qwords unchanged");
        fresh = guest_create();
        expect(guest_map(fresh, 0x1000, 0x1000, GUEST_PERM_READ | GUEST_PERM_WRITE, file, 16) == GUEST_OK,
               "baseline page before a failed map");
        expect(guest_read(fresh, 0x1000, before, 8) == GUEST_OK, "baseline bytes");
        guest_test_fail_allocs_after(0);
        expect(guest_map(fresh, 0x4000, 0x3000, GUEST_PERM_READ | GUEST_PERM_WRITE, file, 4) == GUEST_ERR_NOMEM,
               "allocation failure is reported");
        guest_test_fail_allocs_after(-1);
        expect(guest_page_count(fresh) == 1, "failed map adds no pages");
        expect(guest_read(fresh, 0x1000, after, 8) == GUEST_OK && memcmp(before, after, 8) == 0,
               "failed map leaves previous bytes unchanged");
        expect(guest_read(fresh, 0x4000, after, 1) == GUEST_ERR_UNMAPPED, "failed range is not mapped");
        expect(guest_map(fresh, 0x7000, 0x800, GUEST_PERM_READ, file, 1) == GUEST_OK, "read-only half of a page");
        expect(guest_map(fresh, 0x7800, 0x800, GUEST_PERM_READ | GUEST_PERM_WRITE, file, 1) == GUEST_OK,
               "writable half of the same page");
        expect(guest_write(fresh, 0x7000, "Z", 1) == GUEST_ERR_PERM, "read-only half stays read-only");
        expect(guest_write(fresh, 0x7800, "Q", 1) == GUEST_OK, "writable half accepts a write");
        expect(guest_set_logical_execute(fresh, 0x7000, 0x800, 1) == GUEST_OK, "logical execute on one half");
        expect(guest_logical_execute(fresh, 0x7000) == 1, "requested half is marked");
        expect(guest_logical_execute(fresh, 0x7800) == 0, "neighbor span is not marked executable");
        expect(guest_host_executable(fresh) == 0, "mixed page is still not a host executable mapping");
        guest_destroy(fresh);
    }

    guest_destroy(mem);
    if (g_failures) {
        fprintf(stderr, "%d guest_mem checks failed\n", g_failures);
        return 1;
    }
    return 0;
}
