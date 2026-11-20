#include "ae_abi.h"

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
    PeImport rows[4];
    PeImage image;
    AeRegistry *first = NULL;
    AeRegistry *second = NULL;
    AeProcess proc;
    uint64_t result = 0xdeadbeefdeadbeefULL;
    uint64_t arg = 0x22;
    uint32_t saved;
    memset(&image, 0, sizeof image);
    memset(rows, 0, sizeof rows);
    memcpy(rows[0].dll, "KERNEL32.dll", 13);
    memcpy(rows[0].name, "GetCurrentProcessId", 20);
    memcpy(rows[1].dll, "KERNEL32.dll", 13);
    memcpy(rows[1].name, "SetLastError", 13);
    memcpy(rows[2].dll, "KERNEL32.dll", 13);
    memcpy(rows[2].name, "GetLastError", 13);
    memcpy(rows[3].dll, "KERNEL32.dll", 13);
    memcpy(rows[3].name, "ExitProcess", 12);
    image.imports = rows;
    image.symbol_count = 4;
    image.import_count = 4;
    expect(ae_registry_from_image(&image, &first) == AE_OK, "registry builds");
    expect(ae_registry_from_image(&image, &second) == AE_OK, "registry builds again");
    if (first != NULL && second != NULL) {
        int i;
        expect(first->count == 4 && first->dll_count == 1, "four symbols, one dll");
        for (i = 0; i < 4; i++) {
            expect(first->items[i].thunk_id == second->items[i].thunk_id, "thunk ids are stable");
            expect(first->items[i].thunk_id == (uint32_t)i, "ids follow directory order");
        }
        expect(first->items[0].modeled && first->items[1].modeled && first->items[2].modeled,
               "three kernel32 queries are modeled");
        expect(strcmp(first->items[0].behavior, "synthetic-process") == 0, "modeled label");
        expect(!first->items[3].modeled && strcmp(first->items[3].behavior, "unimplemented") == 0,
               "ExitProcess is not a success stub");
        proc.process_id = 0x1111;
        proc.last_error = 7;
        expect(ae_dispatch(&proc, first->items, first->count, 1, &arg, 1, &result) == AE_OK, "SetLastError");
        expect(proc.last_error == 0x22 && result == 0, "error is the marshaled integer");
        result = 0;
        expect(ae_dispatch(&proc, first->items, first->count, 2, NULL, 0, &result) == AE_OK, "GetLastError");
        expect(result == 0x22, "GetLastError reads synthetic thread state");
        result = 0;
        expect(ae_dispatch(&proc, first->items, first->count, 0, NULL, 0, &result) == AE_OK, "GetCurrentProcessId");
        expect(result == 0x1111, "process id is the virtual process, not the host");
        saved = proc.last_error;
        result = 0xdeadbeefdeadbeefULL;
        expect(ae_dispatch(&proc, first->items, first->count, 3, NULL, 0, &result) == AE_ERR_UNIMPLEMENTED,
               "unimplemented import fails closed");
        expect(result == 0xdeadbeefdeadbeefULL && proc.last_error == saved, "failure does not invent a return");
        ae_registry_destroy(first);
        ae_registry_destroy(second);
    }
    if (g_failures) {
        fprintf(stderr, "%d abi registry checks failed\n", g_failures);
        return 1;
    }
    return 0;
}
