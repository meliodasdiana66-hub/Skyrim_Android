#include "ae_abi.h"

#include <stdlib.h>
#include <string.h>

static int same_text(const char *a, const char *b) {
    size_t i;
    if (a == NULL || b == NULL)
        return 0;
    for (i = 0; a[i] != 0 && b[i] != 0; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb - 'A' + 'a');
        if (ca != cb)
            return 0;
    }
    return a[i] == 0 && b[i] == 0;
}

static int modeled_behavior(const char *dll, const char *name, const char **behavior) {
    if (!same_text(dll, "KERNEL32.dll"))
        return 0;
    if (same_text(name, "GetCurrentProcessId") || same_text(name, "GetLastError") ||
        same_text(name, "SetLastError")) {
        *behavior = "synthetic-process";
        return 1;
    }
    return 0;
}

int ae_registry_from_image(const PeImage *image, AeRegistry **out) {
    AeRegistry *registry;
    int i, dlls, symbol_in_dll;
    const char *previous = "";
    if (out == NULL)
        return AE_ERR_BAD_ID;
    *out = NULL;
    if (image == NULL)
        return AE_ERR_BAD_ID;
    registry = calloc(1, sizeof *registry);
    if (registry == NULL)
        return AE_ERR_BAD_ID;
    if (image->symbol_count > 0) {
        registry->items = calloc((size_t)image->symbol_count, sizeof(AeImport));
        if (registry->items == NULL) {
            free(registry);
            return AE_ERR_BAD_ID;
        }
    }
    dlls = 0;
    symbol_in_dll = 0;
    for (i = 0; i < image->symbol_count; i++) {
        AeImport *row = &registry->items[i];
        const char *behavior = "unimplemented";
        if (!same_text(previous, image->imports[i].dll)) {
            if (i != 0)
                dlls++;
            symbol_in_dll = 0;
            previous = image->imports[i].dll;
        }
        row->thunk_id = ((uint32_t)dlls << 16) | (uint32_t)symbol_in_dll;
        memcpy(row->dll, image->imports[i].dll, sizeof row->dll);
        memcpy(row->name, image->imports[i].name, sizeof row->name);
        row->ordinal = image->imports[i].ordinal;
        row->by_ordinal = image->imports[i].by_ordinal;
        row->modeled = modeled_behavior(row->dll, row->name, &behavior);
        row->behavior = behavior;
        symbol_in_dll++;
    }
    if (image->symbol_count > 0)
        dlls++;
    registry->count = image->symbol_count;
    registry->dll_count = dlls;
    *out = registry;
    return AE_OK;
}

void ae_registry_destroy(AeRegistry *registry) {
    if (registry == NULL)
        return;
    free(registry->items);
    free(registry);
}
