#include "ae_abi.h"

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

int ae_dispatch(AeProcess *proc, const AeImport *items, int count, uint32_t thunk_id,
                const uint64_t *args, int nargs, uint64_t *result) {
    int i;
    const AeImport *hit = NULL;
    if (proc == NULL || result == NULL || count < 0 || (count > 0 && items == NULL))
        return AE_ERR_BAD_ID;
    for (i = 0; i < count; i++) {
        if (items[i].thunk_id == thunk_id) {
            hit = &items[i];
            break;
        }
    }
    if (hit == NULL || !hit->modeled)
        return hit == NULL ? AE_ERR_BAD_ID : AE_ERR_UNIMPLEMENTED;
    if (same_text(hit->name, "GetCurrentProcessId")) {
        if (nargs != 0)
            return AE_ERR_ARITY;
        *result = proc->process_id;
        return AE_OK;
    }
    if (same_text(hit->name, "GetLastError")) {
        if (nargs != 0)
            return AE_ERR_ARITY;
        *result = proc->last_error;
        return AE_OK;
    }
    if (same_text(hit->name, "SetLastError")) {
        if (nargs != 1 || args == NULL)
            return AE_ERR_ARITY;
        proc->last_error = (uint32_t)args[0];
        *result = 0;
        return AE_OK;
    }
    return AE_ERR_UNIMPLEMENTED;
}
