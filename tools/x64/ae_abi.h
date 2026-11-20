/* Unresolved-import registry and a tiny modeled kernel32 subset.

   Thunk ids follow import-directory order: (dll_index << 16) | symbol_index.
   Guest calls pass integer arguments only. They never receive a host pointer.
   Only GetCurrentProcessId, GetLastError, and SetLastError are modeled, and
   they use the synthetic AeProcess, not the host process. Every other import
   fails closed.
*/
#ifndef X64_AE_ABI_H
#define X64_AE_ABI_H

#include "pe_data.h"

#include <stdint.h>

enum {
    AE_OK = 0,
    AE_ERR_UNIMPLEMENTED = 1,
    AE_ERR_BAD_ID = 2,
    AE_ERR_ARITY = 3
};

typedef struct AeProcess {
    uint32_t process_id;
    uint32_t last_error;
} AeProcess;

typedef struct AeImport {
    uint32_t thunk_id;
    char dll[PE_DLL_NAME + 1];
    char name[PE_SYMBOL_NAME + 1];
    uint16_t ordinal;
    int by_ordinal;
    int modeled;
    const char *behavior;
} AeImport;

typedef struct AeRegistry {
    AeImport *items;
    int count;
    int dll_count;
} AeRegistry;

int ae_registry_from_image(const PeImage *image, AeRegistry **out);
void ae_registry_destroy(AeRegistry *registry);
/* args are the Windows x64 integer registers already marshaled: args[0] is RCX.
   On AE_ERR_UNIMPLEMENTED, *result and the process are left unchanged. */
int ae_dispatch(AeProcess *proc, const AeImport *items, int count, uint32_t thunk_id,
                const uint64_t *args, int nargs, uint64_t *result);

#endif
