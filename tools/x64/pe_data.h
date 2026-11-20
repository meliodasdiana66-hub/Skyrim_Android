/* PE32+ data loader on top of guest_mem.

   Maps section bytes and zero-fill into data pages. Records import names as
   unresolved. Does not call the entry point, does not bind an IAT slot, and
   does not request an executable host page. A logical execute flag is only
   a section characteristic.
*/
#ifndef X64_PE_DATA_H
#define X64_PE_DATA_H

#include "guest_mem.h"

#include <stddef.h>
#include <stdint.h>

enum {
    PE_MAX_IMAGE = 64u * 1024u * 1024u,
    PE_MAX_DLLS = 256,
    PE_MAX_SYMBOLS = 16384,
    /* Usable characters, not counting the trailing NUL. DLL names stay short.
       Symbol names must hold MSVC decorated forms (observed up to 109). */
    PE_DLL_NAME = 64,
    PE_SYMBOL_NAME = 256
};

enum {
    PE_OK = 0,
    PE_ERR_FORMAT = 1,
    PE_ERR_RANGE = 2,
    PE_ERR_NOMEM = 3,
    PE_ERR_RELOC = 4,
    PE_ERR_NAME = 5
};

typedef struct PeImport {
    char dll[PE_DLL_NAME + 1];
    char name[PE_SYMBOL_NAME + 1];
    uint16_t ordinal;
    int by_ordinal;
    uint32_t iat_rva;
    int resolved;
} PeImport;

typedef struct PeImage {
    GuestMem *mem;
    uint64_t preferred_base;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t entry_rva;
    int entry_called;
    int imports_bound;
    int relocations_applied;
    int section_count;
    int dll_count;
    int symbol_count;
    int import_count;
    PeImport *imports;
} PeImage;

/* host_read_only forces every span to GUEST_PERM_READ. new_base NULL keeps
   the preferred base and does not apply relocations. On failure *out is NULL
   and no guest pages remain. */
int pe_load_data(const uint8_t *file, size_t file_len, const uint64_t *new_base,
                 int host_read_only, PeImage **out);
void pe_image_destroy(PeImage *image);

#endif
