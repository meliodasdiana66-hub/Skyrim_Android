/* Sparse guest data pages for the AE prototype.

   This is not a loader. It never creates an executable host mapping, never
   calls guest code, and never binds an import. EXECUTE is refused.
   A logical execute bit may be recorded for a PE section and is only a flag.
*/
#ifndef X64_GUEST_MEM_H
#define X64_GUEST_MEM_H

#include <stddef.h>
#include <stdint.h>

enum {
    GUEST_PERM_READ = 1,
    GUEST_PERM_WRITE = 2,
    GUEST_PERM_EXECUTE = 4
};

enum {
    GUEST_OK = 0,
    GUEST_ERR_PERM = 1,
    GUEST_ERR_UNMAPPED = 2,
    GUEST_ERR_EXEC = 3,
    GUEST_ERR_RELOC = 4,
    GUEST_ERR_RANGE = 5,
    GUEST_ERR_NOMEM = 6
};

typedef struct GuestMem GuestMem;

GuestMem *guest_create(void);
void guest_destroy(GuestMem *mem);
/* Always zero. Host pages created here are data pages. */
int guest_host_executable(const GuestMem *mem);
int guest_map(GuestMem *mem, uint64_t addr, size_t size, int perms,
              const uint8_t *file_bytes, size_t file_len);
int guest_read(GuestMem *mem, uint64_t addr, void *dst, size_t n);
int guest_write(GuestMem *mem, uint64_t addr, const void *src, size_t n);
/* Apply a PE relocation directory. Type 10 adds delta. Any other type fails
   and leaves the image unchanged. Nothing is called. */
int guest_apply_dir64(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta);
int guest_set_logical_execute(GuestMem *mem, uint64_t addr, size_t size, int enabled);
int guest_logical_execute(const GuestMem *mem, uint64_t addr);

#endif
