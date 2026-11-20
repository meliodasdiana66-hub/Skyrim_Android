/* Sparse guest data pages for the AE prototype.

   Pages are host data allocations. GUEST_PERM_EXECUTE is refused and
   guest_host_executable is always 0. A logical execute flag is per mapped
   span, not a host mapping and not a permission to write.

   Permissions belong to address spans. Two sections may share a 4 KiB page
   and keep different read/write flags; a writable neighbor does not widen a
   read-only span. guest_map and guest_apply_dir64 either commit completely
   or leave the previous bytes and spans unchanged.
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

/* 64 MiB of 4 KiB pages. The 59 MiB Skyrim image fits. Larger requests fail. */
enum { GUEST_PAGE_SIZE = 4096, GUEST_MAX_PAGES = 16384 };

typedef struct GuestMem GuestMem;

GuestMem *guest_create(void);
void guest_destroy(GuestMem *mem);
int guest_host_executable(const GuestMem *mem);
int guest_page_count(const GuestMem *mem);
/* Test hook. The next n guest allocations succeed, then one fails.
   Pass a negative value to disable. */
void guest_test_fail_allocs_after(int n);
void guest_reset_counters(void);
uint64_t guest_lookup_count(void);
uint64_t guest_span_visit_count(void);
/* Loader-only DIR64. Writes page bytes directly and does not change span
   permissions. Refused after guest_seal. A failure restores every qword
   this call changed. */
int guest_loader_reloc(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta);
/* Loader-only store. Does not change span permissions and does not make a
   host page executable. Refused after guest_seal. */
int guest_loader_store(GuestMem *mem, uint64_t addr, const void *src, size_t n);
void guest_seal(GuestMem *mem);
int guest_is_sealed(const GuestMem *mem);
int guest_map(GuestMem *mem, uint64_t addr, size_t size, int perms,
              const uint8_t *file_bytes, size_t file_len);
int guest_read(GuestMem *mem, uint64_t addr, void *dst, size_t n);
int guest_write(GuestMem *mem, uint64_t addr, const void *src, size_t n);
/* Type 10 adds delta. Unknown types and unmapped or read-only targets fail
   with no qword changed. Nothing is called. */
int guest_apply_dir64(GuestMem *mem, const uint8_t *reloc, size_t reloc_len, uint64_t delta);
int guest_set_logical_execute(GuestMem *mem, uint64_t addr, size_t size, int enabled);
int guest_logical_execute(const GuestMem *mem, uint64_t addr);

#endif
