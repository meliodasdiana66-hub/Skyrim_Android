/* Guest IAT tokens and a tiny call interpreter.

   A token is a guest address with the high bit set. It is not a host pointer
   and it is not an executable page. Only ae_run may consume one, and only
   when the id is in the bound registry. The default data loader does not
   call ae_bind_iat.
*/
#ifndef X64_AE_IAT_H
#define X64_AE_IAT_H

#include "ae_abi.h"

enum { AE_TOKEN_CALL = 1, AE_TOKEN_TRAP = 2 };

/* Above every RVA this loader can map (the image cap is 64 MiB).
   Bit 63 is also IMAGE_ORDINAL_FLAG64 on an unbound import thunk.
   A token is accepted only when kind and id rebuild this exact value. */
static inline uint64_t ae_guest_token(int kind, uint32_t thunk_id) {
    return 0x8000000000000000ULL | ((uint64_t)(kind & 0xF) << 36) |
           ((uint64_t)(thunk_id & 0x0FFFFFFFu) << 4);
}

static inline int ae_token_decode(uint64_t token, int *kind, uint32_t *thunk_id) {
    uint32_t id = (uint32_t)((token >> 4) & 0x0FFFFFFFu);
    int got = (int)((token >> 36) & 0xF);
    if (token != ae_guest_token(got, id))
        return 0;
    if (got != AE_TOKEN_CALL && got != AE_TOKEN_TRAP)
        return 0;
    if (kind != NULL)
        *kind = got;
    if (thunk_id != NULL)
        *thunk_id = id;
    return 1;
}

typedef struct AeBindReport {
    int modeled;
    int traps;
    int slots;
    const char *reason;
} AeBindReport;

/* Writes one guest token into each IAT slot. Modeled imports get a call
   token. Every other import gets a trap token, not a success stub.
   Preflight covers every slot before the first write. A later failure
   restores the previous qwords. Refused after guest_seal. */
int ae_bind_iat(PeImage *image, const AeRegistry *registry, AeBindReport *report);
/* Test hook. The store at this slot index fails and earlier stores roll back.
   Pass a negative value to disable. */
void ae_test_fail_store_at(int index);

enum {
    AE_GPR_RAX = 0,
    AE_GPR_RCX = 1,
    AE_GPR_RDX = 2,
    AE_GPR_RSP = 4,
    AE_GPR_R8 = 8,
    AE_GPR_R9 = 9,
    AE_VSTACK_BASE = 0x20000,
    AE_VSTACK_BYTES = 4096
};

enum {
    AE_OP_SET_GPR = 1,
    AE_OP_SUB_RSP = 2,
    AE_OP_ADD_RSP = 3,
    AE_OP_CALL_IAT = 4,
    AE_OP_HALT = 5
};

typedef struct AeInsn {
    int op;
    int gpr;
    uint64_t imm;
    uint32_t iat_rva;
} AeInsn;

typedef struct AeThread {
    uint64_t gpr[16];
    uint8_t stack[AE_VSTACK_BYTES];
    uint32_t steps_left;
    int depth;
    int max_depth;
} AeThread;

typedef struct AeRunResult {
    int status;
    uint64_t rax;
    const char *trap;
} AeRunResult;

void ae_thread_init(AeThread *thread, uint32_t steps, int max_depth);
/* Runs a synthetic instruction list. It does not fetch bytes from the image
   and it does not call the PE entry point. CALL_IAT reads one guest qword
   and accepts only a registered token. */
int ae_run(GuestMem *mem, AeProcess *proc, const AeRegistry *registry,
           const AeInsn *insns, int count, AeThread *thread, AeRunResult *out);
/* Windows x64 integer arguments: RCX, RDX, R8, R9, then [rsp+0x28]. The
   values are integers copied out of the virtual thread. No host pointer is
   returned. */
int ae_marshal_win64(const AeThread *thread, int nargs, uint64_t *args, const char **reason);

#endif
