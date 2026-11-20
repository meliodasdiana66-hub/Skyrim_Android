#include "ae_iat.h"

#include <stdlib.h>
#include <string.h>

static int g_fail_store_at = -1;

void ae_test_fail_store_at(int index) {
    g_fail_store_at = index;
}

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

static int rows_match(const PeImport *image_row, const AeImport *reg_row) {
    if (image_row->by_ordinal != reg_row->by_ordinal)
        return 0;
    if (image_row->by_ordinal)
        return image_row->ordinal == reg_row->ordinal && same_text(image_row->dll, reg_row->dll);
    return same_text(image_row->dll, reg_row->dll) && same_text(image_row->name, reg_row->name);
}

static int stack_offset(uint64_t addr, size_t *off) {
    uint64_t lo = (uint64_t)AE_VSTACK_BASE - (uint64_t)AE_VSTACK_BYTES;
    if (addr < lo || addr >= (uint64_t)AE_VSTACK_BASE)
        return 0;
    *off = (size_t)(addr - lo);
    return 1;
}

static void fail_report(AeBindReport *report, const char *reason) {
    if (report == NULL)
        return;
    report->modeled = 0;
    report->traps = 0;
    report->slots = 0;
    report->reason = reason;
}

int ae_bind_iat(PeImage *image, const AeRegistry *registry, AeBindReport *report) {
    int i, modeled = 0, traps = 0;
    uint8_t *saved = NULL;
    if (report != NULL) {
        report->modeled = 0;
        report->traps = 0;
        report->slots = 0;
        report->reason = NULL;
    }
    if (image == NULL || image->mem == NULL || registry == NULL)
        return AE_ERR_BIND;
    if (guest_is_sealed(image->mem)) {
        fail_report(report, "sealed image");
        return AE_ERR_BIND;
    }
    if (registry->count != image->symbol_count || registry->count < 0 ||
        (registry->count > 0 && (image->imports == NULL || registry->items == NULL))) {
        fail_report(report, "registry count mismatch");
        return AE_ERR_BIND;
    }
    if (registry->count == 0) {
        image->imports_bound = 1;
        return AE_OK;
    }
    saved = malloc((size_t)registry->count * 8u);
    if (saved == NULL) {
        fail_report(report, "out of memory");
        return AE_ERR_BIND;
    }
    for (i = 0; i < registry->count; i++) {
        const PeImport *slot = &image->imports[i];
        const AeImport *row = &registry->items[i];
        uint64_t token;
        int kind;
        int j;
        if (!rows_match(slot, row)) {
            free(saved);
            fail_report(report, "import name mismatch");
            return AE_ERR_BIND;
        }
        if ((slot->iat_rva & 7u) != 0 || slot->iat_rva > image->size_of_image ||
            slot->iat_rva + 8u < slot->iat_rva || slot->iat_rva + 8u > image->size_of_image) {
            free(saved);
            fail_report(report, "iat slot out of bounds");
            return AE_ERR_BIND;
        }
        if (guest_read(image->mem, slot->iat_rva, saved + (size_t)i * 8u, 8) != GUEST_OK) {
            free(saved);
            fail_report(report, "unmapped iat slot");
            return AE_ERR_BIND;
        }
        kind = row->modeled ? AE_TOKEN_CALL : AE_TOKEN_TRAP;
        token = ae_guest_token(kind, row->thunk_id);
        if (token < image->size_of_image || ae_token_decode(token, NULL, NULL) == 0) {
            free(saved);
            fail_report(report, "token aliases image");
            return AE_ERR_BIND;
        }
        for (j = 0; j < i; j++) {
            uint32_t previous_id = 0;
            int previous_kind = 0;
            uint64_t previous = ae_guest_token(registry->items[j].modeled ? AE_TOKEN_CALL : AE_TOKEN_TRAP,
                                               registry->items[j].thunk_id);
            if (image->imports[j].iat_rva == slot->iat_rva) {
                free(saved);
                fail_report(report, "iat slot collision");
                return AE_ERR_BIND;
            }
            if (previous == token ||
                (ae_token_decode(previous, &previous_kind, &previous_id) &&
                 previous_id == row->thunk_id && previous_kind == kind)) {
                free(saved);
                fail_report(report, "thunk token collision");
                return AE_ERR_BIND;
            }
        }
        if (row->modeled)
            modeled++;
        else
            traps++;
    }
    for (i = 0; i < registry->count; i++) {
        uint64_t token = ae_guest_token(registry->items[i].modeled ? AE_TOKEN_CALL : AE_TOKEN_TRAP,
                                        registry->items[i].thunk_id);
        uint8_t raw[8];
        int b;
        if (g_fail_store_at == i) {
            int back;
            for (back = 0; back < i; back++)
                guest_loader_store(image->mem, image->imports[back].iat_rva, saved + (size_t)back * 8u, 8);
            free(saved);
            g_fail_store_at = -1;
            fail_report(report, "store rolled back");
            return AE_ERR_BIND;
        }
        for (b = 0; b < 8; b++)
            raw[b] = (uint8_t)(token >> (8 * b));
        if (guest_loader_store(image->mem, image->imports[i].iat_rva, raw, 8) != GUEST_OK) {
            int back;
            for (back = 0; back < i; back++)
                guest_loader_store(image->mem, image->imports[back].iat_rva, saved + (size_t)back * 8u, 8);
            free(saved);
            fail_report(report, "store rolled back");
            return AE_ERR_BIND;
        }
        image->imports[i].resolved = registry->items[i].modeled ? 1 : 0;
    }
    free(saved);
    image->imports_bound = 1;
    image->entry_called = 0;
    if (report != NULL) {
        report->modeled = modeled;
        report->traps = traps;
        report->slots = registry->count;
        report->reason = NULL;
    }
    return AE_OK;
}

void ae_thread_init(AeThread *thread, uint32_t steps, int max_depth) {
    int i;
    if (thread == NULL)
        return;
    memset(thread, 0, sizeof *thread);
    for (i = 0; i < 16; i++)
        thread->gpr[i] = 0;
    thread->gpr[AE_GPR_RSP] = AE_VSTACK_BASE;
    thread->steps_left = steps;
    thread->max_depth = max_depth;
}

int ae_marshal_win64(const AeThread *thread, int nargs, uint64_t *args, const char **reason) {
    static const int regs[4] = {AE_GPR_RCX, AE_GPR_RDX, AE_GPR_R8, AE_GPR_R9};
    int n;
    if (reason != NULL)
        *reason = NULL;
    if (thread == NULL || nargs < 0 || (nargs > 0 && args == NULL))
        return AE_ERR_ARITY;
    if ((thread->gpr[AE_GPR_RSP] & 0xF) != 8) {
        if (reason != NULL)
            *reason = "misaligned-stack";
        return AE_ERR_ALIGN;
    }
    {
        size_t shadow;
        if (!stack_offset(thread->gpr[AE_GPR_RSP] + 8, &shadow) ||
            !stack_offset(thread->gpr[AE_GPR_RSP] + 0x27, &shadow)) {
            if (reason != NULL)
                *reason = "shadow-space";
            return AE_ERR_ALIGN;
        }
    }
    for (n = 0; n < nargs; n++) {
        if (n < 4) {
            args[n] = thread->gpr[regs[n]];
            continue;
        }
        {
            uint64_t addr = thread->gpr[AE_GPR_RSP] + 0x28 + (uint64_t)(n - 4) * 8u;
            size_t off;
            int b;
            uint64_t value = 0;
            if (!stack_offset(addr, &off) || !stack_offset(addr + 7, &off)) {
                if (reason != NULL)
                    *reason = "stack-argument";
                return AE_ERR_ARITY;
            }
            stack_offset(addr, &off);
            for (b = 0; b < 8; b++)
                value |= (uint64_t)thread->stack[off + (size_t)b] << (8 * b);
            args[n] = value;
        }
    }
    return AE_OK;
}

static const AeImport *find_id(const AeRegistry *registry, uint32_t thunk_id) {
    int i;
    if (registry == NULL)
        return NULL;
    for (i = 0; i < registry->count; i++) {
        if (registry->items[i].thunk_id == thunk_id)
            return &registry->items[i];
    }
    return NULL;
}

static int modeled_arity(const AeImport *row) {
    if (same_text(row->name, "SetLastError"))
        return 1;
    if (same_text(row->name, "GetLastError") || same_text(row->name, "GetCurrentProcessId"))
        return 0;
    return 0;
}

int ae_run(GuestMem *mem, AeProcess *proc, const AeRegistry *registry,
           const AeInsn *insns, int count, AeThread *thread, AeRunResult *out) {
    int ip;
    if (out != NULL) {
        out->status = AE_ERR_BUDGET;
        out->rax = 0;
        out->trap = NULL;
    }
    if (mem == NULL || proc == NULL || registry == NULL || thread == NULL || out == NULL)
        return AE_ERR_BIND;
    if (count > 0 && insns == NULL)
        return AE_ERR_BIND;
    for (ip = 0; ip < count; ip++) {
        const AeInsn *insn = &insns[ip];
        if (thread->steps_left == 0) {
            out->status = AE_ERR_BUDGET;
            out->trap = "step-budget";
            out->rax = thread->gpr[AE_GPR_RAX];
            return AE_ERR_BUDGET;
        }
        thread->steps_left--;
        if (insn->op == AE_OP_HALT) {
            out->status = AE_OK;
            out->rax = thread->gpr[AE_GPR_RAX];
            out->trap = NULL;
            return AE_OK;
        }
        if (insn->op == AE_OP_SET_GPR) {
            if (insn->gpr < 0 || insn->gpr > 15)
                return AE_ERR_ILLEGAL;
            thread->gpr[insn->gpr] = insn->imm;
            continue;
        }
        if (insn->op == AE_OP_SUB_RSP) {
            if (insn->imm > thread->gpr[AE_GPR_RSP])
                return AE_ERR_ALIGN;
            thread->gpr[AE_GPR_RSP] -= insn->imm;
            continue;
        }
        if (insn->op == AE_OP_ADD_RSP) {
            thread->gpr[AE_GPR_RSP] += insn->imm;
            continue;
        }
        if (insn->op == AE_OP_CALL_IAT) {
            uint8_t raw[8];
            uint64_t target = 0;
            uint64_t args[8];
            uint64_t result = thread->gpr[AE_GPR_RAX];
            uint32_t thunk_id = 0;
            int kind = 0;
            int b, rc;
            const AeImport *row;
            const char *reason = NULL;
            if ((thread->gpr[AE_GPR_RSP] & 0xF) != 8) {
                out->status = AE_ERR_ALIGN;
                out->trap = "misaligned-stack";
                out->rax = thread->gpr[AE_GPR_RAX];
                return AE_ERR_ALIGN;
            }
            {
                size_t shadow;
                if (!stack_offset(thread->gpr[AE_GPR_RSP] + 8, &shadow) ||
                    !stack_offset(thread->gpr[AE_GPR_RSP] + 0x27, &shadow)) {
                    out->status = AE_ERR_ALIGN;
                    out->trap = "shadow-space";
                    out->rax = thread->gpr[AE_GPR_RAX];
                    return AE_ERR_ALIGN;
                }
            }
            if (guest_read(mem, insn->iat_rva, raw, 8) != GUEST_OK) {
                out->status = AE_ERR_ILLEGAL;
                out->trap = "unmapped-target";
                out->rax = thread->gpr[AE_GPR_RAX];
                return AE_ERR_ILLEGAL;
            }
            for (b = 0; b < 8; b++)
                target |= (uint64_t)raw[b] << (8 * b);
            if (thread->depth >= thread->max_depth) {
                out->status = AE_ERR_DEPTH;
                out->trap = "depth-budget";
                out->rax = thread->gpr[AE_GPR_RAX];
                return AE_ERR_DEPTH;
            }
            if (!ae_token_decode(target, &kind, &thunk_id) || (row = find_id(registry, thunk_id)) == NULL) {
                out->status = AE_ERR_ILLEGAL;
                out->trap = "illegal-target";
                out->rax = thread->gpr[AE_GPR_RAX];
                return AE_ERR_ILLEGAL;
            }
            thread->depth++;
            if (kind == AE_TOKEN_TRAP || !row->modeled) {
                thread->depth--;
                out->status = AE_ERR_TRAP;
                out->trap = "unimplemented-import";
                out->rax = thread->gpr[AE_GPR_RAX];
                return AE_ERR_TRAP;
            }
            rc = ae_marshal_win64(thread, modeled_arity(row), args, &reason);
            if (rc != AE_OK) {
                thread->depth--;
                out->status = rc;
                out->trap = reason;
                out->rax = thread->gpr[AE_GPR_RAX];
                return rc;
            }
            rc = ae_dispatch(proc, registry->items, registry->count, thunk_id, args, modeled_arity(row), &result);
            thread->depth--;
            if (rc != AE_OK) {
                out->status = rc;
                out->trap = rc == AE_ERR_UNIMPLEMENTED ? "unimplemented-import" : "dispatch-failed";
                out->rax = thread->gpr[AE_GPR_RAX];
                return rc;
            }
            thread->gpr[AE_GPR_RAX] = result;
            continue;
        }
        out->status = AE_ERR_ILLEGAL;
        out->trap = "illegal-opcode";
        out->rax = thread->gpr[AE_GPR_RAX];
        return AE_ERR_ILLEGAL;
    }
    out->status = AE_OK;
    out->rax = thread->gpr[AE_GPR_RAX];
    return AE_OK;
}
