#include "ae_iat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_host_called;

static void expect(int cond, const char *message) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", message);
        g_failures++;
    }
}

static void u16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void u32(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void u64w(uint8_t *p, unsigned long long v) {
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t read_qword(GuestMem *mem, uint64_t addr) {
    uint8_t raw[8];
    uint64_t value = 0;
    int i;
    if (guest_read(mem, addr, raw, 8) != GUEST_OK)
        return 0;
    for (i = 0; i < 8; i++)
        value |= (uint64_t)raw[i] << (8 * i);
    return value;
}

static void build(uint8_t *file) {
    memset(file, 0, 0xC00);
    file[0] = 'M';
    file[1] = 'Z';
    u32(file + 0x3C, 0x80);
    memcpy(file + 0x80, "PE\0\0", 4);
    u16(file + 0x84, 0x8664);
    u16(file + 0x86, 2);
    u16(file + 0x94, 0xF0);
    u16(file + 0x98, 0x20B);
    u32(file + 0x98 + 16, 0x1000);
    u64w(file + 0x98 + 24, 0x140000000ULL);
    u32(file + 0x98 + 56, 0x3000);
    u32(file + 0x98 + 108, 16);
    u32(file + 0x98 + 112 + 8, 0x2000);
    u32(file + 0x98 + 112 + 12, 40);
    memcpy(file + 0x188, ".text", 5);
    u32(file + 0x188 + 8, 0x1000);
    u32(file + 0x188 + 12, 0x1000);
    u32(file + 0x188 + 16, 0x200);
    u32(file + 0x188 + 20, 0x200);
    u32(file + 0x188 + 36, 0x60000020);
    memcpy(file + 0x188 + 40, ".data", 5);
    u32(file + 0x188 + 48, 0x800);
    u32(file + 0x188 + 52, 0x2000);
    u32(file + 0x188 + 56, 0x600);
    u32(file + 0x188 + 60, 0x400);
    u32(file + 0x188 + 76, 0x40000040);
    file[0x200] = 0xC3;
    u32(file + 0x400, 0x2060);
    u32(file + 0x40C, 0x2100);
    u32(file + 0x410, 0x20A0);
    u64w(file + 0x460, 0x2200);
    u64w(file + 0x468, 0x2240);
    u64w(file + 0x470, 0x2280);
    u64w(file + 0x478, 0x22C0);
    u64w(file + 0x4A0, 0x1111111111111111ULL);
    u64w(file + 0x4A8, 0x1111111111111111ULL);
    u64w(file + 0x4B0, 0x1111111111111111ULL);
    u64w(file + 0x4B8, 0x1111111111111111ULL);
    memcpy(file + 0x500, "KERNEL32.dll", 13);
    memcpy(file + 0x602, "GetLastError", 13);
    memcpy(file + 0x642, "SetLastError", 13);
    memcpy(file + 0x682, "GetCurrentProcessId", 20);
    memcpy(file + 0x6C2, "ExitProcess", 12);
}

static void host_fn(void) { g_host_called = 1; }

static void test_registry_ids(void) {
    PeImport *rows = calloc(135, sizeof *rows);
    PeImage image;
    AeRegistry *registry = NULL;
    int i;
    expect(rows != NULL, "id table allocated");
    if (rows == NULL)
        return;
    memset(&image, 0, sizeof image);
    memcpy(rows[0].dll, "STEAM_API64.dll", 16);
    memcpy(rows[0].name, "SteamAPI_Init", 14);
    for (i = 0; i < 134; i++) {
        memcpy(rows[1 + i].dll, "KERNEL32.dll", 13);
        memcpy(rows[1 + i].name, "Pad", 4);
    }
    memcpy(rows[1 + 63].name, "GetLastError", 13);
    memcpy(rows[1 + 133].name, "GetCurrentProcessId", 20);
    image.imports = rows;
    image.symbol_count = 135;
    image.import_count = 135;
    expect(ae_registry_from_image(&image, &registry) == AE_OK, "registry from the slot table");
    if (registry != NULL) {
        int modeled = 0, traps = 0, steam = 0, has_set = 0;
        expect(registry->dll_count == 2 && registry->count == 135, "two dlls, 135 symbols");
        expect(registry->items[1 + 63].thunk_id == 65599u, "GetLastError id matches the official image");
        expect(registry->items[1 + 133].thunk_id == 65669u, "GetCurrentProcessId id matches the official image");
        expect(((1u << 16) | 63u) == 65599u && ((1u << 16) | 133u) == 65669u, "id formula");
        for (i = 0; i < registry->count; i++) {
            if (registry->items[i].modeled)
                modeled++;
            else
                traps++;
            if (strcmp(registry->items[i].name, "SteamAPI_Init") == 0) {
                steam++;
                expect(!registry->items[i].modeled, "Steam is not modeled");
            }
            if (strcmp(registry->items[i].name, "SetLastError") == 0)
                has_set = 1;
        }
        expect(modeled == 2 && traps == 133 && steam == 1 && !has_set, "two modeled, SetLastError absent");
        ae_registry_destroy(registry);
    }
    free(rows);
}

int main(int argc, char **argv) {
    uint8_t file[0xC00];
    uint8_t original[0xC00];
    PeImage *image = NULL;
    AeRegistry *registry = NULL;
    AeBindReport report;
    AeThread thread;
    AeRunResult result;
    AeProcess proc, ref;
    uint64_t arg = 0x22, ref_rax = 0;
    uint64_t args[5];
    const char *reason = NULL;
    AeInsn program[8];
    build(file);
    memcpy(original, file, sizeof file);
    if (argc > 1) {
        FILE *fp = fopen(argv[1], "wb");
        if (fp == NULL)
            return 1;
        if (fwrite(file, 1, sizeof file, fp) != sizeof file) {
            fclose(fp);
            return 1;
        }
        fclose(fp);
    }
    test_registry_ids();
    expect(pe_load_unsealed(file, sizeof file, NULL, 1, &image) == PE_OK && image != NULL, "unsealed load");
    if (image == NULL)
        return 1;
    expect(!guest_is_sealed(image->mem), "loader has not sealed");
    expect(image->entry_called == 0 && image->imports_bound == 0, "load did not bind or enter");
    expect(guest_write(image->mem, 0x20A0, "Z", 1) == GUEST_ERR_PERM, "iat span is read-only");
    expect(read_qword(image->mem, 0x20A0) == 0x1111111111111111ULL, "readonly slot kept its file qword");
    expect(ae_registry_from_image(image, &registry) == AE_OK, "registry");
    expect(registry != NULL && registry->count == 4, "four synthetic imports");
    if (registry == NULL)
        return 1;
    expect(registry->items[0].modeled && registry->items[1].modeled && registry->items[2].modeled, "three modeled");
    expect(!registry->items[3].modeled && strcmp(registry->items[3].behavior, "unimplemented") == 0, "ExitProcess is a trap");
    image->imports[1].iat_rva = image->imports[0].iat_rva;
    expect(ae_bind_iat(image, registry, &report) == AE_ERR_BIND, "duplicate slot is refused");
    expect(report.reason != NULL && strcmp(report.reason, "iat slot collision") == 0, "collision is named");
    expect(read_qword(image->mem, 0x20A0) == 0x1111111111111111ULL, "refused bind wrote nothing");
    expect(image->imports_bound == 0, "refused bind stays unbound");
    image->imports[1].iat_rva = 0x20A8;
    ae_test_fail_store_at(2);
    expect(ae_bind_iat(image, registry, &report) == AE_ERR_BIND, "mid-bind store failure");
    expect(strcmp(report.reason, "store rolled back") == 0, "rollback is named");
    expect(read_qword(image->mem, 0x20A0) == 0x1111111111111111ULL, "first slot restored");
    expect(read_qword(image->mem, 0x20B0) == 0x1111111111111111ULL, "failed slot untouched");
    expect(image->imports_bound == 0 && image->entry_called == 0, "rolled back image is unbound");
    expect(ae_bind_iat(image, registry, &report) == AE_OK, "bind before seal");
    expect(report.modeled == 3 && report.traps == 1 && report.slots == 4, "three calls and one trap");
    expect(image->imports[0].resolved == 1 && image->imports[3].resolved == 0, "a trap is not a resolved success");
    expect(ae_token_decode(read_qword(image->mem, 0x20A0), NULL, NULL) == 1, "slot holds a guest token");
    expect((read_qword(image->mem, 0x20A0) & 0x8000000000000000ULL) != 0, "token is not a low host pointer");
    expect(read_qword(image->mem, 0x20B8) == ae_guest_token(AE_TOKEN_TRAP, registry->items[3].thunk_id), "trap token");
    expect(ae_bind_iat(image, registry, &report) == AE_OK, "second bind is idempotent");
    expect(read_qword(image->mem, 0x20A0) == ae_guest_token(AE_TOKEN_CALL, registry->items[0].thunk_id), "token unchanged");
    expect(guest_write(image->mem, 0x20A0, "Z", 1) == GUEST_ERR_PERM, "bind did not widen the iat");
    expect(file[0x200] == 0xC3 && memcmp(file, original, sizeof file) == 0, "source file was not written");
    expect(image->entry_called == 0 && guest_host_executable(image->mem) == 0, "bind is not execution");
    proc.process_id = 0xABCD;
    proc.last_error = 0x55;
    ref = proc;
    ae_dispatch(&ref, registry->items, registry->count, registry->items[1].thunk_id, &arg, 1, &ref_rax);
    ae_dispatch(&ref, registry->items, registry->count, registry->items[0].thunk_id, NULL, 0, &ref_rax);
    memset(program, 0, sizeof program);
    program[0].op = AE_OP_SET_GPR;
    program[0].gpr = AE_GPR_RCX;
    program[0].imm = 0x22;
    program[1].op = AE_OP_SUB_RSP;
    program[1].imm = 0x28;
    program[2].op = AE_OP_CALL_IAT;
    program[2].iat_rva = 0x20A8;
    program[3].op = AE_OP_ADD_RSP;
    program[3].imm = 0x28;
    program[4].op = AE_OP_SUB_RSP;
    program[4].imm = 0x28;
    program[5].op = AE_OP_CALL_IAT;
    program[5].iat_rva = 0x20A0;
    program[6].op = AE_OP_ADD_RSP;
    program[6].imm = 0x28;
    program[7].op = AE_OP_HALT;
    ae_thread_init(&thread, 16, 4);
    expect(ae_run(image->mem, &proc, registry, program, 8, &thread, &result) == AE_OK, "call through the iat");
    expect(result.rax == ref_rax && result.rax == 0x22, "result matches the reference shim");
    expect(proc.last_error == ref.last_error && proc.process_id == 0xABCD, "virtual thread state matches the shim");
    expect(image->entry_called == 0, "the program did not enter the image");
    ae_thread_init(&thread, 16, 4);
    program[2].iat_rva = 0x20B8;
    program[5].op = AE_OP_HALT;
    proc.last_error = 0x55;
    expect(ae_run(image->mem, &proc, registry, program, 6, &thread, &result) == AE_ERR_TRAP, "trap token");
    expect(result.trap != NULL && strcmp(result.trap, "unimplemented-import") == 0, "trap is named");
    expect(result.rax == 0 && proc.last_error == 0x55, "trap does not invent a success");
    {
        uint8_t raw[8];
        uint64_t host = (uint64_t)(uintptr_t)host_fn;
        int b;
        g_host_called = 0;
        for (b = 0; b < 8; b++)
            raw[b] = (uint8_t)(host >> (8 * b));
        expect(guest_loader_store(image->mem, 0x20A0, raw, 8) == GUEST_OK, "plant an illegal target");
        ae_thread_init(&thread, 8, 4);
        program[2].iat_rva = 0x20A0;
        program[2].op = AE_OP_CALL_IAT;
        expect(ae_run(image->mem, &proc, registry, program, 3, &thread, &result) == AE_ERR_ILLEGAL, "illegal target");
        expect(strcmp(result.trap, "illegal-target") == 0 && g_host_called == 0, "a host pointer was not called");
        expect(proc.last_error == 0x55, "illegal target left the thread alone");
    }
    ae_thread_init(&thread, 1, 4);
    program[0].op = AE_OP_SUB_RSP;
    program[0].imm = 0x28;
    program[1].op = AE_OP_CALL_IAT;
    program[1].iat_rva = 0x20A8;
    expect(ae_run(image->mem, &proc, registry, program, 2, &thread, &result) == AE_ERR_BUDGET, "step budget");
    expect(strcmp(result.trap, "step-budget") == 0 && proc.last_error == 0x55, "budget stops before the call");
    ae_thread_init(&thread, 8, 0);
    program[0].op = AE_OP_SUB_RSP;
    program[1].op = AE_OP_CALL_IAT;
    program[1].iat_rva = 0x20A8;
    expect(ae_run(image->mem, &proc, registry, program, 2, &thread, &result) == AE_ERR_DEPTH, "depth budget");
    expect(strcmp(result.trap, "depth-budget") == 0, "depth is named");
    ae_thread_init(&thread, 8, 4);
    program[0].op = AE_OP_CALL_IAT;
    program[0].iat_rva = 0x20A8;
    expect(ae_run(image->mem, &proc, registry, program, 1, &thread, &result) == AE_ERR_ALIGN, "alignment");
    expect(strcmp(result.trap, "misaligned-stack") == 0, "alignment is named");
    ae_thread_init(&thread, 8, 4);
    thread.gpr[AE_GPR_RSP] = (uint64_t)AE_VSTACK_BASE - 8u;
    expect(ae_run(image->mem, &proc, registry, program, 1, &thread, &result) == AE_ERR_ALIGN, "shadow");
    expect(strcmp(result.trap, "shadow-space") == 0, "shadow space is named");
    ae_thread_init(&thread, 8, 4);
    thread.gpr[AE_GPR_RSP] = (uint64_t)AE_VSTACK_BASE - 0x38u;
    thread.gpr[AE_GPR_RCX] = 0x11;
    {
        size_t off = (size_t)((thread.gpr[AE_GPR_RSP] + 0x28) - ((uint64_t)AE_VSTACK_BASE - AE_VSTACK_BYTES));
        int b;
        for (b = 0; b < 8; b++)
            thread.stack[off + (size_t)b] = (uint8_t)(0x99 >> (8 * b));
    }
    expect(ae_marshal_win64(&thread, 5, args, &reason) == AE_OK, "marshal");
    expect(args[0] == 0x11 && args[4] == 0x99, "rcx and the stack argument are integers");
    guest_seal(image->mem);
    expect(ae_bind_iat(image, registry, &report) == AE_ERR_BIND, "sealed image refuses another bind");
    expect(strcmp(report.reason, "sealed image") == 0, "seal refusal is named");
    expect(guest_loader_store(image->mem, 0x20A0, "xxxxxxxx", 8) == GUEST_ERR_PERM, "sealed loader store is refused");
    ae_registry_destroy(registry);
    pe_image_destroy(image);
    if (g_failures) {
        fprintf(stderr, "%d iat checks failed\n", g_failures);
        return 1;
    }
    return 0;
}
