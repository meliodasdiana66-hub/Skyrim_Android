/* Host helpers for synthetic x64 snippets lifted by tools/x64/lift64.py.
 * This is not a game loader. MEMSZ is a 64 KiB identity-mapped guest window. */
#ifndef SNIPPET_RT_H
#define SNIPPET_RT_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef MEMSZ
#error MEMSZ required
#endif

typedef struct __attribute__((packed)) {
    uint64_t r[16]; /* rax rcx rdx rbx rsp rbp rsi rdi r8..r15 */
    uint32_t cf, pf, af, zf, sf, of;
} Cpu64;

_Static_assert(sizeof(Cpu64) == 152, "Cpu64 layout");

static inline uint32_t parity_even(uint64_t v) {
    return (uint32_t)((__builtin_parityll(v & 0xffu) ^ 1) & 1);
}

static inline uint64_t width_mask(int bits) {
    return bits >= 64 ? ~0ull : ((1ull << bits) - 1ull);
}

static inline void flags_logic(Cpu64 *c, uint64_t result, int bits) {
    uint64_t mask = width_mask(bits);
    uint64_t sign = 1ull << (bits - 1);
    uint64_t x = result & mask;
    c->cf = 0;
    c->of = 0;
    c->zf = x == 0;
    c->sf = (x & sign) != 0;
    c->pf = parity_even(x);
    /* AF is architecturally undefined for AND/OR/XOR/TEST and is left unchanged. */
}

static inline void flags_add(Cpu64 *c, uint64_t a, uint64_t b, uint64_t result, int bits) {
    uint64_t mask = width_mask(bits);
    uint64_t sign = 1ull << (bits - 1);
    a &= mask;
    b &= mask;
    result &= mask;
    c->cf = result < a;
    c->zf = result == 0;
    c->sf = (result & sign) != 0;
    c->of = ((~(a ^ b) & (a ^ result)) & sign) != 0;
    c->af = ((a & 0xfull) + (b & 0xfull)) > 0xfull;
    c->pf = parity_even(result);
}

static inline void flags_sub(Cpu64 *c, uint64_t a, uint64_t b, uint64_t result, int bits) {
    uint64_t mask = width_mask(bits);
    uint64_t sign = 1ull << (bits - 1);
    a &= mask;
    b &= mask;
    result &= mask;
    c->cf = a < b;
    c->zf = result == 0;
    c->sf = (result & sign) != 0;
    c->of = (((a ^ b) & (a ^ result)) & sign) != 0;
    c->af = (a & 0xfull) < (b & 0xfull);
    c->pf = parity_even(result);
}

static inline uint64_t rd(const Cpu64 *c, int index, int bits) {
    uint64_t v = c->r[index];
    if (bits >= 64) return v;
    return v & width_mask(bits);
}

static inline void wr(Cpu64 *c, int index, uint64_t value, int bits) {
    if (bits >= 64) c->r[index] = value;
    else if (bits == 32) c->r[index] = value & 0xffffffffu; /* zero-extend */
    else c->r[index] = (c->r[index] & ~width_mask(bits)) | (value & width_mask(bits));
}

static inline uint64_t ld(const uint8_t *mem, uint64_t addr, int nbytes) {
    if (nbytes < 1 || nbytes > 8 || addr > (uint64_t)MEMSZ - (uint64_t)nbytes) abort();
    uint64_t v = 0;
    memcpy(&v, mem + addr, (size_t)nbytes);
    return v;
}

static inline void st(uint8_t *mem, uint64_t addr, uint64_t value, int nbytes) {
    if (nbytes < 1 || nbytes > 8 || addr > (uint64_t)MEMSZ - (uint64_t)nbytes) abort();
    memcpy(mem + addr, &value, (size_t)nbytes);
}

#endif
