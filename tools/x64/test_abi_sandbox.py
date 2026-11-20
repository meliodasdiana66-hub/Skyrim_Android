#!/usr/bin/env python3
"""Synthetic Microsoft x64 call/return, checked against Unicorn.

The caller passes two integers in ecx/edx and the callee returns their sum in eax.
No import, no Windows DLL, and no game entry point. Depth is one call.
The leaf scanner still rejects call instructions in an executable image.
"""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

CALLER = 0x4000
CALLEE = 0x4100
DONE = 0x5000
ENTRY_RSP = 0xE008


def _rel32(at, target, size):
    return struct.pack("<i", target - (at + size))


def build():
    # sub rsp, 0x28; mov ecx, 0x11; mov edx, 0x22; call callee; add rsp, 0x28; ret
    call_at = CALLER + 4 + 5 + 5
    caller = bytes.fromhex("4883ec28") + bytes.fromhex("b911000000") + bytes.fromhex("ba22000000")
    caller += b"\xe8" + _rel32(call_at, CALLEE, 5)
    caller += bytes.fromhex("4883c428") + b"\xc3"
    # mov eax, ecx; add eax, edx; ret
    callee = bytes.fromhex("8bc103c2c3")
    return caller, callee


class AbiSandboxTests(unittest.TestCase):
    def test_two_function_sum_matches_unicorn_and_stops(self):
        caller, callee = build()
        self.assertEqual(caller[14], 0xE8)
        mem = bytearray(0x10000)
        mem[CALLER:CALLER + len(caller)] = caller
        mem[CALLEE:CALLEE + len(callee)] = callee
        mem[ENTRY_RSP:ENTRY_RSP + 8] = struct.pack("<Q", DONE)
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0, 0x10000)
        uc.mem_write(0, bytes(mem))
        uc.reg_write(UC_X86_REG_RSP, ENTRY_RSP)
        uc.emu_start(CALLER, DONE)
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX), 0x33)
        self.assertEqual(uc.reg_read(UC_X86_REG_RSP), ENTRY_RSP + 8)
        # The same bytes are rejected by the game leaf scanner: a call is not a leaf.
        import decode_allow
        with self.assertRaises(decode_allow.Reject) as caught:
            decode_allow.decode_leaf(caller, CALLER)
        self.assertEqual(caught.exception.reason, "call")

    def test_host_model_matches_the_register_result(self):
        """A C model of the same chain, compiled for the host and for AArch64 QEMU when present."""
        src = r'''
#if defined(__aarch64__)
typedef unsigned long long uint64_t;
#else
#include <stdint.h>
#include <stdio.h>
#endif
#if defined(__aarch64__)
static void finish(uint64_t rax) {
    char b[16];
    int i;
    for (i = 15; i >= 0; i--) { b[i] = "0123456789abcdef"[rax & 15]; rax >>= 4; }
    register unsigned long x0 __asm__("x0") = 1;
    register unsigned long x1 __asm__("x1") = (unsigned long)b;
    register unsigned long x2 __asm__("x2") = 16;
    register unsigned long x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
    register unsigned long y0 __asm__("x0") = 0;
    register unsigned long y8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" :: "r"(y0), "r"(y8));
}
#else
static void finish(uint64_t rax) { printf("%016llx\n", (unsigned long long)rax); }
#endif
static uint64_t callee(uint64_t ecx, uint64_t edx) { return (ecx + edx) & 0xffffffffu; }
static uint64_t caller(void) {
    uint64_t ecx = 0x11, edx = 0x22, rax;
    rax = callee(ecx, edx);
    return rax;
}
#if defined(__aarch64__)
void _start(void) { finish(caller()); __builtin_trap(); }
#else
int main(void) { finish(caller()); return 0; }
#endif
'''
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "abi.c"
            path.write_text(src)
            host = Path(td) / "abi"
            cc = subprocess.run(["clang", "-O2", str(path), "-o", str(host)], capture_output=True, text=True)
            self.assertEqual(cc.returncode, 0, cc.stderr)
            run = subprocess.run([str(host)], capture_output=True, text=True)
            self.assertEqual(run.stdout.strip(), "0000000000000033")
            import shutil
            qemu = shutil.which("qemu-aarch64-static")
            if not qemu:
                return
            elf = Path(td) / "abi.elf"
            obj = Path(td) / "abi.o"
            one = subprocess.run(
                ["clang", "--target=aarch64-linux-gnu", "-O2", "-ffreestanding", "-fno-stack-protector",
                 "-c", str(path), "-o", str(obj)],
                capture_output=True, text=True)
            self.assertEqual(one.returncode, 0, one.stderr)
            two = subprocess.run(["ld.lld", "-m", "aarch64linux", "-e", "_start", str(obj), "-o", str(elf)],
                                 capture_output=True, text=True)
            self.assertEqual(two.returncode, 0, two.stderr)
            q = subprocess.run([qemu, str(elf)], capture_output=True, text=True)
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertEqual(q.stdout.strip(), "0000000000000033")


if __name__ == "__main__":
    unittest.main(verbosity=2)
