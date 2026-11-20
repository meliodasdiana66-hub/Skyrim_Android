#!/usr/bin/env python3
"""Run one lifted snippet on AArch64 under QEMU user-mode.

This is not a physical Android device, not Adreno, and not the game.
If qemu-aarch64-static is absent the test skips and says that skip is not a pass.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lift64  # noqa: E402

QEMU = shutil.which("qemu-aarch64-static")
HAVE = QEMU is not None and shutil.which("clang") and shutil.which("ld.lld")


@unittest.skipUnless(HAVE, "AArch64 QEMU user-mode skipped: qemu-aarch64-static or ld.lld is absent; this skip is not a pass and is not an Android device")
class AArch64QemuTests(unittest.TestCase):
    def test_push_pop_matches_under_qemu_user_mode(self):
        body = lift64.lift_snippet(bytes.fromhex("5059"), 0x4000)
        src = r'''
#define AE_FREESTANDING 1
#define MEMSZ 65536
#include "snippet_rt.h"
%s
static void putbuf(const char *s, unsigned long n) {
    register unsigned long x0 __asm__("x0") = 1;
    register unsigned long x1 __asm__("x1") = (unsigned long)s;
    register unsigned long x2 __asm__("x2") = n;
    register unsigned long x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
}
static void hex64(unsigned long v) {
    char b[16];
    int i;
    for (i = 15; i >= 0; i--) { b[i] = "0123456789abcdef"[v & 15]; v >>= 4; }
    putbuf(b, 16);
}
static void driver(void) {
    static unsigned char mem[MEMSZ];
    Cpu64 c;
    int i;
    for (i = 0; i < 16; i++) c.r[i] = 0;
    c.cf = c.pf = c.af = c.zf = c.sf = c.of = 0;
    c.r[0] = 0x1122334455667788ull;
    c.r[4] = 0xE000ull;
    snippet(&c, mem);
    hex64(c.r[1]);
    putbuf(" ", 1);
    hex64(c.r[4]);
    putbuf("\n", 1);
}
void _start(void) {
    driver();
    register unsigned long x0 __asm__("x0") = 0;
    register unsigned long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x8));
    __builtin_trap();
}
''' % body
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "run.c").write_text(src)
            obj = td / "run.o"
            elf = td / "run.elf"
            cc = subprocess.run(
                ["clang", "--target=aarch64-linux-gnu", "-nostdinc", "-ffreestanding",
                 "-fno-stack-protector", "-O2", "-I", str(HERE), "-c", str(td / "run.c"), "-o", str(obj)],
                capture_output=True, text=True, check=False)
            self.assertEqual(cc.returncode, 0, cc.stderr)
            ld = subprocess.run(
                ["ld.lld", "-m", "aarch64linux", "-e", "_start", str(obj), "-o", str(elf)],
                capture_output=True, text=True, check=False)
            self.assertEqual(ld.returncode, 0, ld.stderr)
            # Static user-mode emulation. The host is not ARM64 hardware.
            run = subprocess.run([QEMU, str(elf)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.strip(), "1122334455667788 000000000000e000")

    def test_sign_extending_stack_store_under_qemu(self):
        body = lift64.lift_snippet(bytes.fromhex("48c7042400000080"), 0x4000)
        src = r'''
#define AE_FREESTANDING 1
#define MEMSZ 65536
#include "snippet_rt.h"
%s
static void putbuf(const char *s, unsigned long n) {
    register unsigned long x0 __asm__("x0") = 1;
    register unsigned long x1 __asm__("x1") = (unsigned long)s;
    register unsigned long x2 __asm__("x2") = n;
    register unsigned long x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
}
static void hex64(unsigned long v) {
    char b[16];
    int i;
    for (i = 15; i >= 0; i--) { b[i] = "0123456789abcdef"[v & 15]; v >>= 4; }
    putbuf(b, 16);
}
static void driver(void) {
    static unsigned char mem[MEMSZ];
    Cpu64 c;
    int i;
    for (i = 0; i < 16; i++) c.r[i] = 0;
    c.r[4] = 0xE000ull;
    snippet(&c, mem);
    hex64(*(unsigned long *)(mem + 0xE000));
    putbuf("\n", 1);
}
void _start(void) {
    driver();
    register unsigned long x0 __asm__("x0") = 0;
    register unsigned long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x8));
    __builtin_trap();
}
''' % body
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "run.c").write_text(src)
            obj, elf = td / "run.o", td / "run.elf"
            cc = subprocess.run(
                ["clang", "--target=aarch64-linux-gnu", "-nostdinc", "-ffreestanding",
                 "-fno-stack-protector", "-O2", "-I", str(HERE), "-c", str(td / "run.c"), "-o", str(obj)],
                capture_output=True, text=True, check=False)
            self.assertEqual(cc.returncode, 0, cc.stderr)
            ld = subprocess.run(["ld.lld", "-m", "aarch64linux", "-e", "_start", str(obj), "-o", str(elf)],
                                capture_output=True, text=True, check=False)
            self.assertEqual(ld.returncode, 0, ld.stderr)
            run = subprocess.run([QEMU, str(elf)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.strip(), "ffffffff80000000")


    def test_test_immediate_flags_under_qemu_user_mode(self):
            body = lift64.lift_snippet(bytes.fromhex("a9ff000000"), 0x4000)
            src = r'''
    #define AE_FREESTANDING 1
    #define MEMSZ 65536
    #include "snippet_rt.h"
    %s
    static void putbuf(const char *s, unsigned long n) {
        register unsigned long x0 __asm__("x0") = 1;
        register unsigned long x1 __asm__("x1") = (unsigned long)s;
        register unsigned long x2 __asm__("x2") = n;
        register unsigned long x8 __asm__("x8") = 64;
        __asm__ volatile("svc #0" :: "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
    }
    static void driver(void) {
        static unsigned char mem[MEMSZ];
        Cpu64 c;
        int i;
        for (i = 0; i < 16; i++) c.r[i] = 0;
        c.r[0] = 0;
        snippet(&c, mem);
        char b[6] = { c.zf ? '1' : '0', c.pf ? '1' : '0', c.sf ? '1' : '0', c.cf ? '1' : '0', c.of ? '1' : '0', '\n' };
        putbuf(b, 6);
    }
    void _start(void) {
        driver();
        register unsigned long x0 __asm__("x0") = 0;
        register unsigned long x8 __asm__("x8") = 93;
        __asm__ volatile("svc #0" :: "r"(x0), "r"(x8));
        __builtin_trap();
    }
    ''' % body
            with tempfile.TemporaryDirectory() as td:
                td = Path(td)
                (td / "run.c").write_text(src)
                obj, elf = td / "run.o", td / "run.elf"
                cc = subprocess.run(
                    ["clang", "--target=aarch64-linux-gnu", "-nostdinc", "-ffreestanding",
                     "-fno-stack-protector", "-O2", "-I", str(HERE), "-c", str(td / "run.c"), "-o", str(obj)],
                    capture_output=True, text=True, check=False)
                self.assertEqual(cc.returncode, 0, cc.stderr)
                ld = subprocess.run(["ld.lld", "-m", "aarch64linux", "-e", "_start", str(obj), "-o", str(elf)],
                                    capture_output=True, text=True, check=False)
                self.assertEqual(ld.returncode, 0, ld.stderr)
                run = subprocess.run([QEMU, str(elf)], capture_output=True, text=True, check=False)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout, "11000\n")

if __name__ == "__main__":
    unittest.main(verbosity=2)
