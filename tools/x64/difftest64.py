"""Compile a lifted snippet with clang and compare it to Unicorn x86-64.

AF is compared only when the caller says the instructions define it. AND, OR,
XOR and TEST leave AF undefined; the lifter does not guess a value.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_EFLAGS, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
    UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDI,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RSP,
)

import lift64

HERE = Path(__file__).resolve().parent
MEMSZ = 0x10000
CPU_BYTES = 152
NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
UC_REGS = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
           UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
           UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
           UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
FLAGS = ("cf", "pf", "af", "zf", "sf", "of")
_BINS = {}


def pack_cpu(cpu):
    return struct.pack("<16Q6I", *[int(x) & 0xFFFFFFFFFFFFFFFF for x in cpu["r"]],
                       *(int(cpu[name]) & 0xFFFFFFFF for name in FLAGS))


def unpack_cpu(buf):
    vals = struct.unpack("<16Q6I", buf[:CPU_BYTES])
    out = {"r": list(vals[:16])}
    for name, value in zip(FLAGS, vals[16:]):
        out[name] = value
    return out


def _flags_to_eflags(cpu):
    eflags = 2
    if cpu["cf"]:
        eflags |= 1
    if cpu["pf"]:
        eflags |= 1 << 2
    if cpu["af"]:
        eflags |= 1 << 4
    if cpu["zf"]:
        eflags |= 1 << 6
    if cpu["sf"]:
        eflags |= 1 << 7
    if cpu["of"]:
        eflags |= 1 << 11
    return eflags


def _eflags_to_flags(eflags):
    return {
        "cf": eflags & 1,
        "pf": (eflags >> 2) & 1,
        "af": (eflags >> 4) & 1,
        "zf": (eflags >> 6) & 1,
        "sf": (eflags >> 7) & 1,
        "of": (eflags >> 11) & 1,
    }


def _check_window(code, base, mem):
    if not isinstance(base, int) or base < 0 or len(code) <= 0:
        raise lift64.Unsupported("bad snippet window")
    if base + len(code) > MEMSZ:
        raise lift64.Unsupported("snippet is outside the %d-byte guest window" % MEMSZ)
    if len(mem) != MEMSZ:
        raise lift64.Unsupported("memory image must be %d bytes" % MEMSZ)


def binary_for(code, base):
    key = (bytes(code), base)
    if key in _BINS:
        return _BINS[key]
    body = lift64.lift_snippet(code, base)
    td = Path(tempfile.mkdtemp(prefix="x64lift-"))
    src = td / "snippet.c"
    src.write_text(
        "#define MEMSZ %d\n#include <stdio.h>\n#include \"snippet_rt.h\"\n%s\n"
        "int main(void) {\n"
        "    Cpu64 c; uint8_t mem[MEMSZ];\n"
        "    if (fread(&c, sizeof c, 1, stdin) != 1) return 2;\n"
        "    if (fread(mem, 1, MEMSZ, stdin) != MEMSZ) return 3;\n"
        "    snippet(&c, mem);\n"
        "    if (fwrite(&c, sizeof c, 1, stdout) != 1) return 4;\n"
        "    if (fwrite(mem, 1, MEMSZ, stdout) != MEMSZ) return 5;\n"
        "    return 0;\n}\n" % (MEMSZ, body))
    exe = td / "snippet"
    cmd = [os.environ.get("CC", "clang"), "-std=c11", "-O2", "-fwrapv", "-fno-strict-aliasing",
           "-Wall", "-Wextra", "-Werror", "-I", str(HERE), str(src), "-o", str(exe)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("clang failed:\n" + proc.stderr + "\n" + src.read_text())
    _BINS[key] = exe
    return exe


def run_host(code, base, cpu, mem):
    cpu_out, mem_out = exec_host(code, base, cpu, mem)
    return cpu_out


def exec_host(code, base, cpu, mem):
    _check_window(code, base, mem)
    exe = binary_for(code, base)
    proc = subprocess.run([str(exe)], input=pack_cpu(cpu) + bytes(mem),
                          capture_output=True, check=False)
    if proc.returncode != 0 or len(proc.stdout) != CPU_BYTES + MEMSZ:
        raise RuntimeError("host snippet failed: rc=%s stderr=%r" % (proc.returncode, proc.stderr))
    return unpack_cpu(proc.stdout), bytearray(proc.stdout[CPU_BYTES:])


def exec_unicorn(code, base, cpu, mem):
    _check_window(code, base, mem)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, MEMSZ)
    uc.mem_write(0, bytes(mem))
    for reg, value in zip(UC_REGS, cpu["r"]):
        uc.reg_write(reg, int(value) & 0xFFFFFFFFFFFFFFFF)
    uc.reg_write(UC_X86_REG_EFLAGS, _flags_to_eflags(cpu))
    # Stop at a final ret without executing it. Executing ret would pop a
    # return address and is outside the allowlist.
    uc.emu_start(base, base + lift64.executed_length(code, base))
    out = {"r": [uc.reg_read(reg) for reg in UC_REGS]}
    out.update(_eflags_to_flags(uc.reg_read(UC_X86_REG_EFLAGS)))
    return out, bytearray(uc.mem_read(0, MEMSZ))


def compare(code, base, cpu, mem, compare_af=True):
    host_cpu, host_mem = exec_host(code, base, cpu, mem)
    uni_cpu, uni_mem = exec_unicorn(code, base, cpu, mem)
    diffs = []
    for index, name in enumerate(NAMES):
        if host_cpu["r"][index] != uni_cpu["r"][index]:
            diffs.append("%s host=%#x unicorn=%#x" % (name, host_cpu["r"][index], uni_cpu["r"][index]))
    for name in FLAGS:
        if name == "af" and not compare_af:
            continue
        if host_cpu[name] != uni_cpu[name]:
            diffs.append("%s host=%s unicorn=%s" % (name, host_cpu[name], uni_cpu[name]))
    if bytes(host_mem) != bytes(uni_mem):
        for addr, (hb, ub) in enumerate(zip(host_mem, uni_mem)):
            if hb != ub:
                diffs.append("mem[%#x] host=%#x unicorn=%#x" % (addr, hb, ub))
                break
    if diffs:
        raise AssertionError("host/unicorn mismatch:\n" + "\n".join(diffs))
    return host_cpu, host_mem


def run_both(code, base, cpu, mem, compare_af=True):
    return compare(code, base, cpu, mem, compare_af=compare_af)


def _cpu_from_fixture(regs):
    cpu = {"r": [0] * 16, "cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}
    for name, raw in (regs or {}).items():
        value = int(raw, 0) if isinstance(raw, str) else int(raw)
        if name in FLAGS:
            cpu[name] = value
        else:
            cpu["r"][NAMES.index(name)] = value & 0xFFFFFFFFFFFFFFFF
    return cpu


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Differential-test one synthetic x64 fixture against Unicorn. Does not open a PE.")
    parser.add_argument("--fixture", required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.fixture).read_text())
    code = bytes.fromhex(spec["code_hex"])
    base = int(spec["base"])
    cpu = _cpu_from_fixture(spec.get("regs") or {})
    mem = bytearray(MEMSZ)
    if base + len(code) <= MEMSZ:
        mem[base:base + len(code)] = code
    for addr, hex_bytes in (spec.get("mem") or {}).items():
        raw = bytes.fromhex(hex_bytes)
        at = int(addr, 0) if isinstance(addr, str) else int(addr)
        mem[at:at + len(raw)] = raw
    compare(code, base, cpu, mem, compare_af=bool(spec.get("compare_af", True)))
    print("match: host clang -O2 agrees with unicorn x86-64")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (lift64.Unsupported, AssertionError, OSError, ValueError, KeyError) as exc:
        print("difftest64: %s" % exc, file=sys.stderr)
        sys.exit(1)
