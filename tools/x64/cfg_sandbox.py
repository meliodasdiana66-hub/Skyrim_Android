"""Bounded direct call/return and forward branches for synthetic guest programs.

This is not the leaf scanner and it does not run Skyrim. Every call target has
to be an explicit function start. Indirect calls, imports, backward branches,
recursion, and an initial RSP outside the guest stack window are rejected.
Missing imports are named and are not treated as success.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UcError
from unicorn.x86_const import (
    UC_X86_REG_EFLAGS, UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX,
    UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RIP,
    UC_X86_REG_RSI, UC_X86_REG_RSP, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
    UC_X86_REG_R14, UC_X86_REG_R15,
)

import decode_allow
import difftest64
import inspect_pe32plus
import lift64

HERE = Path(__file__).resolve().parent
MEMSZ = difftest64.MEMSZ
STACK_LO = 0xC000
STACK_TOP = 0xE008
MAX_FUNCS = 8
MAX_INSNS = 32
MAX_STEPS_DEFAULT = 64
MAX_DEPTH_DEFAULT = 4
JCC = {
    "jo": "c->of", "jno": "!c->of", "jb": "c->cf", "jae": "!c->cf",
    "je": "c->zf", "jne": "!c->zf", "jbe": "(c->cf || c->zf)", "ja": "(!c->cf && !c->zf)",
    "js": "c->sf", "jns": "!c->sf", "jp": "c->pf", "jnp": "!c->pf",
    "jl": "(c->sf != c->of)", "jge": "(c->sf == c->of)",
    "jle": "(c->zf || (c->sf != c->of))", "jg": "(!c->zf && (c->sf == c->of))",
}
UC_GPRS = [
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
]


class CfgError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _decode(code, base):
    if len(code) > MAX_INSNS * 8:
        raise CfgError("step_budget")
    try:
        insns = decode_allow.decode_stream(code, base, control=True)
    except decode_allow.Reject as exc:
        raise CfgError(exc.reason) from exc
    if len(insns) > MAX_INSNS:
        raise CfgError("step_budget")
    if not insns or insns[-1]["mnemonic"] != "ret":
        raise CfgError("missing_ret")
    return insns


def _edges(insns, base, size):
    calls = []
    for insn in insns:
        name = insn["mnemonic"]
        if name == "call":
            calls.append(insn["target"])
        if name in JCC or name == "jmp":
            target = insn["target"]
            if target <= insn["address"]:
                raise CfgError("back_edge")
            if not (base <= target < base + size):
                raise CfgError("cross_function_branch")
    return calls


def _acyclic(graph):
    color = {}

    def walk(node):
        color[node] = 1
        for nxt in graph.get(node, []):
            state = color.get(nxt, 0)
            if state == 1:
                raise CfgError("recursion")
            if state == 0:
                walk(nxt)
        color[node] = 2

    for node in graph:
        if color.get(node, 0) == 0:
            walk(node)


def prepare(funcs, entry, imports=None, max_steps=MAX_STEPS_DEFAULT):
    """Validate an explicit function map. Does not execute it."""
    if not funcs or entry not in funcs:
        raise CfgError("unknown_target")
    if len(funcs) > MAX_FUNCS:
        raise CfgError("too_many_functions")
    imports = imports or {}
    decoded = {}
    graph = {}
    logical = 0
    for base, code in funcs.items():
        insns = _decode(code, base)
        calls = _edges(insns, base, len(code))
        for target in calls:
            if target in imports:
                raise CfgError("unbound_import:" + imports[target])
            if target not in funcs:
                raise CfgError("unknown_target")
        decoded[base] = insns
        graph[base] = calls
        logical += len(insns)
    if logical > max_steps:
        raise CfgError("step_budget")
    _acyclic(graph)
    reachable = set()
    stack = [entry]
    while stack:
        node = stack.pop()
        if node in reachable:
            continue
        reachable.add(node)
        stack.extend(graph[node])
    return {"insns": decoded, "graph": graph, "reachable": sorted(reachable), "executed": False}


def _leaders(insns, base):
    leaders = {base}
    for insn in insns:
        nxt = insn["address"] + insn["size"]
        if insn["mnemonic"] in JCC or insn["mnemonic"] == "jmp":
            leaders.add(insn["target"])
            leaders.add(nxt)
        elif insn["mnemonic"] == "call":
            leaders.add(nxt)
    return leaders


def _blocks(code, base, insns):
    leaders = _leaders(insns, base)
    blocks = []
    current = None
    straight = []
    for insn in insns:
        if insn["address"] in leaders and straight:
            blocks.append((current, straight, None))
            straight = []
            current = None
        if current is None:
            current = insn["address"]
        if insn["mnemonic"] in JCC or insn["mnemonic"] in ("jmp", "call", "ret"):
            blocks.append((current, straight, insn))
            straight = []
            current = None
        else:
            straight.append(insn)
    if straight:
        blocks.append((current, straight, None))
    out = []
    for start, body, term in blocks:
        if body:
            raw = code[body[0]["address"] - base:body[-1]["address"] + body[-1]["size"] - base]
        else:
            raw = b""
        out.append((start, raw, len(body), term))
    return out


def _c_name(addr):
    return "guest_%x" % addr


def _emit_function(base, code, insns, max_steps, max_depth):
    blocks = _blocks(code, base, insns)
    ids = {start: index for index, (start, _raw, _count, _term) in enumerate(blocks)}
    lines = ["void %s(Cpu64 *c, uint8_t *mem) {" % _c_name(base),
             "    int block = 0;",
             "    int trips = 0;",
             "    if (stop) return;",
             "    while (1) {",
             "        if (stop) return;",
             "        if (++trips > %d) { stop = 10; return; }" % (len(blocks) + 2)]
    for index, (start, raw, count, term) in enumerate(blocks):
        lines.append("        if (block == %d) {" % index)
        if count:
            lines.append("            if ((steps += %d) > %d) { stop = 9; return; }" % (count, max_steps))
            lines.append("            block_%x_%d(c, mem);" % (base, index))
        if term is None:
            if index + 1 == len(blocks):
                lines.append("            return;")
            else:
                lines.append("            block = %d; continue;" % (index + 1))
        elif term["mnemonic"] == "ret":
            lines.append("            ld(mem, rd(c, 4, 64), 8);")
            lines.append("            wr(c, 4, rd(c, 4, 64) + 8, 64);")
            lines.append("            return;")
        elif term["mnemonic"] == "jmp":
            lines.append("            block = %d; continue;" % ids[term["target"]])
        elif term["mnemonic"] in JCC:
            fall = term["address"] + term["size"]
            lines.append("            if (%s) { block = %d; continue; }" % (JCC[term["mnemonic"]], ids[term["target"]]))
            lines.append("            block = %d; continue;" % ids[fall])
        elif term["mnemonic"] == "call":
            nxt = term["address"] + term["size"]
            lines.append("            if (++depth > %d) { stop = 11; return; }" % max_depth)
            lines.append("            if (++steps > %d) { stop = 9; return; }" % max_steps)
            lines.append("            wr(c, 4, rd(c, 4, 64) - 8, 64);")
            lines.append("            st(mem, rd(c, 4, 64), %#xull, 8);" % nxt)
            lines.append("            %s(c, mem);" % _c_name(term["target"]))
            lines.append("            if (stop) return;")
            lines.append("            depth--;")
            lines.append("            block = %d; continue;" % ids[nxt])
        else:
            raise CfgError("unsupported")
        lines.append("        }")
    lines.append("        abort();")
    lines.append("    }")
    lines.append("}")
    helpers = []
    for index, (start, raw, count, _term) in enumerate(blocks):
        if count:
            helpers.append(lift64.lift_snippet(raw, start).replace(
                "void snippet(", "static void block_%x_%d(" % (base, index), 1))
    return "\n".join(helpers + lines)


def emit_program(funcs, entry, imports=None, max_steps=MAX_STEPS_DEFAULT, max_depth=MAX_DEPTH_DEFAULT,
                  freestanding=False):
    prepared = prepare(funcs, entry, imports=imports, max_steps=max_steps)
    uses_depth = any(
        insn["mnemonic"] == "call"
        for base in prepared["reachable"]
        for insn in prepared["insns"][base]
    )
    parts = ["#define MEMSZ %d" % MEMSZ]
    if freestanding:
        parts.append("#define AE_FREESTANDING 1")
    else:
        parts.extend(["#include <stdio.h>", "#ifdef _WIN32", "#include <fcntl.h>", "#include <io.h>", "#endif"])
    parts.append("#include \"snippet_rt.h\"")
    parts.append("static int steps;")
    if uses_depth:
        parts.append("static int depth;")
    parts.append("static int stop;")
    for base in prepared["reachable"]:
        parts.append("void %s(Cpu64 *c, uint8_t *mem);" % _c_name(base))
    for base in prepared["reachable"]:
        parts.append(_emit_function(base, funcs[base], prepared["insns"][base], max_steps, max_depth))
    if not freestanding:
        parts.append("int main(void) {")
        parts.append("#ifdef _WIN32")
        parts.append("    if (_setmode(_fileno(stdin), _O_BINARY) == -1) return 2;")
        parts.append("    if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 2;")
        parts.append("#endif")
        parts.append("    Cpu64 c; uint8_t mem[MEMSZ];")
        parts.append("    if (fread(&c, sizeof c, 1, stdin) != 1) return 2;")
        parts.append("    if (fread(mem, 1, MEMSZ, stdin) != MEMSZ) return 3;")
        reset = "    steps = 0; stop = 0;"
        if uses_depth:
            reset = "    steps = 0; depth = 0; stop = 0;"
        parts.append(reset)
        parts.append("    %s(&c, mem);" % _c_name(entry))
        parts.append("    if (stop) return stop;")
        parts.append("    if (fwrite(&c, sizeof c, 1, stdout) != 1) return 4;")
        parts.append("    if (fwrite(mem, 1, MEMSZ, stdout) != MEMSZ) return 5;")
        parts.append("    return 0;")
        parts.append("}")
    return "\n".join(parts) + "\n", prepared


def _check_stack(cpu, mem, return_ip):
    rsp = cpu["r"][4]
    if rsp < STACK_LO or rsp > STACK_TOP or (rsp & 7) or rsp + 8 > MEMSZ:
        raise CfgError("stack_escape")
    slot = int.from_bytes(mem[rsp:rsp + 8], "little")
    if slot != return_ip:
        raise CfgError("stack_escape")


def execute(funcs, entry, cpu, mem, return_ip, imports=None, max_steps=MAX_STEPS_DEFAULT,
            max_depth=MAX_DEPTH_DEFAULT, compare_af=True):
    """Run one explicit program on the host and under Unicorn. Both must agree."""
    _check_stack(cpu, mem, return_ip)
    image = bytearray(mem)
    spans = []
    for base, code in funcs.items():
        if base < 0 or base + len(code) > MEMSZ or (STACK_LO <= base < STACK_TOP + 8):
            raise CfgError("code_window")
        spans.append((base, base + len(code)))
        image[base:base + len(code)] = code
    spans.sort()
    for (lo, hi), (lo2, _hi2) in zip(spans, spans[1:]):
        if hi > lo2:
            raise CfgError("code_overlap")
    source, prepared = emit_program(funcs, entry, imports=imports, max_steps=max_steps, max_depth=max_depth)
    td = Path(tempfile.mkdtemp(prefix="x64cfg-"))
    src = td / "cfg.c"
    exe = td / "cfg"
    src.write_text(source)
    cmd = [os.environ.get("CC", "clang"), "-std=c11", "-O2", "-fwrapv", "-fno-strict-aliasing",
           "-Wall", "-Wextra", "-Werror", "-I", str(HERE), str(src), "-o", str(exe)]
    built = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if built.returncode != 0:
        raise RuntimeError(built.stderr + "\n" + source)
    host = subprocess.run([str(exe)], input=difftest64.pack_cpu(cpu) + bytes(image),
                          capture_output=True, check=False, timeout=2)
    if host.returncode == 9:
        raise CfgError("step_budget")
    if host.returncode == 10:
        raise CfgError("time_budget")
    if host.returncode == 11:
        raise CfgError("depth_budget")
    if host.returncode != 0 or len(host.stdout) != difftest64.CPU_BYTES + MEMSZ:
        raise CfgError("host_abort")
    host_cpu = difftest64.unpack_cpu(host.stdout)
    host_mem = host.stdout[difftest64.CPU_BYTES:]
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, MEMSZ)
    uc.mem_write(0, bytes(image))
    traced = []

    def _trace(_uc, address, _size, _user):
        traced.append(address)
        if len(traced) > max_steps:
            _uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, _trace)
    for reg, value in zip(UC_GPRS, cpu["r"]):
        uc.reg_write(reg, int(value) & 0xFFFFFFFFFFFFFFFF)
    uc.reg_write(UC_X86_REG_EFLAGS, difftest64._flags_to_eflags(cpu))
    try:
        uc.emu_start(entry, return_ip, timeout=2000000)
    except UcError as exc:
        raise CfgError("unicorn_abort") from exc
    if uc.reg_read(UC_X86_REG_RIP) != return_ip or len(traced) > max_steps:
        raise CfgError("time_budget")
    uni_cpu = {"r": [uc.reg_read(reg) for reg in UC_GPRS]}
    uni_cpu.update(difftest64._eflags_to_flags(uc.reg_read(UC_X86_REG_EFLAGS)))
    uni_mem = bytes(uc.mem_read(0, MEMSZ))
    diffs = []
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    for index, name in enumerate(names):
        if host_cpu["r"][index] != uni_cpu["r"][index]:
            diffs.append(name)
    for flag in ("cf", "pf", "zf", "sf", "of"):
        if host_cpu[flag] != uni_cpu[flag]:
            diffs.append(flag)
    if compare_af and host_cpu["af"] != uni_cpu["af"]:
        diffs.append("af")
    if host_mem != uni_mem:
        diffs.append("mem")
    if diffs:
        raise AssertionError("cfg mismatch: " + ",".join(diffs))
    return {
        "executed": True,
        "entry": entry,
        "reached": prepared["reachable"],
        "instructions": traced,
        "flags": {name: host_cpu[name] for name in ("cf", "pf", "af", "zf", "sf", "of")},
        "rax": host_cpu["r"][0],
        "stepsBudget": max_steps,
        "depthBudget": max_depth,
        "result": "match",
        "stopping": "returned_to_harness",
    }


def classify_graph(funcs, entry, executable_ranges):
    """Read-only verdict for an explicit graph. Never executes it."""
    for base, code in funcs.items():
        end = base + len(code)
        if not any(lo <= base and end <= hi for lo, hi in executable_ranges):
            return {"executed": False, "reason": "non_executable_target", "at": base, "reached": []}
    try:
        prepared = prepare(funcs, entry)
    except CfgError as exc:
        return {"executed": False, "reason": exc.reason, "at": entry, "reached": []}
    return {
        "executed": False,
        "reason": None,
        "stopping": "closed_not_executed",
        "reached": prepared["reachable"],
    }


CALLEE_SAVED = frozenset({3, 5, 6, 7, 12, 13, 14, 15})
GUEST_CODE = 0x4000
GUEST_DATA = 0x8000
DONE = 0x5000
ACCOUNTING = frozenset({"closed_graph_root", "closed_graph_member", "call_free"})
NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def _section_at(sections, rva):
    for sec in sections:
        if sec["virtualAddress"] <= rva < sec["virtualAddress"] + max(sec["virtualSize"], sec["sizeOfRawData"], 1):
            return sec
    return None


def assess_graph(funcs, entry, rip_regions=None, max_functions=MAX_FUNCS, max_instructions=MAX_STEPS_DEFAULT):
    """Return a rejection reason, or None when the graph may be executed.

    rip_regions are (address, bytes, writable). A missing or writable region is
    not filled with zeros. None means every RIP access is a precondition.
    """
    try:
        prepared = prepare(funcs, entry, max_steps=max_instructions)
    except CfgError as exc:
        return exc.reason
    if len(prepared["reachable"]) > max_functions:
        return "too_many_functions"
    try:
        _assess_body(prepared, rip_regions)
    except CfgError as exc:
        return exc.reason
    return None


def _assess_body(prepared, rip_regions):
    covered = []
    if rip_regions is not None:
        for addr, blob, writable in rip_regions:
            covered.append((addr, bytes(blob), bool(writable)))
    for base in prepared["reachable"]:
        _assess_function(prepared["insns"][base], covered, rip_regions is not None)


def _assess_function(insns, covered, have_regions):
    delta = 0
    ptrs = {}
    dirty = set()
    slots = []
    for insn in insns:
        if insn.get("xmm") is not None:
            raise CfgError("xmm_untracked")
        if insn["mnemonic"] == "ret":
            if delta != 0 or slots:
                raise CfgError("stack_unbalanced")
            if dirty & CALLEE_SAVED:
                raise CfgError("abi_unpreserved")
            continue
        if insn["mnemonic"] == "call":
            if STACK_TOP + delta - 8 < STACK_LO:
                raise CfgError("stack_window")
            for index in list(ptrs):
                if index not in CALLEE_SAVED:
                    ptrs.pop(index, None)
            continue
        if insn["mnemonic"] in ("add", "sub") and any(index == 4 for index, _bits in insn["writes"]):
            if "imm" not in insn:
                raise CfgError("rsp_untracked")
            delta += insn["imm"] if insn["mnemonic"] == "add" else -insn["imm"]
            if delta > 0:
                raise CfgError("stack_underflow")
            if STACK_TOP + delta < STACK_LO:
                raise CfgError("stack_window")
            continue
        if any(index == 4 for index, _bits in insn["writes"]) and not insn.get("stack"):
            raise CfgError("rsp_untracked")
        if insn.get("rip"):
            target, nbytes = insn["rip"]
            if insn.get("writes"):
                if not have_regions or not _region_covers(covered, target, nbytes, store=False):
                    raise CfgError("precondition_required")
            else:
                raise CfgError("precondition_required")
            _kill_writes(insn, ptrs, dirty)
            continue
        if insn["mnemonic"] == "lea":
            dest = insn["writes"][0][0]
            disp = insn.get("leaDisp")
            srcs = [index for index, _bits in insn["reads"]]
            if disp is not None and srcs == [4]:
                ptrs[dest] = delta + disp
            elif disp is not None and len(srcs) == 1 and srcs[0] in ptrs:
                ptrs[dest] = ptrs[srcs[0]] + disp
            else:
                ptrs.pop(dest, None)
            if dest in CALLEE_SAVED:
                dirty.add(dest)
            continue
        stack = insn.get("stack")
        if stack:
            if stack[0] == "push":
                delta -= stack[1]
                if STACK_TOP + delta < STACK_LO:
                    raise CfgError("stack_window")
                regs = [index for index, _bits in insn["reads"]]
                reg = regs[0] if regs else None
                slots.append((reg, reg is not None and reg not in dirty))
                continue
            if stack[0] == "pop":
                if delta >= 0 or not slots:
                    raise CfgError("stack_underflow")
                delta += stack[1]
                saved, original = slots.pop()
                dests = [index for index, _bits in insn["writes"] if index != 4]
                dest = dests[0]
                ptrs.pop(dest, None)
                if dest == saved and original:
                    dirty.discard(dest)
                elif dest in CALLEE_SAVED:
                    dirty.add(dest)
                continue
        mem = insn.get("mem")
        if mem and mem[0] == "rsp":
            _base, disp, nbytes, _kind = mem
            if not _slot_in_frame(delta, delta + disp, nbytes):
                raise CfgError("stack_external")
            _kill_writes(insn, ptrs, dirty)
            continue
        if mem and mem[0] == "base":
            _tag, base, disp, nbytes, _kind = mem
            if base not in ptrs:
                raise CfgError("sandbox_untracked")
            if not _slot_in_frame(delta, ptrs[base] + disp, nbytes):
                raise CfgError("stack_external")
            _kill_writes(insn, ptrs, dirty)
            continue
        _kill_writes(insn, ptrs, dirty)


def _slot_in_frame(frame_delta, absolute, nbytes):
    lo = STACK_TOP + absolute
    hi = lo + nbytes
    if nbytes == 16 and (lo & 15):
        raise CfgError("xmm_align")
    return STACK_TOP + frame_delta <= lo and hi <= STACK_TOP


def _region_covers(covered, target, nbytes, store):
    for addr, blob, writable in covered:
        if addr <= target and target + nbytes <= addr + len(blob):
            if writable or store:
                return False
            return True
    return False


def _kill_writes(insn, ptrs, dirty):
    for index, _bits in insn.get("writes") or []:
        if index == 4:
            continue
        ptrs.pop(index, None)
        if index in CALLEE_SAVED:
            dirty.add(index)


def _relocate(funcs, rip_blobs):
    mapping = {}
    cursor = GUEST_CODE
    for base in sorted(funcs):
        mapping[base] = cursor
        cursor += len(funcs[base])
        cursor = (cursor + 15) & ~15
        if cursor > GUEST_DATA:
            raise CfgError("code_window")
    placed = []
    data_cursor = GUEST_DATA
    relocated_blobs = []
    for addr, blob in rip_blobs:
        if data_cursor + len(blob) > STACK_LO:
            raise CfgError("window_too_wide")
        relocated_blobs.append((data_cursor, blob))
        placed.append((addr, data_cursor))
        data_cursor += len(blob)
    new_funcs = {}
    for base in sorted(funcs):
        code = funcs[base]
        patched = bytearray(code)
        guest = mapping[base]
        for insn in decode_allow.decode_stream(code, base, control=True):
            offset = insn["address"] - base
            if insn["mnemonic"] == "call":
                if insn["size"] != 5 or code[offset] != 0xE8:
                    raise CfgError("unrelocatable")
                dest = mapping[insn["target"]]
                disp = dest - (guest + offset + 5)
                struct.pack_into("<i", patched, offset + 1, disp)
            elif insn.get("rip"):
                target, nbytes = insn["rip"]
                host = None
                for origin, guest_data in placed:
                    for addr, blob in rip_blobs:
                        if addr == origin and addr <= target and target + nbytes <= addr + len(blob):
                            host = guest_data + (target - addr)
                            break
                if host is None:
                    raise CfgError("precondition_required")
                disp = host - (guest + offset + insn["size"])
                struct.pack_into("<i", patched, offset + insn["size"] - 4, disp)
        new_funcs[guest] = bytes(patched)
    return new_funcs, mapping, relocated_blobs


def _to_rva(guest_ip, mapping, funcs):
    for origin, guest in mapping.items():
        if guest <= guest_ip < guest + len(funcs[origin]):
            return origin + (guest_ip - guest)
    return None


def _case_cpu(spec):
    regs = [0] * 16
    regs[4] = STACK_TOP
    if spec.get("fill"):
        for index in range(16):
            if index != 4:
                regs[index] = spec["fill"]
    for name, value in spec.get("regs", {}).items():
        regs[NAMES.index(name)] = value
    return {
        "r": regs,
        "cf": spec.get("cf", 0),
        "pf": spec.get("pf", 0),
        "af": spec.get("af", 0),
        "zf": spec.get("zf", 0),
        "sf": spec.get("sf", 0),
        "of": spec.get("of", 0),
    }


def _graph_cases(max_cases):
    specs = (
        {"name": "zeros"},
        {"name": "preserved", "regs": {
            "rax": 0x22, "rbx": 0x1111111111111111, "rbp": 0x2222222222222222,
            "rsi": 0x3333333333333333, "rdi": 0x4444444444444444,
            "r12": 0x5555555555555555, "r13": 0x6666666666666666,
            "r14": 0x7777777777777777, "r15": 0x8888888888888888,
        }},
        {"name": "volatiles", "regs": {"rax": 1, "rcx": 2, "rdx": 3, "r8": 4, "r9": 5, "r10": 6, "r11": 7}},
        {"name": "flags", "cf": 1, "zf": 1, "regs": {"rax": 0x80}},
    )
    return specs[:max(0, max_cases)]


def execute_image(data, max_graphs=8, max_functions=8, max_instructions=64, max_cases=4):
    """Execute discovered closed graphs that pass the safety contract.

    Graphs that need unknown memory or break the frame or the callee-saved
    registers are reported and not run. The PE entry point is not called.
    """
    public, graphs, info = _analyze(data)
    selected = graphs[:max_graphs]
    verified = []
    rejections = []
    graphs_executed = 0
    cases_executed = 0
    cases_matched = 0
    entry_rva = info.get("addressOfEntryPoint")
    for graph in selected:
        if any(begin <= entry_rva < begin + len(graph["code"][begin]) for begin in graph["code"]):
            rejections.append({"entry": graph["entry"], "reason": "contains_entry_point"})
            continue
        if len(graph["functions"]) > max_functions:
            rejections.append({"entry": graph["entry"], "reason": "too_many_functions"})
            continue
        if graph["instructionCount"] > max_instructions:
            rejections.append({"entry": graph["entry"], "reason": "step_budget"})
            continue
        regions = _rip_regions(graph, info["sections"], data)
        if isinstance(regions, str):
            rejections.append({"entry": graph["entry"], "reason": regions})
            continue
        reason = assess_graph(
            graph["code"], graph["entry"], rip_regions=regions,
            max_functions=max_functions, max_instructions=max_instructions,
        )
        if reason:
            rejections.append({"entry": graph["entry"], "reason": reason})
            continue
        try:
            guest_funcs, mapping, copies = _relocate(graph["code"], [(addr, blob) for addr, blob, _writable in regions])
        except CfgError as exc:
            rejections.append({"entry": graph["entry"], "reason": exc.reason})
            continue
        seen = []
        cases = []
        status = "verified_match"
        for spec in _graph_cases(max_cases):
            cpu = _case_cpu(spec)
            mem = bytearray(MEMSZ)
            mem[STACK_TOP:STACK_TOP + 8] = struct.pack("<Q", DONE)
            for addr, blob in copies:
                mem[addr:addr + len(blob)] = blob
            try:
                result = execute(
                    guest_funcs, mapping[graph["entry"]], cpu, mem, DONE,
                    max_steps=max_instructions, compare_af=False,
                )
            except AssertionError as exc:
                status = "verified_mismatch"
                fields = [name for name in str(exc).split("cfg mismatch: ", 1)[-1].split(",") if name]
                cases.append({"name": spec["name"], "result": "mismatch", "fields": fields})
                cases_executed += 1
                break
            except CfgError as exc:
                status = "not_verified"
                cases.append({"name": spec["name"], "result": exc.reason})
                cases_executed += 1
                break
            cases_executed += 1
            cases_matched += 1
            cases.append({"name": spec["name"], "result": "match"})
            for address in result["instructions"]:
                rva = _to_rva(address, mapping, graph["code"])
                if rva is not None and rva not in seen:
                    seen.append(rva)
        if status == "verified_match":
            graphs_executed += 1
        verified.append({
            "entry": graph["entry"],
            "functions": graph["functions"],
            "sizes": graph["sizes"],
            "instructionCount": graph["instructionCount"],
            "status": status,
            "cases": cases,
            "instructions": seen,
            "stopping": "returned_to_harness" if status == "verified_match" else status,
        })
    public["closedGraphs"] = [_public_graph(graph) for graph in graphs[:max_graphs]]
    public["mode"] = "execute"
    public["executed"] = graphs_executed > 0
    public["entryPointExecuted"] = False
    public["graphsDiscovered"] = public["closedGraphsFound"]
    public["graphsSelected"] = len(selected)
    public["graphsExecuted"] = graphs_executed
    public["graphsRejected"] = len(rejections)
    public["rejections"] = rejections
    public["casesExecuted"] = cases_executed
    public["casesMatched"] = cases_matched
    public["verifiedGraphs"] = verified
    public["maxGraphs"] = max_graphs
    public["maxFunctions"] = max_functions
    public["maxInstructions"] = max_instructions
    public["maxCases"] = max_cases
    public["note"] = (
        "verifiedGraphs are lifted C versus Unicorn for closed graphs that passed the "
        "stack, ABI, and memory contract. Rejected graphs were not executed. "
        "instructions are RVAs, not bytes. This is not a game launch and not an ARM64 result."
    )
    return public


def _rip_regions(graph, sections, data):
    found = []
    seen = set()
    for base, code in graph["code"].items():
        for insn in decode_allow.decode_stream(code, base, control=True):
            if not insn.get("rip"):
                continue
            target, nbytes = insn["rip"]
            if not insn.get("writes"):
                return "precondition_required"
            sec = _section_at(sections, target)
            if sec is None or sec["writable"] or sec["name"] == ".bind":
                return "precondition_required"
            try:
                off = inspect_pe32plus.file_offset_for_rva(sections, target, nbytes)
            except inspect_pe32plus.PeFormatError:
                return "precondition_required"
            key = (target, nbytes)
            if key in seen:
                continue
            seen.add(key)
            found.append((target, bytes(data[off:off + nbytes]), False))
    return found


def _public_graph(graph):
    return {
        "entry": graph["entry"],
        "functions": graph["functions"],
        "sizes": graph["sizes"],
        "instructionCount": graph["instructionCount"],
        "executed": False,
        "stopping": "closed_not_executed",
    }


def _analyze(data):
    """One disposition per pdata entry. Graph members are not extra roots."""
    info = inspect_pe32plus.inspect_bytes(data)
    executable = []
    for sec in info["sections"]:
        if sec["name"] == ".bind" or not sec["executable"]:
            continue
        lo = sec["virtualAddress"]
        executable.append((lo, lo + max(sec["virtualSize"], 1)))
    report = {
        "tool": "cfg-discover",
        "executed": False,
        "entryPointExecuted": False,
        "pdataIsNotEligibility": True,
        "closedGraphs": [],
        "pdataEntries": 0,
        "dispositions": {},
        "dispositionTotal": 0,
    }
    exc = info["exceptionDirectory"]
    if not exc["present"] or exc["size"] < 12:
        report["reasons"] = {"no_exception_directory": 1}
        return report, [], info
    try:
        off = inspect_pe32plus.file_offset_for_rva(info["sections"], exc["virtualAddress"], exc["size"])
        blob = data[off:off + exc["size"]]
    except inspect_pe32plus.PeFormatError:
        report["reasons"] = {"unmapped_pdata": 1}
        report["dispositions"] = {}
        return report, [], info
    entries = len(blob) // 12
    report["pdataEntries"] = entries
    report["pdataTrailingBytes"] = exc["size"] % 12
    records = []
    funcs = {}
    seen_begins = set()
    for n in range(entries):
        begin = int.from_bytes(blob[n * 12:n * 12 + 4], "little")
        end = int.from_bytes(blob[n * 12 + 4:n * 12 + 8], "little")
        rec = {"begin": begin, "end": end, "reason": None}
        if begin in seen_begins:
            rec["reason"] = "duplicate_range"
            records.append(rec)
            continue
        seen_begins.add(begin)
        if end <= begin or end - begin > MAX_INSNS * 8:
            rec["reason"] = "pdata_not_eligible"
        elif not any(lo <= begin and end <= hi for lo, hi in executable):
            name = None
            for sec in info["sections"]:
                span = max(sec["virtualSize"], sec["sizeOfRawData"])
                if sec["virtualAddress"] <= begin < sec["virtualAddress"] + span:
                    name = sec["name"]
            rec["reason"] = "bind_not_code" if name == ".bind" else "pdata_not_eligible"
        else:
            try:
                raw_at = inspect_pe32plus.file_offset_for_rva(info["sections"], begin, end - begin)
                code = bytes(data[raw_at:raw_at + (end - begin)])
                _decode(code, begin)
            except inspect_pe32plus.PeFormatError:
                rec["reason"] = "pdata_not_eligible"
            except CfgError as exc_err:
                rec["reason"] = exc_err.reason
            else:
                funcs[begin] = code
        records.append(rec)
    graphs = []
    for rec in records:
        if rec["reason"] is not None:
            continue
        entry = rec["begin"]
        subset = {}
        pending = [entry]
        rejected = None
        while pending and rejected is None:
            cur = pending.pop()
            if cur in subset:
                continue
            if cur not in funcs:
                rejected = "unknown_target"
                break
            subset[cur] = funcs[cur]
            for insn in _decode(subset[cur], cur):
                if insn["mnemonic"] == "call":
                    pending.append(insn["target"])
        if rejected is None:
            try:
                prepared = prepare(subset, entry)
            except CfgError as exc_err:
                rejected = exc_err.reason
        if rejected:
            rec["reason"] = rejected
            continue
        if not any(prepared["graph"][node] for node in prepared["reachable"]):
            continue
        rec["reason"] = "closed_graph_root"
        for other in prepared["reachable"]:
            if other == entry:
                continue
            for other_rec in records:
                if other_rec["begin"] == other and other_rec["reason"] is None:
                    other_rec["reason"] = "closed_graph_member"
        ordered = prepared["reachable"]
        graphs.append({
            "entry": entry,
            "functions": ordered,
            "sizes": [len(funcs[addr]) for addr in ordered],
            "instructionCount": sum(len(_decode(funcs[addr], addr)) for addr in ordered),
            "code": {addr: funcs[addr] for addr in ordered},
        })
    for rec in records:
        if rec["reason"] is None:
            rec["reason"] = "call_free"
    dispositions = Counter(rec["reason"] for rec in records)
    report["dispositions"] = dict(dispositions)
    report["dispositionTotal"] = sum(dispositions.values())
    report["reasons"] = {key: value for key, value in dispositions.items() if key not in ACCOUNTING}
    report["closedGraphsFound"] = len(graphs)
    return report, graphs, info


def discover_closed(data, max_graphs=8):
    """Read-only search for closed direct-call graphs.

    A .pdata entry is not eligible by itself. Every pdata entry gets one
    disposition. A callee inside a closed graph is a member, not another root
    and not a call-free body. Nothing in the image is executed.
    """
    report, graphs, _info = _analyze(data)
    report["closedGraphs"] = [_public_graph(graph) for graph in graphs[:max_graphs]]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only closed direct-call discovery. Does not execute guest code.")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--execute", action="store_true",
                        help="run closed graphs that pass the safety contract; does not call the PE entry")
    parser.add_argument("--max-graphs", type=int, default=8)
    parser.add_argument("--max-functions", type=int, default=8)
    parser.add_argument("--max-instructions", type=int, default=64)
    parser.add_argument("--max-cases", type=int, default=4)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    path = Path(args.exe)
    if not path.is_file():
        print("not a file", file=sys.stderr)
        return 1
    if path.stat().st_size > inspect_pe32plus.MAX_FILE:
        print("file exceeds the 64 MiB cap", file=sys.stderr)
        return 1
    data = path.read_bytes()
    digest = inspect_pe32plus.sha256_hex(data)
    if digest.lower() != args.expect_sha256.lower():
        print("sha256 mismatch", file=sys.stderr)
        return 3
    try:
        if args.execute:
            report = execute_image(
                data, max_graphs=args.max_graphs, max_functions=args.max_functions,
                max_instructions=args.max_instructions, max_cases=args.max_cases,
            )
        else:
            report = discover_closed(data, max_graphs=args.max_graphs)
    except inspect_pe32plus.PeFormatError as exc:
        print("pe: %s" % exc, file=sys.stderr)
        return 2
    report["sha256"] = digest
    if not args.execute:
        report["note"] = (
            "dispositions assign every pdata entry once. closedGraphs are roots only; "
            "members are not extra graphs and call-free bodies are not rejects. "
            "Nothing was executed. This is not a game launch and not an ARM64 result."
        )
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        Path(args.report).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
