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
    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


MAX_GUEST = 64 * 1024 * 1024
# Canonical user address. Bit 63 tokens are not fetchable on every Unicorn build.
STUB_BASE = 0x7FFF00000000
STUB_STRIDE = 32


def canonical_user(addr):
    """x86-64 user pointer: bits 63:47 are all zero. A token fails this on purpose."""
    return 0 <= addr <= 0xFFFFFFFFFFFFFFFF and (addr >> 47) == 0


def guest_token(kind, thunk_id):
    """Same bits as ae_guest_token. The high bit alone is not enough."""
    return 0x8000000000000000 | ((kind & 0xF) << 36) | ((thunk_id & 0x0FFFFFFF) << 4)


def iat_slot_fault(addr, limit):
    """Image-sized slot check. MEMSZ is not a page boundary and not the image."""
    if not isinstance(limit, int) or limit < 0 or limit > MAX_GUEST:
        return "image_limit"
    if not isinstance(addr, int) or addr < 0 or addr > 0xFFFFFFFFFFFFFFFF - 8:
        return "iat_oob"
    if (addr >> 12) != ((addr + 7) >> 12):
        return "iat_cross_page"
    if addr & 7:
        return "iat_misaligned"
    if addr + 8 > limit:
        return "iat_oob"
    return None


def token_decode(token):
    kind = (token >> 36) & 0xF
    thunk_id = (token >> 4) & 0x0FFFFFFF
    if token != guest_token(kind, thunk_id):
        return None
    if kind not in (1, 2):
        return None
    return kind, thunk_id


def _decode(code, base, allow_iat=False):
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
    if not allow_iat and any(insn["mnemonic"] == "call_rip" for insn in insns):
        raise CfgError("indirect_call")
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


def _check_iat_addr(addr, slots, limit):
    if addr not in slots:
        raise CfgError("unknown_iat")
    fault = iat_slot_fault(addr, limit)
    if fault:
        raise CfgError(fault)


def prepare(funcs, entry, imports=None, max_steps=MAX_STEPS_DEFAULT, iat_slots=None,
            image_limit=None):
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
        insns = _decode(code, base, allow_iat=iat_slots is not None)
        for insn in insns:
            if insn["mnemonic"] == "call_rip":
                _check_iat_addr(insn["iat"], iat_slots, MEMSZ if image_limit is None else image_limit)
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
        elif insn["mnemonic"] in ("call", "call_rip"):
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
        if insn["mnemonic"] in JCC or insn["mnemonic"] in ("jmp", "call", "call_rip", "ret"):
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


def _emit_function(base, code, insns, max_steps, max_depth, iat_slots=None, last_addr=0, pid=0):
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
        elif term["mnemonic"] == "call_rip":
            nxt = term["address"] + term["size"]
            slot = iat_slots[term["iat"]]
            api = {"GetLastError": 1, "GetCurrentProcessId": 2, "SetLastError": 3}.get(slot["name"], 0)
            if not slot.get("modeled", True):
                api = 0
            lines.append("            if (ae_iat_call(c, mem, %#xull, %uu, %d, %d, %d, %#xull, %#xull, %#xull) != 0) return;" % (
                term["iat"], slot["id"], api, max_depth, max_steps, nxt, last_addr, pid))
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


def _iat_helper(last_addr, pid, external=None):
    rows = []
    for addr, token in sorted((external or {}).items()):
        rows.append("        else if (slot == %dull) token = %dull;" % (addr, token))
    external_c = "\n".join(rows)
    return """
static int ae_iat_call(Cpu64 *c, uint8_t *mem, uint64_t slot, unsigned expect_id, int api,
                       int max_depth, int max_steps, uint64_t ret_ip, uint64_t last_addr, uint64_t pid) {
    uint64_t rsp = rd(c, 4, 64);
    uint64_t token, kind, id, rebuilt;
    if ((rsp & 15ull) != 0ull) { stop = 12; return 12; }
    if (rsp < %dull || rsp + 0x20ull > %dull) { stop = 14; return 14; }
    if ((slot & 7ull) || slot + 8ull < slot || ((slot >> 12) != ((slot + 7ull) >> 12))) {
        stop = 16; return 16;
    }
    if (++depth > max_depth) { stop = 11; return 11; }
    if (++steps > max_steps) { depth--; stop = 9; return 9; }
    token = ~0ull;
    if (slot + 8ull <= (uint64_t)MEMSZ) token = ld(mem, slot, 8);
    else if (0) token = 0;
%s
    if (token == ~0ull) { depth--; stop = 16; return 16; }
    kind = (token >> 36) & 0xfull;
    id = (token >> 4) & 0x0fffffffull;
    rebuilt = 0x8000000000000000ull | (kind << 36) | (id << 4);
    if (token != rebuilt || (kind != 1ull && kind != 2ull) || id != expect_id) {
        depth--; stop = 15; return 15;
    }
    if (kind == 2ull || api == 0) { depth--; stop = 13; return 13; }
    wr(c, 4, rsp - 8ull, 64);
    st(mem, rsp - 8ull, ret_ip, 8);
    if (api == 1) wr(c, 0, ld(mem, last_addr, 4), 64);
    else if (api == 2) wr(c, 0, pid, 64);
    else if (api == 3) st(mem, last_addr, rd(c, 1, 32), 4);
    else { wr(c, 4, rsp, 64); depth--; stop = 13; return 13; }
    if (ld(mem, rd(c, 4, 64), 8) != ret_ip) { wr(c, 4, rsp, 64); depth--; stop = 18; return 18; }
    wr(c, 4, rd(c, 4, 64) + 8ull, 64);
    depth--;
    return 0;
}
""" % (STACK_LO + 8, STACK_TOP, external_c)


def emit_program(funcs, entry, imports=None, max_steps=MAX_STEPS_DEFAULT, max_depth=MAX_DEPTH_DEFAULT,
                  freestanding=False, iat_slots=None, last_addr=0, pid=0, report_stop=False,
                  image_limit=None, external=None):
    prepared = prepare(funcs, entry, imports=imports, max_steps=max_steps, iat_slots=iat_slots,
                       image_limit=image_limit)
    uses_depth = any(
        insn["mnemonic"] in ("call", "call_rip")
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
    if iat_slots is not None:
        parts.append(_iat_helper(last_addr, pid, external))
    for base in prepared["reachable"]:
        parts.append("void %s(Cpu64 *c, uint8_t *mem);" % _c_name(base))
    for base in prepared["reachable"]:
        parts.append(_emit_function(
            base, funcs[base], prepared["insns"][base], max_steps, max_depth,
            iat_slots=iat_slots, last_addr=last_addr, pid=pid))
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
        if report_stop:
            parts.append("    if (fwrite(&c, sizeof c, 1, stdout) != 1) return 4;")
            parts.append("    if (fwrite(mem, 1, MEMSZ, stdout) != MEMSZ) return 5;")
            parts.append("    return stop;")
        else:
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


_IAT_STOP = {
    9: "step_budget", 11: "depth_budget", 12: "misaligned_stack", 13: "unimplemented_import",
    14: "shadow_space", 15: "illegal_token", 16: "iat_oob", 18: "return_mismatch",
}
_MODELED_APIS = frozenset({"GetLastError", "GetCurrentProcessId", "SetLastError"})


def virtual_api(name, ecx, last, pid, rax):
    """Defined virtual result. Not Unicorn and not a Windows DLL."""
    if name == "SetLastError":
        return rax, ecx & 0xFFFFFFFF
    if name == "GetLastError":
        return last & 0xFFFFFFFF, last
    if name == "GetCurrentProcessId":
        return pid & 0xFFFFFFFF, last
    return None


def _stub_bytes(name, last_addr, pid):
    if name == "GetLastError":
        return b"\x48\xa1" + struct.pack("<Q", last_addr) + b"\xc3"
    if name == "GetCurrentProcessId":
        return b"\xb8" + struct.pack("<I", pid & 0xFFFFFFFF) + b"\xc3"
    if name == "SetLastError":
        return b"\x89\x0c\x25" + struct.pack("<I", last_addr & 0xFFFFFFFF) + b"\xc3"
    raise CfgError("unimplemented_import")


def _production_token(slot):
    kind = 1 if slot.get("modeled") else 2
    token = slot.get("token", guest_token(kind, slot["id"]))
    decoded = token_decode(token)
    if decoded != (kind, slot["id"]) or canonical_user(token):
        raise CfgError("illegal_token")
    return token


def execute_iat(funcs, entry, cpu, mem, return_ip, iat_slots, last_addr, pid,
                max_steps=MAX_STEPS_DEFAULT, max_depth=MAX_DEPTH_DEFAULT, probe=None,
                image_limit=None):
    """Lift call [rip+disp32] through a registered guest token.

    The lifter reads the production token and never fetches it. Unicorn gets
    a separate reference image: each modeled IAT cell is rewritten to a
    canonical stub address. Instruction bytes are not rewritten. Failures are
    decided by the lifter before the push, so they are not compared.
    """
    limit = MEMSZ if image_limit is None else image_limit
    if iat_slot_fault(0, limit) == "image_limit":
        raise CfgError("image_limit")
    _check_stack(cpu, mem, return_ip)
    image = bytearray(mem)
    external = {}
    stack = (STACK_LO, STACK_TOP + 8)
    for base, code in funcs.items():
        if _span_overlap(base, base + len(code), stack[0], stack[1]):
            raise CfgError("range_overlap")
        for addr in iat_slots:
            if _span_overlap(base, base + len(code), addr, addr + 8):
                raise CfgError("range_overlap")
    for addr in iat_slots:
        if _span_overlap(addr, addr + 8, stack[0], stack[1]):
            raise CfgError("range_overlap")
    for base, code in funcs.items():
        if base < MEMSZ < base + len(code) or (base & ~0xFFF) != ((base + len(code) - 1) & ~0xFFF):
            raise CfgError("span_limit")
        high = base >= MEMSZ
        if high and image_limit is None:
            raise CfgError("code_window")
        if STACK_LO <= base < STACK_TOP + 8:
            raise CfgError("code_window")
        if not high:
            image[base:base + len(code)] = code
    for addr, slot in iat_slots.items():
        if addr + 8 <= MEMSZ:
            continue
        if image_limit is None:
            raise CfgError("iat_oob")
        external[addr] = _production_token(slot)
    source, prepared = emit_program(
        funcs, entry, iat_slots=iat_slots, max_steps=max_steps, max_depth=max_depth,
        last_addr=last_addr, pid=pid, report_stop=True, image_limit=limit, external=external)
    td = Path(tempfile.mkdtemp(prefix="x64iat-"))
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
    if len(host.stdout) != difftest64.CPU_BYTES + MEMSZ:
        raise CfgError("host_abort")
    host_cpu = difftest64.unpack_cpu(host.stdout)
    host_mem = host.stdout[difftest64.CPU_BYTES:]
    if host.returncode != 0:
        reason = _IAT_STOP.get(host.returncode, "host_abort")
        rsp = host_cpu["r"][4]
        below = int.from_bytes(host_mem[rsp - 8:rsp], "little") if rsp >= 8 else None
        raise CfgError(reason, {
            "rax": host_cpu["r"][0],
            "rbx": host_cpu["r"][3],
            "rsp": rsp,
            "rcx": host_cpu["r"][1],
            "below": below,
        })
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, MEMSZ)
    reference = bytearray(image)
    stubs = {}
    for index, addr in enumerate(sorted(iat_slots)):
        slot = iat_slots[addr]
        if not slot.get("modeled") or slot["name"] not in _MODELED_APIS:
            continue
        stub = STUB_BASE + index * STUB_STRIDE
        if not canonical_user(stub) or stub + len(_stub_bytes(slot["name"], last_addr, pid)) > STUB_BASE + 0x1000:
            raise CfgError("stub_window")
        if addr + 8 <= MEMSZ:
            reference[addr:addr + 8] = struct.pack("<Q", stub)
        stubs[stub] = (addr, _stub_bytes(slot["name"], last_addr, pid))
    uc.mem_write(0, bytes(reference))
    if stubs:
        uc.mem_map(STUB_BASE, 0x1000)
        for stub, (_addr, blob) in stubs.items():
            uc.mem_write(stub, blob)
    mapped = {0}
    for base, code in funcs.items():
        if base >= MEMSZ:
            page = base & ~0xFFF
            if page not in mapped:
                uc.mem_map(page, 0x1000)
                mapped.add(page)
            uc.mem_write(base, code)
    for addr in external:
        page = addr & ~0xFFF
        if page not in mapped:
            uc.mem_map(page, 0x1000)
            mapped.add(page)
        uc.mem_write(addr, struct.pack("<Q", next(stub for stub, (slot_addr, _blob) in stubs.items() if slot_addr == addr)))
    for reg, value in zip(UC_GPRS, cpu["r"]):
        uc.reg_write(reg, int(value) & 0xFFFFFFFFFFFFFFFF)
    uc.reg_write(UC_X86_REG_EFLAGS, difftest64._flags_to_eflags(cpu))
    try:
        uc.emu_start(entry, return_ip, timeout=2000000)
    except UcError as exc:
        raise CfgError("unicorn_abort") from exc
    uni = [uc.reg_read(reg) for reg in UC_GPRS]
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    diffs = [name for index, name in enumerate(names) if host_cpu["r"][index] != uni[index]]
    uni_mem = bytearray(uc.mem_read(0, MEMSZ))
    host_view = bytearray(host_mem)
    for addr in iat_slots:
        if addr + 8 <= MEMSZ:
            host_view[addr:addr + 8] = b"\x00" * 8
            uni_mem[addr:addr + 8] = b"\x00" * 8
    if host_view != uni_mem:
        diffs.append("mem")
    if diffs:
        raise AssertionError("cfg mismatch: " + ",".join(diffs))
    observed = {}
    for addr in iat_slots:
        if addr + 8 <= MEMSZ:
            observed[addr] = int.from_bytes(host_mem[addr:addr + 8], "little")
        else:
            observed[addr] = external[addr]
    return {
        "executed": True,
        "rax": host_cpu["r"][0],
        "rbx": host_cpu["r"][3],
        "rsp": host_cpu["r"][4],
        "lastError": int.from_bytes(host_mem[last_addr:last_addr + 4], "little"),
        "entryPointExecuted": False,
        "oracle": "unicorn-canonical-stub",
        "reached": prepared["reachable"],
        "slots": observed,
        "probe": None if probe is None else int.from_bytes(host_mem[probe:probe + 8], "little"),
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


VOLATILE = frozenset({0, 1, 2, 8, 9, 10, 11})
ARG_ROLE = {1: "integer_argument_0", 2: "integer_argument_1", 8: "integer_argument_2", 9: "integer_argument_3"}
CONTRACT_FIELDS = ("size", "readable", "writable", "initializedBytes")


def assess_graph(funcs, entry, rip_regions=None, contracts=None, max_functions=MAX_FUNCS,
                 max_instructions=MAX_STEPS_DEFAULT):
    """Return a rejection reason, or None when the graph may be executed."""
    found = diagnose_graph(
        funcs, entry, rip_regions=rip_regions, contracts=contracts,
        max_functions=max_functions, max_instructions=max_instructions,
    )
    return None if found["ok"] else found["reason"]


def diagnose_graph(funcs, entry, rip_regions=None, contracts=None, max_functions=MAX_FUNCS,
                   max_instructions=MAX_STEPS_DEFAULT):
    """Explain a rejection. Does not execute the graph and does not invent an object."""
    try:
        prepared = prepare(funcs, entry, max_steps=max_instructions)
    except CfgError as exc:
        return {"ok": False, "reason": exc.reason, "diagnostic": exc.detail or None}
    if len(prepared["reachable"]) > max_functions:
        return {"ok": False, "reason": "too_many_functions", "diagnostic": None}
    try:
        normalized = _normalize_contracts(contracts)
        _walk(entry, prepared, 0, _entry_pointers(normalized), [], normalized, _cover(rip_regions), rip_regions is not None)
    except CfgError as exc:
        return {"ok": False, "reason": exc.reason, "diagnostic": exc.detail or None}
    return {"ok": True, "reason": None, "diagnostic": None}


def _cover(rip_regions):
    covered = []
    if rip_regions is not None:
        for addr, blob, writable in rip_regions:
            covered.append((addr, bytes(blob), bool(writable)))
    return covered


def _reg_meta(index):
    if index in ARG_ROLE:
        return ARG_ROLE[index], "volatile"
    if index in CALLEE_SAVED:
        return "nonvolatile", "nonvolatile"
    if index == 4:
        return "stack_pointer", "nonvolatile"
    return "volatile", "volatile"


def _context(base, delta, ptrs, frames):
    return {
        "function": base,
        "rspDelta": delta,
        "pointers": [
            {
                "register": NAMES[reg],
                "provenance": prov["kind"],
                "frame": prov.get("frame"),
                "offset": prov.get("offset"),
                "region": prov.get("region"),
            }
            for reg, prov in sorted(ptrs.items())
        ],
        "liveFrames": [
            {"id": frame["id"], "owner": frame["owner"], "lo": frame["delta"], "hi": frame["hi"], "live": frame["live"]}
            for frame in frames if frame["live"]
        ],
    }


def _detail(insn, category, width, access, reg, provenance, ctx, missing=None):
    role, volatility = _reg_meta(reg) if reg is not None else (None, None)
    detail = {
        "rva": insn["address"],
        "category": category,
        "width": width,
        "access": access,
        "register": None if reg is None else NAMES[reg],
        "role": role,
        "volatility": volatility,
        "provenance": provenance,
        "callContext": ctx,
    }
    if missing is not None:
        detail["missing"] = list(missing)
        detail["observedWidthIsNotObjectSize"] = True
    return detail


def _normalize_contracts(contracts):
    if not contracts:
        return {}
    primary = {}
    for name, spec in contracts.items():
        if name not in NAMES:
            raise CfgError("contract_register")
        if "aliasOf" in spec:
            continue
        for field in ("name", "guest", "size", "readable", "writable", "bytes"):
            if field not in spec:
                raise CfgError("contract_shape")
        if not (0 <= spec["writable"] <= spec["readable"] <= spec["size"]):
            raise CfgError("contract_shape")
        if len(spec["bytes"]) < spec["readable"]:
            raise CfgError("contract_shape")
        if spec["guest"] < 0 or spec["guest"] + spec["size"] > STACK_LO:
            raise CfgError("contract_overlap")
        primary[name] = spec
    spans = []
    for spec in primary.values():
        guard = spec.get("guard", 0)
        if guard < 0:
            raise CfgError("contract_shape")
        lo = spec["guest"] - guard
        hi = spec["guest"] + spec["size"] + guard
        if lo < 0 or hi > STACK_LO:
            raise CfgError("contract_overlap")
        spans.append((lo, hi))
    spans.sort()
    for (lo, hi), (lo2, _hi2) in zip(spans, spans[1:]):
        if hi > lo2:
            raise CfgError("contract_overlap")
    out = dict(primary)
    for name, spec in contracts.items():
        if "aliasOf" not in spec:
            continue
        base = primary.get(spec["aliasOf"])
        if base is None:
            raise CfgError("contract_alias")
        offset = spec.get("offset", 0)
        if offset < 0 or offset > base["readable"]:
            raise CfgError("contract_shape")
        out[name] = {
            "aliasOf": spec["aliasOf"],
            "name": base["name"],
            "guest": base["guest"],
            "size": base["size"],
            "readable": base["readable"],
            "writable": base["writable"],
            "bytes": base["bytes"],
            "offset": offset,
        }
    return out


def _entry_pointers(contracts):
    ptrs = {}
    for name, spec in contracts.items():
        ptrs[NAMES.index(name)] = {
            "kind": "argument",
            "region": spec["name"],
            "offset": spec.get("offset", 0),
        }
    return ptrs


def _walk(base, prepared, entry_delta, ptrs, frames, contracts, covered, have_regions):
    if len(frames) > MAX_DEPTH_DEFAULT:
        raise CfgError("depth_budget")
    frame = {"id": len(frames), "owner": base, "delta": entry_delta, "hi": entry_delta, "live": True}
    frames.append(frame)
    delta = entry_delta
    dirty = set()
    slots = []
    killed = set()
    defined = set()
    insns = prepared["insns"][base]
    for insn in insns:
        ctx = _context(base, delta, ptrs, frames)
        if insn.get("xmm") is not None:
            raise CfgError("xmm_untracked", _detail(insn, "xmm", 16, "access", None, "none", ctx))
        if insn["mnemonic"] == "ret":
            if delta != frame["hi"] or slots:
                raise CfgError("stack_unbalanced", _detail(insn, "rsp", 8, "ret", 4, "stack", ctx))
            if dirty & CALLEE_SAVED:
                reg = sorted(dirty & CALLEE_SAVED)[0]
                raise CfgError("abi_unpreserved", _detail(insn, "register", 8, "ret", reg, "clobbered", ctx))
            frame["live"] = False
            return
        if insn["mnemonic"] == "call":
            if STACK_TOP + delta - 8 < STACK_LO:
                raise CfgError("stack_window", _detail(insn, "rsp", 8, "call", 4, "stack", ctx))
            _walk(insn["target"], prepared, delta - 8, dict(ptrs), frames, contracts, covered, have_regions)
            for reg in list(ptrs):
                if reg in VOLATILE:
                    ptrs.pop(reg, None)
                    killed.add(reg)
            continue
        if insn["mnemonic"] in ("add", "sub") and any(index == 4 for index, _bits in insn["writes"]):
            if "imm" not in insn:
                raise CfgError("rsp_untracked", _detail(insn, "rsp", 8, insn["mnemonic"], 4, "none", ctx))
            delta += insn["imm"] if insn["mnemonic"] == "add" else -insn["imm"]
            if delta > frame["hi"]:
                raise CfgError("stack_underflow", _detail(insn, "rsp", 8, insn["mnemonic"], 4, "stack", ctx))
            if STACK_TOP + delta < STACK_LO:
                raise CfgError("stack_window", _detail(insn, "rsp", 8, insn["mnemonic"], 4, "stack", ctx))
            frame["delta"] = delta
            continue
        if any(index == 4 for index, _bits in insn["writes"]) and not insn.get("stack"):
            raise CfgError("rsp_untracked", _detail(insn, "rsp", 8, insn["mnemonic"], 4, "none", ctx))
        if insn.get("rip"):
            target, nbytes = insn["rip"]
            access = "load" if insn.get("writes") else "store"
            if access == "store" or not have_regions or not _region_covers(covered, target, nbytes, store=False):
                raise CfgError("precondition_required", _detail(insn, "rip", nbytes, access, None, "global", ctx))
            _kill_writes(insn, ptrs, dirty, defined, killed)
            continue
        if insn["mnemonic"] == "lea":
            dest = insn["writes"][0][0]
            disp = insn.get("leaDisp")
            srcs = [index for index, _bits in insn["reads"]]
            if disp is not None and srcs == [4]:
                offset = delta + disp
                if not (frame["delta"] <= offset < frame["hi"]):
                    raise CfgError("stack_external", _detail(insn, "rsp", 8, "lea", 4, "stack", ctx))
                ptrs[dest] = {"kind": "stack", "frame": frame["id"], "offset": offset}
            elif disp is not None and len(srcs) == 1 and srcs[0] in ptrs:
                src = ptrs[srcs[0]]
                ptrs[dest] = dict(src)
                ptrs[dest]["offset"] = src["offset"] + disp
            else:
                ptrs.pop(dest, None)
            defined.add(dest)
            killed.discard(dest)
            if dest in CALLEE_SAVED:
                dirty.add(dest)
            continue
        stack = insn.get("stack")
        if stack and stack[0] == "push":
            delta -= stack[1]
            if STACK_TOP + delta < STACK_LO:
                raise CfgError("stack_window", _detail(insn, "rsp", stack[1], "push", 4, "stack", ctx))
            frame["delta"] = delta
            regs = [index for index, _bits in insn["reads"]]
            reg = regs[0] if regs else None
            slots.append((reg, reg is not None and reg not in dirty))
            continue
        if stack and stack[0] == "pop":
            if delta >= frame["hi"] or not slots:
                raise CfgError("stack_underflow", _detail(insn, "rsp", stack[1], "pop", 4, "stack", ctx))
            delta += stack[1]
            frame["delta"] = delta
            saved, original = slots.pop()
            dest = [index for index, _bits in insn["writes"] if index != 4][0]
            ptrs.pop(dest, None)
            defined.add(dest)
            killed.discard(dest)
            if dest == saved and original:
                dirty.discard(dest)
            elif dest in CALLEE_SAVED:
                dirty.add(dest)
            continue
        mem = insn.get("mem")
        if mem and mem[0] == "rsp":
            _base, disp, nbytes, kind = mem
            offset = delta + disp
            if not (frame["delta"] <= offset and offset + nbytes <= frame["hi"]):
                raise CfgError("stack_external", _detail(insn, "rsp", nbytes, kind, 4, "stack", ctx))
            _kill_writes(insn, ptrs, dirty, defined, killed)
            continue
        if mem and mem[0] == "base":
            _tag, reg, disp, nbytes, kind = mem
            _use_base(insn, reg, disp, nbytes, kind, ptrs, frames, contracts, killed, defined, ctx)
            _kill_writes(insn, ptrs, dirty, defined, killed)
            continue
        _kill_writes(insn, ptrs, dirty, defined, killed)
    raise CfgError("missing_ret")


def _use_base(insn, reg, disp, nbytes, kind, ptrs, frames, contracts, killed, defined, ctx):
    prov = ptrs.get(reg)
    if prov is None:
        if reg in ARG_ROLE and reg not in defined and reg not in killed:
            raise CfgError("argument_contract_missing", _detail(
                insn, "base", nbytes, kind, reg, "incoming_unspecified", ctx, CONTRACT_FIELDS))
        provenance = "lost_after_call" if reg in killed else "none"
        raise CfgError("sandbox_untracked", _detail(insn, "base", nbytes, kind, reg, provenance, ctx))
    if prov["kind"] == "stack":
        frame = frames[prov["frame"]]
        offset = prov["offset"] + disp
        if not frame["live"] or offset < frame["delta"]:
            raise CfgError("dangling", _detail(insn, "base", nbytes, kind, reg, "freed_stack", ctx))
        if offset + nbytes > frame["hi"]:
            raise CfgError("stack_external", _detail(insn, "base", nbytes, kind, reg, "stack", ctx))
        return
    region = None
    for spec in contracts.values():
        if spec["name"] == prov["region"] and "aliasOf" not in spec:
            region = spec
            break
    offset = prov["offset"] + disp
    limit = region["writable"] if kind == "store" else region["readable"]
    if region is None or offset < 0 or offset + nbytes > limit:
        raise CfgError("contract_bounds", _detail(insn, "base", nbytes, kind, reg, "argument", ctx))


def _kill_writes(insn, ptrs, dirty, defined, killed):
    for index, _bits in insn.get("writes") or []:
        if index == 4:
            continue
        ptrs.pop(index, None)
        defined.add(index)
        killed.discard(index)
        if index in CALLEE_SAVED:
            dirty.add(index)


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


def diagnose_image(data, max_graphs=8, max_functions=8, max_instructions=64):
    """Assess closed graphs and stop. Never executes them."""
    public, graphs, info = _analyze(data)
    selected = graphs[:max_graphs]
    rows = []
    entry_rva = info.get("addressOfEntryPoint")
    for graph in selected:
        if any(begin <= entry_rva < begin + len(graph["code"][begin]) for begin in graph["code"]):
            rows.append({"entry": graph["entry"], "eligible": False, "reason": "contains_entry_point",
                         "diagnostic": None, "executed": False})
            continue
        if len(graph["functions"]) > max_functions:
            rows.append({"entry": graph["entry"], "eligible": False, "reason": "too_many_functions",
                         "diagnostic": None, "executed": False})
            continue
        if graph["instructionCount"] > max_instructions:
            rows.append({"entry": graph["entry"], "eligible": False, "reason": "step_budget",
                         "diagnostic": None, "executed": False})
            continue
        regions = _rip_regions(graph, info["sections"], data)
        if isinstance(regions, str):
            rows.append({"entry": graph["entry"], "eligible": False, "reason": regions,
                         "diagnostic": None, "executed": False})
            continue
        found = diagnose_graph(
            graph["code"], graph["entry"], rip_regions=regions,
            max_functions=max_functions, max_instructions=max_instructions,
        )
        rows.append({
            "entry": graph["entry"],
            "eligible": found["ok"],
            "reason": found["reason"],
            "diagnostic": found["diagnostic"],
            "executed": False,
        })
    public["closedGraphs"] = [_public_graph(graph) for graph in graphs[:max_graphs]]
    public["mode"] = "diagnose"
    public["executed"] = False
    public["speculativeExecution"] = False
    public["entryPointExecuted"] = False
    public["graphsDiscovered"] = public["closedGraphsFound"]
    public["graphsSelected"] = len(selected)
    public["graphsExecuted"] = 0
    public["casesExecuted"] = 0
    public["diagnostics"] = rows
    public["note"] = (
        "Diagnostic only. No graph was executed. An incoming pointer without a declared "
        "contract is argument_contract_missing; the access width is not an object size."
    )
    return public


def execute_under_contract(funcs, entry, contract, cpu, mem, return_ip=DONE, max_steps=MAX_STEPS_DEFAULT):
    """Run one synthetic program against a declared object. This is not game state."""
    found = diagnose_graph(funcs, entry, contracts=contract, max_instructions=max_steps)
    if not found["ok"]:
        raise CfgError(found["reason"], found["diagnostic"])
    normalized = _normalize_contracts(contract)
    image = bytearray(mem)
    for name, spec in normalized.items():
        if "aliasOf" in spec:
            continue
        guest = spec["guest"]
        blob = bytes(spec["bytes"][:spec["size"]])
        image[guest:guest + len(blob)] = blob
    for name, spec in normalized.items():
        cpu["r"][NAMES.index(name)] = spec["guest"] + spec.get("offset", 0)
    result = execute(funcs, entry, cpu, image, return_ip, max_steps=max_steps, compare_af=False)
    result["memoryContract"] = "synthetic"
    result["actualGameState"] = False
    return result


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
        found = diagnose_graph(
            graph["code"], graph["entry"], rip_regions=regions,
            max_functions=max_functions, max_instructions=max_instructions,
        )
        if not found["ok"]:
            rejections.append({
                "entry": graph["entry"],
                "reason": found["reason"],
                "diagnostic": found["diagnostic"],
            })
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


def _slot_name(data, sections, thunk):
    if thunk & 0x8000000000000000:
        return None
    try:
        off = inspect_pe32plus.file_offset_for_rva(sections, (thunk & 0xFFFFFFFF) + 2, 1)
    except inspect_pe32plus.PeFormatError:
        return None
    chars = []
    for i in range(256):
        try:
            at = inspect_pe32plus.file_offset_for_rva(sections, (thunk & 0xFFFFFFFF) + 2 + i, 1)
        except inspect_pe32plus.PeFormatError:
            return None
        byte = data[at]
        if byte == 0:
            try:
                return bytes(chars).decode("ascii")
            except UnicodeDecodeError:
                return None
        if byte < 0x20 or byte > 0x7E:
            return None
        chars.append(byte)
    return None


def _import_slots(data, info):
    slots = {}
    e_lfanew = inspect_pe32plus.u32(data, 0x3C)
    opt = e_lfanew + 24
    if inspect_pe32plus.u32(data, opt + 108) < 2:
        return slots
    rva = inspect_pe32plus.u32(data, opt + 120)
    size = inspect_pe32plus.u32(data, opt + 124)
    if rva == 0 or size < 20:
        return slots
    sections = info["sections"]
    index = 0
    while index < 64 and index * 20 + 20 <= size:
        try:
            off = inspect_pe32plus.file_offset_for_rva(sections, rva + index * 20, 20)
        except inspect_pe32plus.PeFormatError:
            break
        oft, _tds, _fwd, name_rva, first = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0 and first == 0:
            break
        raw = []
        for i in range(64):
            try:
                at = inspect_pe32plus.file_offset_for_rva(sections, name_rva + i, 1)
            except inspect_pe32plus.PeFormatError:
                break
            if data[at] == 0:
                break
            raw.append(data[at])
        dll = bytes(raw).decode("ascii", "replace")
        thunk_rva = oft or first
        iat_rva = first or oft
        step = 0
        dll_index = index
        while step < 4096:
            try:
                toff = inspect_pe32plus.file_offset_for_rva(sections, thunk_rva + step * 8, 8)
            except inspect_pe32plus.PeFormatError:
                break
            value = struct.unpack_from("<Q", data, toff)[0]
            if value == 0:
                break
            ordinal = bool(value & 0x8000000000000000)
            name = None if ordinal else _slot_name(data, sections, value)
            ordinal_value = (value & 0xFFFF) if ordinal else None
            modeled = (not ordinal and dll.lower() == "kernel32.dll" and
                       name in ("GetLastError", "GetCurrentProcessId"))
            slots[iat_rva + step * 8] = {
                "dll": dll, "name": name, "ordinal": ordinal, "ordinalValue": ordinal_value,
                "modeled": modeled,
                "id": (dll_index << 16) | step,
            }
            step += 1
        index += 1
    return slots


def _span_overlap(a0, a1, b0, b1):
    return a0 < b1 and b0 < a1


def _memory_meta(insn, sections, image_size):
    """Access facts only. Width is not an object size and no bytes are copied."""
    if insn.get("rip"):
        target, nbytes = insn["rip"]
        access = "load" if insn.get("writes") else "store"
        sec = _section_at(sections, target)
        return {
            "at": insn["address"],
            "mnemonic": insn["mnemonic"],
            "kind": "rip",
            "access": access,
            "width": nbytes,
            "target": target,
            "inImage": isinstance(target, int) and 0 <= target and target + nbytes <= image_size,
            "section": None if sec is None else sec["name"],
            "writable": None if sec is None else bool(sec["writable"]),
            "executable": None if sec is None else bool(sec["executable"]),
        }
    mem = insn.get("mem")
    if mem is None:
        return {
            "at": insn["address"],
            "mnemonic": insn["mnemonic"],
            "kind": "other",
            "access": "access",
            "width": None,
        }
    if mem[0] == "rsp":
        return {
            "at": insn["address"],
            "mnemonic": insn["mnemonic"],
            "kind": "rsp",
            "access": mem[3],
            "width": mem[2],
            "disp": mem[1],
        }
    return {
        "at": insn["address"],
        "mnemonic": insn["mnemonic"],
        "kind": "base",
        "access": mem[4],
        "width": mem[3],
        "register": NAMES[mem[1]] if mem[1] < len(NAMES) else None,
        "disp": mem[2],
        "untracked": True,
    }


def discover_modeled_iat(data):
    """Count small routines whose only calls are modeled IAT slots. Executes nothing."""
    info = inspect_pe32plus.inspect_bytes(data)
    slots = _import_slots(data, info)
    report = {
        "tool": "iat-discover",
        "executed": False,
        "entryPointExecuted": False,
        "scanned": 0,
        "withRipCall": 0,
        "eligible": 0,
        "eligibleEntries": [],
        "obstacles": {},
        "modeledSlots": sum(1 for slot in slots.values() if slot["modeled"]),
        "ordinalSlots": sum(1 for slot in slots.values() if slot["ordinal"]),
        "imageSize": info["sizeOfImage"],
        "callRip": 0,
        "modeledCandidates": [],
    }
    membership = Counter()
    image_size = info["sizeOfImage"]
    if not isinstance(image_size, int) or image_size <= 0 or image_size > MAX_GUEST:
        report["obstacles"] = {"image_limit": 1}
        return report
    exc = info["exceptionDirectory"]
    if not exc["present"] or exc["size"] < 12:
        report["obstacles"] = {"no_exception_directory": 1}
        return report
    try:
        off = inspect_pe32plus.file_offset_for_rva(info["sections"], exc["virtualAddress"], exc["size"])
    except inspect_pe32plus.PeFormatError:
        report["obstacles"] = {"unmapped_pdata": 1}
        return report
    blob = data[off:off + exc["size"]]
    executable = []
    for sec in info["sections"]:
        if sec["name"] == ".bind" or not sec["executable"]:
            continue
        lo = sec["virtualAddress"]
        executable.append((lo, lo + max(sec["virtualSize"], 1)))
    obstacles = Counter()
    for n in range(len(blob) // 12):
        begin = int.from_bytes(blob[n * 12:n * 12 + 4], "little")
        end = int.from_bytes(blob[n * 12 + 4:n * 12 + 8], "little")
        if end <= begin or end - begin > MAX_INSNS * 8:
            continue
        if not any(lo <= begin and end <= hi for lo, hi in executable):
            continue
        if begin == info.get("addressOfEntryPoint"):
            continue
        report["scanned"] += 1
        try:
            raw_at = inspect_pe32plus.file_offset_for_rva(info["sections"], begin, end - begin)
            code = bytes(data[raw_at:raw_at + (end - begin)])
            insns = decode_allow.decode_stream(code, begin, control=True)
        except (inspect_pe32plus.PeFormatError, decode_allow.Reject):
            continue
        if not any(insn["mnemonic"] == "call_rip" for insn in insns):
            continue
        report["withRipCall"] += 1
        rank = {
            "iat_oob": 0, "iat_misaligned": 1, "iat_cross_page": 2, "unknown_iat": 3,
            "iat_ordinal": 4, "iat_unmodeled": 5, "direct_call": 6, "memory_or_global": 7,
            "missing_ret": 8,
        }
        reasons = set()
        imports = []
        direct_targets = []
        memory = []
        modeled_calls = 0
        for insn in insns:
            if insn["mnemonic"] == "call_rip":
                report["callRip"] += 1
                addr = insn["iat"]
                fault = iat_slot_fault(addr, image_size)
                slot = None if fault else slots.get(addr)
                if fault:
                    reasons.add(fault)
                    imports.append({"iatRva": addr, "fault": fault})
                elif slot is None:
                    reasons.add("unknown_iat")
                    imports.append({"iatRva": addr, "fault": "unknown_iat"})
                else:
                    row = {
                        "iatRva": addr,
                        "dll": slot["dll"],
                        "ordinal": slot["ordinal"],
                        "modeled": slot["modeled"],
                    }
                    if slot["ordinal"]:
                        row["ordinalValue"] = slot.get("ordinalValue")
                        reasons.add("iat_ordinal")
                    else:
                        row["name"] = slot["name"]
                        if slot["modeled"]:
                            modeled_calls += 1
                        else:
                            reasons.add("iat_unmodeled")
                    imports.append(row)
            elif insn["mnemonic"] == "call":
                reasons.add("direct_call")
                direct_targets.append(insn["target"])
            elif insn["mnemonic"] not in ("mov", "sub", "add", "ret") or insn.get("mem") or insn.get("rip"):
                reasons.add("memory_or_global")
                memory.append(_memory_meta(insn, info["sections"], image_size))
            elif insn["mnemonic"] in ("sub", "add") and not any(index == 4 for index, _bits in insn["writes"]):
                reasons.add("memory_or_global")
                memory.append(_memory_meta(insn, info["sections"], image_size))
        if not insns or insns[-1]["mnemonic"] != "ret":
            reasons.add("missing_ret")
        if not reasons:
            report["eligible"] += 1
            report["eligibleEntries"].append(begin)
        else:
            primary = min(reasons, key=lambda name: rank[name])
            obstacles[primary] += 1
            for name in reasons:
                membership[name] += 1
        if modeled_calls:
            report["modeledCandidates"].append({
                "rva": begin,
                "end": end,
                "reasons": sorted(reasons),
                "modeledCalls": modeled_calls,
                "imports": imports,
                "directCallTargets": direct_targets,
                "memory": memory,
            })
    report["obstacles"] = dict(obstacles)
    report["reasonMembership"] = dict(membership)
    report["modeledCandidateCount"] = len(report["modeledCandidates"])
    report["note"] = (
        "Read-only. No graph was executed and the entry point was not called. "
        "eligibleEntries are RVAs of routines whose only calls are "
        "KERNEL32 GetLastError or GetCurrentProcessId. obstacles is one primary "
        "reason per routine. reasonMembership counts every reason. "
        "modeledCandidates lists every routine that calls one of those two, with "
        "import names, direct-call RVAs, and access metadata. Width is not an "
        "object size. No instruction bytes are included."
    )
    return report


def verify_modeled_iat(data, last_seed=0x55, pid=0xABCD, max_entries=1):
    """Run eligible routines only. The default discover path does not call this."""
    report = discover_modeled_iat(data)
    report["verified"] = []
    report["verifyExecuted"] = False
    if max_entries < 0:
        raise CfgError("image_limit")
    if not report["eligibleEntries"]:
        return report
    info = inspect_pe32plus.inspect_bytes(data)
    slots = _import_slots(data, info)
    exc = info["exceptionDirectory"]
    off = inspect_pe32plus.file_offset_for_rva(info["sections"], exc["virtualAddress"], exc["size"])
    blob = data[off:off + exc["size"]]
    wanted = set(report["eligibleEntries"][:max_entries])
    for n in range(len(blob) // 12):
        begin = int.from_bytes(blob[n * 12:n * 12 + 4], "little")
        end = int.from_bytes(blob[n * 12 + 4:n * 12 + 8], "little")
        if begin not in wanted:
            continue
        raw_at = inspect_pe32plus.file_offset_for_rva(info["sections"], begin, end - begin)
        code = bytes(data[raw_at:raw_at + (end - begin)])
        insns = decode_allow.decode_stream(code, begin, control=True)
        used = {}
        for insn in insns:
            if insn["mnemonic"] != "call_rip":
                continue
            slot = dict(slots[insn["iat"]])
            slot["token"] = guest_token(1, slot["id"])
            used[insn["iat"]] = slot
        mem = bytearray(MEMSZ)
        mem[STACK_TOP:STACK_TOP + 8] = struct.pack("<Q", DONE)
        mem[0x2200:0x2204] = struct.pack("<I", last_seed & 0xFFFFFFFF)
        cpu = {"r": [0] * 16, "cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}
        cpu["r"][3] = 0xA11CE
        cpu["r"][4] = STACK_TOP
        for addr, slot in used.items():
            if addr + 8 <= MEMSZ:
                mem[addr:addr + 8] = struct.pack("<Q", slot["token"])
        result = execute_iat(
            {begin: code}, begin, cpu, mem, DONE, used, 0x2200, pid,
            image_limit=info["sizeOfImage"])
        rax, last = 0, last_seed & 0xFFFFFFFF
        for insn in insns:
            if insn["mnemonic"] == "call_rip":
                rax, last = virtual_api(used[insn["iat"]]["name"], 0, last, pid, rax)
        if rax is None or result["rax"] != rax or result["lastError"] != last:
            raise CfgError("virtual_api_mismatch")
        report["verified"].append({
            "entry": begin,
            "rax": result["rax"],
            "lastError": result["lastError"],
            "rbx": result["rbx"],
            "oracle": result["oracle"],
            "entryPointExecuted": False,
        })
        report["verifyExecuted"] = True
    return report


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
    parser.add_argument("--diagnose", action="store_true",
                        help="metadata-only rejection report; does not execute any graph")
    parser.add_argument("--iat-discover", action="store_true",
                        help="count routines that only call modeled IAT slots; does not execute")
    parser.add_argument("--iat-verify", action="store_true",
                        help="run only the eligible modeled-IAT routines against the virtual API")
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
    chosen = (args.execute, args.diagnose, args.iat_discover, args.iat_verify)
    if sum(bool(flag) for flag in chosen) > 1:
        print("choose only one of --execute, --diagnose, --iat-discover, and --iat-verify", file=sys.stderr)
        return 2
    try:
        if args.iat_verify:
            report = verify_modeled_iat(data)
        elif args.iat_discover:
            report = discover_modeled_iat(data)
        elif args.diagnose:
            report = diagnose_image(
                data, max_graphs=args.max_graphs, max_functions=args.max_functions,
                max_instructions=args.max_instructions,
            )
        elif args.execute:
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
    if args.iat_discover or args.iat_verify:
        pass
    elif args.diagnose:
        report["note"] = (
            "Diagnostic only. No graph was executed. argument_contract_missing does not "
            "supply an object size; the observed access width is not a layout."
        )
    elif not args.execute:
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
