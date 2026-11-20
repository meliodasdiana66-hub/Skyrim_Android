"""Bounded direct call/return and forward branches for synthetic guest programs.

This is not the leaf scanner and it does not run Skyrim. Every call target has
to be an explicit function start. Indirect calls, imports, backward branches,
recursion, and an initial RSP outside the guest stack window are rejected.
Missing imports are named and are not treated as success.
"""
import argparse
import json
import os
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


def emit_program(funcs, entry, imports=None, max_steps=MAX_STEPS_DEFAULT, max_depth=MAX_DEPTH_DEFAULT):
    prepared = prepare(funcs, entry, imports=imports, max_steps=max_steps)
    parts = ["#define MEMSZ %d" % MEMSZ, "#include <stdio.h>",
             "#ifdef _WIN32", "#include <fcntl.h>", "#include <io.h>", "#endif",
             "#include \"snippet_rt.h\"",
             "static int steps;", "static int depth;", "static int stop;"]
    for base in prepared["reachable"]:
        parts.append("void %s(Cpu64 *c, uint8_t *mem);" % _c_name(base))
    for base in prepared["reachable"]:
        parts.append(_emit_function(base, funcs[base], prepared["insns"][base], max_steps, max_depth))
    parts.append("int main(void) {")
    parts.append("#ifdef _WIN32")
    parts.append("    if (_setmode(_fileno(stdin), _O_BINARY) == -1) return 2;")
    parts.append("    if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 2;")
    parts.append("#endif")
    parts.append("    Cpu64 c; uint8_t mem[MEMSZ];")
    parts.append("    if (fread(&c, sizeof c, 1, stdin) != 1) return 2;")
    parts.append("    if (fread(mem, 1, MEMSZ, stdin) != MEMSZ) return 3;")
    parts.append("    steps = 0; depth = 0; stop = 0;")
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


def discover_closed(data, max_graphs=8):
    """Read-only search for closed direct-call graphs.

    A .pdata entry is not eligible by itself. The body has to sit inside an
    executable section other than .bind, decode under the CFG allowlist, and
    call only other such function starts. Nothing in the image is executed.
    """
    info = inspect_pe32plus.inspect_bytes(data)
    reasons = Counter()
    executable = []
    for sec in info["sections"]:
        if sec["name"] == ".bind" or not sec["executable"]:
            continue
        lo = sec["virtualAddress"]
        executable.append((lo, lo + max(sec["virtualSize"], 1)))
    report = {
        "tool": "cfg-discover",
        "executed": False,
        "pdataIsNotEligibility": True,
        "closedGraphs": [],
        "pdataEntries": 0,
    }
    exc = info["exceptionDirectory"]
    if not exc["present"] or exc["size"] < 12:
        reasons["no_exception_directory"] += 1
        report["reasons"] = dict(reasons)
        return report
    try:
        off = inspect_pe32plus.file_offset_for_rva(info["sections"], exc["virtualAddress"], exc["size"])
        blob = data[off:off + exc["size"]]
    except inspect_pe32plus.PeFormatError:
        reasons["unmapped_pdata"] += 1
        report["reasons"] = dict(reasons)
        return report
    entries = len(blob) // 12
    report["pdataEntries"] = entries
    funcs = {}
    for n in range(entries):
        begin = int.from_bytes(blob[n * 12:n * 12 + 4], "little")
        end = int.from_bytes(blob[n * 12 + 4:n * 12 + 8], "little")
        if end <= begin or end - begin > MAX_INSNS * 8:
            reasons["pdata_not_eligible"] += 1
            continue
        if not any(lo <= begin and end <= hi for lo, hi in executable):
            name = None
            for sec in info["sections"]:
                if sec["virtualAddress"] <= begin < sec["virtualAddress"] + max(sec["virtualSize"], sec["sizeOfRawData"]):
                    name = sec["name"]
            reasons["bind_not_code" if name == ".bind" else "pdata_not_eligible"] += 1
            continue
        try:
            raw_at = inspect_pe32plus.file_offset_for_rva(info["sections"], begin, end - begin)
        except inspect_pe32plus.PeFormatError:
            reasons["pdata_not_eligible"] += 1
            continue
        code = bytes(data[raw_at:raw_at + (end - begin)])
        try:
            _decode(code, begin)
        except CfgError as exc_err:
            reasons[exc_err.reason] += 1
            continue
        funcs[begin] = code
    seen = set()
    found_graphs = 0
    for entry, code in funcs.items():
        if entry in seen:
            continue
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
            try:
                insns = _decode(subset[cur], cur)
            except CfgError as exc_err:
                rejected = exc_err.reason
                break
            for insn in insns:
                if insn["mnemonic"] == "call":
                    pending.append(insn["target"])
        if rejected:
            reasons[rejected] += 1
            continue
        try:
            prepared = prepare(subset, entry)
        except CfgError as exc_err:
            reasons[exc_err.reason] += 1
            continue
        if not any(prepared["graph"][node] for node in prepared["reachable"]):
            continue
        key = tuple(prepared["reachable"])
        if key in seen:
            continue
        seen.add(key)
        found_graphs += 1
        if len(report["closedGraphs"]) < max_graphs:
            report["closedGraphs"].append({
                "entry": entry,
                "functions": prepared["reachable"],
                "executed": False,
                "stopping": "closed_not_executed",
            })
    report["closedGraphsFound"] = found_graphs
    report["reasons"] = dict(reasons)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only closed direct-call discovery. Does not execute guest code.")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--max-graphs", type=int, default=8)
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
        report = discover_closed(data, max_graphs=args.max_graphs)
    except inspect_pe32plus.PeFormatError as exc:
        print("pe: %s" % exc, file=sys.stderr)
        return 2
    report["sha256"] = digest
    report["note"] = (
        "closedGraphs are eligible direct-call sets. They were not executed. "
        "A .pdata entry is not eligibility. Missing imports stay unbound. "
        "This is not a game launch and not an ARM64 result."
    )
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        Path(args.report).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
