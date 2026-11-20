#!/usr/bin/env python3
"""Read-only leaf candidate scan for an AMD64 PE32+ image.

Dry-run uses the Python standard library and prints RVAs, sizes, and rejection
reasons. It does not print instruction or data bytes. --execute is separate:
it runs Unicorn against lifted C for candidates only, and only then may a
function be called verified. This tool does not launch the game.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import decode_allow
import inspect_pe32plus

MEMSZ = 0x10000
MAX_LEAF = 4096
MAX_REPORTED = 64
EXPECTED_SHA = "21a6f8244a57e880d02e600adf61178ab5483db7b3cca8dbfc97d7ca1f081e18"

CASES = (
    {"name": "zeros"},
    {"name": "ones", "fill": 1},
    {"name": "high", "regs": {"rax": 0xFFFFFFFFFFFFFFFF, "rcx": 0x8000000000000000}},
    {"name": "flags", "cf": 1, "zf": 1},
)


def _section_at(sections, rva):
    for sec in sections:
        if sec["virtualAddress"] <= rva < sec["virtualAddress"] + max(sec["virtualSize"], 1):
            return sec
    return None


def _guest_base(span_lo, span_hi):
    if span_hi - span_lo > MEMSZ or span_hi < span_lo:
        return None
    base = 0x1000 if span_lo >= 0 else -span_lo
    if base + span_lo < 0 or base + span_hi > MEMSZ:
        if span_lo >= 0 and span_hi <= MEMSZ:
            return 0
        return None
    return base


def _inputs(insns):
    defined = set()
    found = []
    for insn in insns:
        if insn["mnemonic"] == "ret":
            continue
        for index, bits in insn["reads"]:
            if index not in defined and index not in found:
                found.append(index)
        for index, bits in insn["writes"]:
            if bits >= 32:
                defined.add(index)
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    return [names[index] for index in found]


def _consider(data, sections, image_base, entry, begin, end):
    if end <= begin:
        return "empty_range", None
    size = end - begin
    if size > MAX_LEAF:
        return "too_long", None
    if begin <= entry < end:
        return "contains_entry_point", None
    sec = _section_at(sections, begin)
    tail = _section_at(sections, end - 1)
    if sec is None or tail is None or sec is not tail:
        return "spans_sections", None
    if sec["name"] == ".bind":
        return "bind_section", None
    if not sec["executable"]:
        return "not_executable", None
    try:
        off = inspect_pe32plus.file_offset_for_rva(sections, begin, size)
    except inspect_pe32plus.PeFormatError:
        return "unmapped_code", None
    code = data[off:off + size]
    try:
        insns = decode_allow.decode_leaf(code, image_base + begin)
    except decode_allow.Reject as exc:
        return exc.reason, None
    rels = [0, size]
    copies = []
    rip_rvas = []
    for insn in insns:
        if not insn["rip"]:
            continue
        target, nbytes = insn["rip"]
        if target < image_base:
            return "rip_unmapped", None
        target_rva = target - image_base
        dest = _section_at(sections, target_rva)
        if dest is None or target_rva + nbytes > dest["virtualAddress"] + dest["virtualSize"]:
            return "rip_unmapped", None
        if dest["name"] == ".bind":
            return "rip_in_bind", None
        try:
            src = inspect_pe32plus.file_offset_for_rva(sections, target_rva, nbytes)
        except inspect_pe32plus.PeFormatError:
            return "rip_unmapped", None
        rel = target_rva - begin
        rels.append(rel)
        rels.append(rel + nbytes)
        copies.append((rel, data[src:src + nbytes]))
        rip_rvas.append(target_rva)
    span_lo, span_hi = min(rels), max(rels)
    guest = _guest_base(span_lo, span_hi)
    if guest is None:
        return "window_too_wide", None
    logical = any(insn["mnemonic"] in ("and", "or", "xor", "test") for insn in insns)
    public = {
        "rva": begin,
        "endRva": end,
        "size": size,
        "section": sec["name"],
        "instructionCount": len(insns) - 1,
        "registerInputs": _inputs(insns),
        "ripRvas": rip_rvas,
        "guestBase": guest,
        "status": "candidate_not_executed",
    }
    private = {
        "code": code,
        "guest": guest,
        "copies": [(guest + rel, blob) for rel, blob in copies],
        "compare_af": not logical,
    }
    return None, (public, private)


def scan_image(data):
    info = inspect_pe32plus.inspect_bytes(data)
    sections = info["sections"]
    entry = info["addressOfEntryPoint"]
    exc = info["exceptionDirectory"]
    reasons = Counter()
    candidates = []
    plans = []
    pdata_entries = 0
    if not exc["present"] or exc["size"] < 12:
        reasons["no_exception_directory"] += 1
    else:
        try:
            off = inspect_pe32plus.file_offset_for_rva(sections, exc["virtualAddress"], exc["size"])
        except inspect_pe32plus.PeFormatError:
            reasons["unmapped_pdata"] += 1
            off = None
        if off is not None:
            blob = data[off:off + exc["size"]]
            if len(blob) != exc["size"]:
                reasons["unmapped_pdata"] += 1
                blob = b""
            if exc["size"] % 12:
                reasons["pdata_trailing_bytes"] += 1
            pdata_entries = len(blob) // 12
            seen = set()
            for n in range(pdata_entries):
                begin = int.from_bytes(blob[n * 12:n * 12 + 4], "little")
                end = int.from_bytes(blob[n * 12 + 4:n * 12 + 8], "little")
                if (begin, end) in seen:
                    reasons["duplicate_range"] += 1
                    continue
                seen.add((begin, end))
                reason, plan = _consider(data, sections, info["imageBase"], entry, begin, end)
                if reason:
                    reasons[reason] += 1
                else:
                    public, private = plan
                    if len(candidates) < MAX_REPORTED:
                        candidates.append(public)
                        plans.append(private)
                    else:
                        reasons["candidates_omitted"] += 1
    report = {
        "tool": "leafcheck",
        "mode": "dry-run",
        "sha256": inspect_pe32plus.sha256_hex(data),
        "size": len(data),
        "imageBase": info["imageBase"],
        "addressOfEntryPoint": entry,
        "entryPointUsedAsLeaf": False,
        "bindSectionUsedAsLeaf": False,
        "pdataEntries": pdata_entries,
        "executed": False,
        "verifiedFunctions": [],
        "candidates": candidates,
        "candidatesReported": len(candidates),
        "rejectionCounts": dict(sorted(reasons.items())),
        "note": (
            "candidates are scanner results and were not executed. "
            "A function is verified only when it appears in verifiedFunctions "
            "after --execute. Entry point and .bind ranges are not leaves. "
            "The final ret is a terminator and is not executed. "
            "This report contains no instruction or data bytes."
        ),
    }
    return report, plans


def _case_cpu(spec):
    regs = [spec.get("fill", 0)] * 16
    for name, value in (spec.get("regs") or {}).items():
        names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        regs[names.index(name)] = value
    return {
        "r": regs,
        "cf": spec.get("cf", 0), "pf": 0, "af": 0,
        "zf": spec.get("zf", 0), "sf": 0, "of": 0,
    }


def _mismatch_fields(message):
    fields = []
    for line in message.splitlines():
        if line.startswith("host/unicorn"):
            continue
        name = line.split(" ", 1)[0]
        if name and name not in fields:
            fields.append(name)
    return fields


def execute_plans(report, plans):
    import difftest64
    verified = []
    for public, private in zip(report["candidates"], plans):
        code = private["code"]
        guest = private["guest"]
        mem = bytearray(difftest64.MEMSZ)
        mem[guest:guest + len(code)] = code
        for addr, blob in private["copies"]:
            mem[addr:addr + len(blob)] = blob
        cases = []
        status = "verified_match"
        for spec in CASES:
            cpu = _case_cpu(spec)
            try:
                difftest64.compare(code, guest, cpu, mem, compare_af=private["compare_af"])
                cases.append({"name": spec["name"], "result": "match"})
            except difftest64.lift64.Unsupported as exc:
                status = "not_verified"
                cases.append({"name": spec["name"], "result": "lifter_rejected", "reason": exc.__class__.__name__})
                break
            except AssertionError as exc:
                status = "verified_mismatch"
                cases.append({"name": spec["name"], "result": "mismatch", "fields": _mismatch_fields(str(exc))})
                break
        verified.append({
            "rva": public["rva"],
            "size": public["size"],
            "status": status,
            "cases": cases,
        })
    report["mode"] = "execute"
    report["executed"] = True
    report["verifiedFunctions"] = verified
    report["note"] = (
        "verifiedFunctions are Unicorn versus lifted-C results for scanner candidates. "
        "candidate status stays candidate_not_executed. "
        "match does not mean the game runs. The final ret was not executed. "
        "No instruction or data bytes are included."
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only PE32+ leaf scan. Does not launch a game.")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--report", help="write JSON here instead of stdout")
    args = parser.parse_args(argv)
    if args.execute and args.dry_run:
        print("choose only one of --dry-run and --execute", file=sys.stderr)
        return 2
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
        report, plans = scan_image(data)
    except inspect_pe32plus.PeFormatError as exc:
        print("pe: %s" % exc, file=sys.stderr)
        return 2
    if args.execute:
        try:
            execute_plans(report, plans)
        except ImportError:
            print("execute needs capstone, unicorn, and clang; dry-run does not install them", file=sys.stderr)
            return 4
    else:
        report["mode"] = "dry-run"
    text = json.dumps(report, indent=2)
    if args.report:
        Path(args.report).write_text(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
