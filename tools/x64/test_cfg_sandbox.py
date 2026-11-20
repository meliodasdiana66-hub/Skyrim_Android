#!/usr/bin/env python3
"""Synthetic direct calls and forward branches. Not a game scan."""
import json
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import cfg_sandbox  # noqa: E402

DONE = 0x5000
RSP = 0xE008
HELPER = 0x4100
ENTRY = 0x4000


def _cpu(eax):
    regs = [0] * 16
    regs[0] = eax
    regs[4] = RSP
    return {"r": regs, "cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}


def _mem():
    buf = bytearray(cfg_sandbox.MEMSZ)
    buf[RSP:RSP + 8] = struct.pack("<Q", DONE)
    return buf


def _program():
    # test eax, 0xff; jz +7; mov ebx, 1; jmp +5; mov ebx, 2; call helper; ret
    caller = bytes.fromhex("a9ff000000") + bytes.fromhex("7407") + bytes.fromhex("bb01000000")
    caller += bytes.fromhex("eb05") + bytes.fromhex("bb02000000")
    call_at = ENTRY + len(caller)
    caller += b"\xe8" + struct.pack("<i", HELPER - (call_at + 5)) + b"\xc3"
    helper = bytes.fromhex("89d8c3")  # mov eax, ebx; ret
    return {ENTRY: caller, HELPER: helper}


class CfgSandboxTests(unittest.TestCase):
    def test_forward_branch_and_direct_call_match_unicorn(self):
        funcs = _program()
        for eax, expect, taken, skipped in ((0, 2, 0x400E, 0x4007), (1, 1, 0x4007, 0x400E)):
            report = cfg_sandbox.execute(funcs, ENTRY, _cpu(eax), _mem(), DONE, compare_af=False)
            self.assertEqual(report["result"], "match")
            self.assertEqual(report["stopping"], "returned_to_harness")
            self.assertEqual(report["rax"], expect)
            self.assertIn(HELPER, report["reached"])
            self.assertIn(taken, report["instructions"])
            self.assertNotIn(skipped, report["instructions"])
            self.assertEqual(report["flags"]["cf"], 0)
            self.assertEqual(report["flags"]["of"], 0)
            self.assertEqual(report["flags"]["sf"], 0)
            self.assertEqual(report["flags"]["zf"], 0 if eax else 1)
            self.assertEqual(report["flags"]["pf"], 0 if eax else 1)

    def test_carry_branch_matches_unicorn(self):
        # sub eax, 1; jb +7; mov ebx, 0; jmp +5; mov ebx, 1; ret
        code = bytes.fromhex("83e801") + bytes.fromhex("7207") + bytes.fromhex("bb00000000")
        code += bytes.fromhex("eb05") + bytes.fromhex("bb01000000") + b"\xc3"
        for eax, expect, cf in ((0, 1, 1), (1, 0, 0)):
            report = cfg_sandbox.execute({ENTRY: code}, ENTRY, _cpu(eax), _mem(), DONE, compare_af=False)
            self.assertEqual(report["rax"] & 0xFFFFFFFF, (eax - 1) & 0xFFFFFFFF)
            self.assertEqual(report["flags"]["cf"], cf)
            self.assertEqual(report["flags"]["of"], 0)
            self.assertIn(ENTRY + (12 if cf else 5), report["instructions"])

    def test_step_budget_stops_before_execution_completes(self):
        code = b"\x90" * 4 + b"\xc3"
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute({ENTRY: code}, ENTRY, _cpu(0), _mem(), DONE, max_steps=2)
        self.assertEqual(caught.exception.reason, "step_budget")

    def test_safety_negatives_do_not_execute(self):
        back = {ENTRY: bytes.fromhex("ebfe")}  # jmp $
        # missing ret because eb fe doesn't end in ret; decode may see jmp only
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(back, ENTRY)
        self.assertIn(caught.exception.reason, ("back_edge", "missing_ret"))
        loop = {ENTRY: bytes.fromhex("74fe") + b"\xc3"}  # jz $-2; ret if the disp is backward
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(loop, ENTRY)
        self.assertEqual(caught.exception.reason, "back_edge")
        recursive = {ENTRY: b"\xe8" + struct.pack("<i", -5) + b"\xc3"}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(recursive, ENTRY)
        self.assertEqual(caught.exception.reason, "recursion")
        unknown = {ENTRY: b"\xe8" + struct.pack("<i", 0x100) + b"\xc3"}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(unknown, ENTRY)
        self.assertEqual(caught.exception.reason, "unknown_target")
        indirect = {ENTRY: bytes.fromhex("ffd0c3")}
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(indirect, ENTRY)
        self.assertEqual(caught.exception.reason, "indirect_call")
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.prepare(_program(), ENTRY, imports={HELPER: "KERNEL32.dll!ExitProcess"})
        self.assertTrue(caught.exception.reason.startswith("unbound_import:KERNEL32.dll!ExitProcess"))
        bad = _cpu(1)
        bad["r"][4] = 0
        with self.assertRaises(cfg_sandbox.CfgError) as caught:
            cfg_sandbox.execute(_program(), ENTRY, bad, _mem(), DONE)
        self.assertEqual(caught.exception.reason, "stack_escape")

    def test_code_and_data_stay_separate_and_graphs_are_not_executed(self):
        funcs = _program()
        bad = cfg_sandbox.classify_graph(funcs, ENTRY, executable_ranges=[(0x2000, 0x3000)])
        self.assertFalse(bad["executed"])
        self.assertEqual(bad["reason"], "non_executable_target")
        good = cfg_sandbox.classify_graph(funcs, ENTRY, executable_ranges=[(0x4000, 0x4200)])
        self.assertFalse(good["executed"])
        self.assertIsNone(good["reason"])
        self.assertEqual(good["stopping"], "closed_not_executed")
        self.assertEqual(good["reached"], [ENTRY, HELPER])

    def test_pdata_entry_is_not_a_closed_graph(self):
        image = bytearray(0x1400)
        image[0:2] = b"MZ"
        image[0x3C:0x40] = struct.pack("<I", 0x80)
        image[0x80:0x84] = b"PE\0\0"
        fh = 0x84
        image[fh:fh + 2] = struct.pack("<H", 0x8664)
        image[fh + 2:fh + 4] = struct.pack("<H", 4)
        image[fh + 16:fh + 18] = struct.pack("<H", 0xF0)
        image[fh + 18:fh + 20] = struct.pack("<H", 0x22)
        opt = fh + 20
        image[opt:opt + 2] = struct.pack("<H", 0x20B)
        image[opt + 16:opt + 20] = struct.pack("<I", 0x1200)
        image[opt + 24:opt + 32] = struct.pack("<Q", 0x140000000)
        image[opt + 56:opt + 60] = struct.pack("<I", 0x5000)
        image[opt + 108:opt + 112] = struct.pack("<I", 16)
        image[opt + 112 + 24:opt + 112 + 32] = struct.pack("<II", 0x3000, 60)

        def section(index, name, va, raw_ptr, raw_size, chars):
            off = opt + 0xF0 + index * 40
            image[off:off + 8] = name.encode().ljust(8, b"\0")
            image[off + 8:off + 12] = struct.pack("<I", 0x800 if name == ".text" else 0x100)
            image[off + 12:off + 16] = struct.pack("<I", va)
            image[off + 16:off + 20] = struct.pack("<I", raw_size)
            image[off + 20:off + 24] = struct.pack("<I", raw_ptr)
            image[off + 36:off + 40] = struct.pack("<I", chars)

        section(0, ".text", 0x1000, 0x400, 0x800, 0x60000020)
        section(1, ".rdata", 0x2000, 0xC00, 0x200, 0x40000040)
        section(2, ".pdata", 0x3000, 0xE00, 0x200, 0x40000040)
        section(3, ".bind", 0x4000, 0x1000, 0x200, 0x60000000)
        caller = _program()[ENTRY]
        helper = _program()[HELPER]
        image[0x400:0x400 + len(caller)] = caller
        image[0x500:0x500 + len(helper)] = helper
        image[0x600:0x606] = bytes.fromhex("b801000000c3")
        image[0xC00:0xC06] = bytes.fromhex("b801000000c3")
        image[0x1000:0x1006] = caller[:6]
        ranges = [
            (0x1000, 0x1000 + len(caller)),
            (0x1100, 0x1100 + len(helper)),
            (0x1200, 0x1206),
            (0x2000, 0x2006),
            (0x4000, 0x4006),
        ]
        for n, (begin, end) in enumerate(ranges):
            at = 0xE00 + n * 12
            image[at:at + 8] = struct.pack("<II", begin, end)
        # The call inside the copied caller still targets 0x4100, which is not a
        # function start in this image, so the bytes are not a closed graph.
        # Rebuild the caller so its call targets RVA 0x1100.
        call_at = 0x1000 + len(caller) - 6
        fixed = bytearray(caller)
        struct.pack_into("<i", fixed, len(fixed) - 5, 0x1100 - (call_at + 5))
        image[0x400:0x400 + len(fixed)] = fixed
        report = cfg_sandbox.discover_closed(bytes(image))
        self.assertFalse(report["executed"])
        self.assertTrue(report["pdataIsNotEligibility"])
        self.assertEqual(report["pdataEntries"], 5)
        self.assertEqual(len(report["closedGraphs"]), 1)
        self.assertEqual(report["closedGraphs"][0]["functions"], [0x1000, 0x1100])
        self.assertFalse(report["closedGraphs"][0]["executed"])
        self.assertGreaterEqual(report["reasons"].get("pdata_not_eligible", 0), 1)
        self.assertGreaterEqual(report["reasons"].get("bind_not_code", 0), 1)
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            blob = Path(td) / "synthetic.bin"
            blob.write_bytes(bytes(image))
            out = Path(td) / "out.json"
            rc = cfg_sandbox.main([
                "--exe", str(blob),
                "--expect-sha256", __import__("hashlib").sha256(bytes(image)).hexdigest(),
                "--report", str(out),
            ])
            self.assertEqual(rc, 0)
            loaded = json.loads(out.read_text())
            self.assertFalse(loaded["executed"])
            self.assertNotIn(bytes(fixed).hex(), json.dumps(loaded))
        dispositions = report["dispositions"]
        self.assertEqual(sum(dispositions.values()), report["pdataEntries"])
        self.assertEqual(dispositions.get("closed_graph_root"), 1)
        self.assertEqual(dispositions.get("closed_graph_member"), 1)
        self.assertEqual(dispositions.get("call_free"), 1)
        self.assertEqual(report["closedGraphsFound"], 1)
        self.assertEqual(report["closedGraphs"][0]["sizes"], [len(fixed), len(helper)])
        self.assertNotIn("code", report["closedGraphs"][0])

    def test_global_bytes_are_not_invented(self):
        load = bytes.fromhex("8b0500000000") + b"\xe8" + struct.pack("<i", HELPER - (ENTRY + 11)) + b"\xc3"
        helper = bytes.fromhex("83c001c3")
        funcs = {ENTRY: load, HELPER: helper}
        target = ENTRY + 6
        self.assertEqual(cfg_sandbox.assess_graph(funcs, ENTRY), "precondition_required")
        self.assertEqual(
            cfg_sandbox.assess_graph(funcs, ENTRY, rip_regions=[(target, b"\x11\x22\x33\x44", True)]),
            "precondition_required",
        )
        self.assertIsNone(
            cfg_sandbox.assess_graph(funcs, ENTRY, rip_regions=[(target, b"\x11\x22\x33\x44", False)])
        )

    def test_carry_emitter_does_not_set_unread_depth(self):
        code = bytes.fromhex("83e801") + bytes.fromhex("7207") + bytes.fromhex("bb00000000")
        code += bytes.fromhex("eb05") + bytes.fromhex("bb01000000") + b"\xc3"
        source, _prepared = cfg_sandbox.emit_program({ENTRY: code}, ENTRY)
        self.assertNotRegex(source, r"\bdepth\b")
        called, _prepared = cfg_sandbox.emit_program(_program(), ENTRY)
        self.assertIn("++depth", called)
        self.assertIn("depth--", called)

    def test_execute_closed_graph_preserves_abi_and_rejects_unsafe(self):
        # push rbx; mov ebx, eax; call helper; pop rbx; ret / mov eax, ebx; ret
        caller = bytes.fromhex("5389c3") + b"\xe8" + struct.pack("<i", 0x1100 - (0x1003 + 5)) + bytes.fromhex("5bc3")
        helper = bytes.fromhex("89d8c3")
        image = _image_with({
            0x1000: caller,
            0x1100: helper,
            0x1200: bytes.fromhex("8b01") + b"\xe8" + struct.pack("<i", 0x1100 - (0x1202 + 5)) + b"\xc3",
            0x1300: bytes.fromhex("bb01000000") + b"\xe8" + struct.pack("<i", 0x1100 - (0x1305 + 5)) + b"\xc3",
            0x1400: bytes.fromhex("488b4424f8") + b"\xe8" + struct.pack("<i", 0x1100 - (0x1405 + 5)) + b"\xc3",
        })
        report = cfg_sandbox.execute_image(bytes(image), max_graphs=8, max_functions=4, max_instructions=32, max_cases=2)
        self.assertEqual(sum(report["dispositions"].values()), report["pdataEntries"])
        self.assertEqual(report["closedGraphsFound"], 4)
        self.assertEqual(report["graphsExecuted"], 1)
        self.assertEqual(report["casesMatched"], 2)
        self.assertEqual(report["casesExecuted"], 2)
        executed = [row for row in report["verifiedGraphs"] if row["status"] == "verified_match"]
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0]["entry"], 0x1000)
        self.assertTrue(executed[0]["instructions"])
        self.assertNotIn(0x1200, executed[0]["instructions"])
        rejected = {row["entry"]: row["reason"] for row in report["rejections"]}
        self.assertEqual(rejected[0x1200], "sandbox_untracked")
        self.assertEqual(rejected[0x1300], "abi_unpreserved")
        self.assertEqual(rejected[0x1400], "stack_external")
        blob = json.dumps(report)
        self.assertNotIn(caller.hex(), blob)
        self.assertNotIn(helper.hex(), blob)
        limited = cfg_sandbox.execute_image(bytes(image), max_graphs=1, max_functions=1, max_instructions=32, max_cases=1)
        self.assertEqual(limited["graphsExecuted"], 0)
        self.assertTrue(any(row["reason"] == "too_many_functions" for row in limited["rejections"]))


def _image_with(bodies):
    image = bytearray(0x1600)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = struct.pack("<I", 0x80)
    image[0x80:0x84] = b"PE\0\0"
    fh = 0x84
    image[fh:fh + 2] = struct.pack("<H", 0x8664)
    image[fh + 2:fh + 4] = struct.pack("<H", 4)
    image[fh + 16:fh + 18] = struct.pack("<H", 0xF0)
    image[fh + 18:fh + 20] = struct.pack("<H", 0x22)
    opt = fh + 20
    image[opt:opt + 2] = struct.pack("<H", 0x20B)
    image[opt + 16:opt + 20] = struct.pack("<I", 0x5000)
    image[opt + 24:opt + 32] = struct.pack("<Q", 0x140000000)
    image[opt + 56:opt + 60] = struct.pack("<I", 0x600)
    image[opt + 108:opt + 112] = struct.pack("<I", 16)
    ranges = sorted(bodies)
    image[opt + 112 + 24:opt + 112 + 32] = struct.pack("<II", 0x3000, len(ranges) * 12)

    def section(index, name, va, raw_ptr, raw_size, chars):
        off = opt + 0xF0 + index * 40
        image[off:off + 8] = name.encode().ljust(8, b"\0")
        image[off + 8:off + 12] = struct.pack("<I", 0x800 if name == ".text" else 0x200)
        image[off + 12:off + 16] = struct.pack("<I", va)
        image[off + 16:off + 20] = struct.pack("<I", raw_size)
        image[off + 20:off + 24] = struct.pack("<I", raw_ptr)
        image[off + 36:off + 40] = struct.pack("<I", chars)

    section(0, ".text", 0x1000, 0x400, 0x800, 0x60000020)
    section(1, ".rdata", 0x2000, 0xC00, 0x200, 0x40000040)
    section(2, ".pdata", 0x3000, 0xE00, 0x200, 0x40000040)
    section(3, ".bind", 0x4000, 0x1000, 0x200, 0x60000000)
    for rva, code in bodies.items():
        image[0x400 + (rva - 0x1000):0x400 + (rva - 0x1000) + len(code)] = code
    for n, rva in enumerate(ranges):
        image[0xE00 + n * 12:0xE00 + n * 12 + 8] = struct.pack("<II", rva, rva + len(bodies[rva]))
    return image


if __name__ == "__main__":
    unittest.main(verbosity=2)
