#!/usr/bin/env python3
"""Scanner tests use a synthetic PE32+ image, never a game executable."""
import json
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import decode_allow  # noqa: E402
import difftest64  # noqa: E402
import leafcheck  # noqa: E402
import lift64  # noqa: E402

SENTINEL_IMM = "e8c3c3e8"
SENTINEL_QWORD = "1122334455667788"


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def build_synthetic():
    data = bytearray(0x1400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = u32(0x80)
    data[0x80:0x84] = b"PE\0\0"
    fh = 0x84
    data[fh:fh + 2] = u16(0x8664)
    data[fh + 2:fh + 4] = u16(4)
    data[fh + 4:fh + 8] = u32(0x65A5F4D5)
    data[fh + 16:fh + 18] = u16(0xF0)
    data[fh + 18:fh + 20] = u16(0x22)
    opt = fh + 20
    data[opt:opt + 2] = u16(0x20B)
    data[opt + 16:opt + 20] = u32(0x1200)
    data[opt + 24:opt + 32] = u64(0x140000000)
    data[opt + 32:opt + 36] = u32(0x1000)
    data[opt + 36:opt + 40] = u32(0x200)
    data[opt + 56:opt + 60] = u32(0x5000)
    data[opt + 60:opt + 64] = u32(0x400)
    data[opt + 68:opt + 70] = u16(2)
    data[opt + 108:opt + 112] = u32(16)
    data[opt + 112 + 3 * 8:opt + 112 + 3 * 8 + 8] = u32(0x3000) + u32(60)

    def section(index, name, va, raw_ptr, raw_size, chars):
        off = opt + 0xF0 + index * 40
        data[off:off + 8] = name.encode().ljust(8, b"\0")
        data[off + 8:off + 12] = u32(0x800 if name == ".text" else 0x100)
        data[off + 12:off + 16] = u32(va)
        data[off + 16:off + 20] = u32(raw_size)
        data[off + 20:off + 24] = u32(raw_ptr)
        data[off + 36:off + 40] = u32(chars)

    section(0, ".text", 0x1000, 0x400, 0x800, 0x60000020)
    section(1, ".rdata", 0x2000, 0xC00, 0x200, 0x40000040)
    section(2, ".pdata", 0x3000, 0xE00, 0x200, 0x40000040)
    section(3, ".bind", 0x4000, 0x1000, 0x200, 0x60000000)
    # mov eax, imm containing call/ret bytes; ret. Not the entry point.
    data[0x400:0x406] = bytes.fromhex("b8e8c3c3e8c3")
    data[0x500:0x506] = bytes.fromhex("e800000000c3")
    data[0x600:0x606] = bytes.fromhex("b801000000c3")
    data[0x700:0x708] = bytes.fromhex("488b05f9010000c3")
    data[0x900:0x908] = bytes.fromhex(SENTINEL_QWORD)
    data[0x1000:0x1006] = bytes.fromhex("b801000000c3")
    ranges = [(0x1000, 0x1006), (0x1100, 0x1106), (0x1200, 0x1206), (0x1300, 0x1308), (0x4000, 0x4006)]
    for n, (begin, end) in enumerate(ranges):
        at = 0xE00 + n * 12
        data[at:at + 4] = u32(begin)
        data[at + 4:at + 8] = u32(end)
    return bytes(data)


class DecoderAgreementTests(unittest.TestCase):
    def test_known_snippets_match_the_lifter(self):
        snippets = [
            bytes.fromhex("b8ffffffff"),
            bytes.fromhex("31c0"),
            bytes.fromhex("83c001"),
            bytes.fromhex("0501000000"),
            bytes.fromhex("4883c001"),
            bytes.fromhex("90"),
            bytes.fromhex("b801000000c3"),
            bytes.fromhex("4809d8"),
            bytes.fromhex("4885c0"),
            bytes.fromhex("66b83412"),
            bytes.fromhex("488b05f9010000"),
        ]
        for code in snippets:
            decode_allow.decode_stream(code, 0x4000)
            lift64.lift_snippet(code, 0x4000)

    def test_decoder_never_accepts_what_the_lifter_rejects(self):
        rng = random.Random(0x1170)
        accepted = 0
        for _ in range(400):
            blob = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
            try:
                decode_allow.decode_stream(blob, 0x4000)
            except decode_allow.Reject:
                continue
            accepted += 1
            lift64.lift_snippet(blob, 0x4000)
        self.assertGreater(accepted, 0)

    def test_leaf_with_ret_bytes_inside_an_immediate(self):
        code = bytes.fromhex("b8e8c3c3e8c3")
        insns = decode_allow.decode_leaf(code, 0x140001000)
        self.assertEqual([insn["mnemonic"] for insn in insns], ["mov", "ret"])
        state = {"r": [0] * 16, "cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0}
        mem = bytearray(difftest64.MEMSZ)
        mem[0x4000:0x4000 + len(code)] = code
        got, _mem = difftest64.compare(code, 0x4000, state, mem)
        self.assertEqual(got["r"][0], 0xE8C3C3E8)


class LeafScanTests(unittest.TestCase):
    def setUp(self):
        self.blob = build_synthetic()

    def test_dry_run_selects_only_bounded_leaves_and_hides_bytes(self):
        report, plans = leafcheck.scan_image(self.blob)
        self.assertFalse(report["executed"])
        self.assertEqual(report["verifiedFunctions"], [])
        self.assertFalse(report["entryPointUsedAsLeaf"])
        self.assertFalse(report["bindSectionUsedAsLeaf"])
        rvas = [row["rva"] for row in report["candidates"]]
        self.assertEqual(rvas, [0x1000, 0x1300])
        self.assertEqual(report["candidates"][0]["status"], "candidate_not_executed")
        self.assertEqual(report["candidates"][1]["ripRvas"], [0x1500])
        reasons = report["rejectionCounts"]
        self.assertGreaterEqual(reasons.get("call", 0), 1)
        self.assertGreaterEqual(reasons.get("contains_entry_point", 0), 1)
        self.assertGreaterEqual(reasons.get("bind_section", 0), 1)
        text = json.dumps(report)
        self.assertNotIn(SENTINEL_IMM, text.lower())
        self.assertNotIn(SENTINEL_QWORD, text.lower())
        self.assertNotIn("code_hex", text)
        self.assertEqual(len(plans), 2)

    def test_execute_verifies_synthetic_leaves_without_logging_bytes(self):
        report, plans = leafcheck.scan_image(self.blob)
        leafcheck.execute_plans(report, plans)
        self.assertTrue(report["executed"])
        self.assertEqual([row["status"] for row in report["verifiedFunctions"]],
                         ["verified_match", "verified_match"])
        for row in report["verifiedFunctions"]:
            self.assertEqual([case["result"] for case in row["cases"]], ["match"] * 4)
        self.assertTrue(all(row["status"] == "candidate_not_executed" for row in report["candidates"]))
        text = json.dumps(report)
        self.assertNotIn(SENTINEL_IMM, text.lower())
        self.assertNotIn(SENTINEL_QWORD, text.lower())

    def test_cli_dry_run_and_sha_mismatch(self):
        digest = leafcheck.inspect_pe32plus.sha256_hex(self.blob)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.exe"
            report = Path(td) / "report.json"
            path.write_bytes(self.blob)
            bad = subprocess.run(
                [sys.executable, str(HERE / "leafcheck.py"), "--exe", str(path),
                 "--expect-sha256", "00" * 32, "--dry-run", "--report", str(report)],
                capture_output=True, text=True, check=False)
            self.assertEqual(bad.returncode, 3)
            self.assertFalse(report.exists())
            good = subprocess.run(
                [sys.executable, str(HERE / "leafcheck.py"), "--exe", str(path),
                 "--expect-sha256", digest, "--dry-run", "--report", str(report)],
                capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0, good.stderr)
            got = json.loads(report.read_text())
            self.assertEqual(got["mode"], "dry-run")
            self.assertFalse(got["executed"])
            self.assertEqual([row["rva"] for row in got["candidates"]], [0x1000, 0x1300])


class AArch64AvailabilityTests(unittest.TestCase):
    def test_freestanding_c_compiles_for_aarch64_and_is_not_run(self):
        """Object codegen only. No QEMU invocation and no Android device."""
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "add.c"
            obj = Path(td) / "add.o"
            src.write_text("typedef unsigned long long u64; void set(u64 *r) { r[0] = 1; }\n")
            proc = subprocess.run(
                ["clang", "--target=aarch64-linux-gnu", "-c", "-nostdinc", "-ffreestanding",
                 "-O2", str(src), "-o", str(obj)],
                capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            blob = obj.read_bytes()
            self.assertEqual(blob[:4], b"\x7fELF")
            self.assertEqual(int.from_bytes(blob[18:20], "little"), 183)
            self.assertFalse(obj.with_suffix(".out").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
