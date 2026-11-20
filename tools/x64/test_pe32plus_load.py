#!/usr/bin/env python3
"""Synthetic PE32+ inventory and mapping. No game image."""
import json
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pe32plus_load  # noqa: E402


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def build(size_of_image=0x3000, magic=0x20B, machine=0x8664):
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = u32(0x80)
    data[0x80:0x84] = b"PE\0\0"
    fh = 0x84
    data[fh:fh + 2] = u16(machine)
    data[fh + 2:fh + 4] = u16(3)
    data[fh + 16:fh + 18] = u16(0xF0)
    data[fh + 18:fh + 20] = u16(0x22)
    opt = fh + 20
    data[opt:opt + 2] = u16(magic)
    data[opt + 16:opt + 20] = u32(0x1000)
    if magic == 0x20B:
        data[opt + 24:opt + 32] = u64(0x140000000)
    data[opt + 32:opt + 36] = u32(0x1000)
    data[opt + 36:opt + 40] = u32(0x200)
    data[opt + 56:opt + 60] = u32(size_of_image)
    data[opt + 60:opt + 64] = u32(0x400)
    data[opt + 68:opt + 70] = u16(2)
    data[opt + 108:opt + 112] = u32(16)
    # import directory and base reloc
    data[opt + 120:opt + 128] = u32(0x2000) + u32(40)
    data[opt + 112 + 5 * 8:opt + 112 + 5 * 8 + 8] = u32(0x2100) + u32(12)

    def section(index, name, va, raw_ptr, raw_size, chars):
        off = opt + 0xF0 + index * 40
        data[off:off + 8] = name.encode().ljust(8, b"\0")
        data[off + 8:off + 12] = u32(0x100)
        data[off + 12:off + 16] = u32(va)
        data[off + 16:off + 20] = u32(raw_size)
        data[off + 20:off + 24] = u32(raw_ptr)
        data[off + 36:off + 40] = u32(chars)

    section(0, ".text", 0x1000, 0x400, 0x200, 0x60000020)
    section(1, ".rdata", 0x2000, 0x600, 0x200, 0x40000040)
    # absolute pointer stored in .text at RVA 0x1000, equal to the preferred base
    data[0x400:0x408] = u64(0x140000000)
    # import: KERNEL32.dll, one ordinal thunk
    data[0x600:0x604] = u32(0x2080)
    data[0x60C:0x610] = u32(0x20A0)
    data[0x610:0x614] = u32(0x2080)
    data[0x680:0x688] = u64(0x8000000000000001)
    data[0x6A0:0x6A0 + 13] = b"KERNEL32.dll\0"
    # DIR64 reloc for RVA 0x1000. Block VA 0x1000, one entry type 10 offset 0, pad.
    data[0x700:0x704] = u32(0x1000)
    data[0x704:0x708] = u32(12)
    data[0x708:0x70A] = u16((10 << 12) | 0)
    data[0x70A:0x70C] = u16(0)
    return bytes(data)


class Pe32PlusLoadTests(unittest.TestCase):
    def test_inventory_does_not_map_or_call(self):
        report = pe32plus_load.inventory(build())
        self.assertFalse(report["mapped"])
        self.assertFalse(report["entryCalled"])
        self.assertEqual(report["imports"], [{
            "dll": "KERNEL32.dll", "slots": 1, "binding": "not_implemented",
        }])
        self.assertIn("import_binding", report["inventoried_not_implemented"])
        self.assertIn("entry_point_call", report["inventoried_not_implemented"])
        self.assertNotIn("image", report)

    def test_map_applies_dir64_and_refuses_pe32_and_large_images(self):
        mapped = pe32plus_load.map_synthetic(build(), relocate_to=0x140010000)
        self.assertTrue(mapped["mapped"])
        self.assertFalse(mapped["entryCalled"])
        self.assertEqual(mapped["relocationsApplied"], 1)
        self.assertEqual(mapped["importsBound"], 0)
        self.assertEqual(struct.unpack_from("<Q", mapped["image"], 0x1000)[0], 0x140010000)
        with self.assertRaises(pe32plus_load.inspect_pe32plus.PeFormatError):
            pe32plus_load.inventory(build(magic=0x10B))
        with self.assertRaises(pe32plus_load.LoadError):
            pe32plus_load.map_synthetic(build(size_of_image=0x200000))

    def test_unknown_reloc_type_fails_closed(self):
        blob = bytearray(build())
        blob[0x708:0x70A] = u16((3 << 12) | 0)  # PE32 HIGHLOW, not DIR64
        with self.assertRaises(pe32plus_load.LoadError) as caught:
            pe32plus_load.map_synthetic(bytes(blob), relocate_to=0x140010000)
        self.assertIn("unsupported relocation", str(caught.exception))

    def test_cli_inventory_has_no_image_bytes(self):
        blob = build()
        path = HERE / "_tmp_synth.exe"
        try:
            path.write_bytes(blob)
            proc = __import__("subprocess").run(
                [sys.executable, str(HERE / "pe32plus_load.py"), "--exe", str(path), "--inventory"],
                capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            got = json.loads(proc.stdout)
            self.assertFalse(got["mapped"])
            self.assertFalse(got["entryCalled"])
            self.assertNotIn("140000000", proc.stdout.lower().replace("imagebase", ""))
        finally:
            if path.exists():
                path.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
