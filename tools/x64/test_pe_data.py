#!/usr/bin/env python3
"""Synthetic PE32+ data-map checks. The game executable is not opened."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class PeDataTests(unittest.TestCase):
    def test_loader_and_cli_do_not_execute_or_modify(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            unit = td / "pe_data_test"
            cli = td / "pe_data_map"
            built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "test_pe_data.c"), str(HERE / "pe_data.c"), str(HERE / "guest_mem.c"),
                 "-I", str(HERE), "-o", str(unit)],
                capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            cli_built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "pe_data_map.c"), str(HERE / "pe_data.c"), str(HERE / "guest_mem.c"),
                 str(HERE / "ae_abi.c"), str(HERE / "ae_dispatch.c"), str(HERE / "ae_iat.c"),
                 "-I", str(HERE), "-o", str(cli)],
                capture_output=True, text=True, check=False)
            self.assertEqual(cli_built.returncode, 0, cli_built.stderr)
            fixture = td / "fixture.bin"
            long_fix = td / "long.bin"
            huge_fix = td / "huge.bin"
            ran = subprocess.run([str(unit), str(fixture), str(long_fix), str(huge_fix)],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            before = fixture.read_bytes()
            digest = hashlib.sha256(before).hexdigest()
            mapped = subprocess.run(
                [str(cli), "--exe", str(fixture), "--expect-sha256", digest],
                capture_output=True, text=True, check=False)
            self.assertEqual(mapped.returncode, 0, mapped.stderr)
            self.assertEqual(fixture.read_bytes(), before)
            report = json.loads(mapped.stdout)
            self.assertTrue(report["mapped"])
            self.assertFalse(report["entryCalled"])
            self.assertFalse(report["importsBound"])
            self.assertFalse(report["hostExecutable"])
            self.assertEqual(report["dllCount"], 1)
            self.assertEqual(report["symbolCount"], 2)
            self.assertEqual(report["importCount"], 2)
            self.assertEqual(report["unresolvedImports"], 2)
            self.assertEqual(report["relocationsApplied"], 0)
            self.assertNotIn("CC", json.dumps(report))
            moved = subprocess.run(
                [str(cli), "--exe", str(fixture), "--expect-sha256", digest, "--image-base", "0x180000000"],
                capture_output=True, text=True, check=False)
            self.assertEqual(moved.returncode, 0, moved.stderr)
            self.assertEqual(fixture.read_bytes(), before)
            moved_report = json.loads(moved.stdout)
            self.assertEqual(moved_report["relocationsApplied"], 1)
            self.assertFalse(moved_report["entryCalled"])
            self.assertFalse(moved_report["importsBound"])
            self.assertFalse(moved_report["hostExecutable"])
            self.assertEqual(moved_report["imageBase"], 0x180000000)
            long_bytes = long_fix.read_bytes()
            long_sha = hashlib.sha256(long_bytes).hexdigest()
            official = subprocess.run(
                [str(cli), "--exe", str(long_fix), "--expect-sha256", long_sha],
                capture_output=True, text=True, check=False)
            self.assertEqual(official.returncode, 0, official.stderr)
            self.assertEqual(long_fix.read_bytes(), long_bytes)
            official_report = json.loads(official.stdout)
            self.assertTrue(official_report["mapped"])
            self.assertEqual(official_report["symbolCount"], 1)
            self.assertFalse(official_report["entryCalled"])
            self.assertFalse(official_report["hostExecutable"])
            refused = subprocess.run(
                [str(cli), "--exe", str(huge_fix)],
                capture_output=True, text=True, check=False)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("import name exceeds cap", refused.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
