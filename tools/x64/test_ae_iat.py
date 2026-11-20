#!/usr/bin/env python3
"""Guest IAT tokens. Not a Windows DLL and not a game launch."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = [
    "test_ae_iat.c", "pe_data.c", "guest_mem.c", "ae_abi.c", "ae_dispatch.c", "ae_iat.c",
]


class IatTests(unittest.TestCase):
    def test_tokens_bind_only_when_asked(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            exe = td / "ae_iat_test"
            cli = td / "pe_data_map"
            built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", *[str(HERE / name) for name in SOURCES],
                 "-I", str(HERE), "-o", str(exe)],
                capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            cli_built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "pe_data_map.c"), str(HERE / "pe_data.c"), str(HERE / "guest_mem.c"),
                 str(HERE / "ae_abi.c"), str(HERE / "ae_dispatch.c"), str(HERE / "ae_iat.c"),
                 "-I", str(HERE), "-o", str(cli)],
                capture_output=True, text=True, check=False)
            self.assertEqual(cli_built.returncode, 0, cli_built.stderr)
            fixture = td / "iat.bin"
            ran = subprocess.run([str(exe), str(fixture)], capture_output=True, text=True, check=False)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            before = fixture.read_bytes()
            plain = subprocess.run(
                [str(cli), "--exe", str(fixture), "--expect-sha256", hashlib.sha256(before).hexdigest()],
                capture_output=True, text=True, check=False)
            self.assertEqual(plain.returncode, 0, plain.stderr)
            self.assertEqual(fixture.read_bytes(), before)
            report = json.loads(plain.stdout)
            self.assertFalse(report["bindRequested"])
            self.assertFalse(report["importsBound"])
            self.assertFalse(report["entryCalled"])
            bound = subprocess.run(
                [str(cli), "--exe", str(fixture), "--bind-iat"],
                capture_output=True, text=True, check=False)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            self.assertEqual(fixture.read_bytes(), before)
            bound_report = json.loads(bound.stdout)
            self.assertTrue(bound_report["bindRequested"])
            self.assertTrue(bound_report["importsBound"])
            self.assertFalse(bound_report["entryCalled"])
            self.assertFalse(bound_report["hostExecutable"])
            self.assertEqual(bound_report["modeledBound"], 3)
            self.assertEqual(bound_report["trapBound"], 1)
            self.assertEqual(bound_report["unresolvedImports"], 1)
            self.assertNotEqual(bound_report["addressOfEntryPoint"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
