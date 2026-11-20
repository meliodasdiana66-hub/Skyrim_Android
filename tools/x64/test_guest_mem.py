#!/usr/bin/env python3
"""Compile and run the sparse guest-memory checks.

The C code maps data pages only. It does not call x64 instructions or imports.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class GuestMemTests(unittest.TestCase):
    def test_sparse_pages_relocate_and_refuse_executable_host_pages(self):
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "guest_mem_test"
            built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "test_guest_mem.c"), str(HERE / "guest_mem.c"),
                 "-I", str(HERE), "-o", str(exe)],
                capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
