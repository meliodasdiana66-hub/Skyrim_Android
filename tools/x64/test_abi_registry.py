#!/usr/bin/env python3
"""Modeled kernel32 subset. Not a game import binder."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class AbiRegistryTests(unittest.TestCase):
    def test_stable_ids_and_fail_closed_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "abi_registry_test"
            built = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 str(HERE / "test_abi_registry.c"), str(HERE / "ae_abi.c"), str(HERE / "ae_dispatch.c"),
                 "-I", str(HERE), "-o", str(exe)],
                capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
