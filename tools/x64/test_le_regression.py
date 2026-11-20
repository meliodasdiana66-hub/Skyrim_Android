#!/usr/bin/env python3
"""Full-repo checks that the 2011 lifter stayed 32-bit.

This file is not part of the standalone x64 package contract. If the legacy
tree is absent, every test skips with an explicit message. A skip is not a pass
of the Legendary Edition pipeline.
"""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEGACY = ROOT / "tools" / "lift.py"
HAVE_LEGACY = LEGACY.is_file() and (ROOT / "runtime" / "main.c").is_file()
SKIP = "LE regression skipped: legacy tree absent; this skip is not a pass"


@unittest.skipUnless(HAVE_LEGACY, SKIP)
class LegendaryEditionUntouchedTests(unittest.TestCase):
    def test_le_lifter_stays_32bit(self):
        lift = (ROOT / "tools" / "lift.py").read_text()
        discover = (ROOT / "tools" / "discover.py").read_text()
        self.assertIn("CS_MODE_32", lift)
        self.assertNotIn("CS_MODE_64", lift)
        self.assertIn("CS_MODE_32", discover)
        self.assertNotIn("CS_MODE_64", discover)
        main = (ROOT / "runtime" / "main.c").read_text()
        self.assertIn("opt + 28", main)
        self.assertIn("1ull << 32", main)

    def test_le_sources_still_parse(self):
        for name in ("lift.py", "discover.py", "difftest.py", "peimg.py"):
            src = ROOT / "tools" / name
            proc = subprocess.run(
                [sys.executable, "-m", "py_compile", str(src)],
                capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
