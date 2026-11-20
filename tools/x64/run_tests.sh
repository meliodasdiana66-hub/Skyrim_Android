#!/bin/sh
# Synthetic x64 prototype tests, plus a parse check of the untouched LE tools.
set -eu
cd "$(dirname "$0")"
python3 -B test_proto.py
python3 -B test_leafcheck.py
python3 -B test_pe32plus_load.py
python3 -B test_aarch64_qemu.py
python3 -B test_abi_sandbox.py
python3 -B test_cfg_sandbox.py
python3 -B test_guest_mem.py
python3 -B test_pe_data.py
python3 -B test_abi_registry.py
if [ -f ../lift.py ] && [ -f ../../runtime/main.c ]; then
  python3 -B test_le_regression.py
  echo "LE regression: PASS"
else
  echo "LE regression: SKIPPED (legacy tree not in this package; this is not a pass)"
fi
echo "x64 package tests finished"
