#!/bin/sh
# Synthetic x64 prototype tests, plus a parse check of the untouched LE tools.
set -eu
cd "$(dirname "$0")"
python3 -B test_proto.py
python3 -m py_compile ../lift.py ../discover.py ../difftest.py ../peimg.py
echo "x64 prototype tests passed; LE py_compile passed"
