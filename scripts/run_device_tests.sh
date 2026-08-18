#!/usr/bin/env bash
#
# L2 hardware-in-the-loop suite. Requires a flashed Cryptick Token on USB
# (1209:BEEE); --device turns "no board" from a skip into a failure.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m pip install -q -r tests/requirements.txt
exec python3 -m pytest tests/device -v --device "$@"
