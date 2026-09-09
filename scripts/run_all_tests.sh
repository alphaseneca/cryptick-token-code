#!/usr/bin/env bash
#
# Run every automated layer that can run on this machine:
#   L0 host pytest    — always
#   L1 Unity compile  — when PlatformIO is installed (no board needed)
#   L2 device pytest  — skips itself when no board is attached
#
# Pass --device to make L2 a hard failure instead of a skip.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.platformio/penv/bin:${PATH}"

# Keep in sync with the L1 matrix in .github/workflows/ci.yml.
UNITY_ENVS=(test_totp test_event_bus test_fp_enroll test_nav test_secret_crypto)

echo "=== L0 host unit tests ==="
python3 -m pip install -q -r tests/requirements-host.txt
python3 -m pytest tests/host -q

echo
echo "=== Scaffold syntax check (sources outside build_src_filter) ==="
./scripts/syntax_check_scaffolds.sh

echo
echo "=== BLE reassembly fuzz (ASan/UBSan over random fragment streams) ==="
python3 -m pytest tests/host/test_ble_fido_fuzz.py -q

echo
echo "=== L1 Unity (compile only, no upload) ==="
if command -v pio >/dev/null 2>&1; then
  for e in "${UNITY_ENVS[@]}"; do
    echo "--- compile $e ---"
    pio test -e "$e" --without-uploading --without-testing
  done
else
  echo "pio not installed — skipping L1 compile"
fi

echo
echo "=== L2 device tests (skip when no board unless --device) ==="
python3 -m pytest tests/device -q "$@"

echo
echo "ALL LAYERS OK"
