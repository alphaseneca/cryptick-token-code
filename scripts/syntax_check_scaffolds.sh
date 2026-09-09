#!/usr/bin/env bash
#
# Compile-check the sources that are deliberately absent from the product image.
#
# `drivers/usb_ccid.cpp` is the next thing on the Mac login roadmap, but it is
# not in any `build_src_filter`, so neither `pio run` nor CI compiles it. It is
# free to accumulate syntax errors and signature drift against `ctap.h` /
# `device.h` with nothing to catch it.
#
# `core/piv/` graduated out of this list when the applet became product code.
#
# Syntax-only, so nothing lands in the flash budget. Add a source here the day
# it is written; move it to `build_src_filter` the day it is wired up.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INCLUDES=(-I core -I core/fido2 -I include -I drivers)

C_SCAFFOLDS=()
CXX_SCAFFOLDS=(drivers/usb_ccid.cpp)

status=0

# `${arr[@]}` on an empty array trips `set -u` under bash 3.2, which is what
# macOS still ships. The `+` expansion keeps an empty list empty.
for src in ${C_SCAFFOLDS[@]+"${C_SCAFFOLDS[@]}"}; do
  echo "--- cc  $src"
  gcc -fsyntax-only -std=c11 -Wall -Wextra "${INCLUDES[@]}" "$src" || status=1
done

for src in ${CXX_SCAFFOLDS[@]+"${CXX_SCAFFOLDS[@]}"}; do
  echo "--- c++ $src"
  g++ -fsyntax-only -std=c++17 -Wall -Wextra "${INCLUDES[@]}" "$src" || status=1
done

if [ "$status" -ne 0 ]; then
  echo "scaffold syntax check FAILED"
  exit 1
fi
echo "scaffold syntax check OK"
