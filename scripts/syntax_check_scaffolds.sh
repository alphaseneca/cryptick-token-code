#!/usr/bin/env bash
#
# Compile-check the sources that are deliberately absent from the product image.
#
# A source in no `build_src_filter` is compiled by neither `pio run` nor CI, so
# it is free to accumulate syntax errors and signature drift with nothing to
# catch it. This checks those, syntax-only, so nothing lands in the flash
# budget.
#
# The list is currently empty, which is the goal state rather than an oversight:
# `core/piv/` graduated when the applet became product code, and
# `drivers/usb_ccid.cpp` when the CCID interface joined the composite.
#
# Add a source here the day it is written; move it out the day it is wired up.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INCLUDES=(-I core -I core/fido2 -I include -I drivers)

C_SCAFFOLDS=()
CXX_SCAFFOLDS=()

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

# Say so rather than printing OK for having checked nothing.
if [ ${#C_SCAFFOLDS[@]} -eq 0 ] && [ ${#CXX_SCAFFOLDS[@]} -eq 0 ]; then
  echo "no scaffolds: every source is in a build_src_filter"
  exit 0
fi
echo "scaffold syntax check OK"
