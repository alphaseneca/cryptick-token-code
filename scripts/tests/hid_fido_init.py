#!/usr/bin/env python3
"""L3 ad-hoc: CTAPHID_INIT smoke against Cryptick FIDO HID (1209:BEEE).

Exits 0 and prints "skip: ..." when hidapi or the device is missing, so it is
safe to call from a shell loop. Never sends ENTERBOOT.

The framing lives in tests/support/cryptick_ctaphid.py — the same module the
L2 pytest suite uses, so this script cannot drift from it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from support.cryptick_ctaphid import HidError, ctaphid_init, open_fido  # noqa: E402


def main() -> int:
    try:
        import hid  # noqa: F401
    except ImportError:
        print("skip: hidapi not installed (pip install -r tests/requirements.txt)")
        return 0

    try:
        dev = open_fido()
    except HidError as e:
        print(f"skip: {e}")
        return 0

    try:
        cid = ctaphid_init(dev)
    except HidError as e:
        print(f"fail: {e}")
        return 1
    finally:
        dev.close()

    print(f"ok: CTAPHID_INIT assigned cid=0x{cid:08x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
