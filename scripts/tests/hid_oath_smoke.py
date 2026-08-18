#!/usr/bin/env python3
"""L3 ad-hoc: OATH LIST smoke over CTAPHID (docs/HID_HOST.md, INS 0xA1).

LIST is not user-verification gated, so this runs without a fingerprint.
Exits 0 and prints "skip: ..." when hidapi or the device is missing. Never
sends ENTERBOOT.

The framing lives in tests/support/cryptick_ctaphid.py — the same module the
L2 pytest suite uses, so this script cannot drift from it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from support.cryptick_ctaphid import (  # noqa: E402
    HidError,
    ctaphid_init,
    oath_list,
    oath_sw,
    open_fido,
)

SW_OK = 0x9000


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
        payload = oath_list(dev, cid)
    except HidError as e:
        print(f"fail: {e}")
        return 1
    finally:
        dev.close()

    sw = oath_sw(payload)
    print(f"OATH LIST payload={payload.hex()} sw=0x{sw:04X}")
    if sw != SW_OK:
        print(f"fail: expected SW 0x{SW_OK:04X}")
        return 1
    print("ok: OATH LIST returned SW 9000")
    return 0


if __name__ == "__main__":
    sys.exit(main())
