#!/usr/bin/env python3
"""L2: CTAPHID_INIT smoke against Cryptick FIDO HID (VID 1209 PID BEEE).

Requires: pip install hid
Skips cleanly if no device. Never ENTERBOOT.
"""
from __future__ import annotations

import struct
import sys

VID, PID = 0x1209, 0xBEEE
CTAPHID_INIT = 0x86
BROADCAST = 0xFFFFFFFF


def main() -> int:
    try:
        import hid
    except ImportError:
        print("skip: hid module not installed")
        return 0

    dev = None
    for d in hid.enumerate(VID, PID):
        # Prefer FIDO usage page if present
        dev = hid.device()
        try:
            dev.open_path(d["path"])
            break
        except Exception:
            dev = None
    if not dev:
        print("skip: no Cryptick HID 1209:BEEE")
        return 0

    nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    pkt = bytearray(64)
    struct.pack_into("<I", pkt, 0, BROADCAST)
    pkt[4] = CTAPHID_INIT
    pkt[5] = 0
    pkt[6] = 8
    pkt[7:15] = nonce
    dev.write(b"\x00" + bytes(pkt))  # report id 0
    resp = bytes(dev.read(64, timeout_ms=1000))
    dev.close()
    if len(resp) < 17:
        print("fail: short response", resp.hex())
        return 1
    print("ok: CTAPHID_INIT response", resp[:17].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
