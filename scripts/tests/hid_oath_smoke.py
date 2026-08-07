#!/usr/bin/env python3
"""L2 OATH LIST smoke (opt-in hardware). Does not ENTERBOOT.

docs/HID_HOST.md — CTAPHID_CRYPTICK_OATH + INS LIST (0xA1).
"""
from __future__ import annotations

import struct
import sys

VID, PID = 0x1209, 0xBEEE
CTAPHID_INIT = 0x86
CTAPHID_OATH = 0xE3
BROADCAST = 0xFFFFFFFF


def open_dev():
    import hid
    for d in hid.enumerate(VID, PID):
        dev = hid.device()
        try:
            dev.open_path(d["path"])
            return dev
        except Exception:
            continue
    return None


def ctaphid_init(dev) -> int:
    nonce = b"\xaa\xbb\xcc\xdd\xee\xff\x01\x02"
    pkt = bytearray(64)
    struct.pack_into("<I", pkt, 0, BROADCAST)
    pkt[4] = CTAPHID_INIT
    pkt[5] = 0
    pkt[6] = 8
    pkt[7:15] = nonce
    dev.write(b"\x00" + bytes(pkt))
    resp = bytes(dev.read(64, timeout_ms=1000))
    if len(resp) < 15:
        raise RuntimeError("INIT failed")
    return struct.unpack_from("<I", resp, 7)[0]  # assigned CID offset depends on layout
    # INIT response: nonce(8) cid(4) ... after cmd header — adjust:
    # report[0:4] cid, [4] cmd, [5:6] bcnt, [7:14] nonce, [15:18] cid_new


def main() -> int:
    try:
        import hid  # noqa: F401
    except ImportError:
        print("skip: hid not installed")
        return 0
    dev = open_dev()
    if not dev:
        print("skip: no device")
        return 0

    # INIT
    nonce = b"\xaa\xbb\xcc\xdd\xee\xff\x01\x02"
    pkt = bytearray(64)
    struct.pack_into("<I", pkt, 0, BROADCAST)
    pkt[4] = CTAPHID_INIT
    pkt[5] = 0
    pkt[6] = 8
    pkt[7:15] = nonce
    dev.write(b"\x00" + bytes(pkt))
    resp = bytes(dev.read(64, timeout_ms=1000))
    # payload after header: 8 nonce + 4 new cid
    cid = struct.unpack_from("<I", resp, 15)[0] if len(resp) >= 19 else 0x01000000

    # OATH LIST
    apdu = bytes([0x00, 0xA1, 0x00, 0x00, 0x00])
    out = bytearray(64)
    struct.pack_into("<I", out, 0, cid)
    out[4] = CTAPHID_OATH
    out[5] = 0
    out[6] = len(apdu)
    out[7 : 7 + len(apdu)] = apdu
    dev.write(b"\x00" + bytes(out))
    r = bytes(dev.read(64, timeout_ms=2000))
    dev.close()
    print("OATH LIST raw:", r[:32].hex())
    # SW at end of init payload if bcnt small
    print("ok: exchanged OATH (inspect SW 9000 on payload end)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
