"""L0 pure CTAPHID framing helpers (no board)."""
from __future__ import annotations

import struct

from support.cryptick_ctaphid import (
    BROADCAST,
    CTAPHID_INIT,
    CTAPHID_OATH,
    REPORT_LEN,
)


def test_init_packet_layout():
    nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    pkt = bytearray(REPORT_LEN)
    struct.pack_into("<I", pkt, 0, BROADCAST)
    pkt[4] = CTAPHID_INIT
    pkt[5] = 0
    pkt[6] = 8
    pkt[7:15] = nonce
    assert len(pkt) == 64
    assert struct.unpack_from("<I", pkt, 0)[0] == 0xFFFFFFFF
    assert pkt[4] == 0x86
    assert pkt[7:15] == nonce


def test_oath_list_apdu():
    apdu = bytes([0x00, 0xA1, 0x00, 0x00, 0x00])
    pkt = bytearray(REPORT_LEN)
    cid = 0x01000001
    struct.pack_into("<I", pkt, 0, cid)
    pkt[4] = CTAPHID_OATH
    pkt[5] = 0
    pkt[6] = len(apdu)
    pkt[7 : 7 + len(apdu)] = apdu
    assert pkt[4] == 0xE3
    assert pkt[7:12] == apdu
