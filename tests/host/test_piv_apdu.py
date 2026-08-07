"""PIV SELECT APDU builders (match core/piv stub)."""
from __future__ import annotations

PIV_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00])


def select_piv() -> bytes:
    return bytes([0x00, 0xA4, 0x04, 0x00, len(PIV_AID)]) + PIV_AID


def test_select_piv_aid_len():
    apdu = select_piv()
    assert apdu[0:4] == b"\x00\xa4\x04\x00"
    assert apdu[4] == 11
    assert apdu[5:] == PIV_AID
