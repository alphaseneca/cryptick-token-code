"""OATH APDU + TLV builders — parity with docs/HID_HOST.md."""
from __future__ import annotations

import struct


OATH_INS_PUT = 0x01
OATH_INS_DELETE = 0x02
OATH_INS_LIST = 0xA1
OATH_INS_CALCULATE = 0xA2
OATH_INS_SET_TIME = 0x04
OATH_INS_PUT_OTPAUTH = 0x40
TAG_NAME = 0x71
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74


def tlv(tag: int, data: bytes) -> bytes:
    assert len(data) < 256
    return bytes([tag, len(data)]) + data


def apdu(ins: int, data: bytes = b"") -> bytes:
    return bytes([0x00, ins, 0x00, 0x00, len(data)]) + data


def test_put_apdu_shape():
    name = b"Example:user"
    secret = b"Hello!\xde\xad\xbe\xef"  # 10 bytes sample
    key = bytes([0x21, 0x06]) + secret
    body = tlv(TAG_NAME, name) + tlv(TAG_KEY, key)
    pkt = apdu(OATH_INS_PUT, body)
    assert pkt[0:4] == b"\x00\x01\x00\x00"
    assert pkt[4] == len(body)
    assert pkt[5] == TAG_NAME
    assert pkt[5 + 2 + len(name)] == TAG_KEY


def test_calculate_challenge_counter():
    name = b"Example:user"
    counter = 1  # floor(unix/30)
    chal = struct.pack(">Q", counter)
    body = tlv(TAG_NAME, name) + tlv(TAG_CHALLENGE, chal)
    pkt = apdu(OATH_INS_CALCULATE, body)
    assert pkt[1] == OATH_INS_CALCULATE
    assert len(chal) == 8


def test_set_time_raw():
    ts = 1700000000
    data = struct.pack(">I", ts)
    pkt = apdu(OATH_INS_SET_TIME, data)
    assert pkt[5:9] == data


def test_sw_constants():
    assert 0x9000 >> 8 == 0x90
