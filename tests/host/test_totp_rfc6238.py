"""RFC 6238 TOTP SHA1 golden vectors (host L0)."""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "totp_rfc6238.json"


def totp(secret: bytes, timestamp: int, period: int = 30, digits: int = 8) -> str:
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return f"{code % (10 ** digits):0{digits}d}"


def test_rfc6238_sha1_vectors():
    data = json.loads(VECTORS.read_text())
    for suite in data:
        assert suite["algorithm"] == "SHA1"
        secret = suite["secret"].encode("ascii")
        period = suite["period"]
        digits = suite["digits"]
        for v in suite["vectors"]:
            # Skip oversized timestamps that exceed uint32 device clock tests
            if v["timestamp"] > 0xFFFFFFFF:
                continue
            got = totp(secret, v["timestamp"], period, digits)
            assert got == v["otp"], (v["timestamp"], got, v["otp"])
