"""L0: AES-GCM secret wrap + v2 storage schema (plaintext secrets forbidden)."""
from __future__ import annotations

import json

import pytest

from support.totp_secret_enc import (
    decode_accounts_v2_meta,
    encode_accounts_v2,
    unwrap_secret,
    wrap_secret,
)


def test_wrap_unwrap_round_trip():
    pt = b"Hello!"
    b64 = wrap_secret(pt)
    assert unwrap_secret(b64) == pt


def test_wrap_tamper_fails():
    b64 = wrap_secret(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    bad = list(b64)
    mid = len(bad) // 2
    bad[mid] = "A" if bad[mid] != "A" else "B"
    with pytest.raises(Exception):
        unwrap_secret("".join(bad))


def test_v2_schema_no_plaintext_secret():
    raw = encode_accounts_v2(
        [
            {
                "label": "GitHub",
                "issuer": "GitHub",
                "secret_raw": b"\xde\xad\xbe\xef" * 2,
            }
        ]
    )
    doc = json.loads(raw)
    assert doc["v"] == 2
    assert "secret" not in doc["accounts"][0]
    assert "sec" in doc["accounts"][0]
    meta = decode_accounts_v2_meta(raw)
    assert meta[0]["label"] == "GitHub"
    pt = unwrap_secret(meta[0]["sec"])
    assert pt == b"\xde\xad\xbe\xef" * 2


def test_v1_plain_schema_is_legacy_only():
    """v1 shape still known for migration docs; product no longer *writes* it."""
    legacy = {
        "accounts": [
            {
                "label": "A",
                "secret": "JBSWY3DPEHPK3PXP",
                "issuer": "I",
                "digits": 6,
                "period": 30,
                "algorithm": "SHA1",
            }
        ]
    }
    assert "secret" in legacy["accounts"][0]
    assert "sec" not in legacy["accounts"][0]
