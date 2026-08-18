"""Mirrors core/secret_crypto AES-256-GCM blob (test-key fixed nonce)."""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOB_VER = 0x01
NONCE_LEN = 12
TAG_LEN = 16

# Matches secret_crypto_set_test_key + fixed nonce path
TEST_KEY = bytes(range(32))
TEST_NONCE = bytes((0xA0 + i) & 0xFF for i in range(NONCE_LEN))


def wrap_secret(pt: bytes, key: bytes = TEST_KEY, nonce: bytes = TEST_NONCE) -> str:
    if not pt:
        raise ValueError("empty plaintext")
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(nonce, pt, None)
    blob = bytes([BLOB_VER]) + nonce + ct_tag
    return base64.b64encode(blob).decode("ascii")


def unwrap_secret(b64: str, key: bytes = TEST_KEY) -> bytes:
    blob = base64.b64decode(b64)
    if len(blob) < 1 + NONCE_LEN + TAG_LEN + 1:
        raise ValueError("blob too short")
    if blob[0] != BLOB_VER:
        raise ValueError("bad version")
    nonce = blob[1 : 1 + NONCE_LEN]
    ct_tag = blob[1 + NONCE_LEN :]
    return AESGCM(key).decrypt(nonce, ct_tag, None)


def encode_accounts_v2(accounts: list[dict], key: bytes = TEST_KEY) -> str:
    """Ship schema: v=2, secrets only as encrypted `sec`, never plaintext `secret`."""
    out = []
    for a in accounts:
        # optional pre-encoded or raw bytes base32 decoded by caller
        if "sec" in a:
            sec = a["sec"]
        else:
            raw = a.get("secret_raw")
            if raw is None:
                # treat secret as UTF-8 of base32? product encrypts raw key bytes.
                # For schema tests use secret_raw or encode ascii of base32 for demo.
                raw = (a.get("secret") or "").encode("ascii")
            sec = wrap_secret(raw if isinstance(raw, (bytes, bytearray)) else raw.encode("ascii"), key=key)
        out.append(
            {
                "label": a["label"],
                "issuer": a.get("issuer", ""),
                "digits": int(a.get("digits", 6)),
                "period": int(a.get("period", 30)),
                "algorithm": "SHA1",
                "sec": sec,
            }
        )
    return json.dumps({"v": 2, "accounts": out}, separators=(",", ":"))


def decode_accounts_v2_meta(raw: str) -> list[dict]:
    """Decode metadata only (does not need key) — secret_enc present, no plaintext."""
    doc = json.loads(raw)
    assert int(doc.get("v", 0)) == 2
    arr = doc.get("accounts") or []
    out = []
    for obj in arr:
        assert "secret" not in obj or not obj["secret"]
        assert obj.get("sec")
        out.append(
            {
                "label": obj.get("label") or "",
                "issuer": obj.get("issuer") or "",
                "digits": int(obj["digits"]) if "digits" in obj else 6,
                "period": int(obj["period"]) if "period" in obj else 30,
                "sec": obj["sec"],
            }
        )
    return out
