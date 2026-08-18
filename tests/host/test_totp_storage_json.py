"""Update host storage schema tests for product v2 (encrypted) + v1 round-trip legacy helpers."""
from __future__ import annotations

import json


def encode_accounts_v1(accounts: list[dict]) -> str:
    """Legacy plaintext schema (migration only — firmware no longer writes this)."""
    out = []
    for a in accounts:
        out.append(
            {
                "label": a["label"],
                "secret": a["secret"],
                "issuer": a.get("issuer", ""),
                "digits": int(a.get("digits", 6)),
                "period": int(a.get("period", 30)),
                "algorithm": "SHA1",
            }
        )
    return json.dumps({"accounts": out}, separators=(",", ":"))


def decode_accounts_v1(raw: str) -> list[dict]:
    doc = json.loads(raw)
    arr = doc.get("accounts") or []
    out = []
    for obj in arr:
        out.append(
            {
                "label": obj.get("label") or "",
                "secret": obj.get("secret") or "",
                "issuer": obj.get("issuer") or "",
                "digits": int(obj["digits"]) if "digits" in obj else 6,
                "period": int(obj["period"]) if "period" in obj else 30,
                "algorithm": "SHA1",
            }
        )
    return out


def test_empty_accounts_round_trip():
    raw = encode_accounts_v1([])
    assert decode_accounts_v1(raw) == []
    assert json.loads(raw) == {"accounts": []}


def test_single_account_round_trip():
    src = [
        {
            "label": "GitHub",
            "secret": "JBSWY3DPEHPK3PXP",
            "issuer": "GitHub",
            "digits": 6,
            "period": 30,
        }
    ]
    raw = encode_accounts_v1(src)
    got = decode_accounts_v1(raw)
    assert len(got) == 1
    assert got[0]["label"] == "GitHub"
    assert got[0]["secret"] == "JBSWY3DPEHPK3PXP"
    assert got[0]["issuer"] == "GitHub"
    assert got[0]["digits"] == 6
    assert got[0]["period"] == 30
    assert got[0]["algorithm"] == "SHA1"


def test_defaults_when_digits_period_missing():
    raw = json.dumps(
        {"accounts": [{"label": "A", "secret": "GEZDGNBV", "issuer": "I"}]}
    )
    got = decode_accounts_v1(raw)
    assert got[0]["digits"] == 6
    assert got[0]["period"] == 30
    assert got[0]["algorithm"] == "SHA1"


def test_multi_account_preserve_order():
    src = [
        {"label": "one", "secret": "AA", "issuer": "X", "digits": 6, "period": 30},
        {"label": "two", "secret": "BB", "issuer": "Y", "digits": 8, "period": 60},
    ]
    got = decode_accounts_v1(encode_accounts_v1(src))
    assert [g["label"] for g in got] == ["one", "two"]
    assert got[1]["digits"] == 8
    assert got[1]["period"] == 60
