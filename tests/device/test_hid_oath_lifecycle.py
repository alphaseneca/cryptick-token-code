"""L2: OATH PUT → LIST → CALCULATE → DELETE lifecycle.

Product UV: if fingerprints are enrolled, place finger when OLED says Manage/Code
(25s window per op). Bootstrap (no templates) needs no finger.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

import pytest

from support.cryptick_ctaphid import (
    HidError,
    oath_calculate,
    oath_delete,
    oath_list,
    oath_put,
    oath_sw,
)

pytestmark = pytest.mark.device

# RFC 6238 test secret base32: JBSWY3DPEHPK3PXP → "Hello!"
RFC_SECRET_RAW = b"Hello!"
ACCT = "CryptickTest:L2user"


def _hotp_truncate(key: bytes, counter: int) -> int:
    msg = counter.to_bytes(8, "big")
    dig = hmac.new(key, msg, hashlib.sha1).digest()
    off = dig[-1] & 0x0F
    code = struct.unpack(">I", dig[off : off + 4])[0] & 0x7FFFFFFF
    return code % 1_000_000


def _need_uv_fail(payload: bytes) -> bool:
    return oath_sw(payload) == 0x6985


def test_oath_put_list_calculate_delete(fido_hid):
    dev, cid = fido_hid.dev, fido_hid.cid

    print("\n>>> WATCH OLED: place ENROLLED finger when it shows Manage or Code")
    print(">>> First steps may wait up to ~25s each for UV\n", flush=True)

    # Ensure clean slate of our test account (ignore not-found after UV)
    try:
        p = oath_delete(dev, cid, ACCT, timeout_ms=35000)
        sw = oath_sw(p)
        if sw == 0x6985:
            pytest.fail(
                "OATH UV timeout (6985). Place finger when OLED shows Manage, re-run."
            )
        assert sw in (0x9000, 0x6A82), f"DELETE prep SW=0x{sw:04X}"
    except HidError as e:
        pytest.fail(f"DELETE prep failed: {e}")

    print(">>> PUT: place finger if Manage…", flush=True)
    put = oath_put(dev, cid, ACCT, RFC_SECRET_RAW, timeout_ms=35000)
    sw = oath_sw(put)
    if sw == 0x6985:
        pytest.fail(
            "PUT UV timeout (6985). Place finger when prompted (Manage), then re-run."
        )
    assert sw == 0x9000, f"PUT SW=0x{sw:04X} body={put.hex()}"

    listed = oath_list(dev, cid)
    assert oath_sw(listed) == 0x9000
    assert ACCT.encode("utf-8") in listed or b"L2user" in listed

    counter = 1  # ts = 30 when period=30
    print(">>> CALCULATE: place finger if Code…", flush=True)
    calc = oath_calculate(dev, cid, ACCT, counter, timeout_ms=35000)
    csw = oath_sw(calc)
    if csw == 0x6985:
        pytest.fail(
            "CALCULATE UV timeout (6985). Place finger when prompted (Code), then re-run."
        )
    assert csw == 0x9000, f"CALC SW=0x{csw:04X} body={calc.hex()}"
    assert len(calc) >= 9 and calc[0] == 0x75 and calc[1] == 5 and calc[2] == 6
    code = struct.unpack(">I", calc[3:7])[0]
    expect = _hotp_truncate(RFC_SECRET_RAW, counter)
    assert code == expect, f"code={code:06d} expect={expect:06d}"

    print(">>> DELETE: place finger if Manage…", flush=True)
    delete = oath_delete(dev, cid, ACCT, timeout_ms=35000)
    dsw = oath_sw(delete)
    if dsw == 0x6985:
        pytest.fail(
            "DELETE UV timeout (6985). Place finger when prompted (Manage), then re-run."
        )
    assert dsw == 0x9000, f"DELETE SW=0x{dsw:04X}"

    listed2 = oath_list(dev, cid)
    assert oath_sw(listed2) == 0x9000
    assert ACCT.encode("utf-8") not in listed2
    print(">>> OATH lifecycle + UV OK", flush=True)
