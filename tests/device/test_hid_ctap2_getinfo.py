"""L2: CTAP2 authenticatorGetInfo + Cryptick product AAGUID."""
from __future__ import annotations

import pytest

from support.cryptick_ctaphid import ctap2_get_info, ctap2_info_looks_fido2

pytestmark = pytest.mark.device

# docs/ATTESTATION.md — stable product AAGUID
CRYPTICK_AAGUID = bytes(
    [
        0xC7,
        0xA5,
        0xE1,
        0xE0,
        0x7C,
        0x4B,
        0x4F,
        0x0A,
        0x9D,
        0x2E,
        0x55,
        0xC4,
        0x1C,
        0x71,
        0x00,
        0x01,
    ]
)


def test_ctap2_get_info_ok(fido_hid):
    status, cbor = ctap2_get_info(fido_hid.dev, fido_hid.cid, timeout_ms=5000)
    assert status == 0x00, f"CTAP status=0x{status:02x} cbor={cbor[:40].hex()}"
    assert len(cbor) >= 8
    assert ctap2_info_looks_fido2(cbor), f"no FIDO version string in GetInfo: {cbor[:80]!r}"


def test_ctap2_get_info_contains_product_aaguid(fido_hid):
    status, cbor = ctap2_get_info(fido_hid.dev, fido_hid.cid, timeout_ms=5000)
    assert status == 0x00
    assert CRYPTICK_AAGUID in cbor, (
        f"product AAGUID missing from GetInfo CBOR; got head={cbor[:48].hex()}"
    )
