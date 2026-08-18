"""L0: Chrome GetTouch APDU layout + product attestation cert/key match.

Mirrors core/fido2/apdu.c (extended APDU) and Chromium kBogusChallenge/AppParam
so a 73-byte CTAPHID_MSG U2F_REGISTER is decoded as 64-byte chal||app — the
path macOS Chrome uses before CTAP2 MakeCredential.
"""
from __future__ import annotations

import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
ATTEST_INC = ROOT / "core" / "fido2" / "cryptick_attestation.inc"


def _parse_c_array(name: str, text: str) -> bytes:
    block = re.search(
        rf"static const uint8_t {re.escape(name)}\[\] = \{{(.*?)\}};",
        text,
        re.S,
    )
    assert block, f"missing {name} in {ATTEST_INC}"
    nums = re.findall(r"0x([0-9a-fA-F]{2})", block.group(1))
    return bytes(int(n, 16) for n in nums)


def _apdu_decode(data: bytes) -> tuple[int, bytes]:
    """Return (lc, payload) for short/extended ISO7816 command APDUs."""
    if len(data) < 4:
        raise ValueError("short")
    b0 = data[4] if len(data) >= 5 else 0
    if len(data) >= 7 and b0 == 0:
        extlen = (data[5] << 8) + data[6]
        if len(data) == 7 + extlen + 2:  # case 4E + 2-byte Le (Chrome)
            return extlen, data[7 : 7 + extlen]
        if len(data) == 7 + extlen:
            return extlen, data[7 : 7 + extlen]
    if len(data) == 5 + b0 and b0 != 0:
        return b0, data[5 : 5 + b0]
    raise ValueError(f"unhandled APDU len={len(data)}")


def test_chrome_extended_u2f_register_is_64_byte_body():
    chal = bytes([0x11]) * 32
    app = bytes([0x22]) * 32
    # CLA INS P1 P2 LC=0x000040 + chal||app + Le=0x0000  → 73 bytes
    pkt = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40]) + chal + app + bytes(
        [0x00, 0x00]
    )
    assert len(pkt) == 73
    lc, payload = _apdu_decode(pkt)
    assert lc == 64
    assert payload == chal + app


def test_chrome_gettouch_bogus_params():
    """Chromium ConstructBogusU2fRegistrationCommand: chal=0x42… app=0x41…"""
    chal = bytes([0x42]) * 32
    app = bytes([0x41]) * 32
    pkt = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40]) + chal + app + bytes(
        [0x00, 0x00]
    )
    _, payload = _apdu_decode(pkt)
    assert payload[:32] == chal
    assert payload[32:] == app


def test_attestation_cert_matches_private_key():
    text = ATTEST_INC.read_text()
    priv = _parse_c_array("kCryptickTokenAttestKey", text)
    der = _parse_c_array("kCryptickTokenAttestCertDer", text)
    assert len(priv) == 32
    assert der[0] == 0x30
    cert = x509.load_der_x509_certificate(der)
    key = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
    cert_nums = cert.public_key().public_numbers()
    key_nums = key.public_key().public_numbers()
    assert cert_nums.x == key_nums.x
    assert cert_nums.y == key_nums.y
    # Self-signed batch cert must parse as a leaf (Chrome U2F GetTouch/create).
    assert cert.subject == cert.issuer
