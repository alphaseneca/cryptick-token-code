"""Drive the exact provisioning exchange the daemon's tool will send.

The daemon owns certificate issuance: the device generates the key and never
releases it, the host builds the certificate and writes it back. That split
means the wire format between the two is the integration seam, and it is
specified rather than negotiated -- SP 800-73-4 object tags, a 0x53 container
holding 0x70/0x71/0xFE, chained PUT DATA in, GET RESPONSE out.

These tests send those bytes literally instead of going through helpers, so a
change on either side that breaks the agreed format fails here rather than on
a device someone is trying to log in with. A certificate is 500-900 bytes,
which is past every short-APDU boundary in the path: Lc stops at 255 going in
and Le stops at 256 coming back, so both directions exercise chaining.
"""
from __future__ import annotations

import pytest

from test_piv_apdu import CORRECT_PIN, Card, SW_OK, lib, card  # noqa: F401

# SP 800-73-4 object tags, as the daemon will send them.
OBJ = {"9A": 0x5FC105, "9C": 0x5FC10A, "9D": 0x5FC10B, "9E": 0x5FC101}

SW_MORE = 0x6100  # 61xx: more data available via GET RESPONSE


def _tlv(tag: int, value: bytes) -> bytes:
    """BER-TLV with a definite length. Long form past 127, as the spec requires."""
    if len(value) < 0x80:
        length = bytes([len(value)])
    elif len(value) <= 0xFF:
        length = bytes([0x81, len(value)])
    else:
        length = bytes([0x82, len(value) >> 8, len(value) & 0xFF])
    return bytes([tag]) + length + value


def container(cert: bytes) -> bytes:
    """The certificate container the daemon writes, inside its 0x53 wrapper.

    0x71 CertInfo 0x00 means uncompressed; the daemon states it will never send
    0x01 (gzip), which the applet could not inflate. 0xFE is the error
    detection code and is always empty.
    """
    inner = _tlv(0x70, cert) + bytes([0x71, 0x01, 0x00]) + bytes([0xFE, 0x00])
    return _tlv(0x53, inner)


def data_object_tl(tag: int) -> bytes:
    return bytes([0x5C, 0x03, (tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])


def put_data(card: Card, tag: int, payload: bytes) -> int:
    """PUT DATA, chained across as many blocks as the body needs.

    00 DB 3F FF Lc  5C 03 <tag> || 53 <len> <container>

    CLA 0x10 marks every block but the last. The applet answers 9000 to each
    without acting, then processes the assembled command once.
    """
    body = data_object_tl(tag) + payload
    sw = None
    while body:
        block, body = body[:255], body[255:]
        cla = 0x10 if body else 0x00
        sw, _ = card.transceive(bytes([cla, 0xDB, 0x3F, 0xFF, len(block)]) + block)
    return sw


def get_data(card: Card, tag: int) -> tuple[int, bytes]:
    """GET DATA: 00 CB 3F FF Lc 5C 03 <tag>, following 61xx with GET RESPONSE."""
    tl = data_object_tl(tag)
    return card.transceive(bytes([0x00, 0xCB, 0x3F, 0xFF, len(tl)]) + tl)


def fake_cert(size: int) -> bytes:
    """Stand-in for a DER certificate. The applet stores bytes and never parses
    them, so the only property that matters here is the length."""
    return bytes((i * 7 + 13) & 0xFF for i in range(size))


@pytest.fixture
def provisioned(card):
    card.select()
    assert card.verify(CORRECT_PIN) == SW_OK
    return card


@pytest.mark.parametrize("slot,tag", sorted(OBJ.items()))
def test_every_slot_object_tag_round_trips(provisioned, slot, tag):
    """9A and 9D are what login reads; 9C and 9E must not be special-cased away."""
    cert = fake_cert(600)
    assert put_data(provisioned, tag, container(cert)) == SW_OK
    sw, body = get_data(provisioned, tag)
    assert sw == SW_OK
    assert body == container(cert), f"slot {slot} did not read back what was written"


@pytest.mark.parametrize("size", [64, 127, 128, 255, 256, 700, 900])
def test_certificate_sizes_across_every_length_boundary(provisioned, size):
    """
    128 is the BER long-form boundary, 255 the short-APDU Lc limit and 256 the
    Le limit. A naive encoder or an off-by-one in chaining shows up at one of
    these and nowhere else.
    """
    cert = fake_cert(size)
    assert put_data(provisioned, OBJ["9A"], container(cert)) == SW_OK
    sw, body = get_data(provisioned, OBJ["9A"])
    assert sw == SW_OK
    assert body == container(cert)


def test_stored_object_keeps_its_53_container(provisioned):
    """
    GET DATA returns stored bytes verbatim and the synthesised CCC and CHUID
    include their container, so a provisioned certificate must too. Returning
    the bare 0x70 makes provisioned and synthesised objects disagree on shape.
    """
    payload = container(fake_cert(300))
    assert put_data(provisioned, OBJ["9A"], payload) == SW_OK
    _, body = get_data(provisioned, OBJ["9A"])
    assert body[0] == 0x53, "container tag was stripped on the way in or out"
    assert body == payload


def test_certinfo_and_error_detection_survive(provisioned):
    """The daemon sends 71 01 00 and FE 00 after the certificate; a host reads
    CertInfo to decide whether to inflate, so losing it is not cosmetic."""
    payload = container(fake_cert(400))
    assert put_data(provisioned, OBJ["9A"], payload) == SW_OK
    _, body = get_data(provisioned, OBJ["9A"])
    assert bytes([0x71, 0x01, 0x00]) in body
    assert body.endswith(bytes([0xFE, 0x00]))


def test_read_of_a_long_object_is_chained_not_truncated(provisioned):
    """A 900-byte certificate cannot fit one short-APDU response. The first
    answer must be 61xx with more to come, never 9000 with a truncated body."""
    payload = container(fake_cert(900))
    assert put_data(provisioned, OBJ["9A"], payload) == SW_OK

    tl = data_object_tl(OBJ["9A"])
    sw, first = provisioned.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, len(tl)]) + tl)
    assert sw & 0xFF00 == SW_MORE, f"expected 61xx, got {sw:04X}"
    assert len(first) <= 256


def test_put_data_without_pin_is_refused(card):
    """Writing a login credential is not something an unauthenticated caller does."""
    card.select()
    sw = put_data(card, OBJ["9A"], container(fake_cert(200)))
    assert sw != SW_OK, "a certificate was written with no PIN verified"


def test_interrupted_chain_is_dropped_not_stitched(provisioned):
    """
    A chain whose command changes mid-way is abandoned. Concatenating the
    blocks would hand the applet a body its sender never wrote, which is worse
    than costing the interrupting command one round trip.
    """
    body = data_object_tl(OBJ["9A"]) + container(fake_cert(600))
    first, _ = body[:255], body[255:]
    assert provisioned.transceive(bytes([0x10, 0xDB, 0x3F, 0xFF, len(first)]) + first)[0] == SW_OK

    provisioned.transceive(bytes([0x00, 0xCB, 0x3F, 0xFF, 5]) + data_object_tl(OBJ["9C"]))

    # Whatever the abandoned chain left behind, it must not be a partial
    # object presented as a whole one. Absence is a fine outcome; a short read
    # that claims success is not.
    sw, leftover = get_data(provisioned, OBJ["9A"])
    if sw == SW_OK:
        assert leftover == container(fake_cert(600)), (
            "an interrupted chain left a truncated object readable as complete"
        )

    assert put_data(provisioned, OBJ["9A"], container(fake_cert(600))) == SW_OK
    sw, readback = get_data(provisioned, OBJ["9A"])
    assert sw == SW_OK and readback == container(fake_cert(600))


def test_gzip_certinfo_is_stored_verbatim(provisioned):
    """
    The daemon states it will only ever send CertInfo 0x00. The applet stores
    containers without parsing them, so a 0x01 must round-trip unchanged rather
    than be rejected or rewritten -- the device is not the place that decides
    what a host may compress.
    """
    inner = _tlv(0x70, fake_cert(200)) + bytes([0x71, 0x01, 0x01]) + bytes([0xFE, 0x00])
    payload = _tlv(0x53, inner)
    assert put_data(provisioned, OBJ["9A"], payload) == SW_OK
    _, body = get_data(provisioned, OBJ["9A"])
    assert body == payload
