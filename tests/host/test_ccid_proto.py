"""Drive the CCID bulk layer in drivers/ccid_proto.c, with the real PIV applet
underneath it.

This is the protocol an OS smartcard stack speaks: PC/SC on Windows, pcscd on
Linux, CryptoTokenKit on macOS. Both halves are freestanding C, so the whole
login path — CCID message in, APDU through the applet, CCID message out — runs
on the host without a reader.

Two things carry most of the weight here:

* **bSeq echo.** A reply carrying the wrong sequence number is worse than no
  reply, because the host matches on it and pairs our answer with a different
  request.
* **Never go silent on a malformed body.** CCID reports those inside a
  well-formed reply; a reader that stays quiet wedges the host's stack waiting
  for a bSeq that never comes.
"""
from __future__ import annotations

import ctypes

import pytest

from support.native import build_shared_lib
from test_piv_apdu import CORRECT_PIN, PivHal, Card, SW_OK

HDR = 10

PC_POWER_ON = 0x62
PC_POWER_OFF = 0x63
PC_GET_SLOT_STATUS = 0x65
PC_XFR_BLOCK = 0x6F
PC_GET_PARAMETERS = 0x6C
PC_ABORT = 0x72

RDR_DATA_BLOCK = 0x80
RDR_SLOT_STATUS = 0x81
RDR_PARAMETERS = 0x82

ICC_ACTIVE = 0x00
ICC_INACTIVE = 0x01
CMD_FAILED = 0x40

ERR_SLOT_NOT_EXIST = 0x05
ERR_ICC_MUTE = 0xFE
ERR_BAD_LENGTH = 0x01

EXPECTED_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00])


class Reader:
    """The CCID layer with the PIV applet's platform stubbed underneath."""

    def __init__(self, lib):
        self.lib = lib
        self.card = Card(lib)  # installs piv_hal_t and resets applet state
        lib.ccid_reset()

    def send(self, msg: bytes, out_max: int = 600) -> bytes:
        buf = (ctypes.c_uint8 * out_max)()
        inp = (ctypes.c_uint8 * max(len(msg), 1))(*msg)
        n = self.lib.ccid_handle_message(inp, len(msg), buf, out_max)
        return bytes(buf[:n])

    @staticmethod
    def msg(mtype: int, body: bytes = b"", slot: int = 0, seq: int = 0,
            p: bytes = b"\x00\x00\x00", dw: int | None = None) -> bytes:
        n = len(body) if dw is None else dw
        return bytes([mtype]) + n.to_bytes(4, "little") + bytes([slot, seq]) + p + body

    @staticmethod
    def parse(resp: bytes) -> dict:
        assert len(resp) >= HDR, f"reply shorter than a header: {resp.hex()}"
        return {
            "type": resp[0],
            "len": int.from_bytes(resp[1:5], "little"),
            "slot": resp[5],
            "seq": resp[6],
            "status": resp[7],
            "error": resp[8],
            "param": resp[9],
            "body": resp[HDR:],
        }

    def exchange(self, mtype: int, body: bytes = b"", **kw) -> dict:
        r = self.parse(self.send(self.msg(mtype, body, **kw)))
        assert r["len"] == len(r["body"]), "dwLength disagrees with the body"
        return r

    def power_on(self, seq: int = 0) -> dict:
        return self.exchange(PC_POWER_ON, seq=seq)

    def apdu(self, apdu: bytes, seq: int = 0) -> tuple[int, bytes]:
        r = self.exchange(PC_XFR_BLOCK, apdu, seq=seq)
        assert r["type"] == RDR_DATA_BLOCK, f"expected a data block, got {r['type']:#x}"
        body = r["body"]
        assert len(body) >= 2, "APDU response with no status word"
        return (body[-2] << 8) | body[-1], body[:-2]

    def transceive(self, apdu: bytes) -> tuple[int, bytes]:
        """Follow 61xx chaining the way a real host does."""
        sw, body = self.apdu(apdu)
        while (sw & 0xFF00) == 0x6100:
            sw2, more = self.apdu(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            body += more
            sw = sw2
        return sw, body


@pytest.fixture(scope="module")
def lib(tmp_path_factory):
    lib = build_shared_lib(
        ["drivers/ccid_proto.c", "core/piv/piv.c"],
        tmp_path_factory.mktemp("ccid"),
        name="libccid",
    )
    lib.ccid_handle_message.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ]
    lib.ccid_handle_message.restype = ctypes.c_size_t
    lib.piv_handle_apdu.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ]
    lib.piv_handle_apdu.restype = ctypes.c_int
    lib.piv_init.argtypes = [ctypes.POINTER(PivHal)]
    lib.piv_pin_is_verified.restype = ctypes.c_int
    lib.ccid_icc_powered.restype = ctypes.c_int
    lib.ccid_get_atr.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8))]
    lib.ccid_get_atr.restype = ctypes.c_size_t
    return lib


@pytest.fixture
def rdr(lib):
    return Reader(lib)


# --- The ATR --------------------------------------------------------------


def test_atr_checksum_is_correct(lib):
    """TCK is the XOR of every byte after TS and is mandatory when T=1 is
    offered. A wrong one makes the card unreadable with no other symptom."""
    p = ctypes.POINTER(ctypes.c_uint8)()
    n = lib.ccid_get_atr(ctypes.byref(p))
    atr = bytes(p[:n])
    assert atr[0] == 0x3B, "direct convention"
    tck = 0
    for b in atr[1:-1]:
        tck ^= b
    assert atr[-1] == tck, f"bad TCK in {atr.hex()}"


def test_atr_offers_t1(lib):
    p = ctypes.POINTER(ctypes.c_uint8)()
    n = lib.ccid_get_atr(ctypes.byref(p))
    atr = bytes(p[:n])
    assert atr[1] & 0x80, "TD1 must be present"
    assert atr[2] & 0x0F == 1, "protocol must be T=1"


# --- Power and slot status ------------------------------------------------


def test_power_on_returns_the_atr(rdr, lib):
    r = rdr.power_on()
    assert r["type"] == RDR_DATA_BLOCK
    assert r["status"] == ICC_ACTIVE
    p = ctypes.POINTER(ctypes.c_uint8)()
    n = lib.ccid_get_atr(ctypes.byref(p))
    assert r["body"] == bytes(p[:n])
    assert lib.ccid_icc_powered()


def test_slot_status_before_and_after_power_on(rdr):
    assert rdr.exchange(PC_GET_SLOT_STATUS)["status"] == ICC_INACTIVE
    rdr.power_on()
    assert rdr.exchange(PC_GET_SLOT_STATUS)["status"] == ICC_ACTIVE


def test_power_off_clears_pin_verification(rdr, lib):
    """Otherwise an attacker with physical access power-cycles the reader and
    inherits the previous session's authentication."""
    rdr.power_on()
    assert rdr.transceive(bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)[0] == SW_OK
    assert rdr.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + CORRECT_PIN + b"\xff\xff")[0] == SW_OK
    assert lib.piv_pin_is_verified()

    r = rdr.exchange(PC_POWER_OFF)
    assert r["type"] == RDR_SLOT_STATUS
    assert r["status"] == ICC_INACTIVE
    assert not lib.piv_pin_is_verified()


def test_power_on_also_resets_the_applet(rdr, lib):
    rdr.power_on()
    rdr.transceive(bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)
    rdr.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + CORRECT_PIN + b"\xff\xff")
    assert lib.piv_pin_is_verified()
    rdr.power_on(seq=1)
    assert not lib.piv_pin_is_verified(), "a fresh card must be unauthenticated"


def test_apdu_before_power_on_reports_a_mute_card(rdr):
    r = rdr.exchange(PC_XFR_BLOCK, bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)
    assert r["status"] & CMD_FAILED
    assert r["error"] == ERR_ICC_MUTE


# --- Sequence numbers and framing -----------------------------------------


@pytest.mark.parametrize("seq", [0, 1, 7, 128, 255])
def test_sequence_number_is_echoed(rdr, seq):
    """The host pairs replies to requests by bSeq. Getting this wrong pairs our
    answer with someone else's question."""
    assert rdr.exchange(PC_GET_SLOT_STATUS, seq=seq)["seq"] == seq


@pytest.mark.parametrize("seq", [3, 200])
def test_sequence_is_echoed_on_failure_too(rdr, seq):
    r = rdr.parse(rdr.send(rdr.msg(0xFF, seq=seq)))
    assert r["seq"] == seq
    assert r["status"] & CMD_FAILED


def test_unknown_message_type_fails_cleanly(rdr):
    r = rdr.parse(rdr.send(rdr.msg(0xFF)))
    assert r["type"] == RDR_SLOT_STATUS
    assert r["status"] & CMD_FAILED


def test_wrong_slot_is_refused_not_ignored(rdr):
    r = rdr.parse(rdr.send(rdr.msg(PC_GET_SLOT_STATUS, slot=1)))
    assert r["slot"] == 1
    assert r["status"] & CMD_FAILED
    assert r["error"] == ERR_SLOT_NOT_EXIST


def test_dwlength_disagreeing_with_the_body_is_refused(rdr):
    """A length field that lies is the classic CCID parsing bug; the header is
    little-endian here, the opposite of the BLE transport."""
    r = rdr.parse(rdr.send(rdr.msg(PC_XFR_BLOCK, b"\x00\xa4", dw=99)))
    assert r["status"] & CMD_FAILED
    assert r["error"] == ERR_BAD_LENGTH


def test_short_message_has_no_reply(rdr):
    """Below a full header there is no bSeq, so there is nothing to answer."""
    for n in range(0, HDR):
        assert rdr.send(bytes(n)) == b"", f"replied to a {n}-byte message"


def test_empty_xfr_block_is_refused(rdr):
    rdr.power_on()
    r = rdr.exchange(PC_XFR_BLOCK, b"")
    assert r["status"] & CMD_FAILED
    assert r["error"] == ERR_BAD_LENGTH


def test_oversize_xfr_block_is_refused(rdr):
    rdr.power_on()
    r = rdr.parse(rdr.send(rdr.msg(PC_XFR_BLOCK, bytes(513)), out_max=1200))
    assert r["status"] & CMD_FAILED


def test_get_parameters_reports_t1(rdr):
    rdr.power_on()
    r = rdr.exchange(PC_GET_PARAMETERS)
    assert r["type"] == RDR_PARAMETERS
    assert r["param"] == 0x01, "bProtocolNum must say T=1"
    assert len(r["body"]) == 7


def test_abort_is_answered(rdr):
    rdr.power_on()
    assert rdr.exchange(PC_ABORT)["type"] == RDR_SLOT_STATUS


# --- The whole login path -------------------------------------------------


def test_select_verify_sign_over_ccid(rdr):
    """The sequence a login actually performs, end to end through both layers
    for the first time: power on, select the applet, verify the PIN, sign a
    challenge with the 9A key."""
    rdr.power_on()

    sw, body = rdr.transceive(bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)
    assert sw == SW_OK
    assert body[0] == 0x61, "SELECT must return the application property template"

    sw, _ = rdr.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + CORRECT_PIN + b"\xff\xff")
    assert sw == SW_OK

    digest = bytes(range(32))
    inner = bytes([0x81, 0x20]) + digest
    tmpl = bytes([0x7C, len(inner)]) + inner
    sw, resp = rdr.transceive(bytes([0x00, 0x87, 0x11, 0x9A, len(tmpl)]) + tmpl)
    assert sw == SW_OK
    assert resp[0] == 0x7C, "missing dynamic authentication template"


def test_certificate_read_chains_over_ccid(rdr):
    """A real 9A certificate needs several GET RESPONSEs, each its own CCID
    exchange. This is the path that actually failed when the applet misread
    byte 4 of a 5-byte APDU as Lc."""
    cert = bytes((i * 7) & 0xFF for i in range(900))
    rdr.card.objects[0x5FC105] = cert
    rdr.power_on()
    rdr.transceive(bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)

    sw, body = rdr.transceive(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05,
                                     0x5C, 0x03, 0x5F, 0xC1, 0x05]))
    assert sw == SW_OK
    assert body == cert


def test_signing_without_a_pin_is_refused_through_ccid(rdr):
    rdr.power_on()
    rdr.transceive(bytes([0x00, 0xA4, 0x04, 0x00, 9]) + EXPECTED_AID)
    inner = bytes([0x81, 0x20]) + bytes(32)
    tmpl = bytes([0x7C, len(inner)]) + inner
    sw, _ = rdr.transceive(bytes([0x00, 0x87, 0x11, 0x9A, len(tmpl)]) + tmpl)
    assert sw == 0x6982
