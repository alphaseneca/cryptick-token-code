"""Drive the real PIV applet in core/piv/piv.c.

This used to assert against a Python re-implementation of the APDU builder,
which passed happily while the C rejected the truncated AID that OpenSC and
CryptoTokenKit actually send. The applet is freestanding C with its crypto,
storage and presence behind `piv_hal_t`, so the host can compile it and drive
the whole thing: a failure here means the firmware is wrong.

The applet is what macOS CryptoTokenKit and Linux pam_pkcs11 talk to for login
and screen unlock, so the security-relevant cases — signing without a PIN, a
wrong PIN clearing an earlier verification, the retry counter surviving — carry
as much weight as the happy path.
"""
from __future__ import annotations

import ctypes
import re
from pathlib import Path

import pytest

from support.native import build_shared_lib

REPO_ROOT = Path(__file__).resolve().parents[2]
PIV_C = REPO_ROOT / "core" / "piv" / "piv.c"
PIV_H = REPO_ROOT / "core" / "piv" / "piv.h"

EXPECTED_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00])
TRUNCATED_AID = EXPECTED_AID[:9]

SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_SECURITY = 0x6982
SW_BLOCKED = 0x6983
SW_WRONG_DATA = 0x6A80
SW_NOT_FOUND = 0x6A82
SW_WRONG_P1P2 = 0x6A86
SW_INS_UNSUPPORTED = 0x6D00
SW_CLA_UNSUPPORTED = 0x6E00

SLOT_9A, SLOT_9C, SLOT_9D, SLOT_9E = 0x9A, 0x9C, 0x9D, 0x9E
OBJ_CERT_9A = 0x5FC105

CORRECT_PIN = b"123456"

# --- HAL callback types ---------------------------------------------------

GET_OBJ = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint32,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t),
)
SET_OBJ = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
)
SIGN = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t),
)
PIN_CHECK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
PIN_SET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
PUBKEY = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8))
KEYGEN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8)
RETRIES_GET = ctypes.CFUNCTYPE(ctypes.c_int)
RETRIES_SET = ctypes.CFUNCTYPE(None, ctypes.c_int)
PRESENCE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8)


class PivHal(ctypes.Structure):
    _fields_ = [
        ("get_object", GET_OBJ),
        ("set_object", SET_OBJ),
        ("sign_p256", SIGN),
        ("pin_check", PIN_CHECK),
        ("pin_set", PIN_SET),
        ("public_key", PUBKEY),
        ("key_generate", KEYGEN),
        ("pin_retries_get", RETRIES_GET),
        ("pin_retries_set", RETRIES_SET),
        ("user_presence", PRESENCE),
    ]


class Card:
    """The applet plus a scriptable platform underneath it."""

    def __init__(self, lib, *, presence=True, with_presence_hook=True):
        self.lib = lib
        self.objects: dict[int, bytes] = {}
        self.retries = 3
        self.pin = CORRECT_PIN
        self.generation: dict[int, int] = {}
        self.presence_ok = presence
        self.sign_calls: list[tuple[int, bytes]] = []
        self.presence_calls: list[int] = []
        self._bufs: dict[int, ctypes.Array] = {}

        def _get(tag, out_pp, out_len):
            blob = self.objects.get(int(tag))
            if blob is None:
                return 0
            buf = (ctypes.c_uint8 * len(blob))(*blob)
            self._bufs[int(tag)] = buf  # keep alive for the applet to read
            out_pp[0] = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8))
            out_len[0] = len(blob)
            return 1

        def _set(tag, data, n):
            self.objects[int(tag)] = bytes(data[:n])
            return 1

        def _sign(slot, h32, der_out, der_len):
            digest = bytes(h32[:32])
            self.sign_calls.append((int(slot), digest))
            # A DER-shaped stand-in; the applet must not look inside it.
            sig = bytes([0x30, 0x06, 0x02, 0x01, slot, 0x02, 0x01, digest[0]])
            if der_len[0] < len(sig):
                return 0
            for i, b in enumerate(sig):
                der_out[i] = b
            der_len[0] = len(sig)
            return 1

        def _pin(p, n):
            return 1 if bytes(p[:n]) == self.pin else 0

        def _pin_set(p, n):
            self.pin = bytes(p[:n])
            return 1

        def _pubkey(slot, out65):
            # Distinct per slot and per generation, so a rolled key is visible.
            gen = self.generation.get(int(slot), 0)
            pub = bytes([0x04]) + bytes(((i + slot + gen * 31) & 0xFF) for i in range(64))
            for i, b in enumerate(pub):
                out65[i] = b
            return 1

        def _keygen(slot):
            self.generation[int(slot)] = self.generation.get(int(slot), 0) + 1
            return 1

        def _rget():
            return self.retries

        def _rset(n):
            self.retries = int(n)

        def _presence(slot):
            self.presence_calls.append(int(slot))
            return 1 if self.presence_ok else 0

        self._cbs = [
            GET_OBJ(_get), SET_OBJ(_set), SIGN(_sign), PIN_CHECK(_pin),
            PIN_SET(_pin_set), PUBKEY(_pubkey), KEYGEN(_keygen),
            RETRIES_GET(_rget), RETRIES_SET(_rset),
            PRESENCE(_presence) if with_presence_hook else ctypes.cast(None, PRESENCE),
        ]
        self.hal = PivHal(*self._cbs)
        lib.piv_init(ctypes.byref(self.hal))

    def apdu(self, cmd: bytes, out_max: int = 300) -> tuple[int, bytes]:
        buf = (ctypes.c_uint8 * out_max)()
        inp = (ctypes.c_uint8 * max(len(cmd), 1))(*cmd)
        n = self.lib.piv_handle_apdu(inp, len(cmd), buf, out_max)
        assert n >= 2, f"applet returned {n}"
        resp = bytes(buf[:n])
        return (resp[-2] << 8) | resp[-1], resp[:-2]

    def transceive(self, cmd: bytes) -> tuple[int, bytes]:
        """Send a command and follow every 61xx with GET RESPONSE."""
        sw, body = self.apdu(cmd)
        while (sw & 0xFF00) == 0x6100:
            sw2, more = self.apdu(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            body += more
            sw = sw2
        return sw, body

    def select(self, aid: bytes = EXPECTED_AID) -> tuple[int, bytes]:
        return self.transceive(bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid)

    def verify(self, pin: bytes = CORRECT_PIN) -> int:
        block = pin + b"\xff" * (8 - len(pin))
        return self.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + block)[0]

    def sign(self, slot: int = SLOT_9A, digest: bytes = bytes(range(32)), alg=0x11):
        inner = bytes([0x81, 0x20]) + digest
        body = bytes([0x7C, len(inner)]) + inner
        return self.transceive(bytes([0x00, 0x87, alg, slot, len(body)]) + body)

    def change_pin(self, old: bytes, new: bytes) -> int:
        blocks = (old + b"\xff" * (8 - len(old))) + (new + b"\xff" * (8 - len(new)))
        return self.apdu(bytes([0x00, 0x24, 0x00, 0x80, len(blocks)]) + blocks)[0]

    def generate(self, slot: int = SLOT_9A, alg: int = 0x11, p1: int = 0x00):
        body = bytes([0xAC, 0x03, 0x80, 0x01, alg])
        return self.transceive(bytes([0x00, 0x47, p1, slot, len(body)]) + body)

    def get_data(self, tag: int = OBJ_CERT_9A):
        tl = bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
        body = bytes([0x5C, len(tl)]) + tl
        return self.transceive(bytes([0x00, 0xCB, 0x3F, 0xFF, len(body)]) + body)


@pytest.fixture(scope="module")
def lib(tmp_path_factory):
    lib = build_shared_lib(["core/piv/piv.c"], tmp_path_factory.mktemp("piv"), name="libpiv")
    lib.piv_handle_apdu.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ]
    lib.piv_handle_apdu.restype = ctypes.c_int
    lib.piv_init.argtypes = [ctypes.POINTER(PivHal)]
    lib.piv_pin_is_verified.restype = ctypes.c_int
    return lib


@pytest.fixture
def card(lib):
    return Card(lib)


# --- The AID constant, guarded against the source -------------------------


def test_piv_aid_matches_nist():
    m = re.search(r"PIV_AID\[PIV_AID_LEN\]\s*=\s*\{(.*?)\}", PIV_C.read_text(), re.S)
    assert m, "PIV_AID array not found"
    parsed = bytes(int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
    assert parsed == EXPECTED_AID


@pytest.mark.parametrize("macro,expected", [("PIV_AID_LEN", 11), ("PIV_AID_MIN_LEN", 9)])
def test_aid_length_macros(macro, expected):
    m = re.search(rf"#define\s+{macro}\s+(\d+)", PIV_H.read_text())
    assert m and int(m.group(1)) == expected


# --- SELECT ---------------------------------------------------------------


def test_select_full_aid(card):
    assert card.select(EXPECTED_AID)[0] == SW_OK


def test_select_truncated_aid(card):
    """The 9-byte right-truncated AID is what OpenSC and CryptoTokenKit send."""
    assert card.select(TRUNCATED_AID)[0] == SW_OK


@pytest.mark.parametrize("length", [9, 10, 11])
def test_select_accepts_every_valid_prefix(card, length):
    assert card.select(EXPECTED_AID[:length])[0] == SW_OK


@pytest.mark.parametrize("length", [0, 5, 8])
def test_select_rejects_aid_shorter_than_rid_plus_pix(card, length):
    assert card.select(EXPECTED_AID[:length])[0] == SW_NOT_FOUND


def test_select_rejects_foreign_aid(card):
    assert card.select(bytes([0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1, 0]))[0] == SW_NOT_FOUND


def test_select_returns_application_property_template(card):
    """A bare 9000 is enough for OpenSC, but CryptoTokenKit reads the AID back."""
    sw, body = card.select()
    assert sw == SW_OK
    assert body[0] == 0x61, "missing application property template"
    assert bytes([0x4F, 0x09]) + TRUNCATED_AID in body


def test_select_clears_pin_verification(card):
    card.select()
    assert card.verify() == SW_OK
    assert card.lib.piv_pin_is_verified()
    card.select()
    assert not card.lib.piv_pin_is_verified(), "re-select must reset the session"


# --- VERIFY ---------------------------------------------------------------


def test_correct_pin_verifies(card):
    assert card.verify() == SW_OK
    assert card.lib.piv_pin_is_verified()


def test_wrong_pin_decrements_and_reports_retries(card):
    assert card.verify(b"999999") == 0x63C2
    assert card.retries == 2
    assert card.verify(b"999999") == 0x63C1
    assert card.retries == 1


def test_pin_blocks_at_zero_retries(card):
    for _ in range(3):
        card.verify(b"999999")
    assert card.retries == 0
    assert card.verify(b"999999") == SW_BLOCKED
    assert card.verify(CORRECT_PIN) == SW_BLOCKED, "a blocked PIN must stay blocked"


def test_correct_pin_restores_the_retry_counter(card):
    card.verify(b"999999")
    assert card.retries == 2
    assert card.verify() == SW_OK
    assert card.retries == 3


def test_wrong_pin_clears_an_earlier_verification(card):
    """Otherwise a caller who authenticated once keeps signing while guessing."""
    assert card.verify() == SW_OK
    assert card.lib.piv_pin_is_verified()
    card.verify(b"999999")
    assert not card.lib.piv_pin_is_verified()
    assert card.sign()[0] == SW_SECURITY


def test_empty_verify_queries_retries_without_spending_one(card):
    sw, _ = card.apdu(bytes([0x00, 0x20, 0x00, 0x80]))
    assert sw == 0x63C3
    assert card.retries == 3, "querying must not consume an attempt"


def test_verify_reset_forgets_the_session(card):
    assert card.verify() == SW_OK
    assert card.apdu(bytes([0x00, 0x20, 0xFF, 0x80]))[0] == SW_OK
    assert not card.lib.piv_pin_is_verified()


@pytest.mark.parametrize("p2", [0x00, 0x81, 0x01])
def test_verify_rejects_unsupported_pin_reference(card, p2):
    assert card.apdu(bytes([0x00, 0x20, 0x00, p2, 0x08]) + b"1" * 8)[0] == SW_WRONG_P1P2


def test_verify_rejects_short_pin(card):
    block = b"123" + b"\xff" * 5
    assert card.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + block)[0] == SW_WRONG_DATA


def test_verify_rejects_padding_before_digits(card):
    block = b"12\xff45\xff\xff\xff"
    assert card.apdu(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + block)[0] == SW_WRONG_DATA


# --- GENERAL AUTHENTICATE -------------------------------------------------


def test_signing_requires_a_verified_pin(card):
    """The whole point of the applet: no PIN, no login credential."""
    assert card.sign()[0] == SW_SECURITY
    assert card.sign_calls == []


def test_signing_after_verify_returns_a_wrapped_signature(card):
    assert card.verify() == SW_OK
    sw, body = card.sign()
    assert sw == SW_OK
    assert body[0] == 0x7C
    assert 0x82 in body
    assert card.sign_calls[0][0] == SLOT_9A
    assert card.sign_calls[0][1] == bytes(range(32))


def test_card_authentication_slot_signs_without_a_pin(card):
    """9E is defined to work PIN-less; it exists for contactless door access."""
    sw, _ = card.sign(slot=SLOT_9E)
    assert sw == SW_OK


@pytest.mark.parametrize("slot", [SLOT_9A, SLOT_9C, SLOT_9D])
def test_login_slots_never_sign_without_a_pin(card, slot):
    assert card.sign(slot=slot)[0] == SW_SECURITY


def test_signing_requires_user_presence(lib):
    """The PIN proves who is asking; presence proves someone is physically
    here, which is what stops silent signing by malware that saw the PIN."""
    card = Card(lib, presence=False)
    assert card.verify() == SW_OK
    assert card.sign()[0] == SW_SECURITY
    assert card.presence_calls == [SLOT_9A]
    assert card.sign_calls == [], "must not reach the key without presence"


def test_presence_hook_is_optional(lib):
    card = Card(lib, with_presence_hook=False)
    assert card.verify() == SW_OK
    assert card.sign()[0] == SW_OK


@pytest.mark.parametrize("slot", [0x00, 0x82, 0x9B, 0xFF])
def test_unknown_slots_are_rejected(card, slot):
    card.verify()
    assert card.sign(slot=slot)[0] == SW_WRONG_P1P2


def test_non_p256_algorithm_is_rejected(card):
    card.verify()
    assert card.sign(alg=0x07)[0] == SW_WRONG_P1P2


def test_challenge_must_be_a_32_byte_hash(card):
    card.verify()
    for n in (0, 16, 31, 33, 64):
        inner = bytes([0x81, n]) + bytes(n)
        body = bytes([0x7C, len(inner)]) + inner
        sw, _ = card.apdu(bytes([0x00, 0x87, 0x11, SLOT_9A, len(body)]) + body)
        assert sw == SW_WRONG_DATA, f"accepted a {n}-byte challenge"


def test_malformed_authentication_template_is_rejected(card):
    card.verify()
    for body in (b"\x00\x02\x81\x00", b"\x7c", b"\x7c\x20", b"\x7c\x02\x81\x20"):
        sw, _ = card.apdu(bytes([0x00, 0x87, 0x11, SLOT_9A, len(body)]) + body)
        assert sw in (SW_WRONG_DATA, SW_WRONG_LENGTH), body.hex()


# --- GET DATA and response chaining ---------------------------------------


def test_get_data_missing_object(card):
    assert card.get_data()[0] == SW_NOT_FOUND


def test_get_data_small_object(card):
    card.objects[OBJ_CERT_9A] = b"\x53\x03ABC"
    sw, body = card.get_data()
    assert sw == SW_OK
    assert body == b"\x53\x03ABC"


def test_certificate_larger_than_one_apdu_is_chained(card):
    """A real 9A certificate is far bigger than 256 bytes. Without GET RESPONSE
    chaining, GET DATA simply cannot answer and login never starts."""
    cert = bytes((i * 7) & 0xFF for i in range(900))
    card.objects[OBJ_CERT_9A] = cert

    sw, first = card.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05]))
    assert (sw & 0xFF00) == 0x6100, "expected more-data status"
    assert len(first) == 256

    sw, whole = card.get_data()
    assert sw == SW_OK
    assert whole == cert, "chained reassembly lost or reordered bytes"


def test_get_response_without_a_pending_response(card):
    assert card.apdu(bytes([0x00, 0xC0, 0x00, 0x00, 0x10]))[0] == SW_INS_UNSUPPORTED


def test_another_command_abandons_a_chained_response(card):
    """A client that interleaves commands has lost its place; handing it the
    tail of a stale certificate would be worse than an error."""
    card.objects[OBJ_CERT_9A] = bytes(900)
    sw, _ = card.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05]))
    assert (sw & 0xFF00) == 0x6100
    assert card.verify() == SW_OK
    assert card.apdu(bytes([0x00, 0xC0, 0x00, 0x00, 0x10]))[0] == SW_INS_UNSUPPORTED


def test_get_data_rejects_a_malformed_tag_list(card):
    for body in (b"\x5c\x00", b"\x5c\x04\x01\x02\x03\x04", b"\x4c\x03\x5f\xc1\x05"):
        sw, _ = card.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, len(body)]) + body)
        assert sw == SW_WRONG_DATA, body.hex()


def test_get_data_rejects_wrong_p1p2(card):
    assert card.apdu(bytes([0x00, 0xCB, 0x00, 0x00, 0x02, 0x5C, 0x00]))[0] == SW_WRONG_P1P2


# --- PUT DATA -------------------------------------------------------------


def test_put_data_requires_a_pin(card):
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03ABC"
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_SECURITY
    assert card.objects == {}


def test_put_data_stores_the_object(card):
    card.verify()
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03ABC"
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    assert card.objects[OBJ_CERT_9A] == b"ABC"
    assert card.get_data()[1] == b"ABC"


# --- Framing --------------------------------------------------------------


def test_truncated_header(card):
    assert card.apdu(bytes([0x00, 0xA4, 0x04]))[0] == SW_WRONG_LENGTH


def test_lc_longer_than_body(card):
    assert card.apdu(bytes([0x00, 0xA4, 0x04, 0x00, 0x0B]) + EXPECTED_AID[:4])[0] == SW_WRONG_LENGTH


def test_unknown_instruction(card):
    assert card.apdu(bytes([0x00, 0xFF, 0x00, 0x00]))[0] == SW_INS_UNSUPPORTED


@pytest.mark.parametrize("cla", [0x10, 0x80, 0xFF])
def test_unsupported_class_is_rejected(card, cla):
    """Chaining and secure messaging are not implemented; ignoring those bits
    would misread the APDU rather than refuse it."""
    assert card.apdu(bytes([cla, 0xA4, 0x04, 0x00]))[0] == SW_CLA_UNSUPPORTED


def test_out_buffer_too_small(card):
    buf = (ctypes.c_uint8 * 1)()
    cmd = bytes([0x00, 0xA4, 0x04, 0x00, 0x0B]) + EXPECTED_AID
    inp = (ctypes.c_uint8 * len(cmd))(*cmd)
    assert card.lib.piv_handle_apdu(inp, len(cmd), buf, 1) == -1


def test_null_arguments(card):
    buf = (ctypes.c_uint8 * 8)()
    assert card.lib.piv_handle_apdu(None, 0, buf, 8) == -1


# --- CHANGE REFERENCE DATA ------------------------------------------------


def test_pin_can_be_changed(card):
    """Without this the device ships on the SP 800-73 default with no way off
    it, which makes the PIN decorative."""
    assert card.change_pin(CORRECT_PIN, b"654321") == SW_OK
    assert card.pin == b"654321"
    assert card.verify(b"654321") == SW_OK
    assert card.verify(CORRECT_PIN) != SW_OK


def test_change_pin_leaves_the_session_verified(card):
    assert card.change_pin(CORRECT_PIN, b"654321") == SW_OK
    assert card.lib.piv_pin_is_verified()


def test_wrong_current_pin_spends_a_retry(card):
    """Otherwise CHANGE REFERENCE DATA is a counter-free oracle for guessing
    the PIN — unlimited attempts with none of them costing anything."""
    assert card.change_pin(b"999999", b"654321") == 0x63C2
    assert card.retries == 2
    assert card.pin == CORRECT_PIN, "PIN must not change on a failed attempt"


def test_wrong_current_pin_drops_the_session(card):
    assert card.verify() == SW_OK
    card.change_pin(b"999999", b"654321")
    assert not card.lib.piv_pin_is_verified()


def test_change_pin_blocks_at_zero_retries(card):
    for _ in range(3):
        card.change_pin(b"999999", b"654321")
    assert card.change_pin(CORRECT_PIN, b"654321") == SW_BLOCKED
    assert card.pin == CORRECT_PIN


def test_successful_change_restores_the_retry_counter(card):
    card.change_pin(b"999999", b"654321")
    assert card.retries == 2
    assert card.change_pin(CORRECT_PIN, b"654321") == SW_OK
    assert card.retries == 3


@pytest.mark.parametrize("new", [b"12345", b"1", b""])
def test_new_pin_must_be_long_enough(card, new):
    assert card.change_pin(CORRECT_PIN, new) == SW_WRONG_DATA
    assert card.pin == CORRECT_PIN


def test_change_pin_rejects_a_short_body(card):
    assert card.apdu(bytes([0x00, 0x24, 0x00, 0x80, 0x08]) + b"1" * 8)[0] == SW_WRONG_LENGTH


@pytest.mark.parametrize("p1,p2", [(0x01, 0x80), (0x00, 0x81), (0x00, 0x00)])
def test_change_pin_rejects_other_references(card, p1, p2):
    body = b"1" * 16
    assert card.apdu(bytes([0x00, 0x24, p1, p2, 0x10]) + body)[0] == SW_WRONG_P1P2


# --- GENERATE ASYMMETRIC KEY PAIR -----------------------------------------


def test_generate_requires_a_pin(card):
    """It destroys the usability of any certificate already issued for the
    slot, so it must not be reachable unauthenticated."""
    assert card.generate()[0] == SW_SECURITY
    assert card.generation == {}


def test_generate_returns_an_uncompressed_point(card):
    """Without a published public key no certificate can be issued, and a PIV
    card with no certificate cannot log anyone in."""
    card.verify()
    sw, body = card.generate()
    assert sw == SW_OK
    assert body[:2] == b"\x7f\x49", "missing public key template"
    assert 0x86 in body
    idx = body.index(0x86)
    assert body[idx + 1] == 65
    point = body[idx + 2 : idx + 2 + 65]
    assert len(point) == 65 and point[0] == 0x04


def test_generate_rolls_the_key(card):
    card.verify()
    _, first = card.generate()
    _, second = card.generate()
    assert first != second, "generate must produce a new key, not re-derive one"
    assert card.generation[SLOT_9A] == 2


def test_generate_requires_presence(lib):
    card = Card(lib, presence=False)
    card.verify()
    assert card.generate()[0] == SW_SECURITY
    assert card.generation == {}, "must not roll the key without presence"


@pytest.mark.parametrize("slot", [0x00, 0x9B, 0xFF])
def test_generate_rejects_unknown_slots(card, slot):
    card.verify()
    assert card.generate(slot=slot)[0] == SW_WRONG_P1P2


def test_generate_rejects_non_p256(card):
    card.verify()
    assert card.generate(alg=0x07)[0] == SW_WRONG_P1P2


def test_generate_rejects_a_malformed_template(card):
    card.verify()
    for body in (b"\xac", b"\xac\x00", b"\xac\x03\x81\x01\x11", b"\x7c\x03\x80\x01\x11"):
        sw, _ = card.apdu(bytes([0x00, 0x47, 0x00, SLOT_9A, len(body)]) + body)
        assert sw in (SW_WRONG_DATA, SW_WRONG_LENGTH), body.hex()


def test_generated_key_is_immediately_usable_for_signing(card):
    """The whole provisioning round trip: generate, then sign with the slot."""
    card.verify()
    assert card.generate()[0] == SW_OK
    sw, body = card.sign()
    assert sw == SW_OK and body[0] == 0x7C
