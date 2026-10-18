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
import os
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


def PIV_SW_VERIFY_FAILED(retries: int) -> int:
    """Mirrors the C macro of the same name in piv.h."""
    return 0x63C0 | (retries & 0x0F)

SLOT_9A, SLOT_9C, SLOT_9D, SLOT_9E = 0x9A, 0x9C, 0x9D, 0x9E
OBJ_CERT_9A = 0x5FC105
OBJ_CERT_9C = 0x5FC10A
OBJ_CERT_9D = 0x5FC10B
OBJ_CERT_9E = 0x5FC101

CORRECT_PIN = b"123456"
DEFAULT_PUK = b"12345678"  # SP 800-73-5 Part 1 §2.4.3's default PUK.

# --- HAL callback types ---------------------------------------------------

GET_OBJ = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint32,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t),
)
SET_OBJ = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
)
DELETE_OBJ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
SIGN = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t),
)
ECDH = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)
)
PIN_CHECK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
PIN_SET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
PUBKEY = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8))
GUID = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8))
KEYGEN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8)
RETRIES_GET = ctypes.CFUNCTYPE(ctypes.c_int)
RETRIES_SET = ctypes.CFUNCTYPE(None, ctypes.c_int)
PRESENCE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint8)

# --- PUK, configurable retry ceilings, and the management key -------------
# Same shapes as their PIN equivalents above; see piv_hal_t in piv.h.
PUK_CHECK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
PUK_SET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
RETRY_MAX_GET = ctypes.CFUNCTYPE(ctypes.c_int)
SET_RETRIES = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)
MGMT_CRYPT = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)
)
MGMT_SET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
MGMT_IS_DEFAULT = ctypes.CFUNCTYPE(ctypes.c_int)
RANDOM_BYTES = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

# --- RESET APPLICATION's one new hook --------------------------------------
# Appended after random_bytes, not inserted beside mgmt_key_set/
# mgmt_key_is_default where it would read more naturally — see piv.h's own
# comment on this field for why: an insertion anywhere but the end risks the
# exact ctypes/struct drift "PIV PUK and management key support" (NOTES.md)
# already found and fixed once in this same file.
MGMT_RESET_DEFAULT = ctypes.CFUNCTYPE(ctypes.c_int)


class PivHal(ctypes.Structure):
    _fields_ = [
        ("get_object", GET_OBJ),
        ("set_object", SET_OBJ),
        ("delete_object", DELETE_OBJ),
        ("sign_p256", SIGN),
        ("ecdh_p256", ECDH),
        ("pin_check", PIN_CHECK),
        ("pin_set", PIN_SET),
        ("public_key", PUBKEY),
        ("device_guid", GUID),
        ("key_generate", KEYGEN),
        ("pin_retries_get", RETRIES_GET),
        ("pin_retries_set", RETRIES_SET),
        ("user_presence", PRESENCE),
        ("puk_check", PUK_CHECK),
        ("puk_set", PUK_SET),
        ("puk_retries_get", RETRIES_GET),
        ("puk_retries_set", RETRIES_SET),
        ("pin_retry_max_get", RETRY_MAX_GET),
        ("puk_retry_max_get", RETRY_MAX_GET),
        ("set_pin_puk_retries", SET_RETRIES),
        ("mgmt_key_crypt_block", MGMT_CRYPT),
        ("mgmt_key_set", MGMT_SET),
        ("mgmt_key_is_default", MGMT_IS_DEFAULT),
        ("random_bytes", RANDOM_BYTES),
        ("mgmt_key_reset_to_default", MGMT_RESET_DEFAULT),
    ]


class Card:
    """The applet plus a scriptable platform underneath it."""

    def __init__(self, lib, *, presence=True, with_presence_hook=True,
                 with_mgmt_reset_hook=True):
        self.lib = lib
        self.objects: dict[int, bytes] = {}
        self.retries = 3
        self.pin = CORRECT_PIN
        self.generation: dict[int, int] = {}
        self.guid = bytes(range(0x10, 0x20))
        self.presence_ok = presence
        self.sign_calls: list[tuple[int, bytes]] = []
        self.presence_calls: list[int] = []
        self._bufs: dict[int, ctypes.Array] = {}
        self.deleted: list[int] = []

        # PUK: same shape and SP 800-73 default as the PIN above.
        self.puk = DEFAULT_PUK
        self.puk_retries = 3
        # Configurable ceilings SET PIN RETRIES reconfigures; start at the
        # compile-time default both constants in piv.h fall back to.
        self.pin_max = 3
        self.puk_max = 3
        # A fake, deterministic, *reversible* stand-in for AES-192-ECB: XOR
        # each byte of a 16-byte block with the matching byte of a 24-byte
        # key, wrapped to 16. Real AES is verified by code review and on
        # hardware, same split this file already uses for sign_p256/ecdh_p256
        # above — what this harness can usefully pin down is the *protocol*
        # (witness/challenge/response, session gating, replay rejection),
        # not NIST FIPS-197 itself.
        self.mgmt_key = bytes((i * 7 + 3) & 0xFF for i in range(24))
        self.mgmt_key_is_default = True
        self.random_calls = 0
        self.mgmt_key_reset_calls = 0

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

        def _ecdh(slot, peer_pub, shared32):
            for i in range(32):
                shared32[i] = (slot ^ 0x42 ^ i) & 0xFF
            return 1

        def _delete(tag):
            self.deleted.append(int(tag))
            self.objects.pop(int(tag), None)
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

        def _guid(out16):
            if not self.guid:
                return 0
            for i, b in enumerate(self.guid):
                out16[i] = b
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

        def _puk_check(p, n):
            return 1 if bytes(p[:n]) == self.puk else 0

        def _puk_set(p, n):
            self.puk = bytes(p[:n])
            return 1

        def _puk_rget():
            return self.puk_retries

        def _puk_rset(n):
            self.puk_retries = int(n)

        def _pin_max():
            return self.pin_max

        def _puk_max():
            return self.puk_max

        def _set_retries(pin_max, puk_max):
            # Mirrors piv_hal_t's set_pin_puk_retries doc comment: the
            # ceiling and the stored secret share one rewrite, so this
            # resets both secrets to their SP 800-73 defaults too.
            self.pin_max = int(pin_max)
            self.puk_max = int(puk_max)
            self.pin = CORRECT_PIN
            self.puk = DEFAULT_PUK
            self.retries = self.pin_max
            self.puk_retries = self.puk_max
            return 1

        def _mgmt_crypt(in16, out16):
            block = bytes(in16[:16])
            enc = self.mgmt_crypt(block)
            for i, b in enumerate(enc):
                out16[i] = b
            return 1

        def _mgmt_set(key, n):
            self.mgmt_key = bytes(key[:n])
            self.mgmt_key_is_default = False
            return 1

        def _mgmt_is_default():
            return 1 if self.mgmt_key_is_default else 0

        def _random(out, n):
            self.random_calls += 1
            # Deterministic, not cryptographic — this harness tests protocol
            # shape, not entropy quality (real randomness is ESP32 hardware
            # TRNG territory, out of this host build's reach).
            data = os.urandom(int(n))
            for i, b in enumerate(data):
                out[i] = b
            return 1

        def _mgmt_reset_default():
            self.mgmt_key_reset_calls += 1
            # Unconditionally a *new* value, never a reuse of whatever was
            # there — mirrors piv_mgmt_key_reset_to_default's own doc
            # comment: a factory reset must not leave an owner-rotated key
            # operative just because this call did not change its bytes.
            self.mgmt_key = os.urandom(24)
            self.mgmt_key_is_default = True
            return 1

        self._cbs = [
            GET_OBJ(_get), SET_OBJ(_set), DELETE_OBJ(_delete), SIGN(_sign),
            ECDH(_ecdh), PIN_CHECK(_pin), PIN_SET(_pin_set), PUBKEY(_pubkey),
            GUID(_guid), KEYGEN(_keygen), RETRIES_GET(_rget), RETRIES_SET(_rset),
            PRESENCE(_presence) if with_presence_hook else ctypes.cast(None, PRESENCE),
            PUK_CHECK(_puk_check), PUK_SET(_puk_set),
            RETRIES_GET(_puk_rget), RETRIES_SET(_puk_rset),
            RETRY_MAX_GET(_pin_max), RETRY_MAX_GET(_puk_max),
            SET_RETRIES(_set_retries), MGMT_CRYPT(_mgmt_crypt),
            MGMT_SET(_mgmt_set), MGMT_IS_DEFAULT(_mgmt_is_default),
            RANDOM_BYTES(_random),
            MGMT_RESET_DEFAULT(_mgmt_reset_default) if with_mgmt_reset_hook
            else ctypes.cast(None, MGMT_RESET_DEFAULT),
        ]
        self.hal = PivHal(*self._cbs)
        lib.piv_init(ctypes.byref(self.hal))

    def mgmt_crypt(self, block: bytes, key: bytes | None = None) -> bytes:
        """What a *host* holding `key` (defaulting to this card's real key,
        i.e. a legitimate holder) would compute for the same fake cipher
        `_mgmt_crypt` above implements card-side. Tests pass a wrong `key`
        to simulate a caller that does not actually hold the management
        key."""
        key = self.mgmt_key if key is None else key
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(block))

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

    def change_puk(self, old: bytes, new: bytes) -> int:
        blocks = old.ljust(8, b"\xff") + new.ljust(8, b"\xff")
        return self.apdu(bytes([0x00, 0x24, 0x00, 0x81, 0x10]) + blocks)[0]

    def reset_retry(self, puk: bytes, new_pin: bytes) -> int:
        """RESET RETRY COUNTER: unblock the PIN with the PUK."""
        body = puk.ljust(8, b"\xff") + new_pin.ljust(8, b"\xff")
        return self.apdu(bytes([0x00, 0x2C, 0x00, 0x80, len(body)]) + body)[0]

    def set_pin_retries(self, pin_max: int, puk_max: int) -> int:
        return self.apdu(bytes([0x00, 0xFA, pin_max, puk_max]))[0]

    def set_management_key(self, key: bytes, alg: int = 0x0A) -> int:
        body = bytes([alg, len(key)]) + key
        return self.apdu(bytes([0x00, 0xFF, 0xFF, 0xFF, len(body)]) + body)[0]

    def reset_application(self) -> int:
        """RESET APPLICATION (vendor, INS 0xFB): factory-reset the whole
        applet. Only succeeds once both the PIN and PUK are already
        blocked — see test_piv_apdu.py's own RESET APPLICATION section."""
        return self.apdu(bytes([0x00, 0xFB, 0x00, 0x00]))[0]

    def mgmt_request_witness(self) -> tuple[int, bytes]:
        """First half of GENERAL AUTHENTICATE's mutual exchange: ask the
        card for its (encrypted) witness. Returns (sw, encrypted_witness)."""
        body = bytes([0x7C, 0x02, 0x80, 0x00])
        sw, resp = self.transceive(bytes([0x00, 0x87, 0x0A, 0x9B, len(body)]) + body)
        if sw != SW_OK:
            return sw, b""
        elements = parse_dynamic_auth(resp)
        return sw, elements.get(0x80, b"")

    def mgmt_respond(self, witness_plain: bytes, challenge: bytes) -> tuple[int, bytes]:
        """Second half: return the decrypted witness plus a fresh challenge
        of our own. Returns (sw, encrypted_response_to_our_challenge)."""
        inner = bytes([0x80, len(witness_plain)]) + witness_plain
        inner += bytes([0x81, len(challenge)]) + challenge
        body = bytes([0x7C, len(inner)]) + inner
        sw, resp = self.transceive(bytes([0x00, 0x87, 0x0A, 0x9B, len(body)]) + body)
        if sw != SW_OK:
            return sw, b""
        elements = parse_dynamic_auth(resp)
        return sw, elements.get(0x82, b"")

    def authenticate_management_key(self, key: bytes | None = None) -> int:
        """Drives the full mutual-authenticate exchange as a legitimate
        host holding `key` (defaulting to this card's real key) would."""
        sw, enc_witness = self.mgmt_request_witness()
        if sw != SW_OK:
            return sw
        witness_plain = self.mgmt_crypt(enc_witness, key)
        challenge = bytes(range(16))
        sw, enc_response = self.mgmt_respond(witness_plain, challenge)
        if sw != SW_OK:
            return sw
        # A real host would now also verify the card's response decrypts
        # back to `challenge` — i.e. mutual, not just one-directional —
        # which is exactly what test_mutual_auth_is_actually_mutual below
        # checks explicitly rather than folding it silently in here.
        return sw


def parse_dynamic_auth(resp: bytes) -> dict[int, bytes]:
    """Reads a 7C-wrapped dynamic authentication template's immediate
    children into {tag: value}. Minimal on purpose — this file's own BER-TLV
    parsing, not a general one, so a shape this applet never emits is a
    bug worth seeing fail rather than a case worth silently handling."""
    assert resp and resp[0] == 0x7C, f"expected a 7C template, got {resp[:1].hex()}"
    length = resp[1]
    body = resp[2 : 2 + length]
    out: dict[int, bytes] = {}
    i = 0
    while i + 1 < len(body):
        tag = body[i]
        l = body[i + 1]
        out[tag] = body[i + 2 : i + 2 + l]
        i += 2 + l
    return out


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
    """The stored object keeps its 0x53 container. SP 800-73 defines GET DATA
    as returning the object *with* that tag, which is what the synthesised CCC
    and CHUID emit — storing only the inner value made a provisioned
    certificate come back a different shape from a synthesised object."""
    card.verify()
    container = b"\x53\x03ABC"
    body = b"\x5c\x03\x5f\xc1\x05" + container
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    assert card.objects[OBJ_CERT_9A] == container
    assert card.get_data()[1] == container


def ber_len(n: int) -> bytes:
    """BER length. A single byte only encodes 0..127; 0x80 and above is the
    long form, so a naive one-byte length silently makes a 200-byte object
    malformed."""
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


@pytest.mark.parametrize("payload", [b"A", b"ABC", bytes(range(64)),
                                     bytes(127), bytes(128), bytes(200)])
def test_put_data_get_data_round_trip(card, payload):
    """Anything we store, we must read back byte for byte — the property that
    caught the container bug. The 127/128 pair straddles the BER long-form
    boundary, which is where length encoding goes wrong."""
    card.verify()
    container = bytes([0x53]) + ber_len(len(payload)) + payload
    body = b"\x5c\x03\x5f\xc1\x05" + container
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    sw, got = card.get_data()
    assert sw == SW_OK
    assert got == container


def test_provisioned_and_synthesised_objects_have_the_same_shape(card):
    """Both must open with 0x53 and a length that matches the body, or a host
    parses one of them wrong."""
    card.verify()
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03ABC"
    card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)

    for tag in (OBJ_CERT_9A, OBJ_CHUID, OBJ_CCC):
        sw, obj = card.get_data(tag)
        assert sw == SW_OK, f"{tag:#x}"
        assert obj[0] == 0x53, f"{tag:#x} is not a 0x53 container"
        assert obj[1] == len(obj) - 2, f"{tag:#x} length disagrees with its body"


# --- Framing --------------------------------------------------------------


def test_truncated_header(card):
    assert card.apdu(bytes([0x00, 0xA4, 0x04]))[0] == SW_WRONG_LENGTH


def test_lc_longer_than_body(card):
    assert card.apdu(bytes([0x00, 0xA4, 0x04, 0x00, 0x0B]) + EXPECTED_AID[:4])[0] == SW_WRONG_LENGTH


def test_unknown_instruction(card):
    """0xFF is deliberately not used here any more — it is SET MANAGEMENT
    KEY now (see test_set_management_key_* below); 0xEE stays genuinely
    unassigned by both SP 800-73 and this applet's vendor extensions."""
    assert card.apdu(bytes([0x00, 0xEE, 0x00, 0x00]))[0] == SW_INS_UNSUPPORTED


@pytest.mark.parametrize("cla", [0x80, 0xFF, 0x0C, 0x01])
def test_unsupported_class_is_rejected(card, cla):
    """Secure messaging and logical channels are not implemented; ignoring
    those bits would misread the APDU rather than refuse it. 0x10 is valid —
    it is command chaining, which certificate provisioning requires."""
    assert card.apdu(bytes([cla, 0xA4, 0x04, 0x00]))[0] == SW_CLA_UNSUPPORTED


def test_extended_length_body_is_rejected(card):
    """device-protocol.md: "The applet accepts short APDUs only;
    extended-length encoding is rejected with 6700." This used to be parsed
    (case 3E/4E) instead of refused — a certificate too big for a short Lc
    must go through GET RESPONSE chaining, the same shape on every
    transport, including BLE PIV's 261-byte ceiling, which cannot carry an
    extended APDU intact in the first place."""
    cmd = bytes([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x0B]) + EXPECTED_AID
    assert card.apdu(cmd)[0] == SW_WRONG_LENGTH


def test_extended_length_le_only_is_rejected(card):
    """Case 2E (Lc escape byte present, encoded length 0, meaning Le-only)
    used to be accepted as Le=65536; it is extended-length encoding too."""
    cmd = bytes([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x00])
    assert card.apdu(cmd)[0] == SW_WRONG_LENGTH


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


@pytest.mark.parametrize("p1,p2", [(0x01, 0x80), (0x00, 0x00), (0x00, 0x9B)])
def test_change_pin_rejects_other_references(card, p1, p2):
    """P2 0x81 (the PUK) is deliberately not one of these cases any more —
    CHANGE REFERENCE DATA legitimately supports it now; see
    test_change_puk_* below for its own behaviour."""
    body = b"1" * 16
    assert card.apdu(bytes([0x00, 0x24, p1, p2, 0x10]) + body)[0] == SW_WRONG_P1P2


# --- CHANGE REFERENCE DATA (PUK) and RESET RETRY COUNTER ------------------
#
# Mirrors the CHANGE REFERENCE DATA (PIN) tests above almost exactly: same
# instruction, same 16-byte old-block/new-block shape, same retry mechanics —
# SP 800-73 Part 2 §3.2.2 defines one CHANGE REFERENCE DATA command for both
# secrets, distinguished only by P2. The PUK's own retry counter is entirely
# separate from the PIN's, which RESET RETRY COUNTER's own tests exist to
# pin down (literally: changing one must never touch the other's count).


def test_verify_reports_puk_retries_without_spending_one(card):
    """SP 800-73 has no 'verify the PUK' operation — this is query-only, the
    same empty-body convention VERIFY already uses for the PIN."""
    assert card.apdu(bytes([0x00, 0x20, 0x00, 0x81]))[0] == PIV_SW_VERIFY_FAILED(3)
    assert card.puk_retries == 3, "a query must never spend a retry"


def test_verify_rejects_a_non_empty_body_for_the_puk(card):
    assert card.apdu(bytes([0x00, 0x20, 0x00, 0x81, 0x08]) + b"1" * 8)[0] == SW_WRONG_P1P2


def test_puk_can_be_changed(card):
    assert card.change_puk(DEFAULT_PUK, b"87654321") == SW_OK
    assert card.puk == b"87654321"


def test_wrong_current_puk_spends_a_retry_not_the_pins(card):
    assert card.change_puk(b"00000000", b"87654321") == PIV_SW_VERIFY_FAILED(2)
    assert card.puk_retries == 2
    assert card.retries == 3, "a wrong PUK must never spend a PIN retry"


def test_puk_blocks_at_zero_retries(card):
    for _ in range(3):
        card.change_puk(b"00000000", b"87654321")
    assert card.puk_retries == 0
    assert card.change_puk(b"00000000", b"87654321") == SW_BLOCKED
    assert card.change_puk(DEFAULT_PUK, b"87654321") == SW_BLOCKED, \
        "a blocked PUK must stay blocked even against its own correct value"


def test_successful_puk_change_restores_the_retry_counter(card):
    card.change_puk(b"00000000", b"ignored1")  # spend one retry
    assert card.puk_retries == 2
    assert card.change_puk(DEFAULT_PUK, b"87654321") == SW_OK
    assert card.puk_retries == 3


def test_reset_retry_unblocks_a_blocked_pin(card):
    for _ in range(3):
        card.verify(b"000000")
    assert card.retries == 0
    assert card.verify(CORRECT_PIN) == SW_BLOCKED, "sanity: really blocked"

    assert card.reset_retry(DEFAULT_PUK, b"999999") == SW_OK
    assert card.pin == b"999999"
    assert card.retries == 3
    assert card.verify(b"999999") == SW_OK


def test_reset_retry_does_not_verify_the_new_pin(card):
    """SP 800-73: RESET RETRY COUNTER clears the block, it is not a VERIFY.
    A caller that wants the session authenticated still has to present the
    new PIN afterward."""
    card.reset_retry(DEFAULT_PUK, b"999999")
    assert not card.lib.piv_pin_is_verified()


def test_reset_retry_rejects_a_wrong_puk_and_spends_its_retry(card):
    assert card.reset_retry(b"00000000", b"999999") == PIV_SW_VERIFY_FAILED(2)
    assert card.puk_retries == 2
    assert card.pin == CORRECT_PIN, "the PIN must be untouched by a failed attempt"


def test_reset_retry_blocks_at_zero_puk_retries(card):
    for _ in range(3):
        card.reset_retry(b"00000000", b"999999")
    assert card.reset_retry(DEFAULT_PUK, b"999999") == SW_BLOCKED


@pytest.mark.parametrize("p1,p2", [(0x01, 0x80), (0x00, 0x81), (0x00, 0x9B)])
def test_reset_retry_rejects_other_references(card, p1, p2):
    """SP 800-73 defines RESET RETRY COUNTER only for the PIN (P2 0x80) —
    there is no standard operation to reset the PUK's own counter with a
    third secret, so every other P2 is refused the same as a wrong P1."""
    body = b"1" * 16
    assert card.apdu(bytes([0x00, 0x2C, p1, p2, 0x10]) + body)[0] == SW_WRONG_P1P2


def test_reset_retry_rejects_a_short_body(card):
    assert card.apdu(bytes([0x00, 0x2C, 0x00, 0x80, 0x08]) + b"1" * 8)[0] == SW_WRONG_LENGTH


# --- Management key: GENERAL AUTHENTICATE mutual exchange -----------------
#
# SP 800-73 Part 2 §3.2.4 Table 7. `Card.mgmt_crypt()` plays the legitimate
# host's side (it knows the same key the fake HAL's `_mgmt_crypt` closure
# uses); passing a wrong key there is this harness's way of simulating a
# caller that does not actually hold the management key.


def test_mgmt_key_authenticates_with_the_right_key(card):
    assert card.authenticate_management_key() == SW_OK


def test_mgmt_key_rejects_the_wrong_key(card):
    wrong = bytes((b + 1) & 0xFF for b in card.mgmt_key)
    sw, enc_witness = card.mgmt_request_witness()
    assert sw == SW_OK
    # Decrypted with the *wrong* key — not what the card actually encrypted
    # its witness with, so the applet must reject it.
    bad_witness = card.mgmt_crypt(enc_witness, wrong)
    sw, _ = card.mgmt_respond(bad_witness, bytes(range(16)))
    assert sw == SW_SECURITY


def test_mutual_auth_is_actually_mutual(card):
    """Not just "the host proved it holds the key" — the card's own
    response must decrypt back to the exact challenge the host sent, or
    the host has no way to tell this card from an impostor that merely
    forwarded the witness somewhere else."""
    sw, enc_witness = card.mgmt_request_witness()
    assert sw == SW_OK
    witness_plain = card.mgmt_crypt(enc_witness)
    challenge = bytes(range(16))
    sw, enc_response = card.mgmt_respond(witness_plain, challenge)
    assert sw == SW_OK
    assert card.mgmt_crypt(enc_response) == challenge


def test_mgmt_witness_is_single_use(card):
    """A witness is good for exactly one follow-up request. Replaying an
    old (already-consumed) witness against a *new* request must fail, not
    silently re-validate against stale state."""
    sw, enc_witness_1 = card.mgmt_request_witness()
    assert sw == SW_OK
    witness_1_plain = card.mgmt_crypt(enc_witness_1)
    # Spend it once, successfully.
    assert card.mgmt_respond(witness_1_plain, bytes(range(16)))[0] == SW_OK

    # A second, fresh witness request — the old plaintext must no longer
    # be the one this applet is holding.
    sw, enc_witness_2 = card.mgmt_request_witness()
    assert sw == SW_OK
    assert enc_witness_2 != enc_witness_1, "two witnesses must differ (random)"
    sw, _ = card.mgmt_respond(witness_1_plain, bytes(range(16)))
    assert sw == SW_SECURITY, "a stale witness must not authenticate a new exchange"


def test_mgmt_auth_does_not_survive_a_reset(card):
    assert card.authenticate_management_key() == SW_OK
    card.select()  # re-select resets the session, same as SELECT already does for the PIN
    assert card.set_management_key(card.mgmt_key) == SW_SECURITY, \
        "an admin op must require authenticating again after a session reset"


def test_general_authenticate_mgmt_rejects_other_algorithms(card):
    # 0x11 is this device's ECDSA P-256 identifier, not a valid management
    # key algorithm — reusing it here must not be mistaken for a signing
    # request against key reference 0x9B.
    body = bytes([0x7C, 0x02, 0x80, 0x00])
    assert card.apdu(bytes([0x00, 0x87, 0x11, 0x9B, len(body)]) + body)[0] == SW_WRONG_P1P2


def test_general_authenticate_mgmt_rejects_malformed_templates(card):
    # Neither a witness tag nor a challenge tag present.
    body = bytes([0x7C, 0x02, 0x83, 0x00])
    assert card.apdu(bytes([0x00, 0x87, 0x0A, 0x9B, len(body)]) + body)[0] == SW_WRONG_DATA


# --- SET MANAGEMENT KEY ----------------------------------------------------


def test_set_management_key_requires_prior_authentication(card):
    new_key = bytes(range(24))
    assert card.set_management_key(new_key) == SW_SECURITY
    assert card.mgmt_key_is_default


def test_set_management_key_changes_the_key(card):
    new_key = bytes(range(24))
    assert card.authenticate_management_key() == SW_OK
    assert card.set_management_key(new_key) == SW_OK
    assert card.mgmt_key == new_key
    assert not card.mgmt_key_is_default

    # The *old* key no longer authenticates...
    card.select()
    assert card.authenticate_management_key(key=bytes((i * 7 + 3) & 0xFF for i in range(24))) == SW_SECURITY
    # ...but the new one does.
    assert card.authenticate_management_key(key=new_key) == SW_OK


def test_set_management_key_requires_fresh_authentication_each_time(card):
    """Changing the key invalidates *this* session's authentication too —
    a second SET MANAGEMENT KEY right after the first must not ride the
    same handshake."""
    new_key = bytes(range(24))
    assert card.authenticate_management_key() == SW_OK
    assert card.set_management_key(new_key) == SW_OK
    assert card.set_management_key(bytes(range(24, 48))) == SW_SECURITY


@pytest.mark.parametrize("p1,p2", [(0x00, 0xFF), (0xFF, 0x00), (0x00, 0x00)])
def test_set_management_key_rejects_wrong_p1p2(card, p1, p2):
    card.authenticate_management_key()
    body = bytes([0x0A, 24]) + bytes(range(24))
    assert card.apdu(bytes([0x00, 0xFF, p1, p2, len(body)]) + body)[0] == SW_WRONG_P1P2


def test_set_management_key_rejects_wrong_algorithm_or_length(card):
    card.authenticate_management_key()
    # Right length, wrong algorithm id.
    body = bytes([0x03, 24]) + bytes(range(24))
    assert card.apdu(bytes([0x00, 0xFF, 0xFF, 0xFF, len(body)]) + body)[0] == SW_WRONG_DATA
    # Right algorithm, wrong length (16 bytes — an AES-128 length, which
    # this applet does not support).
    card.authenticate_management_key()
    body = bytes([0x0A, 16]) + bytes(range(16))
    assert card.apdu(bytes([0x00, 0xFF, 0xFF, 0xFF, len(body)]) + body)[0] == SW_WRONG_DATA


# --- SET PIN RETRIES --------------------------------------------------------


def test_set_pin_retries_requires_pin_and_mgmt_auth(card):
    assert card.set_pin_retries(5, 5) == SW_SECURITY
    card.verify()
    assert card.set_pin_retries(5, 5) == SW_SECURITY, "mgmt auth alone is not enough"


def test_set_pin_retries_resets_both_secrets_and_ceilings(card):
    card.verify()
    assert card.authenticate_management_key() == SW_OK
    assert card.set_pin_retries(5, 7) == SW_OK

    assert card.pin_max == 5
    assert card.puk_max == 7
    assert card.pin == CORRECT_PIN
    assert card.puk == DEFAULT_PUK
    assert card.retries == 5
    assert card.puk_retries == 7
    # Successful verification now restores to the *new* ceiling, not the
    # compile-time default of 3.
    card.verify(b"000000")
    assert card.verify() == SW_OK
    assert card.retries == 5


@pytest.mark.parametrize("pin_max,puk_max", [(0, 3), (3, 0), (16, 3), (3, 16)])
def test_set_pin_retries_rejects_ceilings_outside_one_to_fifteen(card, pin_max, puk_max):
    card.verify()
    card.authenticate_management_key()
    assert card.set_pin_retries(pin_max, puk_max) == SW_WRONG_P1P2


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


# --- CCC and CHUID --------------------------------------------------------

OBJ_CHUID = 0x5FC102
OBJ_CCC = 0x5FC107


def tlv_parse(buf: bytes) -> dict[int, bytes]:
    """Flat one-byte-length TLV walk, the way a host reads these objects."""
    out, i = {}, 0
    while i + 1 < len(buf):
        tag, n = buf[i], buf[i + 1]
        assert i + 2 + n <= len(buf), f"TLV overruns at {i}: {buf.hex()}"
        out[tag] = buf[i + 2 : i + 2 + n]
        i += 2 + n
    assert i == len(buf), f"trailing bytes in TLV: {buf.hex()}"
    return out


def test_chuid_is_synthesised_when_absent(card):
    """A host that finds no CHUID concludes there is no card worth talking to,
    so login never starts however good the rest of the applet is."""
    sw, body = card.get_data(OBJ_CHUID)
    assert sw == SW_OK
    assert body[0] == 0x53, "must be wrapped in a 0x53 container"
    assert body[1] == len(body) - 2, "container length disagrees with its body"

    f = tlv_parse(body[2:])
    assert len(f[0x30]) == 25, "FASC-N must be 25 bytes"
    assert f[0x34] == card.guid, "GUID must be the device's"
    assert len(f[0x35]) == 8 and f[0x35].isdigit(), "expiry is 8 ASCII digits"
    assert 0x3E in f, "issuer signature field must be present, even if empty"
    assert 0xFE in f, "error detection code field must be present"


def test_ccc_is_synthesised_when_absent(card):
    sw, body = card.get_data(OBJ_CCC)
    assert sw == SW_OK
    assert body[0] == 0x53
    assert body[1] == len(body) - 2

    f = tlv_parse(body[2:])
    assert len(f[0xF0]) == 21, "card identifier must be 21 bytes"
    assert f[0xF0][:5] == bytes([0xA0, 0x00, 0x00, 0x01, 0x16]), "GSC-RID"
    assert f[0xF1] == b"\x21" and f[0xF2] == b"\x21", "version bytes"
    for tag in (0xF6, 0xF7, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE):
        assert tag in f, f"container {tag:#x} must be present even when empty"


def test_ccc_and_chuid_agree_on_identity(card):
    """Two objects describing the same card must not disagree about which
    card it is."""
    _, chuid = card.get_data(OBJ_CHUID)
    _, ccc = card.get_data(OBJ_CCC)
    guid = tlv_parse(chuid[2:])[0x34]
    card_id = tlv_parse(ccc[2:])[0xF0]
    assert card_id[6:] == guid[: len(card_id) - 6]


def test_identity_objects_are_stable_across_reads(card):
    """A card whose identity changes between reads is not a card."""
    assert card.get_data(OBJ_CHUID)[1] == card.get_data(OBJ_CHUID)[1]
    assert card.get_data(OBJ_CCC)[1] == card.get_data(OBJ_CCC)[1]


def test_two_devices_get_different_identities(card):
    """Hosts key their record of a card on the GUID, so two tokens sharing one
    would look like the same card.

    (The applet holds a single global HAL, so this swaps the GUID under one
    card rather than building two — an earlier version of this test built two
    Cards and silently read the same GUID twice.)
    """
    _, first = card.get_data(OBJ_CHUID)
    card.guid = bytes(range(0x80, 0x90))
    _, second = card.get_data(OBJ_CHUID)
    assert first != second, "distinct GUIDs must yield distinct CHUIDs"
    assert tlv_parse(second[2:])[0x34] == card.guid


def test_a_stored_object_overrides_the_synthesised_one(card):
    """Provisioning a real CHUID must win over the placeholder."""
    real = b"\x53\x03\x01\x02\x03"
    card.objects[OBJ_CHUID] = real
    assert card.get_data(OBJ_CHUID)[1] == real


def test_synthesis_needs_a_guid(lib):
    card = Card(lib)
    card.guid = b""  # HAL reports no identity
    assert card.get_data(OBJ_CHUID)[0] == SW_NOT_FOUND
    assert card.get_data(OBJ_CCC)[0] == SW_NOT_FOUND


def test_only_ccc_and_chuid_are_synthesised(card):
    """Certificates must never be invented — an empty one would look like a
    provisioned card that simply cannot authenticate."""
    for tag in (OBJ_CERT_9A, 0x5FC10A, 0x5FC101):
        assert card.get_data(tag)[0] == SW_NOT_FOUND, f"{tag:#x} was synthesised"


# --- Command chaining -----------------------------------------------------


def chained_put(card, tag: int, container: bytes, block: int = 200):
    """PUT DATA split across a command chain, the way a real client writes a
    certificate too large for one short APDU."""
    tl = bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
    body = bytes([0x5C, len(tl)]) + tl + container
    sws = []
    for i in range(0, len(body), block):
        chunk = body[i : i + block]
        last = i + block >= len(body)
        cla = 0x00 if last else 0x10
        sws.append(card.apdu(bytes([cla, 0xDB, 0x3F, 0xFF, len(chunk)]) + chunk)[0])
    return sws


def test_certificate_sized_object_needs_chaining(card):
    """The blocker this exists for: a 700-byte certificate needs a 716-byte
    PUT DATA body, and Lc stops at 255. Without chaining a certificate cannot
    be written at all, so the applet could never be provisioned."""
    cert = bytes((i * 7) & 0xFF for i in range(700))
    inner = bytes([0x70]) + ber_len(len(cert)) + cert + b"\x71\x01\x00\xfe\x00"
    container = bytes([0x53]) + ber_len(len(inner)) + inner
    assert len(container) > 255, "test data no longer exercises chaining"

    card.verify()
    sws = chained_put(card, OBJ_CERT_9A, container)
    assert all(sw == SW_OK for sw in sws), sws
    assert len(sws) > 1, "expected a multi-block chain"

    sw, got = card.get_data(OBJ_CERT_9A)
    assert sw == SW_OK
    assert got == container, "chained write did not round trip"


def test_chain_blocks_are_acknowledged_without_acting(card):
    card.verify()
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03AB"
    assert card.apdu(bytes([0x10, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    assert card.objects == {}, "a non-final block must not be acted on"
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, 0x01]) + b"C")[0] == SW_OK
    assert card.objects[OBJ_CERT_9A] == b"\x53\x03ABC"


def test_a_chain_that_changes_command_is_abandoned(card):
    """Blocks that are not one command must not be stitched together."""
    card.verify()
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03AB"
    assert card.apdu(bytes([0x10, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    # different INS mid-chain
    assert card.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x01]) + b"C")[0] == SW_WRONG_DATA
    assert card.objects == {}
    # and the chain is gone, not merely paused
    assert card.apdu(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05,
                            0x5C, 0x03, 0x5F, 0xC1, 0x05]))[0] == SW_NOT_FOUND


def test_an_oversize_chain_is_refused(card):
    card.verify()
    blk = bytes(255)
    sw = SW_OK
    for _ in range(12):  # 12 * 255 > PIV_MAX_CHAIN (2048)
        sw = card.apdu(bytes([0x10, 0xDB, 0x3F, 0xFF, 0xFF]) + blk)[0]
        if sw != SW_OK:
            break
    assert sw == SW_WRONG_LENGTH, "chain buffer must be bounded"


def test_any_other_command_mid_chain_is_refused_then_recovers(card):
    """Interrupting a chain is refused and abandons it — the same fail-closed
    shape as an init fragment mid-transaction on the BLE side. It does not
    wedge: the interrupting command works on its second attempt."""
    card.verify()
    body = b"\x5c\x03\x5f\xc1\x05\x53\x03AB"
    assert card.apdu(bytes([0x10, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK

    # SELECT arrives mid-chain: refused, chain abandoned.
    assert card.select()[0] == SW_WRONG_DATA
    # Retry succeeds, and the reset it performs clears the PIN.
    assert card.select()[0] == SW_OK
    assert not card.lib.piv_pin_is_verified()

    # The abandoned block is gone rather than waiting to be completed.
    assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, 0x01]) + b"C")[0] == SW_SECURITY
    assert card.objects == {}


# --- RESET APPLICATION ------------------------------------------------------
#
# Vendor INS 0xFB: a full factory reset, gated on a verified PIN this session
# and nothing else. SP 800-73 defines neither the instruction nor the gate;
# VERIFY-then-reset is the same bar GENERATE ASYMMETRIC KEY PAIR already
# accepts for an operation that likewise destroys certificates already
# issued. Physical possession alone is never enough — a thief who does not
# know the PIN cannot wipe the device and install their own keys just by
# holding it.
#
# Earlier drafts of this instruction (see NOTES.md, "PIV factory reset" and
# the two entries after it) also accepted a PIN-free lockout-recovery path —
# both the PIN and PUK retry counters already at zero — so an owner who had
# lost both secrets was not permanently locked out. That path was removed at
# the device owner's explicit direction: reaching "both blocked" needs no
# knowledge of either secret, only physical possession and a few deliberate
# wrong guesses, which made the lockout-recovery path reachable by anyone
# holding the device, not just its legitimate owner. The accepted cost,
# flagged there and pinned down by tests here: forgetting the PIN *and* the
# PUK now has no way back into this device at all.


def _block_pin(card: Card) -> None:
    for _ in range(card.pin_max):
        card.verify(b"000000")
    assert card.retries == 0, "sanity: PIN really is blocked"


def _block_puk(card: Card) -> None:
    for _ in range(card.puk_max):
        card.change_puk(b"00000000", b"11111111")
    assert card.puk_retries == 0, "sanity: PUK really is blocked"


def test_reset_application_rejects_other_p1p2_regardless_of_pin_state(card):
    """The P1/P2 check must not depend on whether a reset would otherwise be
    allowed — a card with a freshly-verified PIN still rejects a malformed
    request rather than reporting the (also true) success path."""
    card.verify()
    assert card.apdu(bytes([0x00, 0xFB, 0x01, 0x00]))[0] == SW_WRONG_P1P2
    assert card.apdu(bytes([0x00, 0xFB, 0x00, 0x01]))[0] == SW_WRONG_P1P2


def test_reset_application_rejects_a_data_field(card):
    """ISO case 1: no data field. SP 800-73 gives this instruction no syntax
    of its own to be lenient about."""
    assert card.apdu(bytes([0x00, 0xFB, 0x00, 0x00, 0x01, 0xAA]))[0] == SW_WRONG_LENGTH


def test_reset_application_rejects_an_unverified_pin(card):
    """A fresh card: the PIN has not been verified this session. Physical
    possession alone must never be enough."""
    assert card.reset_application() == SW_SECURITY


def test_reset_application_has_no_lockout_recovery_path(card):
    """The behaviour change this test exists to pin down: exhausting both
    retry counters — reachable by anyone holding the device, with no
    knowledge of either secret — must not open a PIN-free way to reset.
    There is deliberately no recovery once both are gone."""
    _block_pin(card)
    _block_puk(card)
    assert card.retries == 0
    assert card.puk_retries == 0
    assert card.reset_application() == SW_SECURITY


def test_reset_application_succeeds_with_a_verified_pin(card):
    """The only path: VERIFY with the correct PIN, then reset — regardless
    of the PUK's own state, which this instruction never looks at."""
    assert card.verify() == SW_OK
    assert card.puk_retries == 3  # never touched by the gate
    assert card.reset_application() == SW_OK


def test_reset_application_needs_current_verification_not_history(card):
    """A PIN verified earlier and then un-verified by a later wrong attempt
    must not leave a stale "was verified at some point" credential behind —
    the same session-scoped lifetime _pin_verified already has everywhere
    else (SELECT, a wrong PIN, etc.)."""
    assert card.verify() == SW_OK
    assert card.verify(b"999999") == PIV_SW_VERIFY_FAILED(2)  # clears it again
    assert card.reset_application() == SW_SECURITY


def test_reset_application_restores_compile_time_ceilings_not_a_custom_one(card):
    """A ceiling raised by SET PIN RETRIES must not survive a factory reset —
    "factory" means the compile-time default (3), not whatever an operator
    last configured."""
    card.verify()
    assert card.authenticate_management_key() == SW_OK
    assert card.set_pin_retries(5, 7) == SW_OK
    assert card.pin_max == 5
    assert card.puk_max == 7

    assert card.verify() == SW_OK  # SET PIN RETRIES reset the PIN and cleared verification
    assert card.reset_application() == SW_OK
    assert card.pin_max == 3
    assert card.puk_max == 3
    assert card.retries == 3
    assert card.puk_retries == 3


def test_reset_application_wipes_every_stored_object(card):
    card.verify()
    for tag in (OBJ_CERT_9A, OBJ_CERT_9C, OBJ_CERT_9D, OBJ_CERT_9E, OBJ_CHUID, OBJ_CCC):
        body = bytes([0x5C, 0x03, (tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF,
                      0x53, 0x02, 0xAA, 0xBB])
        assert card.apdu(bytes([0x00, 0xDB, 0x3F, 0xFF, len(body)]) + body)[0] == SW_OK
    assert len(card.objects) == 6

    assert card.reset_application() == SW_OK

    assert card.objects == {}
    for tag in (OBJ_CERT_9A, OBJ_CERT_9C, OBJ_CERT_9D, OBJ_CERT_9E, OBJ_CHUID, OBJ_CCC):
        assert tag in card.deleted


def test_reset_application_rolls_every_slot_key(card):
    before = {slot: card.generation.get(slot, 0)
              for slot in (SLOT_9A, SLOT_9C, SLOT_9D, SLOT_9E)}

    card.verify()
    assert card.reset_application() == SW_OK

    for slot in (SLOT_9A, SLOT_9C, SLOT_9D, SLOT_9E):
        assert card.generation.get(slot, 0) == before[slot] + 1, hex(slot)


def test_reset_application_replaces_the_management_key_with_a_new_random_default(card):
    old_key = bytes(range(24))
    assert card.authenticate_management_key() == SW_OK
    assert card.set_management_key(old_key) == SW_OK
    assert not card.mgmt_key_is_default

    assert card.verify() == SW_OK
    assert card.reset_application() == SW_OK

    assert card.mgmt_key_is_default
    assert card.mgmt_key != old_key
    assert card.mgmt_key_reset_calls == 1
    # The old, owner-rotated key must no longer authenticate — a factory
    # reset that merely re-labelled it "default" without changing its bytes
    # would leave it fully operative, which is not a reset at all.
    card.select()
    assert card.authenticate_management_key(key=old_key) == SW_SECURITY


def test_reset_application_clears_session_state(card):
    """_mgmt_authenticated (and _pin_verified) must not survive a reset any
    more than they survive piv_reset() for any other reason — an admin
    command right after must re-authenticate against whatever key the reset
    just installed, not ride the pre-reset session."""
    assert card.authenticate_management_key() == SW_OK
    assert card.verify() == SW_OK
    assert card.reset_application() == SW_OK

    assert not card.lib.piv_pin_is_verified()
    assert card.set_management_key(bytes(range(24))) == SW_SECURITY


def test_reset_application_unsupported_without_the_hook(lib):
    """The HAL-support check must fire before the PIN gate is even
    consulted — a build missing the one new hook answers INS_UNSUPPORTED
    regardless of PIN state, verified or not."""
    card = Card(lib, with_mgmt_reset_hook=False)
    assert card.reset_application() == SW_INS_UNSUPPORTED
    card.verify()
    assert card.reset_application() == SW_INS_UNSUPPORTED
