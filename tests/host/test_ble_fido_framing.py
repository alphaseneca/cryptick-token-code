"""Drive the real FIDO BLE framing state machine in core/ble_fido/ble_fido.c.

FIDO BLE is not CTAPHID over BLE: no channel IDs, a 3-byte init header
(CMD | HLEN big-endian) and a 1-byte continuation header (SEQ). The file is
freestanding C, so these tests compile it and feed it fragments through
ctypes rather than re-implementing the framing in Python.

The bounds cases matter more than the happy path. HLEN is 16-bit, so a peer
can declare 65535 bytes; a continuation with no payload lets a peer stall the
transport forever. Half-flashed firmware and interrupted OTAs produce exactly
this class of malformed-but-authenticated input.
"""
from __future__ import annotations

import ctypes

import pytest

from support.native import build_shared_lib

# Mirrors core/ble_fido/ble_fido.h.
CMD_PING = 0x81
CMD_KEEPALIVE = 0x82
CMD_MSG = 0x83
CMD_CANCEL = 0xBE
CMD_ERROR = 0xBF

ERR_NONE = 0x00
ERR_INVALID_CMD = 0x01
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_BUSY = 0x06  # a real BLE code; only 0x0a/0x0b are HID-reserved

MAX_MSG = 1200
MIN_CP_LEN = 20
MAX_CP_LEN = 512

NOTIFY_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16)
DELIVER_FN = ctypes.CFUNCTYPE(
    None, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16
)


class Transport:
    """The C library plus the two callbacks it notifies and delivers through."""

    def __init__(self, lib):
        self.lib = lib
        self.notified: list[bytes] = []
        self.delivered: list[tuple[int, bytes]] = []
        self.notify_ok = True

        def _notify(buf, n):
            self.notified.append(bytes(buf[:n]))
            return 1 if self.notify_ok else 0

        def _deliver(cmd, buf, n):
            payload = b"" if not buf else bytes(buf[:n])
            self.delivered.append((cmd, payload))

        # Keep references alive; ctypes will not.
        self._notify_cb = NOTIFY_FN(_notify)
        self._deliver_cb = DELIVER_FN(_deliver)
        lib.ble_fido_set_notify(self._notify_cb)
        lib.ble_fido_set_deliver(self._deliver_cb)
        lib.ble_fido_reset()

    def rx(self, frag: bytes) -> int:
        buf = (ctypes.c_uint8 * max(len(frag), 1))(*frag)
        return self.lib.ble_fido_rx_fragment(buf, len(frag))

    def set_mtu(self, mtu: int) -> None:
        self.lib.ble_fido_set_mtu(mtu)

    @property
    def cp_len(self) -> int:
        return self.lib.ble_fido_control_point_length()

    @property
    def receiving(self) -> bool:
        return bool(self.lib.ble_fido_is_receiving())

    def send_response(self, cmd: int, data: bytes) -> int:
        buf = (ctypes.c_uint8 * max(len(data), 1))(*data)
        return self.lib.ble_fido_send_response(cmd, buf, len(data))

    @property
    def errors(self) -> list[int]:
        """Error codes carried by CMD_ERROR notifications."""
        return [f[3] for f in self.notified if f and f[0] == CMD_ERROR and len(f) == 4]


@pytest.fixture(scope="module")
def lib(tmp_path_factory):
    lib = build_shared_lib(
        ["core/ble_fido/ble_fido.c"], tmp_path_factory.mktemp("ble"), name="libblefido"
    )
    lib.ble_fido_rx_fragment.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16]
    lib.ble_fido_rx_fragment.restype = ctypes.c_uint8
    lib.ble_fido_set_mtu.argtypes = [ctypes.c_uint16]
    lib.ble_fido_control_point_length.restype = ctypes.c_uint16
    lib.ble_fido_is_receiving.restype = ctypes.c_int
    lib.ble_fido_send_response.argtypes = [
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint16,
    ]
    lib.ble_fido_send_response.restype = ctypes.c_int
    lib.ble_fido_send_keepalive.argtypes = [ctypes.c_uint8]
    lib.ble_fido_send_keepalive.restype = ctypes.c_int
    lib.ble_fido_set_notify.argtypes = [NOTIFY_FN]
    lib.ble_fido_set_deliver.argtypes = [DELIVER_FN]
    return lib


@pytest.fixture
def t(lib):
    tr = Transport(lib)
    tr.set_mtu(512 + 3)  # a roomy control point unless a test says otherwise
    return tr


def init_frag(cmd: int, total: int, data: bytes = b"") -> bytes:
    return bytes([cmd, (total >> 8) & 0xFF, total & 0xFF]) + data


def cont_frag(seq: int, data: bytes) -> bytes:
    return bytes([seq & 0x7F]) + data


# --- fidoControlPointLength ----------------------------------------------


def test_control_point_length_is_conservative_before_mtu_exchange(lib):
    tr = Transport(lib)
    assert tr.cp_len == MIN_CP_LEN


@pytest.mark.parametrize(
    "mtu,expected",
    [
        (23, 20),          # the BLE default MTU, exactly the floor
        (100, 97),         # ATT_MTU - 3
        (247, 244),
        (515, 512),        # clamped at the ceiling
        (2000, 512),
        (10, 20),          # nonsense MTU still yields a legal length
    ],
)
def test_control_point_length_tracks_att_mtu(t, mtu, expected):
    t.set_mtu(mtu)
    assert t.cp_len == expected
    assert MIN_CP_LEN <= t.cp_len <= MAX_CP_LEN


# --- Happy path -----------------------------------------------------------


def test_single_fragment_msg_is_delivered(t):
    payload = bytes(range(10))
    assert t.rx(init_frag(CMD_MSG, len(payload), payload)) == ERR_NONE
    assert t.delivered == [(CMD_MSG, payload)]
    assert not t.receiving


def test_message_spanning_continuations_is_reassembled(t):
    t.set_mtu(23)  # 20-byte control point: 17 init bytes, 19 per continuation
    payload = bytes((i * 7) & 0xFF for i in range(200))
    assert t.rx(init_frag(CMD_MSG, len(payload), payload[:17])) == ERR_NONE
    assert t.receiving

    off, seq = 17, 0
    while off < len(payload):
        chunk = payload[off : off + 19]
        assert t.rx(cont_frag(seq, chunk)) == ERR_NONE
        off += len(chunk)
        seq += 1

    assert t.delivered == [(CMD_MSG, payload)]
    assert not t.receiving


def test_longest_possible_message_at_the_smallest_fragment_size(t):
    """The worst case the device can be asked to reassemble.

    Note this does *not* exercise the SEQ wrap: 1200 bytes at a 20-byte
    fragment size is 17 + 63x19, so SEQ tops out at 62 and never reaches 0x7f.
    The wrap is unreachable behind CTAP_MAX_MESSAGE_SIZE and is pinned on the
    host side of the shared corpus instead — see tests/conformance/.
    """
    t.set_mtu(23)
    payload = bytes((i * 3) & 0xFF for i in range(MAX_MSG))
    assert t.rx(init_frag(CMD_MSG, len(payload), payload[:17])) == ERR_NONE

    off, seq = 17, 0
    while off < len(payload):
        chunk = payload[off : off + 19]
        assert t.rx(cont_frag(seq, chunk)) == ERR_NONE, f"failed at seq {seq}"
        off += len(chunk)
        seq += 1
    assert seq == 63, "fragment arithmetic changed; re-check the wrap argument"
    assert t.delivered == [(CMD_MSG, payload)]


def test_sequence_arithmetic_wraps_correctly_in_the_sender(t):
    """The transmit path must wrap SEQ, even though the receive path cannot
    reach the wrap against this device's ceiling. Responses are not bounded by
    CTAP_MAX_MESSAGE_SIZE, so this one is reachable."""
    t.set_mtu(23)
    body = bytes((i * 13) & 0xFF for i in range(19 * 200))
    assert t.send_response(CMD_MSG, body) == 1

    seqs = [f[0] for f in t.notified[1:]]
    assert len(seqs) > 0x7F, "response too short to reach the wrap"
    assert seqs[:3] == [0, 1, 2]
    assert seqs[0x7F] == 0x7F
    assert seqs[0x80] == 0x00, "SEQ must wrap 0x7f -> 0x00, not overflow to 0x80"


def test_empty_message_is_delivered_immediately(t):
    assert t.rx(init_frag(CMD_MSG, 0)) == ERR_NONE
    assert t.delivered == [(CMD_MSG, b"")]


def test_max_size_message_is_accepted(t):
    payload = bytes(MAX_MSG)
    t.set_mtu(MAX_CP_LEN + 3)
    assert t.rx(init_frag(CMD_MSG, MAX_MSG, payload[: MAX_CP_LEN - 3])) == ERR_NONE
    off, seq = MAX_CP_LEN - 3, 0
    while off < MAX_MSG:
        chunk = payload[off : off + (MAX_CP_LEN - 1)]
        assert t.rx(cont_frag(seq, chunk)) == ERR_NONE
        off += len(chunk)
        seq = (seq + 1) & 0x7F
    assert t.delivered == [(CMD_MSG, payload)]


# --- PING and CANCEL ------------------------------------------------------


def test_ping_is_echoed_and_never_reaches_the_ctap_core(t):
    payload = b"cryptick"
    assert t.rx(init_frag(CMD_PING, len(payload), payload)) == ERR_NONE
    assert t.delivered == []
    assert t.notified == [init_frag(CMD_PING, len(payload), payload)]


def test_cancel_from_idle_is_delivered(t):
    """The normal case: CANCEL arrives while the device is processing a
    request that has already been fully reassembled."""
    assert t.rx(init_frag(CMD_CANCEL, 0)) == ERR_NONE
    assert t.delivered == [(CMD_CANCEL, b"")]
    assert not t.receiving


def test_cancel_mid_reassembly_abandons_and_stays_silent(t):
    """CTAP2 §11.4.8 — "the authenticator MUST NOT reply to the cancel message
    itself." So CANCEL is the one command allowed to interrupt a message in
    flight, and it emits nothing at all.

    This file previously asserted the opposite (ERR_INVALID_SEQ), matching the
    daemon, which was also wrong. Agreeing with the other implementation is not
    evidence — neither of us had read 11.4.8.
    """
    t.set_mtu(23)
    assert t.rx(init_frag(CMD_MSG, 100, bytes(17))) == ERR_NONE
    assert t.receiving
    assert t.rx(init_frag(CMD_CANCEL, 0)) == ERR_NONE
    assert not t.receiving
    assert t.delivered == [(CMD_CANCEL, b"")]
    assert t.notified == [], "MUST NOT reply to a cancel"


def test_cancel_never_emits_however_malformed(t):
    """There is no legal way to report a bad cancel, so rejecting one is
    unimplementable rather than strict. Every shape stays silent."""
    t.set_mtu(23)
    for frag in (
        init_frag(CMD_CANCEL, 0),
        init_frag(CMD_CANCEL, 500, b"junk"),   # payload ignored, not validated
        bytes([CMD_CANCEL]),                    # truncated before HLEN
        bytes([CMD_CANCEL, 0x00]),
        bytes([CMD_CANCEL, 0, 0]) + bytes(40),  # longer than the control point
    ):
        t.notified.clear()
        t.delivered.clear()
        assert t.rx(frag) == ERR_NONE, frag.hex()
        assert t.notified == [], f"replied to a cancel: {frag.hex()}"
        assert t.delivered == [(CMD_CANCEL, b"")], frag.hex()


def test_transport_recovers_after_a_cancel(t):
    """Silence must not mean stuck. (The shared corpus keeps one delivery per
    vector, so this two-delivery case lives here.)"""
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(init_frag(CMD_CANCEL, 0)) == ERR_NONE
    payload = b"\x01\x02"
    assert t.rx(init_frag(CMD_MSG, len(payload), payload)) == ERR_NONE
    assert t.delivered == [(CMD_CANCEL, b""), (CMD_MSG, payload)]


def test_a_continuation_after_a_cancel_has_nothing_to_continue(t):
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    t.rx(init_frag(CMD_CANCEL, 0))
    assert t.rx(cont_frag(0, bytes(19))) == ERR_INVALID_SEQ


# --- Adversarial: bounds and framing --------------------------------------


def test_declared_length_above_the_ceiling_is_refused_before_allocating(t):
    """HLEN is 16-bit; 65535 must not be allocated."""
    assert t.rx(init_frag(CMD_MSG, 0xFFFF, b"\x00")) == ERR_INVALID_LEN
    assert not t.receiving
    assert t.errors == [ERR_INVALID_LEN]


@pytest.mark.parametrize("hlen", [MAX_MSG + 1, 2000, 0xFFFF])
def test_oversize_declared_length_is_refused(t, hlen):
    assert t.rx(init_frag(CMD_MSG, hlen)) == ERR_INVALID_LEN


def test_init_fragment_carrying_more_than_it_declared_is_refused(t):
    assert t.rx(init_frag(CMD_MSG, 2, b"\x01\x02\x03\x04")) == ERR_INVALID_LEN


def test_continuation_without_an_active_transaction_is_a_sequence_error(t):
    assert t.rx(cont_frag(0, b"\x01\x02")) == ERR_INVALID_SEQ
    assert t.errors == [ERR_INVALID_SEQ]


@pytest.mark.parametrize("bad_seq", [1, 2, 0x7F])
def test_first_continuation_must_be_sequence_zero(t, bad_seq):
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(cont_frag(bad_seq, bytes(19))) == ERR_INVALID_SEQ
    assert not t.receiving


def test_out_of_order_continuation_is_refused(t):
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(cont_frag(0, bytes(19))) == ERR_NONE
    assert t.rx(cont_frag(2, bytes(19))) == ERR_INVALID_SEQ  # skipped 1
    assert not t.receiving


def test_replayed_continuation_is_refused(t):
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(cont_frag(0, bytes(19))) == ERR_NONE
    assert t.rx(cont_frag(0, bytes(19))) == ERR_INVALID_SEQ


def test_empty_continuation_cannot_stall_the_transport(t):
    """A zero-data continuation makes no progress; allowing it lets a peer
    hold the reassembly buffer open indefinitely."""
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(cont_frag(0, b"")) == ERR_INVALID_LEN
    assert not t.receiving


def test_continuations_exceeding_the_declared_length_are_refused(t):
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 30, bytes(17)))
    # 17 + 19 = 36 > 30
    assert t.rx(cont_frag(0, bytes(19))) == ERR_INVALID_LEN
    assert not t.receiving


def test_fragment_larger_than_the_published_control_point_is_refused(t):
    """We must never accept more than fidoControlPointLength says we will."""
    t.set_mtu(23)  # publishes 20
    assert t.rx(init_frag(CMD_MSG, 100, bytes(30))) == ERR_INVALID_LEN


def test_empty_fragment_is_refused(t):
    assert t.rx(b"") == ERR_INVALID_LEN


def test_init_fragment_shorter_than_its_header_is_refused(t):
    assert t.rx(bytes([CMD_MSG])) == ERR_INVALID_LEN
    assert t.rx(bytes([CMD_MSG, 0x00])) == ERR_INVALID_LEN


@pytest.mark.parametrize("cmd", [0x80, 0x84, 0xA0, 0xBF, 0xFF])
def test_unknown_commands_are_refused(t, cmd):
    assert t.rx(init_frag(cmd, 0)) == ERR_INVALID_CMD
    assert t.errors == [ERR_INVALID_CMD]


def test_init_mid_transaction_is_a_protocol_violation(t):
    """This transport has no channels, so an init fragment arriving
    mid-transaction is a violation, not a second conversation."""
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.receiving
    assert t.rx(init_frag(CMD_MSG, 5, b"retry")) == ERR_INVALID_SEQ
    assert t.delivered == []


def test_a_host_retry_succeeds_on_its_next_attempt(t):
    """Failing closed must not wedge the transport: the abort leaves the
    reassembler idle, so the retry after the error goes through."""
    t.set_mtu(23)
    t.rx(init_frag(CMD_MSG, 100, bytes(17)))
    assert t.rx(init_frag(CMD_MSG, 5, b"retry")) == ERR_INVALID_SEQ
    assert not t.receiving
    payload = b"retry"
    assert t.rx(init_frag(CMD_MSG, len(payload), payload)) == ERR_NONE
    assert t.delivered == [(CMD_MSG, payload)]


def test_error_resets_state_so_the_next_transaction_succeeds(t):
    assert t.rx(cont_frag(0, b"junk")) == ERR_INVALID_SEQ
    payload = b"ok now"
    assert t.rx(init_frag(CMD_MSG, len(payload), payload)) == ERR_NONE
    assert t.delivered == [(CMD_MSG, payload)]


# --- Outbound fragmentation ------------------------------------------------


def test_keepalive_is_a_single_one_byte_notification(t):
    assert t.lib.ble_fido_send_keepalive(0x02) == 1
    assert t.notified == [bytes([CMD_KEEPALIVE, 0x00, 0x01, 0x02])]


def test_short_response_is_one_fragment(t):
    body = b"\x00\xa1\x01"
    assert t.send_response(CMD_MSG, body) == 1
    assert t.notified == [init_frag(CMD_MSG, len(body), body)]


def test_long_response_is_fragmented_within_the_published_length(t):
    t.set_mtu(23)  # 20-byte control point
    body = bytes((i * 5) & 0xFF for i in range(300))
    assert t.send_response(CMD_MSG, body) == 1

    assert all(len(f) <= MIN_CP_LEN for f in t.notified), "fragment exceeded cp_len"

    head = t.notified[0]
    assert head[0] == CMD_MSG
    assert (head[1] << 8) | head[2] == len(body)

    rebuilt = head[3:]
    for i, frag in enumerate(t.notified[1:]):
        assert frag[0] == (i & 0x7F), "continuation SEQ out of order"
        rebuilt += frag[1:]
    assert rebuilt == body


def test_response_round_trips_through_the_receiver(t):
    """What we emit must be what we can parse: fragment a response, then feed
    those fragments back in as if they had arrived from a peer."""
    t.set_mtu(23)
    body = bytes((i * 11) & 0xFF for i in range(500))
    assert t.send_response(CMD_MSG, body) == 1
    fragments = list(t.notified)

    t.notified.clear()
    for frag in fragments:
        assert t.rx(frag) == ERR_NONE
    assert t.delivered == [(CMD_MSG, body)]


def test_send_reports_failure_when_the_link_drops_mid_response(t):
    t.set_mtu(23)
    t.notify_ok = False
    assert t.send_response(CMD_MSG, bytes(300)) == 0
