"""Two GATT services sharing one framing implementation must not share state.

PIV over BLE reuses this framing byte for byte on its own service. That is
only safe if a context is genuinely self-contained: a fragment written to one
service must not advance, corrupt or abort a message being assembled on the
other, and neither peer would have any way to notice if it did.

The refactor that made this possible is behaviour-preserving for the FIDO path
-- the conformance corpus and the framing suite both pass unchanged against it
-- so what is left to prove is the part those suites cannot see, which is that
a second context exists and is independent.
"""
from __future__ import annotations

import ctypes

import pytest

from support.native import build_shared_lib
from test_ble_fido_framing import (
    CMD_ERROR,
    CMD_MSG,
    CMD_PING,
    ERR_INVALID_CMD,
    ERR_INVALID_LEN,
    ERR_NONE,
    NOTIFY_FN,
    DELIVER_FN,
)

CTX_NO_PING = 0x01

# Caps from docs: CTAP messages reach 1200 bytes, the PIV service is capped at
# 261 -- one extended-length APDU header plus a 255-byte body.
FIDO_CAP = 1200
PIV_CAP = 261


class Ctx:
    """One ble_fido_ctx_t, its buffer, and the callbacks it drives."""

    def __init__(self, lib, cap: int, flags: int = 0, cp_len: int = 512):
        self.lib = lib
        self.notified: list[bytes] = []
        self.delivered: list[tuple[int, bytes]] = []

        self._raw = ctypes.create_string_buffer(256)  # >= sizeof(ble_fido_ctx_t)
        self._buf = (ctypes.c_uint8 * cap)()

        def _notify(buf, n):
            self.notified.append(bytes(buf[:n]))
            return 1

        def _deliver(cmd, buf, n):
            self.delivered.append((cmd, b"" if not buf else bytes(buf[:n])))

        self._notify_cb = NOTIFY_FN(_notify)
        self._deliver_cb = DELIVER_FN(_deliver)

        lib.ble_fido_ctx_init(self._raw, self._buf, cap, flags)
        lib.ble_fido_ctx_set_notify(self._raw, self._notify_cb)
        lib.ble_fido_ctx_set_deliver(self._raw, self._deliver_cb)
        lib.ble_fido_ctx_set_mtu(self._raw, cp_len + 3)

    def rx(self, frag: bytes) -> int:
        buf = (ctypes.c_uint8 * max(len(frag), 1))(*frag)
        return self.lib.ble_fido_ctx_rx_fragment(self._raw, buf, len(frag))

    @property
    def receiving(self) -> bool:
        return bool(self.lib.ble_fido_ctx_is_receiving(self._raw))

    @property
    def cp_len(self) -> int:
        return self.lib.ble_fido_ctx_control_point_length(self._raw)


@pytest.fixture(scope="module")
def lib(tmp_path_factory):
    lib = build_shared_lib(
        ["core/ble_fido/ble_fido.c"],
        tmp_path_factory.mktemp("ble_ctx"),
        name="libblectx",
    )
    p = ctypes.c_void_p
    lib.ble_fido_ctx_init.argtypes = [p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16, ctypes.c_uint32]
    lib.ble_fido_ctx_set_notify.argtypes = [p, NOTIFY_FN]
    lib.ble_fido_ctx_set_deliver.argtypes = [p, DELIVER_FN]
    lib.ble_fido_ctx_rx_fragment.argtypes = [p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16]
    lib.ble_fido_ctx_rx_fragment.restype = ctypes.c_uint8
    lib.ble_fido_ctx_set_mtu.argtypes = [p, ctypes.c_uint16]
    lib.ble_fido_ctx_is_receiving.argtypes = [p]
    lib.ble_fido_ctx_is_receiving.restype = ctypes.c_int
    lib.ble_fido_ctx_control_point_length.argtypes = [p]
    lib.ble_fido_ctx_control_point_length.restype = ctypes.c_uint16
    return lib


def init(cmd: int, total: int, body: bytes = b"") -> bytes:
    return bytes([cmd, total >> 8, total & 0xFF]) + body


def test_a_half_received_message_survives_traffic_on_the_other_service(lib):
    """The failure this refactor exists to prevent."""
    fido = Ctx(lib, FIDO_CAP)
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)

    assert fido.rx(init(CMD_MSG, 8, b"abcd")) == ERR_NONE
    assert fido.receiving

    # A whole unrelated transaction on the other service, start to finish.
    assert piv.rx(init(CMD_MSG, 3, b"xyz")) == ERR_NONE
    assert piv.delivered == [(CMD_MSG, b"xyz")]
    assert not piv.receiving

    assert fido.receiving, "the other service's traffic aborted this reassembly"
    assert fido.rx(bytes([0x00]) + b"efgh") == ERR_NONE
    assert fido.delivered == [(CMD_MSG, b"abcdefgh")]


def test_an_error_on_one_service_is_not_notified_on_the_other(lib):
    fido = Ctx(lib, FIDO_CAP)
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)

    assert piv.rx(bytes([0x00, 0xAA])) != ERR_NONE  # continuation with no init
    assert len(piv.notified) == 1 and piv.notified[0][0] == CMD_ERROR
    assert fido.notified == [], "an error was notified to the wrong peer"


def test_each_context_keeps_its_own_sequence_counter(lib):
    """Interleaved continuations must not satisfy each other's expected SEQ."""
    a = Ctx(lib, FIDO_CAP)
    b = Ctx(lib, FIDO_CAP)

    a.rx(init(CMD_MSG, 6, b"aa"))
    b.rx(init(CMD_MSG, 6, b"bb"))
    assert a.rx(bytes([0x00]) + b"aa") == ERR_NONE
    assert b.rx(bytes([0x00]) + b"bb") == ERR_NONE
    assert a.rx(bytes([0x01]) + b"aa") == ERR_NONE
    assert b.rx(bytes([0x01]) + b"bb") == ERR_NONE

    assert a.delivered == [(CMD_MSG, b"aaaaaa")]
    assert b.delivered == [(CMD_MSG, b"bbbbbb")]


def test_each_context_enforces_its_own_message_cap(lib):
    """
    The PIV service caps messages far below CTAP's. Declaring a length the
    buffer cannot hold must be refused before anything is copied, and the cap
    that applies is the one belonging to the service written to.
    """
    fido = Ctx(lib, FIDO_CAP)
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)

    assert piv.rx(init(CMD_MSG, PIV_CAP + 1)) == ERR_INVALID_LEN
    assert not piv.receiving
    assert fido.rx(init(CMD_MSG, PIV_CAP + 1, b"ok")) == ERR_NONE, (
        "the FIDO service must not inherit the PIV cap"
    )
    assert fido.receiving


@pytest.mark.parametrize("declared", [PIV_CAP, PIV_CAP - 1, 2, 1])
def test_piv_cap_accepts_everything_up_to_its_limit(lib, declared):
    """The cap is a ceiling, not a target: every length up to it is accepted.

    A one-byte message is complete in its init fragment and is delivered there
    rather than leaving the reassembler active, so acceptance is what is
    asserted -- either still assembling, or already handed over whole.
    """
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)
    assert piv.rx(init(CMD_MSG, declared, b"\x00")) == ERR_NONE
    if declared == 1:
        assert not piv.receiving
        assert piv.delivered == [(CMD_MSG, b"\x00")]
    else:
        assert piv.receiving
        assert piv.delivered == []


def test_ping_is_refused_on_a_service_that_does_not_offer_it(lib):
    """
    The PIV service has no PING. Echoing one would answer a command the peer
    was never told about, on a service reachable only after an authenticated
    bond -- where an echo oracle has no purpose but has a cost.
    """
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)
    assert piv.rx(init(CMD_PING, 4, b"ping")) == ERR_INVALID_CMD
    assert piv.delivered == []
    assert len(piv.notified) == 1 and piv.notified[0][0] == CMD_ERROR
    assert not piv.receiving


def test_ping_still_works_where_it_is_offered(lib):
    fido = Ctx(lib, FIDO_CAP)
    assert fido.rx(init(CMD_PING, 4, b"ping")) == ERR_NONE
    assert fido.notified == [init(CMD_PING, 4, b"ping")]
    assert fido.delivered == [], "PING must never reach the CTAP core"


def test_contexts_do_not_share_a_control_point_length(lib):
    """Each service negotiates its own MTU; one must not publish the other's."""
    a = Ctx(lib, FIDO_CAP, cp_len=512)
    b = Ctx(lib, PIV_CAP, flags=CTX_NO_PING, cp_len=100)
    assert a.cp_len == 512
    assert b.cp_len == 100


def test_a_cancel_on_one_service_leaves_the_other_assembling(lib):
    """CANCEL is the one command that may interrupt a message in flight -- but
    only the message on its own service."""
    fido = Ctx(lib, FIDO_CAP)
    piv = Ctx(lib, PIV_CAP, flags=CTX_NO_PING)

    fido.rx(init(CMD_MSG, 8, b"abcd"))
    piv.rx(init(CMD_MSG, 8, b"wxyz"))
    assert fido.receiving and piv.receiving

    assert piv.rx(bytes([0xBE, 0x00, 0x00])) == ERR_NONE
    assert not piv.receiving
    assert piv.notified == [], "CTAP2 11.4.8: never reply to the cancel itself"

    assert fido.receiving, "a cancel crossed services"
    assert fido.rx(bytes([0x00]) + b"efgh") == ERR_NONE
    assert fido.delivered == [(CMD_MSG, b"abcdefgh")]
