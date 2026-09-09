#!/usr/bin/env python3
"""Generate the shared FIDO BLE conformance corpus.

The corpus is a **specification**, not a snapshot. Every expectation below is
written by hand from CTAP2 §11.2 and the bounds argued in docs/BLE_FIDO.md —
never captured from whatever the implementation happens to do. A corpus
generated from an implementation only proves that implementation is
self-consistent, which is what the old PIV test did and why it missed a bug.

Two implementations of this wire format exist and must agree:

  * `core/ble_fido/ble_fido.c`                   (firmware, this repo)
  * `crates/ble-framing`                         (cryptick-token-daemon)

Both replay this file. When they disagree, one of them is wrong on the wire —
which is the whole point (daemon PROJECT.md §14, "golden transcripts ... fails
if transcripts drift").

Regenerate with:  python3 tests/conformance/generate.py
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "ble_fido_v1.json"

CMD_PING, CMD_KEEPALIVE, CMD_MSG, CMD_CANCEL, CMD_ERROR = 0x81, 0x82, 0x83, 0xBE, 0xBF

ERR_INVALID_CMD = 0x01
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
# 0x06 is a real BLE code (CTAP2 11.4.4.3); only 0x0a/0x0b are HID-reserved.
ERR_BUSY = 0x06

MAX_MSG = 1200

# Which side of the link a vector constrains.
#   h2d  the device reassembling writes to fidoControlPoint  (firmware RX)
#   d2h  the host reassembling notifications on fidoStatus   (daemon RX)
#   both identical on either side
H2D, D2H, BOTH = "host_to_device", "device_to_host", "both"

cases: list[dict] = []


def case(name, *, fragments, expect, size=20, direction=BOTH, why="", max_len=None):
    cases.append(
        {
            "name": name,
            "direction": direction,
            "fragment_size": size,
            "max_message_len": MAX_MSG if max_len is None else max_len,
            "fragments": [f.hex() for f in fragments],
            "expect": expect,
            "why": why,
        }
    )


def init(cmd: int, declared: int, data: bytes = b"") -> bytes:
    return bytes([cmd, (declared >> 8) & 0xFF, declared & 0xFF]) + data


def cont(seq: int, data: bytes) -> bytes:
    return bytes([seq & 0x7F]) + data


def message(cmd: int, payload: bytes) -> dict:
    return {"kind": "message", "command": cmd, "payload": payload.hex()}


def error(code: int) -> dict:
    return {"kind": "error", "ble_error": code}


INCOMPLETE = {"kind": "incomplete"}


def split(payload: bytes, size: int):
    """The canonical fragmentation of a payload, per CTAP2 §11.2."""
    out = [init(CMD_MSG, len(payload), payload[: size - 3])]
    off, seq = size - 3, 0
    while off < len(payload):
        chunk = payload[off : off + (size - 1)]
        out.append(cont(seq, chunk))
        off += len(chunk)
        seq = (seq + 1) & 0x7F
    return out


# --- Well-formed ----------------------------------------------------------

case(
    "single_fragment_message",
    fragments=[init(CMD_MSG, 4, b"\x01\x02\x03\x04")],
    expect=message(CMD_MSG, b"\x01\x02\x03\x04"),
    why="An init fragment whose data length equals HLEN completes immediately.",
)

case(
    "empty_message",
    fragments=[init(CMD_MSG, 0)],
    expect=message(CMD_MSG, b""),
    why="HLEN 0 completes on the init fragment. This is how CANCEL is sent.",
)

case(
    "cancel_from_idle",
    fragments=[init(CMD_CANCEL, 0)],
    expect=message(CMD_CANCEL, b""),
    why="CANCEL is a zero-length message, not a special frame.",
)

_p = bytes((i * 7) & 0xFF for i in range(200))
case(
    "multi_fragment_message",
    fragments=split(_p, 20),
    expect=message(CMD_MSG, _p),
    why="17 bytes in the init fragment, 19 per continuation at the 20-byte floor.",
)

for _size in (20, 21, 23, 64, 255, 511, 512):
    _q = bytes((i * 3) & 0xFF for i in range(300))
    case(
        f"fragmentation_boundary_size_{_size}",
        fragments=split(_q, _size),
        expect=message(CMD_MSG, _q),
        size=_size,
        why="Fragment size is negotiated per connection; every legal size must work.",
    )

# SEQ wrap is unreachable on the device: at the 20-byte floor a 1200-byte
# message needs 63 continuations, so SEQ never passes 62. It IS reachable on
# the host side, whose ceiling is the full 16-bit HLEN range — so this vector
# is device-to-host only, and carries its own larger max_message_len.
_wrap = bytes((i * 11) & 0xFF for i in range(19 * 200))
case(
    "sequence_wraps_at_0x7f",
    fragments=split(_wrap, 20),
    expect=message(CMD_MSG, _wrap),
    direction=D2H,
    max_len=0xFFFF,
    why="SEQ is 7-bit and wraps 0x7f -> 0x00 rather than overflowing into the "
    "init bit. Unreachable against the firmware's 1200-byte ceiling, which is "
    "why it is pinned on the host side instead of being dropped.",
)

case(
    "sequence_cannot_wrap_within_the_device_ceiling",
    fragments=split(bytes(MAX_MSG), 20),
    expect=message(CMD_MSG, bytes(MAX_MSG)),
    direction=H2D,
    why="The largest message the device accepts, at the smallest legal fragment "
    "size, is 63 continuations. If this ever needs more than 0x7f, the wrap "
    "path becomes reachable on the device too and needs its own coverage.",
)

_max = bytes((i * 5) & 0xFF for i in range(MAX_MSG))
case(
    "max_length_message",
    fragments=split(_max, 512),
    expect=message(CMD_MSG, _max),
    size=512,
    why="CTAP_MAX_MESSAGE_SIZE exactly; the largest the firmware will accept.",
)

case(
    "incomplete_message_yields_nothing",
    fragments=[init(CMD_MSG, 100, bytes(17))],
    expect=INCOMPLETE,
    why="A partial transaction must not be delivered.",
)

case(
    "ping_payload_is_preserved",
    fragments=[init(CMD_PING, 8, b"cryptick")],
    expect=message(CMD_PING, b"cryptick"),
    why="PING echoes its payload; the firmware answers it without the CTAP core.",
)

# --- Bounds and hostile input ---------------------------------------------

case(
    "empty_fragment",
    fragments=[b""],
    expect=error(ERR_INVALID_LEN),
    why="A zero-byte write carries neither a command nor a sequence number.",
)

case(
    "init_fragment_truncated_before_hlen",
    fragments=[bytes([CMD_MSG, 0x00])],
    expect=error(ERR_INVALID_LEN),
    why="The 3-byte init header must be complete before HLEN can be read.",
)

case(
    "declared_length_above_ceiling",
    fragments=[init(CMD_MSG, 0xFFFF, b"\x00")],
    expect=error(ERR_INVALID_LEN),
    why="HLEN is 16-bit, so a peer can declare 65535. Reject before allocating.",
)

case(
    "declared_length_just_above_ceiling",
    fragments=[init(CMD_MSG, MAX_MSG + 1)],
    expect=error(ERR_INVALID_LEN),
    why="The ceiling is inclusive; 1201 is one byte too many.",
)

case(
    "init_fragment_carries_more_than_declared",
    fragments=[init(CMD_MSG, 2, b"\x01\x02\x03\x04")],
    expect=error(ERR_INVALID_LEN),
    why="Data beyond HLEN in the init fragment is a length contradiction.",
)

case(
    "continuation_without_init",
    fragments=[cont(0, b"\x01\x02")],
    expect=error(ERR_INVALID_SEQ),
    why="A continuation with no transaction in flight has nothing to continue.",
)

case(
    "first_continuation_must_be_seq_zero",
    fragments=[init(CMD_MSG, 100, bytes(17)), cont(1, bytes(19))],
    expect=error(ERR_INVALID_SEQ),
    why="Sequence numbers start at 0, not at 1.",
)

case(
    "skipped_sequence_number",
    fragments=[init(CMD_MSG, 100, bytes(17)), cont(0, bytes(19)), cont(2, bytes(19))],
    expect=error(ERR_INVALID_SEQ),
    why="A gap means a lost fragment; the message would be silently corrupt.",
)

case(
    "replayed_sequence_number",
    fragments=[init(CMD_MSG, 100, bytes(17)), cont(0, bytes(19)), cont(0, bytes(19))],
    expect=error(ERR_INVALID_SEQ),
    why="Replaying a fragment must not append it twice.",
)

case(
    "empty_continuation",
    fragments=[init(CMD_MSG, 100, bytes(17)), cont(0, b"")],
    expect=error(ERR_INVALID_LEN),
    why="A continuation with no data makes no progress, so a peer could hold the "
    "transaction open forever sending them.",
)

case(
    "continuations_exceed_declared_length",
    fragments=[init(CMD_MSG, 30, bytes(17)), cont(0, bytes(19))],
    expect=error(ERR_INVALID_LEN),
    why="17 + 19 overruns the declared 30; the buffer bound is HLEN, not the fragment.",
)

case(
    "fragment_longer_than_negotiated_size",
    fragments=[init(CMD_MSG, 100, bytes(30))],
    expect=error(ERR_INVALID_LEN),
    direction=H2D,
    why="fidoControlPointLength bounds *writes to fidoControlPoint*, so this "
    "rule is the device's alone. Inbound fragments reach the host as "
    "notifications on fidoStatus, sized by the negotiated ATT MTU, which may "
    "legitimately exceed it — a device advertising 20 and notifying at MTU-3 "
    "is conformant, so enforcing this host-side would be an interop bug.",
)

case(
    "init_fragment_mid_transaction",
    fragments=[init(CMD_MSG, 100, bytes(17)), init(CMD_MSG, 5, b"retry")],
    expect=error(ERR_INVALID_SEQ),
    why="No channels exist, so an init mid-transaction is a protocol violation "
    "rather than a second conversation. Both implementations fail closed.",
)

case(
    "cancel_mid_transaction_abandons_and_stays_silent",
    fragments=[init(CMD_MSG, 100, bytes(17)), init(CMD_CANCEL, 0)],
    expect=message(CMD_CANCEL, b""),
    why="CTAP2 11.4.8: 'Whether a request was cancelled or not, the "
    "authenticator MUST NOT reply to the cancel message itself.' So CANCEL is "
    "the one command permitted to interrupt a message in flight, and it emits "
    "nothing. Both implementations previously answered CMD_ERROR here, which "
    "is a MUST NOT violation neither of us caught by agreeing with the other.",
)

case(
    "cancel_with_a_payload_is_still_silent",
    fragments=[init(CMD_CANCEL, 100, bytes(10))],
    expect=message(CMD_CANCEL, b""),
    why="Rejecting a malformed CANCEL would mean replying to it, which 11.4.8 "
    "forbids — the strict reading is unimplementable, not merely strict. The "
    "declared length is ignored and the payload discarded.",
)

# Recovery after a cancel would deliver twice (the cancel, then the next
# message). Every vector here delivers at most once, and the daemon's replayer
# was written against that; keeping the shared contract simple is worth more
# than one vector, so that case lives in tests/host/test_ble_fido_framing.py.

case(
    "recovers_after_an_error",
    fragments=[cont(0, b"junk"), init(CMD_MSG, 2, b"\x01\x02")],
    expect=message(CMD_MSG, b"\x01\x02"),
    why="Failing closed must not wedge the transport: the abort leaves the "
    "reassembler idle, so the next well-formed init succeeds.",
)

# --- Role-asymmetric ------------------------------------------------------

for _cmd, _name in ((CMD_KEEPALIVE, "keepalive"), (CMD_ERROR, "error")):
    case(
        f"{_name}_written_to_control_point_is_rejected",
        fragments=[init(_cmd, 0)],
        expect=error(ERR_INVALID_CMD),
        direction=H2D,
        why=f"{_name.upper()} is device-to-host only. The daemon's reassembler "
        "accepts it because it sits on the receiving end; the firmware must not.",
    )

for _byte in (0x80, 0x84, 0xA0, 0xFF):
    case(
        f"unknown_command_0x{_byte:02x}",
        fragments=[init(_byte, 0)],
        expect=error(ERR_INVALID_CMD),
        why="Only the five defined commands exist; the high bit alone is not enough.",
    )


def main() -> None:
    doc = {
        "version": 1,
        "spec": "CTAP2 §11.2 FIDO BLE transport",
        "generated_by": "tests/conformance/generate.py",
        "note": (
            "Hand-authored expectations, not captured output. Replayed by "
            "tests/host/test_ble_fido_conformance.py (firmware C) and intended "
            "for crates/ble-framing (daemon Rust). A disagreement means one "
            "side is wrong on the wire."
        ),
        "directions": {
            "host_to_device": "device reassembling fidoControlPoint writes",
            "device_to_host": "host reassembling fidoStatus notifications",
            "both": "identical on either side",
        },
        "vectors": cases,
    }
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"{OUT}: {len(cases)} vectors")


if __name__ == "__main__":
    main()
