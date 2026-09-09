"""Replay the shared FIDO BLE conformance corpus against the firmware C.

The corpus (`tests/conformance/ble_fido_v1.json`) is hand-authored from
CTAP2 §11.2 and is the contract between the two implementations of this wire
format:

  * `core/ble_fido/ble_fido.c`   — firmware, driven here
  * `crates/ble-framing`         — cryptick-token-daemon, replays the same file

A failure here means the firmware disagrees with the specification. A failure
on the daemon side against the same file means the two halves of the product
disagree with each other, which is the drift the daemon's PROJECT.md §14 asks
golden transcripts to catch.

`tests/host/test_ble_fido_framing.py` is the unit layer — finer-grained, C-only,
and free to assert on internals. This file asserts only what is observable on
the wire, because that is all the Rust side can be held to.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from support.native import build_shared_lib

CORPUS = (
    Path(__file__).resolve().parents[1] / "conformance" / "ble_fido_v1.json"
)

# The firmware is the device: it reassembles writes to fidoControlPoint.
APPLICABLE = {"both", "host_to_device"}

CMD_ERROR = 0xBF


def load_corpus() -> dict:
    assert CORPUS.exists(), f"conformance corpus missing: {CORPUS}"
    return json.loads(CORPUS.read_text())


CORPUS_DOC = load_corpus()
VECTORS = [v for v in CORPUS_DOC["vectors"] if v["direction"] in APPLICABLE]


@pytest.fixture(scope="module")
def transport(tmp_path_factory):
    """The C framing layer with recording callbacks."""
    from test_ble_fido_framing import DELIVER_FN, NOTIFY_FN, Transport
    import ctypes

    lib = build_shared_lib(
        ["core/ble_fido/ble_fido.c"],
        tmp_path_factory.mktemp("ble_conf"),
        name="libblefido",
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


def test_corpus_is_present_and_versioned():
    assert CORPUS_DOC["version"] == 1
    assert VECTORS, "no vectors applicable to the device side"


def test_corpus_matches_its_generator():
    """The committed JSON must be what generate.py produces, so a hand-edit
    to the corpus cannot silently diverge from the spec it documents."""
    import subprocess
    import sys

    before = CORPUS.read_text()
    subprocess.run(
        [sys.executable, str(CORPUS.parent / "generate.py")],
        check=True,
        capture_output=True,
    )
    after = CORPUS.read_text()
    assert before == after, (
        "tests/conformance/ble_fido_v1.json is out of date — "
        "run `python3 tests/conformance/generate.py` and commit the result"
    )


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_conformance_vector(transport, vector):
    from test_ble_fido_framing import Transport

    t = Transport(transport)
    t.set_mtu(vector["fragment_size"] + 3)
    assert t.cp_len == vector["fragment_size"], "fragment size not established"

    fragments = [bytes.fromhex(f) for f in vector["fragments"]]
    expect = vector.get("expect")
    why = vector.get("why", "")
    assert ("expect" in vector) != ("deliveries" in vector), (
        f"{vector['name']}: exactly one of expect / deliveries"
    )

    last = None
    for frag in fragments:
        last = t.rx(frag)

    # `deliveries` checks every delivery in order; `expect` checks only the
    # last. Under a last-only rule an implementation that swallowed an
    # intermediate delivery would pass, which is the divergence worth catching.
    if "deliveries" in vector:
        want = [
            (d["command"], bytes.fromhex(d["payload"])) for d in vector["deliveries"]
        ]
        assert t.delivered == want, why
        assert not t.receiving, f"reassembler should be idle. {why}"
        return

    if expect["kind"] == "message":
        want = (expect["command"], bytes.fromhex(expect["payload"]))
        # PING is answered by the transport itself rather than delivered up.
        if want[0] == 0x81:
            assert t.notified, f"PING was not echoed. {why}"
            head = t.notified[0]
            assert head[0] == 0x81
            assert (head[1] << 8) | head[2] == len(want[1])
            rebuilt = head[3:]
            for i, frag in enumerate(t.notified[1:]):
                assert frag[0] == (i & 0x7F)
                rebuilt += frag[1:]
            assert rebuilt == want[1], why
        else:
            assert t.delivered, f"nothing was delivered. {why}"
            assert t.delivered[-1] == want, why
        assert not t.receiving, f"reassembler should be idle. {why}"

    elif expect["kind"] == "error":
        want = expect["ble_error"]
        assert last == want, (
            f"expected BLE error 0x{want:02x}, got 0x{(last or 0):02x}. {why}"
        )
        assert want in t.errors, f"error was not reported on the wire. {why}"
        assert t.delivered == [], f"a failed transaction must deliver nothing. {why}"
        assert not t.receiving, f"an error must leave the reassembler idle. {why}"

    elif expect["kind"] == "incomplete":
        assert t.delivered == [], why
        assert t.receiving, f"expected a transaction still in progress. {why}"
        assert t.errors == [], f"an incomplete message is not an error. {why}"

    else:  # pragma: no cover
        pytest.fail(f"unknown expectation kind {expect['kind']!r}")


def test_every_error_vector_names_its_reason():
    """A corpus entry without a `why` is a regression trap, not a spec."""
    missing = [v["name"] for v in CORPUS_DOC["vectors"] if not v.get("why")]
    assert not missing, f"vectors missing a rationale: {missing}"
