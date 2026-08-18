"""CTAPHID helpers for Cryptick FIDO HID (Solo-class layout)."""
from __future__ import annotations

import struct
from typing import Optional

VID, PID = 0x1209, 0xBEEE
CTAPHID_INIT = 0x86
CTAPHID_MSG = 0x83
CTAPHID_CBOR = 0x90
CTAPHID_ERROR = 0x3F
CTAPHID_KEEPALIVE = 0x3B
CTAPHID_OATH = 0xE3  # TYPE_INIT | 0x63
CTAPHID_ENTERBOOT = 0xD1
BROADCAST = 0xFFFFFFFF
REPORT_LEN = 64

# CTAP2 command bytes (prefix of CBOR/MSG payload)
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_GET_ASSERTION = 0x02
CTAP_GET_INFO = 0x04
CTAP_CLIENT_PIN = 0x06
CTAP_RESET = 0x07

# OATH (YKOATH-style) data-object tags used by the Cryptick APDUs.
TAG_NAME = 0x71
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74


class HidError(RuntimeError):
    pass


def enumerate_fido_paths():
    import hid

    paths = []
    for d in hid.enumerate(VID, PID):
        # Prefer FIDO usage page 0xF1D0 if present
        up = d.get("usage_page") or 0
        paths.append((up, d["path"], d))
    paths.sort(key=lambda x: 0 if x[0] == 0xF1D0 else 1)
    return [p[1] for p in paths]


def open_fido():
    import hid

    last_err = None
    for path in enumerate_fido_paths():
        dev = hid.device()
        try:
            dev.open_path(path)
            return dev
        except Exception as e:  # pragma: no cover
            last_err = e
            continue
    raise HidError(f"No Cryptick FIDO HID 1209:BEEE ({last_err})")


def _write(dev, pkt: bytes) -> None:
    if len(pkt) != REPORT_LEN:
        raise ValueError("HID packet must be 64 bytes")
    # macOS hidapi: try report-id 0 prefix first (65 bytes), then raw 64
    for blob in (b"\x00" + pkt, pkt):
        n = dev.write(blob)
        if n and n > 0:
            return
    err = ""
    try:
        err = dev.error()  # type: ignore[attr-defined]
    except Exception:
        pass
    raise HidError(f"HID write failed ({err or 'n<=0'})")


def _read(dev, timeout_ms: int = 1000) -> bytes:
    r = bytes(dev.read(REPORT_LEN, timeout_ms=timeout_ms))
    if not r:
        raise HidError("HID read timeout")
    # Some stacks prepend report id
    if len(r) == REPORT_LEN + 1 and r[0] == 0:
        r = r[1:]
    if len(r) < REPORT_LEN:
        r = r + bytes(REPORT_LEN - len(r))
    return r[:REPORT_LEN]


def ctaphid_init(dev, timeout_ms: int = 1000) -> int:
    """Allocate a channel on the broadcast CID and return the assigned CID.

    Response frame: cid(4) cmd(1) bcnt(2) nonce(8) newcid(4) versions...
    """
    nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    pkt = bytearray(REPORT_LEN)
    struct.pack_into("<I", pkt, 0, BROADCAST)
    pkt[4] = CTAPHID_INIT
    pkt[5] = 0
    pkt[6] = 8  # bcnt
    pkt[7:15] = nonce
    _write(dev, bytes(pkt))

    resp = _read(dev, timeout_ms=timeout_ms)
    if resp[4] & 0x7F != CTAPHID_INIT & 0x7F:
        raise HidError(f"unexpected INIT cmd 0x{resp[4]:02x} payload={resp[:20].hex()}")
    bcnt = (resp[5] << 8) | resp[6]
    if bcnt < 12:
        raise HidError(f"short INIT response (bcnt={bcnt})")
    if resp[7:15] != nonce:
        raise HidError(f"INIT nonce mismatch: {resp[7:15].hex()}")

    new_cid = struct.unpack_from("<I", resp, 15)[0]
    if new_cid in (0, BROADCAST):
        raise HidError(f"INIT returned unusable cid 0x{new_cid:08x}")
    return new_cid


def ctaphid_send(dev, cid: int, cmd: int, payload: bytes, timeout_ms: int = 2000) -> bytes:
    """Send init packet(s); return full payload (no channel header).

    Skips CTAPHID_KEEPALIVE frames (sent while device waits for fingerprint UV).
    timeout_ms is the *overall* wall-clock budget for the full response, not
    only a single HID poll, so OATH UV ops can run ~25s.
    """
    import time

    if len(payload) > 7609:
        raise ValueError("payload too large")
    remaining = payload
    seq = 0
    out_payload = bytearray()
    # write init
    pkt = bytearray(REPORT_LEN)
    struct.pack_into("<I", pkt, 0, cid)
    pkt[4] = cmd
    pkt[5] = (len(payload) >> 8) & 0xFF
    pkt[6] = len(payload) & 0xFF
    take = min(64 - 7, len(remaining))
    pkt[7 : 7 + take] = remaining[:take]
    remaining = remaining[take:]
    _write(dev, bytes(pkt))
    while remaining:
        pkt = bytearray(REPORT_LEN)
        struct.pack_into("<I", pkt, 0, cid)
        pkt[4] = seq & 0x7F
        seq += 1
        take = min(64 - 5, len(remaining))
        pkt[5 : 5 + take] = remaining[:take]
        remaining = remaining[take:]
        _write(dev, bytes(pkt))

    # read response assembly — wall clock for UV
    total = None
    got = 0
    deadline = time.time() + (timeout_ms / 1000.0)
    poll_ms = min(1000, max(200, timeout_ms // 30))
    while True:
        left_ms = int((deadline - time.time()) * 1000)
        if left_ms <= 0:
            raise HidError("HID read timeout (including UV wait)")
        try:
            resp = _read(dev, timeout_ms=min(poll_ms, left_ms))
        except HidError:
            # keep polling until wall-clock budget ends (finger UV)
            if time.time() >= deadline:
                raise
            continue
        rcid = struct.unpack_from("<I", resp, 0)[0]
        if rcid != cid and rcid != BROADCAST:
            continue
        rcmd = resp[4]
        opcode = rcmd & 0x7F
        # Fingerprint wait: device streams keepalive status
        if opcode == CTAPHID_KEEPALIVE:
            continue
        # CTAPHID error frame
        if opcode == CTAPHID_ERROR:
            err = resp[7] if len(resp) > 7 else 0
            raise HidError(f"CTAPHID error frame cmd=0x{rcmd:02x} err=0x{err:02x}")
        if total is None:
            # Accept only the response for the command we sent
            if opcode != (cmd & 0x7F):
                continue
            total = (resp[5] << 8) | resp[6]
            chunk = resp[7:]
            out_payload.extend(chunk[: min(len(chunk), total)])
            got = len(out_payload)
        else:
            # continuation packets: bit7 clear, seq in low 7 bits
            if rcmd & 0x80:
                continue
            chunk = resp[5:]
            need = total - got
            out_payload.extend(chunk[:need])
            got = len(out_payload)
        if total is not None and got >= total:
            return bytes(out_payload[:total])


def _apdu(ins: int, data: bytes = b"") -> bytes:
    """CLA=0 short APDU. The firmware parser is single-byte-Lc only."""
    if len(data) > 255:
        raise ValueError("Lc single-byte only in MVP APDU")
    return bytes([0x00, ins, 0x00, 0x00, len(data)]) + data


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError(f"TLV 0x{tag:02X} too long")
    return bytes([tag, len(value)]) + value


def oath_list(dev, cid: int, timeout_ms: int = 2000) -> bytes:
    """LIST (INS 0xA1) — not UV-gated, so it works without a fingerprint."""
    return ctaphid_send(dev, cid, CTAPHID_OATH, _apdu(0xA1), timeout_ms=timeout_ms)


def oath_put(dev, cid: int, name: str, secret: bytes, timeout_ms: int = 30000) -> bytes:
    """PUT (INS 0x01) name + TOTP/SHA1/6-digit secret. UV-gated: may wait for FP."""
    key = bytes([0x21, 0x06]) + secret  # type_algo TOTP|SHA1, digits 6
    data = _tlv(TAG_NAME, name.encode("utf-8")) + _tlv(TAG_KEY, key)
    return ctaphid_send(dev, cid, CTAPHID_OATH, _apdu(0x01, data), timeout_ms=timeout_ms)


def oath_delete(dev, cid: int, name: str, timeout_ms: int = 30000) -> bytes:
    """DELETE (INS 0x02). UV-gated: may wait for FP."""
    data = _tlv(TAG_NAME, name.encode("utf-8"))
    return ctaphid_send(dev, cid, CTAPHID_OATH, _apdu(0x02, data), timeout_ms=timeout_ms)


def oath_calculate(dev, cid: int, name: str, counter: int, timeout_ms: int = 30000) -> bytes:
    """CALCULATE (INS 0xA2) for a TOTP time-step counter. UV-gated."""
    data = _tlv(TAG_NAME, name.encode("utf-8")) + _tlv(TAG_CHALLENGE, counter.to_bytes(8, "big"))
    return ctaphid_send(dev, cid, CTAPHID_OATH, _apdu(0xA2, data), timeout_ms=timeout_ms)


def oath_sw(payload: bytes) -> int:
    if len(payload) < 2:
        raise HidError("short OATH response")
    return (payload[-2] << 8) | payload[-1]


def ctap2_raw(dev, cid: int, cmd: int, cbor_body: bytes = b"", timeout_ms: int = 5000) -> tuple[int, bytes]:
    """Send CTAPHID_CBOR: (ctap_cmd || cbor). Return (status_byte, rest)."""
    payload = bytes([cmd & 0xFF]) + cbor_body
    body = ctaphid_send(dev, cid, CTAPHID_CBOR, payload, timeout_ms=timeout_ms)
    if not body:
        raise HidError("empty CTAP2 response")
    return body[0], body[1:]


def ctap2_get_info(dev, cid: int, timeout_ms: int = 5000) -> tuple[int, bytes]:
    """CTAP2 authenticatorGetInfo (0x04). Returns (status, cbor_bytes)."""
    return ctap2_raw(dev, cid, CTAP_GET_INFO, b"", timeout_ms=timeout_ms)


def ctap2_info_looks_fido2(cbor: bytes) -> bool:
    """Heuristic: Solo/Cryptick advertises FIDO_2_0 in GetInfo CBOR text."""
    return b"FIDO_2_0" in cbor or b"FIDO_2_1" in cbor or b"U2F_V2" in cbor
