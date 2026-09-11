"""Assert on the CCID descriptor bytes the firmware actually emits.

Descriptors are the part of a USB transport that cannot be exercised without a
host and a reader, and in this project they are also the part with no history
of being right first time. drivers/ccid_descriptors.c is freestanding for that
reason: the bytes checked here are compiled from the same source the firmware
links, so a failure means the device would enumerate wrong.

The assertions that carry weight are the ones tying the descriptor to code
elsewhere in the tree — the declared exchange level against what piv.c can
parse, dwProtocols against the ATR, dwMaxCCIDMessageLength against the
reassembly buffer. A descriptor that is internally consistent but disagrees
with the applet underneath it is the failure mode worth catching, and it is
invisible to any check that reads the descriptor alone.
"""
from __future__ import annotations

import ctypes
import re
from pathlib import Path

import pytest

from support.native import build_shared_lib

REPO_ROOT = Path(__file__).resolve().parents[2]

ITF_LEN, FUNC_LEN, EP_LEN = 9, 54, 7
TOTAL = ITF_LEN + FUNC_LEN + 2 * EP_LEN


@pytest.fixture(scope="module")
def desc(tmp_path_factory) -> bytes:
    lib = build_shared_lib(
        ["drivers/ccid_descriptors.c"],
        tmp_path_factory.mktemp("ccid_desc"),
        name="libccid_desc",
    )
    lib.ccid_descriptor_template.restype = ctypes.POINTER(ctypes.c_uint8)
    lib.ccid_descriptor_template.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
    n = ctypes.c_size_t()
    p = lib.ccid_descriptor_template(ctypes.byref(n))
    return bytes(bytearray(p[i] for i in range(n.value)))


def _u16(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def _u32(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def _define(path: str, name: str) -> int:
    src = (REPO_ROOT / path).read_text()
    m = re.search(rf"#define\s+{name}\s+(0x[0-9A-Fa-f]+|\d+)", src)
    assert m, f"{name} not found in {path}"
    return int(m.group(1), 0)


def test_total_length_is_the_sum_of_the_parts(desc):
    """A host reads bLength to step through the set; a wrong total desynchronises it."""
    assert len(desc) == TOTAL
    walked, seen = 0, 0
    while walked < len(desc):
        blen = desc[walked]
        assert blen > 0, f"zero-length descriptor at offset {walked} would hang the walk"
        walked += blen
        seen += 1
    assert walked == len(desc), "descriptor lengths do not tile the set exactly"
    assert seen == 4, "expected interface + functional + two endpoints"


def test_interface_is_what_a_smartcard_stack_binds_to(desc):
    assert desc[0] == ITF_LEN
    assert desc[1] == 0x04, "not an interface descriptor"
    assert desc[4] == 2, "bNumEndpoints must match the two endpoints below"
    assert desc[5] == 0x0B, "bInterfaceClass 0x0B is what makes PC/SC bind"
    assert desc[6] == 0x00, "bInterfaceSubClass must be 0 for a bulk CCID reader"
    assert desc[7] == 0x00, "bInterfaceProtocol 0 = bulk; 1/2 would claim ICCD"


def test_functional_descriptor_shape(desc):
    f = ITF_LEN
    assert desc[f] == FUNC_LEN, "CCID functional descriptor is 54 bytes"
    assert desc[f + 1] == 0x21, "wrong descriptor type for the CCID class descriptor"
    assert _u16(desc, f + 2) == 0x0110, "bcdCCID"
    assert desc[f + 4] == 0x00, "bMaxSlotIndex — this reader has one slot"
    assert desc[f + 53] == 0x01, "bMaxCCIDBusySlots — one command in flight"


def test_declared_protocol_matches_the_atr(desc, tmp_path_factory):
    """
    dwProtocols and the ATR must agree, or the host negotiates a protocol the
    card never offered. The ATR is read out of the compiled reader rather than
    parsed, so this compares the two values the device actually emits.
    """
    dw = _u32(desc, ITF_LEN + 6)
    assert dw == 0x02, "dwProtocols must be T=1 only"

    lib = build_shared_lib(
        ["drivers/ccid_proto.c", "core/piv/piv.c"],
        tmp_path_factory.mktemp("ccid_atr"),
        name="libccid",
    )
    lib.ccid_get_atr.restype = ctypes.c_size_t
    lib.ccid_get_atr.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8))]
    p = ctypes.POINTER(ctypes.c_uint8)()
    n = lib.ccid_get_atr(ctypes.byref(p))
    atr = bytes(bytearray(p[i] for i in range(n)))

    assert len(atr) >= 3, "ATR too short to carry TD1"
    assert atr[0] == 0x3B, "ATR must be direct convention"
    # TS T0 TD1 [TCK]; TD1's low nibble names the first offered protocol.
    offered = atr[2] & 0x0F
    assert offered == 1, f"ATR offers T={offered}, dwProtocols offers T=1"
    # T != 0 makes TCK mandatory, and a bad one makes the card unreadable.
    assert len(atr) == 4, "T=1 ATR of this shape is four bytes including TCK"
    tck = 0
    for b in atr[1:-1]:
        tck ^= b
    assert atr[-1] == tck, f"ATR checksum is 0x{atr[-1]:02X}, should be 0x{tck:02X}"


def test_exchange_level_matches_what_the_applet_can_parse(desc):
    """
    The single most consequential field here.

    Short APDU level (0x00020000) tells the host to send whole short APDUs,
    which is what piv.c decodes. Claiming extended as well (0x00040000) invites
    a 3-byte Lc that piv.c reads as a one-byte zero; claiming TPDU level
    (0x00010000) invites T=1 blocks that ccid_proto.c has no layer to strip.
    """
    features = _u32(desc, ITF_LEN + 40)
    level = features & 0x000F0000
    assert level == 0x00020000, (
        f"exchange level 0x{level:08X}: piv.c decodes short APDUs only"
    )
    assert not (features & 0x00000080), (
        "automatic PPS and automatic parameter negotiation are mutually exclusive"
    )


def test_max_message_length_matches_the_reassembly_buffer(desc):
    """
    A host may send up to dwMaxCCIDMessageLength. Advertising more than the
    reassembler holds is an overflow invitation; advertising less than the
    applet can answer truncates replies.
    """
    declared = _u32(desc, ITF_LEN + 44)
    assert declared == _define("drivers/ccid_proto.h", "CCID_HEADER_LEN") + _define(
        "drivers/ccid_proto.h", "CCID_MAX_APDU"
    )


def test_endpoints_are_bulk_and_full_size(desc):
    for base, name, dir_bit in (
        (ITF_LEN + FUNC_LEN, "OUT", 0x00),
        (ITF_LEN + FUNC_LEN + EP_LEN, "IN", 0x80),
    ):
        assert desc[base] == EP_LEN, f"{name} endpoint descriptor length"
        assert desc[base + 1] == 0x05, f"{name} is not an endpoint descriptor"
        assert desc[base + 2] & 0x80 == dir_bit, f"{name} endpoint has the wrong direction bit"
        assert desc[base + 3] == 0x02, f"{name} endpoint must be bulk"
        assert _u16(desc, base + 4) == 64, f"{name} wMaxPacketSize must be 64 on full speed"
        assert desc[base + 6] == 0, f"{name} bInterval is ignored for bulk and must be 0"


def test_patch_offsets_point_at_the_fields_they_name(desc):
    """
    usb_ccid.cpp writes four bytes into this template at registration. If an
    offset drifts, it corrupts a neighbouring field instead — a descriptor that
    is still the right length and still enumerates, just wrong.
    """
    h = "drivers/ccid_descriptors.h"
    assert _define(h, "CCID_OFF_ITF_NUM") == 2
    assert _define(h, "CCID_OFF_ITF_STR") == 8

    off_out = ITF_LEN + FUNC_LEN + 2
    off_in = ITF_LEN + FUNC_LEN + EP_LEN + 2
    src = (REPO_ROOT / h).read_text()
    assert "CCID_OFF_EP_OUT  (CCID_ITF_DESC_LEN + CCID_FUNC_DESC_LEN + 2)" in src
    assert desc[off_out] & 0x80 == 0x00, "EP_OUT offset does not land on an OUT address"
    assert desc[off_in] & 0x80 == 0x80, "EP_IN offset does not land on an IN address"
    assert desc[off_out - 1] == 0x05 and desc[off_in - 1] == 0x05, (
        "patch offsets are not inside an endpoint descriptor"
    )


def test_no_pin_pad_is_claimed(desc):
    """
    bPINSupport tells the host it can delegate PIN entry to the reader. This
    device verifies the PIN in the applet and has no keypad, so claiming it
    would make a host route VERIFY somewhere that cannot answer.
    """
    assert desc[ITF_LEN + 52] == 0x00
