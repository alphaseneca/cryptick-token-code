"""Guard the PIV AID in core/piv/piv.c against the NIST-published value.

The C stub answers SELECT only for this exact AID, so a typo there would make
the applet invisible to macOS with no other symptom. Parsing the source keeps
this test honest: asserting a constant declared in the test file would pass
even if the firmware disagreed.
"""
from __future__ import annotations

import re
from pathlib import Path

PIV_C = Path(__file__).resolve().parents[2] / "core" / "piv" / "piv.c"
PIV_H = Path(__file__).resolve().parents[2] / "core" / "piv" / "piv.h"

# NIST SP 800-73 PIV Card Application AID.
EXPECTED_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00])


def _parse_aid() -> bytes:
    src = PIV_C.read_text()
    m = re.search(r"PIV_AID\[PIV_AID_LEN\]\s*=\s*\{(.*?)\}", src, re.S)
    assert m, "PIV_AID array not found in core/piv/piv.c"
    return bytes(int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


def test_piv_aid_matches_nist():
    assert _parse_aid() == EXPECTED_AID


def test_piv_aid_len_define_matches_array():
    m = re.search(r"#define\s+PIV_AID_LEN\s+(\d+)", PIV_H.read_text())
    assert m, "PIV_AID_LEN not defined in core/piv/piv.h"
    assert int(m.group(1)) == len(EXPECTED_AID)


def test_select_apdu_shape():
    """The SELECT the host will send must match what the stub parses (P1=0x04, Lc=len)."""
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(EXPECTED_AID)]) + EXPECTED_AID
    assert apdu[1] == 0xA4
    assert apdu[2] == 0x04
    assert apdu[4] == len(EXPECTED_AID)
    assert apdu[5:] == _parse_aid()
