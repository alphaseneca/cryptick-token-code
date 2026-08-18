"""L2: optional post-boot markers when REBOOT or long capture is available.

Does not reboot the device by default (that would break parallel tests).
Marks are checked if present in idle stream after HELP.
"""
from __future__ import annotations

import pytest

from support.cryptick_usb import cdc_command, cdc_read_for

pytestmark = pytest.mark.device


def test_soft_markers_if_present(cdc):
    text = cdc_read_for(cdc, 1.0) + cdc_command(cdc, "HELP", 1.0)
    # Soft assertions — informational via warnings
    saw_usb = "[USB]" in text or "TinyUSB" in text or "1209" in text
    saw_fp = "[FP]" in text
    # At least HELP works (covered elsewhere); document optional boots markers
    assert "HELP" in text.upper() or "BOOTLOADER" in text or "CDC" in text
    # Keep as soft checks so failure is only hard on broken console
    if not saw_usb:
        pytest.skip("boot USB banner not in live capture (open after boot); HELP ok")
