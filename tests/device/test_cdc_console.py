"""L2: CDC console (TinyUSB) — requires DTR-asserted open on macOS."""
from __future__ import annotations

import re
import time

import pytest

from support.cryptick_usb import cdc_command, cdc_read_for

pytestmark = pytest.mark.device


def test_cdc_heartbeat_or_ready(cdc):
    # Collect a few seconds of background + optional HELP
    text = cdc_read_for(cdc, 2.5)
    if "[HB]" not in text and "mounted=" not in text and "cryptick>" not in text.lower():
        more = cdc_command(cdc, "HELP", wait_s=1.2)
        text += more
    assert text.strip(), "CDC silent — assert DTR / product TinyUSB connected"
    # Heartbeat or HELP response proves app + CDC
    ok = (
        "[HB]" in text
        or "mounted=" in text
        or "CDC/log console" in text
        or "cryptick>" in text.lower()
        or "BOOTLOADER" in text
    )
    assert ok, f"unexpected CDC traffic:\n{text[-800:]}"


def test_cdc_help_command(cdc):
    text = cdc_command(cdc, "HELP", wait_s=1.5)
    assert "BOOTLOADER" in text or "REBOOT" in text or "CDC/log" in text
    assert "cryptick>" in text.lower() or "Commands:" in text


def test_cdc_help_mentions_hid(cdc):
    text = cdc_command(cdc, "HELP", wait_s=1.0)
    assert "HID" in text or "OATH" in text or "docs" in text.lower()
