"""L2: USB identity — product MODE=0 TinyUSB brand."""
from __future__ import annotations

import pytest

from support.cryptick_usb import VID_PRODUCT, PID_PRODUCT, find_product_cdc, macos_usb_product_ids

pytestmark = pytest.mark.device


def test_product_vid_pid_present(product_usb):
    assert product_usb["vid"] == VID_PRODUCT
    assert product_usb["pid"] == PID_PRODUCT


def test_product_cdc_port_exists(product_usb):
    port = product_usb.get("serial") or find_product_cdc()
    assert port, "expected /dev/cu.usbmodem* Cryptick CDC"
    assert "usbmodem" in port or "COM" in port.upper()


def test_no_only_jtag_identity(product_usb):
    """If product is live, 1209:BEEE must be among USB devices."""
    ids = macos_usb_product_ids()
    if not ids:
        pytest.skip("ioreg unavailable")
    assert any(v == VID_PRODUCT and p == PID_PRODUCT for v, p, _ in ids)
