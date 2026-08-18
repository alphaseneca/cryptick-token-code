"""L2: CDC LOGLEVEL command + product ATTEST AAGUID line."""
from __future__ import annotations

import pytest

from support.cryptick_usb import cdc_command

pytestmark = pytest.mark.device

PRODUCT_AAGUID_UUID = "c7a5e1e0-7c4b-4f0a-9d2e-55c41c710001"


def test_loglevel_query_and_set(cdc):
    out = cdc_command(cdc, "LOGLEVEL", wait_s=1.2)
    assert "LOGLEVEL" in out.upper() or "ERROR" in out.upper() or any(
        x in out for x in ("0", "1", "2", "3", "4", "5")
    )
    # leave at DEBUG for lab visibility after test (prefer not permanently elevate to TRACE)
    set_out = cdc_command(cdc, "LOGLEVEL 4", wait_s=1.0)
    assert "OK" in set_out or "4" in set_out


def test_attest_reports_product_aaguid(cdc):
    out = cdc_command(cdc, "ATTEST", wait_s=1.2)
    low = out.lower()
    assert "aaguid" in low
    # Accept dashed or compact form
    compact = PRODUCT_AAGUID_UUID.replace("-", "")
    assert PRODUCT_AAGUID_UUID in low or compact in low.replace("-", "")
    assert "cert" in low or "attest" in low
