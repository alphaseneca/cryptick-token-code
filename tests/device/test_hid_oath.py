"""L2: Cryptick OATH over CTAPHID — LIST returns SW 9000."""
from __future__ import annotations

import pytest

from support.cryptick_ctaphid import ctaphid_init, oath_list

pytestmark = pytest.mark.device


def test_oath_list_sw_ok(fido_hid):
    cid = fido_hid.cid if fido_hid.cid else ctaphid_init(fido_hid.dev)
    payload = oath_list(fido_hid.dev, cid)
    assert len(payload) >= 2, payload.hex()
    sw = (payload[-2] << 8) | payload[-1]
    assert sw == 0x9000, f"SW=0x{sw:04X} payload={payload.hex()}"
