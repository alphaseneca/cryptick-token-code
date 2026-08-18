"""L2: CTAPHID_INIT on product FIDO HID."""
from __future__ import annotations

import pytest

from support.cryptick_ctaphid import ctaphid_init, BROADCAST

pytestmark = pytest.mark.device


def test_ctaphid_init_assigns_cid(fido_hid):
    # fixture already probed INIT; re-run if cid missing
    cid = getattr(fido_hid, "cid", None)
    if cid is None:
        cid = ctaphid_init(fido_hid.dev)
    assert isinstance(cid, int)
    assert cid != 0
    assert cid != BROADCAST
    assert cid != 0xFFFFFFFF
