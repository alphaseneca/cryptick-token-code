"""Pytest fixtures for L2 on-device tests. Skip cleanly when hardware missing."""
from __future__ import annotations

import pytest

from support.cryptick_usb import find_product_cdc, macos_usb_product_ids, open_cdc, VID_PRODUCT, PID_PRODUCT


def pytest_addoption(parser):
    parser.addoption(
        "--device",
        action="store_true",
        default=False,
        help="Require Cryptick hardware (fail if missing instead of skip)",
    )
    parser.addoption("--port", action="store", default=None, help="Force CDC port")


def pytest_configure(config):
    config.addinivalue_line("markers", "device: needs Cryptick Token attached (USB)")


@pytest.fixture(scope="session")
def require_device(pytestconfig) -> bool:
    return bool(pytestconfig.getoption("--device"))


@pytest.fixture(scope="session")
def product_usb(require_device):
    import time

    port = find_product_cdc()
    ids = macos_usb_product_ids()
    hit = [(v, p, n) for v, p, n in ids if v == VID_PRODUCT and p == PID_PRODUCT]

    # After reflash host re-enumeration can lag
    if not port and not hit:
        for _ in range(10):
            time.sleep(0.5)
            port = find_product_cdc()
            ids = macos_usb_product_ids()
            hit = [(v, p, n) for v, p, n in ids if v == VID_PRODUCT and p == PID_PRODUCT]
            if port or hit:
                break

    if hit:
        v, p, n = hit[0]
        return {
            "vid": v,
            "pid": p,
            "name": n,
            "serial": port or find_product_cdc(),
        }

    # Serial / pyserial alone is enough for product CDC on all OSes
    if port:
        return {
            "vid": VID_PRODUCT,
            "pid": PID_PRODUCT,
            "name": "Cryptick Token",
            "serial": port,
        }

    if require_device:
        pytest.fail("Cryptick product USB 1209:BEEE not found")
    pytest.skip("no Cryptick product USB (1209:BEEE)")


@pytest.fixture
def cdc(pytestconfig, product_usb, require_device):
    port = pytestconfig.getoption("--port") or product_usb.get("serial")
    try:
        from support.cryptick_usb import cdc_command, open_cdc

        ser = open_cdc(port)
        # Health: live app should answer HELP; hung product USB often enumerates only
        probe = cdc_command(ser, "HELP", wait_s=1.2)
        if not probe.strip():
            try:
                ser.close()
            except Exception:
                pass
            msg = "CDC silent (app hung or not running) — reflash product MODE=0"
            if require_device:
                pytest.fail(msg)
            pytest.skip(msg)
    except Exception as e:
        if require_device:
            pytest.fail(f"CDC open failed: {e}")
        pytest.skip(f"CDC open failed: {e}")
    yield ser
    try:
        ser.close()
    except Exception:
        pass


class _FidoSession:
    """Wrap hid.device — C extension may not allow setattr on the device."""

    __slots__ = ("dev", "cid")

    def __init__(self, dev, cid: int):
        self.dev = dev
        self.cid = cid

    def close(self):
        self.dev.close()


@pytest.fixture
def fido_hid(require_device, product_usb):
    try:
        import hid  # noqa: F401
    except ImportError:
        if require_device:
            pytest.fail("hidapi not installed (pip install hidapi)")
        pytest.skip("hidapi not installed")
    from support.cryptick_ctaphid import open_fido, HidError, ctaphid_init

    sess = None
    try:
        dev = open_fido()
        # Probe INIT early so hung stacks skip instead of long assert fails
        try:
            cid = ctaphid_init(dev, timeout_ms=1500)
            sess = _FidoSession(dev, cid)
        except HidError as e:
            try:
                dev.close()
            except Exception:
                pass
            msg = f"FIDO HID unresponsive: {e} — reflash or check main loop USB"
            if require_device:
                pytest.fail(msg)
            pytest.skip(msg)
    except HidError as e:
        if require_device:
            pytest.fail(str(e))
        pytest.skip(str(e))
    yield sess
    try:
        if sess is not None:
            sess.close()
    except Exception:
        pass
