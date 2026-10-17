# Cryptick Token — testing framework

Four layers. **CI always runs L0 + product `pio run`.** Device L2 is bench-local.

| Layer | Name | Tool | When |
|-------|------|------|------|
| **L0** | Host pure | `pytest tests/host` | Every commit / CI |
| **L1** | On-device Unity | `pio test -e test_*` | Board; or compile-only in `scripts/run_all_tests.sh` |
| **L1 (native)** | `test_nav` on the host | `pio test -e test_nav_native` | Every commit / CI — no board, and it actually *runs* (see `[env:test_nav_native]` in `platformio.ini`) |

| **L2** | Hardware integration | `pytest tests/device --device` | Product USB `1209:BEEE` attached |
| **L3** | Acceptance | Manual + scripts | Release / WebAuthn |

## Quick commands

```bash
# L0 only (what CI installs — pure Python, no USB libs)
pip install -r tests/requirements-host.txt
pytest tests/host -q

# Full bench install (adds pyserial + hidapi + fido2 for L2/L3)
pip install -r tests/requirements.txt

# test_nav, host-run — no board, no ESP32 toolchain download
pip install -U platformio
pio test -e test_nav_native

# L0 + L1 compile + L1 (native) + L2 (skips if no board)
chmod +x scripts/run_all_tests.sh
./scripts/run_all_tests.sh

# L2 only — require hardware (fail if missing)
./scripts/run_device_tests.sh
# or:
pytest tests/device -v --device
pytest tests/device --port /dev/cu.usbmodemCRYPTICK2 --device
```

## L2 design notes

- CDC open **must assert DTR** on macOS TinyUSB or the DATA interface is silent.
- Helpers: `tests/support/cryptick_usb.py`, `cryptick_ctaphid.py` (LIST/PUT/DELETE/CALCULATE, CTAP2 GetInfo).
- OATH lifecycle (`test_hid_oath_lifecycle.py`): place finger when OLED shows **Manage** / **Code** if templates exist.
- CTAP2 GetInfo: `test_hid_ctap2_getinfo.py`. Host register/assert: `scripts/tests/webauthn_ctap2_smoke.py` (see `docs/WEBAUTHN_L3.md`).
- Markers: `@pytest.mark.device`.
- Without a board attached, L2 **skips**; it never errors at collection. Missing
  `pyserial`/`hidapi` also skips, so a host-only checkout stays green.

## Shared helpers — do not re-implement

`tests/support/` is the single source of truth for talking to the device, and
the ad-hoc scripts under `scripts/tests/` import from it rather than carrying
their own copy of the framing:

| Module | Provides |
| --- | --- |
| `cryptick_ctaphid.py` | HID open, CTAPHID INIT/send, OATH APDU + TLV builders, CTAP2 GetInfo |
| `cryptick_usb.py` | Product CDC discovery, DTR-correct open, console command helper |
| `totp_secret_enc.py` | AES-GCM blob format mirror for host-side assertions |

A drifted second copy of CTAPHID framing is how the earlier smoke scripts ended
up silently broken. Add to these modules instead.

## Post-flash smoke

```bash
python scripts/post_flash_check.py /dev/cu.usbmodemCRYPTICK2
python scripts/serial_smoke.py
```

Expect button map `RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15` after a full boot capture.

## Product firmware

```bash
pio run -e esp32-s3-n16r8 -t upload
# recovery from JTAG:
./scripts/flash_product_usb.sh
```
