# Tests

Multi-layer framework for Cryptick Token.

## Layers

| Layer | When | Tooling | Path |
|-------|------|---------|------|
| **L0 Host** | Every PR / every commit locally | `pytest` | `tests/host/` |
| **L1 Device Unity** | Board attached | PlatformIO Unity | `test/test_*/` |
| **L2 Integration** | Hardware bench | Python hidapi scripts | `scripts/tests/` |
| **L3 Acceptance** | Release | checklists | `docs/MAC_LOGIN.md`, WebAuthn manual |

Shared vectors: `tests/vectors/` (L0 and L1 should stay aligned).

## L0 — host (no board)

```bash
pip install -r tests/requirements.txt
pytest tests/host -q
# or
scripts/ci/run_host_tests.sh
```

Covers RFC 6238 TOTP, OATH TLV/APDU shape, PIV SELECT AID builders.

## L1 — device Unity

```bash
pio test -e test_event_bus
pio test -e test_totp
pio test -e test_fp_enroll
```

Test envs force `ARDUINO_USB_MODE=1` and disable LTO. **Do not** use product env `esp32-s3-n16r8` for Unity.

| Path | Covers | Env |
|------|--------|-----|
| `test_totp/` | Base32 + TOTP | `test_totp` |
| `test_event_bus/` | Event ring | `test_event_bus` |
| `test_fp_enroll/` | Enroll mock Stream | `test_fp_enroll` |

## L2 — hardware HID

```bash
python scripts/tests/hid_fido_init.py    # CTAPHID_INIT, skip if no device
python scripts/tests/hid_oath_smoke.py   # OATH LIST
```

Requires `pip install hid` and a board showing VID `1209` PID `BEEE`. **Never** enable ENTERBOOT in CI.

## Product firmware

```bash
pio run -e esp32-s3-n16r8
# upload…
python scripts/post_flash_check.py COMxx
```

## CI

`.github/workflows/ci.yml` runs **L0 pytest** + **`pio run -e esp32-s3-n16r8`**.

Channel model: HID = FIDO + OATH + ENTERBOOT; CDC = logs — see `docs/HID_HOST.md`.
