# Tests (`test/`)

PlatformIO **Unity** suites — one **folder per suite**. Each run builds a small firmware image, flashes the board, and reads results over **USB Serial/JTAG** (COM with VID `303A`).

## What’s here

| Path | Covers | Env |
| ---- | ------ | --- |
| `test_totp/` | Base32 + TOTP (`core/totp`) | `test_totp` |
| `test_event_bus/` | Event ring buffer | `test_event_bus` |
| `test_fp_enroll/` | Fingerprint enroll start (mock `Stream`) | `test_fp_enroll` |

Legacy flat file `test/test_totp.cpp` was moved into `test/test_totp/test_main.cpp` so each suite is isolated.

## What’s *not* here (yet)

There is no second “secret” test tree. Missing coverage lives on the backlog in `AGENTS.md` (P1/P2):

- RFC 6238 golden codes at fixed timestamps  
- `totp_storage` JSON round-trip  
- Full enroll FSM unit tests  
- Nav state machine via bus inject (no GPIO)  
- WebAuthn / FIDO smoke (host tools, not Unity)

Reason they were sparse before: product bring-up first; device Unity = full link + flash; OLED/buttons/real R557/CTAP need hardware or heavy mocks.

## Run

```bash
# One suite at a time (safer on Windows COM re-enum)
pio test -e test_event_bus
pio test -e test_totp
pio test -e test_fp_enroll

# All three (same order as ini)
pio test -e test_totp -e test_event_bus -e test_fp_enroll
```

Test envs force **`ARDUINO_USB_MODE=1`** (Serial/JTAG) and **disable LTO** so sparse `build_src_filter` links correctly. Do **not** use product env `esp32-s3-n16r8` for Unity (TinyUSB MODE=0).

If upload says **port busy / write timeout**: unplug USB-C, close serial monitors, re-plug, retry. Prefer flashing after the 303A COM is stable (`pio device list`).

## Product firmware smoke (not Unity)

```bash
pio run -e esp32-s3-n16r8 -t upload
python scripts/serial_smoke.py
# Expect VID 1209:BEEE “Cryptick Token” after unplug/replug if needed
```
