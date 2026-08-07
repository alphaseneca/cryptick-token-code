# Cryptick Token

Hardware security token for **Cryptick PCB v0.1.0** (ESP32-S3 N16R8): **TOTP + FIDO2 + fingerprint**.

- Agent guide: **[AGENTS.md](AGENTS.md)**
- Architecture: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**
- Host HID protocol: **[docs/HID_HOST.md](docs/HID_HOST.md)**
- Mac login (PIV roadmap): **[docs/MAC_LOGIN.md](docs/MAC_LOGIN.md)**
- Security: **[docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md)**

## Features

- OLED UI: clock, TOTP, settings, enroll, FIDO prompt / success
- R557 fingerprint (UI gate + FIDO user presence)
- USB composite: **CDC logs** + **FIDO HID** (CTAP + Cryptick OATH + ENTERBOOT)
- Firmware programming **without BOOT/RESET buttons**

## USB channels

| Interface | Use |
|-----------|-----|
| HID CTAPHID | WebAuthn FIDO2; put/list/calculate TOTP secrets; ENTERBOOT |
| CDC @ 115200 | Logs; `BOOTLOADER` reflash only (no product secret CLI) |
| CCID | Future PIV Mac login (scaffold) |

Brand: VID **`0x1209`** PID **`0xBEEE`** “Cryptick Token”.

## PCB pins

| Function | GPIO |
| -------- | ---- |
| RIGHT / DOWN / UP / LEFT / CENTER | **5 / 4 / 7 / 6 / 15** (active-low) |
| OLED SDA/SCL | 8 / 9 |
| Fingerprint RX/TX/IRQ | 17 / 18 / 16 (UART auto-swap at boot) |
| STAT1/STAT2 | 38 / 39 |

After flash, confirm:

```text
[IN] map  RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15
```

If directions are wrong, edit pin numbers in `include/board_config.h` only.

## Build & flash

```bash
pio run -e esp32-s3-n16r8
pio run -e esp32-s3-n16r8 -t upload
pio device monitor -e esp32-s3-n16r8 -b 115200
```

Programming: CTAPHID **ENTERBOOT**, **1200 bps** on CDC, or type `BOOTLOADER`. Then esptool/`pio` upload; hard_reset after flash.

## Enroll fingerprint

Settings → Enroll:

1. Place finger firmly → 2. Lift completely → 3. Place again → stored.

Watch `[FP] enroll …` lines.

## Tests

```bash
# Host L0 (no board)
pip install -r tests/requirements.txt && pytest tests/host -q

# Device Unity (needs board, MODE=1 test envs)
pio test -e test_totp -e test_event_bus -e test_fp_enroll
```

See **[test/README.md](test/README.md)**.

## Layout

```text
include/     board_config.h
drivers/     fingerprint, usb_device, usb_ccid scaffold
core/        totp, crypto, fido2, piv stub, ble_fido scaffold
src/systems  UI + FP + auth + battery
src/host     CDC logs, totp_storage, cryptick_oath_hid
tests/host   L0 pytest
test/        L1 Unity
scripts/tests  L2 HID smoke
```

**Security note:** TOTP secrets on LittleFS are **not encrypted** yet (`docs/SECURITY_ROADMAP.md`).
