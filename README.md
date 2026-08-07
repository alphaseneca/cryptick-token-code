# Cryptick Token

Hardware security token for **Cryptick PCB v0.1.0** (ESP32-S3 N16R8): **TOTP + FIDO2 + fingerprint**, configured over USB serial.

Full agent/product backlog: **[AGENTS.md](AGENTS.md)** · Architecture: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**

## Features

- OLED UI: clock, TOTP, settings, enroll, FIDO prompt
- R557 fingerprint (UI gate + FIDO user presence)
- USB composite: CDC CLI @ 115200 + FIDO HID
- Firmware USB programming **without BOOT/RESET buttons**

## PCB pins

| Function | GPIO |
| -------- | ---- |
| RIGHT / DOWN / UP / LEFT / CENTER | **5 / 4 / 7 / 6 / 15** (active-low) |
| OLED SDA/SCL | 8 / 9 |
| Fingerprint RX/TX/IRQ | 17 / 18 / 16 (UART auto-swap at boot) |
| STAT1/STAT2 | 38 / 39 |

After flash, open serial and confirm:

```text
[IN] map  RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15
```

Press each direction — the printed name **must** match the physical key. If not, fix numbers in `include/board_config.h` and re-upload (not a soft remap).

## Build & flash

```bash
pio run -e esp32-s3-n16r8
pio run -e esp32-s3-n16r8 -t upload   # close Serial Monitor first
pio device monitor -e esp32-s3-n16r8 -b 115200
```

**Programming path:** 1200bps touch on running CDC, or type `BOOTLOADER` then upload to the download COM.  
Stuck port: unplug USB-C and re-plug.

## Serial CLI

| Command | Action |
| ------- | ------ |
| `DATE` / `SETTIME <unix>` | RTC |
| `TOTP_ADD <otpauth_uri>` | Add account |
| `TOTP_LIST` / `TOTP <i>` / `TOTP_DELETE <i>` | Manage TOTP |
| `FINGER_ENROLL` / `FINGER_ABORT` | Async enroll |
| `FINGER_COUNT` / `FINGER_CLEAR` / `FINGER_DELETE <id>` | Templates |
| `BOOTLOADER` | Enter ROM download |
| `FIDO_RESET` | Wipe FIDO NVS |
| `HELP` | List commands |

## Enroll fingerprint

Settings → Enroll, **or** `FINGER_ENROLL`:

1. Place finger firmly → 2. Lift completely → 3. Place again → stored.

Watch `[FP] enroll …` lines. Lift failures advance incorrectly if the finger never fully leaves the window — hold clear of the sensor when asked.

## Tests

```bash
pio test -e esp32-s3-n16r8 -f test_totp
```

## Layout

```text
include/     board_config.h
hal/         device HAL headers
drivers/     fingerprint, usb_device
core/        totp, crypto, fido2
src/systems  UI + FP + auth + battery
src/host     serial CLI, storage
test/        Unity tests
```

## Troubleshooting

| Issue | Check |
| ----- | ----- |
| Directions wrong after map fix | Serial still shows **old** `[IN] map` → flash never landed / stale bin |
| Enroll hangs | Serial logs; ensure lift step; `FINGER_ABORT` |
| Upload fail | Close COM tools; re-plug; `upload_port = COMx` |
| OLED blank | I2C 8/9, 3.3 V |
| TOTP wrong codes | `SETTIME` / RTC |

## Security notes

- TOTP secrets in LittleFS are **not encrypted**.
- Serial USB can manage credentials without a fingerprint.
- Physical access allows flash readout.

## License

See repository license if present.
