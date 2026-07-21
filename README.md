# Cryptick Token

A hardware TOTP (Time-based One-Time Password) authenticator with optional fingerprint protection. Built with ESP8266, OLED display, DS3231 RTC, and optional R558-S fingerprint sensor. Configuration is done over **serial** (57600 baud); no WiFi or web server.

## Features

- **RFC 6238 TOTP** — Standard 6/8-digit codes, 30s period, Base32 secrets
- **OLED UI** — 128×64 display: clock, TOTP (label, issuer, code, countdown), settings placeholder
- **Optional fingerprint (R558-S)** — Only the clock page is public; TOTP and other pages require verification. Auth is cleared only on **inactivity timeout** (configurable, e.g. 30s). Green LED on success (2s), red on fail; LED off when auth cleared
- **Serial configuration** — Add/list/delete accounts and set time via line-based commands (see [Serial commands](#serial-commands))
- **otpauth URI** — Add accounts with `TOTP_ADD otpauth://totp/...` (compatible with Google Authenticator / Key URI format)
- **RTC** — DS3231 for accurate time; set via `DATE <unix_ts>` or `SETTIME <unix_ts>`
- **Persistent storage** — Credentials in LittleFS (`/totp_config.json`), standard keys: `label`, `secret`, `issuer`, `digits`, `period`
- **Button navigation** — Single button: clock ↔ TOTP, cycle accounts

## Hardware

### Supported board

- **HW364A** (NodeMCU-style ESP-12E) with built-in OLED

### Pinout (config in `src/config.h`)

| Function       | Pin                                     |
| -------------- | --------------------------------------- |
| OLED SDA       | GPIO14 (D5)                             |
| OLED SCL       | GPIO12 (D6)                             |
| RTC            | Same I2C (SDA/SCL)                      |
| Button         | GPIO0 (FLASH)                           |
| Fingerprint RX | GPIO13 (D7) — when `ENABLE_FINGERPRINT` |
| Fingerprint TX | GPIO15 (D8) — when `ENABLE_FINGERPRINT` |

### Optional: R558-S fingerprint

- Enable in `src/config.h`: `#define ENABLE_FINGERPRINT`
- Comment out that line to disable; then all pages are reachable without verification.

## Installation

### PlatformIO

```bash
git clone <repository-url>
cd cryptick-token
pio run -e hw364a -t upload
pio device monitor -b 57600
```

### Dependencies (PlatformIO)

- Adafruit SSD1306, Adafruit GFX
- RTClib
- ArduinoJson
- TOTP (RFC 6238)
- LittleFS (ESP8266)
- Optional: SoftwareSerial, R558-S driver (when `ENABLE_FINGERPRINT`)

## Quick start

1. **Flash** the firmware and open serial at **57600 baud**.
2. **Set time** (Unix timestamp, UTC):
   ```text
   SETTIME 1739347200
   ```
   Or use `DATE` to show current time, and `DATE <unix_ts>` to set.
3. **Add account** (otpauth URI):
   ```text
   TOTP_ADD otpauth://totp/MyService:user%40mail.com?secret=JBSWY3DPEHPK3PXP&issuer=MyService&digits=6&period=30
   ```
4. **On device** — Press button: clock → (if fingerprint enabled) verify finger → TOTP page. Button again cycles accounts or returns to clock. After inactivity timeout (e.g. 30s), device returns to clock and auth is cleared.

## Serial commands

Line-based: one command per line, newline terminator. All time is **Unix/POSIX** (seconds since 1970-01-01 00:00:00 UTC).

| Command                  | Description                                                    |
| ------------------------ | -------------------------------------------------------------- |
| `DATE`                   | Show current date/time and Unix timestamp                      |
| `DATE <unix_ts>`         | Set RTC (alias for SETTIME)                                    |
| `SETTIME <unix_ts>`      | Set RTC from Unix timestamp                                    |
| `TOTP_ADD <otpauth_uri>` | Add credential. Use `otpauth://totp/...` or `otp://totp/...`   |
| `TOTP_LIST`              | List credentials (index, label, issuer, digits, period)        |
| `TOTP <index>`           | Generate current TOTP for credential at index                  |
| `TOTP_DELETE <index>`    | Delete credential at index and save                            |
| `HELP` or `?`            | Show command list                                              |
| `FINGER_ENROLL` [id]     | Enroll fingerprint (optional id). Only when ENABLE_FINGERPRINT |
| `FINGER_DELETE <id>`     | Delete fingerprint by id                                       |
| `FINGER_COUNT`           | Number of stored fingerprints                                  |
| `FINGER_CLEAR`           | Clear all fingerprints                                         |

No legacy aliases (TIME, ACCOUNTS, LIST, ADD, DELETE, GET); only the above are accepted. Full reference: `src/serial_comm.h`.

## Display and navigation

- **Clock** — Date, time, user, battery (placeholder). No auth required.
- **TOTP** — Account label, issuer, 6-digit code, countdown. Requires fingerprint when enabled.
- **Auth prompt** — “Place your finger on sensor” when opening TOTP with fingerprint enabled.
- **Auth error** — “Fingerprint could not be verified” on wrong finger; then return to clock.

**Inactivity** — If no button press for `INACTIVITY_TIMEOUT_SEC` (see `src/config.h`) while not on clock, device goes to clock and clears auth. Auth is **not** cleared when you press button to go back to clock; only on timeout.

## Configuration

Edit `src/config.h`:

- **Pins** — OLED, RTC, button, fingerprint (when used)
- **ENABLE_FINGERPRINT** — Define to enable R558-S and fingerprint-gated pages; comment out to disable
- **INACTIVITY_TIMEOUT_SEC** — Seconds without button press before return to clock and clear auth (e.g. 30)
- **AUTH_ERROR_DISPLAY_MS** — How long to show “Fingerprint could not be verified” (e.g. 2000)
- **FINGERPRINT*LED*** — LED colors (ready, error, match, etc.)

## Project structure

```text
cryptick-token/
├── core/           # Hardware-independent: TOTP, device HAL, storage HAL
├── src/            # Main, config, auth_handler, display_handler, navigation, serial_comm, storage
├── drivers/        # display_ssd1306, fingerprint_r558s
├── test/           # Unity tests (e.g. test_totp)
├── docs/           # Implementation plan, index.html (serial dashboard)
└── platformio.ini
```

- **Auth** — `src/auth_handler`: page-to-show, clear, set_authenticated, verify_failed, LED callbacks, record_activity, check_inactivity.
- **Navigation** — `src/navigation`: button-driven page changes; calls auth_handler for activity and (when returning to clock) no longer clears auth; only inactivity in auth_handler clears it.
- **Storage** — Standard otpauth keys only: `label`, `secret`, `issuer`, `digits`, `period` in `accounts[]`.

## Troubleshooting

- **OLED not working** — Check I2C (SDA/SCL), 3.3V, address 0x3C.
- **RTC error** — Same I2C bus, backup battery, correct time via `SETTIME`/`DATE <ts>`.
- **TOTP mismatch** — Set RTC correctly; use `DATE` to confirm; ensure secret is Base32 (A–Z, 2–7).
- **Serial** — 57600 baud, one command per line, newline at end.

## Security notes

- Secrets are stored in flash (LittleFS), not encrypted.
- Physical access can allow access to secrets; keep device secure.
- Fingerprint protects only the device UI; serial access (if exposed) can still run commands.

## License

MIT. See LICENSE file.

---

**Built with ❤️ for hardware 2FA enthusiasts**
