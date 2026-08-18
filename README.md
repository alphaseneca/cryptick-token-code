# Cryptick Token

Hardware security token on the **Cryptick PCB v0.1.0** (ESP32-S3-WROOM-1 N16R8):
**TOTP + FIDO2 + fingerprint**, over a single USB-C cable.

The device enumerates as VID `0x1209` / PID `0xBEEE` "Cryptick Token" and
exposes two interfaces at once: a CDC console for logs and a HID interface
carrying FIDO2/CTAP and OATH credential management.

## Documentation

| Doc | What it covers |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Working agreement for agents and humans; backlog |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layer diagram, threading model, event bus |
| [docs/HID_HOST.md](docs/HID_HOST.md) | CTAPHID + OATH wire protocol |
| [docs/LOGGING.md](docs/LOGGING.md) | Log levels, tags, `LOGLEVEL` command |
| [docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md) | Secret-at-rest design and what is *not* hardened yet |
| [docs/ATTESTATION.md](docs/ATTESTATION.md) | Batch attestation key, AAGUID, cert generation |
| [docs/WEBAUTHN_L3.md](docs/WEBAUTHN_L3.md) | Browser WebAuthn checklist |
| [docs/MAC_LOGIN.md](docs/MAC_LOGIN.md) | PIV / CCID roadmap (scaffold only) |
| [test/README.md](test/README.md) | Test layers L0–L3 and how to run them |
| [docs/datasheets/](docs/datasheets/) | Fingerprint module manuals, PCB schematic |

`docs/index.html` is a standalone WebHID/Web Serial configuration dashboard —
open it in Chrome or Edge to manage credentials without the CLI. It has three
tabs: **WebHID** for OATH credential programming, **Web Serial** for the CDC
console, and **Device Settings** for sleep timeout, clock, log level,
attestation, and recovery.

## Features

- OLED UI: opening animation, clock, TOTP codes, scrolling settings, device
  info, fingerprint enroll, FIDO prompt/success
- R558-S fingerprint sensor gates the TOTP UI and supplies FIDO user presence
- Idle screen sleep with CENTER wake — the panel powers down and the unlock
  session is dropped, while USB and FIDO keep answering the host
- TOTP secrets encrypted at rest (AES-256-GCM, wrap key in NVS)
- Reflash without BOOT pads: 1200 bps touch, `BOOTLOADER` command, or HID ENTERBOOT

## Product channels

| Interface | Role |
|-----------|------|
| USB CDC @ 115200 | Logs and console: `HELP`, `REBOOT`, `BOOTLOADER`, `LOGLEVEL`, `SLEEP`, `ATTEST`, `TOTP_*` |
| USB HID | FIDO2 / OATH / ENTERBOOT — see [docs/HID_HOST.md](docs/HID_HOST.md) |
| macOS port | `/dev/cu.usbmodem*` (the product CDC, not a CH340 `usbserial`) |

Web Serial needs 115200 **and** DTR asserted — TinyUSB only routes the CDC data
interface once the host raises DTR, so a port opened without it stays silent.

## PCB pins

| Function | GPIO |
| -------- | ---- |
| RIGHT / DOWN / UP / LEFT / CENTER | **5 / 4 / 7 / 6 / 15** (active-low) |
| OLED SDA / SCL | 8 / 9 |
| Fingerprint RX / TX / IRQ | 17 / 18 / 16 (UART orientation auto-detected at boot) |
| STAT1 / STAT2 | 38 / 39 |

Pins live only in `include/board_config.h`. If a physical direction reports the
wrong name, change the GPIO number there — never remap keys in `nav_system`.

After flashing, the product CDC should print:

```text
[USB] CDC ready…
[IN] map  RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15
[DISP] OK …
[BOOT] Ready
```

## Build and flash (macOS)

```bash
# First load, or recovery while the board is still Espressif Serial/JTAG (303A)
./scripts/flash_product_usb.sh

# Normal reflash once the product CDC is running (1200 bps touch → ROM)
pio run -e esp32-s3-n16r8 -t upload

# Watch the console
pio device monitor -e esp32-s3-n16r8 -b 115200 --port /dev/cu.usbmodemXXXX
```

Build environments:

| Environment | Purpose |
| --- | --- |
| `esp32-s3-n16r8` | Product (default): TinyUSB CDC + FIDO HID, verbose logs |
| `esp32-s3-n16r8-ship` | Product with a quiet console (`DEBUG_LEVEL=0`) |
| `esp32-s3-n16r8-install` | First load / recovery over USB Serial-JTAG |
| `esp32-s3-n16r8-jtag` | Lab fallback: Serial/JTAG logs only, no FIDO HID |

### Stuck or silent serial

1. Unplug USB-C, wait 2 s, replug, then run `./scripts/flash_product_usb.sh`
2. If the CDC is alive: type `BOOTLOADER`, or use a host 1200 bps touch, or HID ENTERBOOT
3. Logs-only lab build (no FIDO HID): `pio run -e esp32-s3-n16r8-jtag -t upload`

## Enroll a fingerprint

From the clock, press CENTER → Settings → Enroll:

1. Place the finger firmly and hold until the screen advances
2. Lift completely when prompted
3. Place the same finger again — the template is stored

LEFT aborts. Follow along with the `[FP]` lines on the console.

## Screen sleep

The OLED blanks after 45 s idle by default. The fingerprint matcher stops and the
unlock session is dropped at the same time, so a token that goes dark is also
locked. **USB and FIDO stay up** — the host can still use the key with the screen
off, which is why this is not an `esp_sleep`.

Press **CENTER** to wake; a host presence request wakes it too. Change the
timeout from Settings → Sleep, from the Device Settings tab of
`docs/index.html`, or over the console:

```text
SLEEP          # show current timeout and whether the screen is asleep
SLEEP 120      # blank after 2 minutes
SLEEP OFF      # never blank
SLEEP NOW      # blank immediately
WAKE
```

All three routes persist the value in NVS.

## Tests

```bash
# L0 host (no hardware)
pip install -r tests/requirements-host.txt
pytest tests/host -q

# Everything runnable on this machine (L0 + L1 compile + L2 if a board is attached)
./scripts/run_all_tests.sh

# L1 Unity on a connected board
pio test -e test_totp
```

Full layer breakdown in [test/README.md](test/README.md).

## Layout

```text
include/       board_config.h (pins), cryptick_log.h, cryptick_console.h
drivers/       fingerprint_r558s, usb_device (CDC+HID), usb_ccid (scaffold)
core/          totp, secret_crypto, cryptick_log, crypto_esp32
core/fido2/    vendored Solo CTAP stack + Cryptick ESP32 HAL
core/piv/      PIV APDU stub for the Mac-login roadmap (not compiled yet)
src/systems/   input, nav, display, fp, auth, battery, event_bus
src/host/      serial console, totp_storage, OATH-over-HID, credential_store
test/          L1 Unity suites (run on the board)
tests/         L0 host pytest, L2 device pytest, shared support helpers
scripts/       flashing, post-flash smoke, test runners
```

**Security:** TOTP secrets are AES-256-GCM encrypted on LittleFS with a wrap key
in NVS. HID OATH management requires a fingerprint once any template is
enrolled. The NVS wrap key is **not** eFuse-locked yet — see
[docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md) for the honest threat model.
