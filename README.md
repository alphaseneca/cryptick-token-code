# Cryptick Token

Hardware security token on the **Cryptick PCB v0.1.0** (ESP32-S3-WROOM-1 N16R8):
**TOTP + FIDO2 + PIV smart card + fingerprint**, over USB-C and BLE.

The device enumerates as VID `0x1209` / PID `0xBEEE` "Cryptick Token" with a
factory-unique USB serial number, and exposes three USB interfaces at once: a
CDC console for logs, a HID interface carrying FIDO2/CTAP and OATH credential
management, and a CCID smart-card interface for the PIV applet. The same
FIDO2 and PIV surfaces are also reachable over BLE GATT. A fingerprint on the
R558-S sensor is the user-verification/presence gate shared by all of them.

## Documentation

| Doc | What it covers |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Subsystem diagram, layer diagram, threading model, event bus |
| [PROJECT.md](PROJECT.md) | Hardware, USB composite descriptor, PIV object model, real boot order |
| [docs/HID_HOST.md](docs/HID_HOST.md) | CTAPHID + OATH wire protocol |
| [docs/BLE_FIDO.md](docs/BLE_FIDO.md) | FIDO BLE transport (GATT `0xFFFD`), framing, pairing, arbitration with USB |
| [docs/MAC_LOGIN.md](docs/MAC_LOGIN.md) | PIV / CCID honest status — what's done, what needs hardware |
| [docs/LOGGING.md](docs/LOGGING.md) | Log levels, tags, `LOGLEVEL` command |
| [docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md) | Secret-at-rest design and what is *not* hardened yet |
| [docs/ATTESTATION.md](docs/ATTESTATION.md) | Batch attestation key, AAGUID, cert generation |
| [docs/WEBAUTHN_L3.md](docs/WEBAUTHN_L3.md) | Browser WebAuthn checklist |
| [test/README.md](test/README.md) | Test layers L0–L3 and how to run them |
| [docs/datasheets/](docs/datasheets/) | Fingerprint module manuals, PCB schematic |

`docs/index.html` is a standalone WebHID/Web Serial configuration dashboard —
open it in Chrome or Edge to manage credentials without the CLI. It has three
tabs: **WebHID** for OATH credential programming, **Web Serial** for the CDC
console, and **Device Settings** for sleep timeout, clock, log level,
attestation, and recovery.

## Features

- OLED UI: opening animation, clock, TOTP codes, scrolling settings, device
  info, fingerprint enroll, FIDO prompt/success, 5-way nav + SW2 rotary encoder
- R558-S fingerprint sensor gates the TOTP UI and supplies FIDO/PIV user
  presence; the same sensor also gates three destructive on-device actions
  (enroll, clear-FP, BLE unpair) behind a fresh touch, not just an existing
  unlock session
- FIDO2/CTAP2 credential management can be unlocked with a fingerprint
  instead of a PIN (CTAP2.1 `getPinUvAuthTokenUsingUvWithPermissions`) — see
  `core/fido2/ctap.c`
- PIV smart-card applet (`core/piv/`) over USB CCID and BLE — SELECT/GET
  DATA/PUT DATA/VERIFY/GENERATE/GENERAL AUTHENTICATE, host-tested; **CCID
  enumeration and BLE pairing are written but not yet confirmed on real
  hardware** — see [docs/MAC_LOGIN.md](docs/MAC_LOGIN.md)
- FIDO2 over BLE GATT (`0xFFFD`) alongside USB, with LESC+MITM passkey
  pairing shown on the OLED — see [docs/BLE_FIDO.md](docs/BLE_FIDO.md)
- Factory-unique USB serial number (`CT-XXXXXXXXXXXX`, derived from the
  ESP32-S3's eFuse MAC) for host-side device identity; also readable over
  CDC with `SERIAL`
- Idle screen sleep with CENTER wake — the panel powers down and the unlock
  session is dropped, while USB and FIDO keep answering the host
- TOTP secrets encrypted at rest (AES-256-GCM, wrap key in NVS)
- Reflash without BOOT pads: 1200 bps touch, `BOOTLOADER` command, or HID ENTERBOOT

## Product channels

| Interface | Role |
|-----------|------|
| USB CDC @ 115200 | Logs and console: `HELP`, `REBOOT`, `BOOTLOADER`, `LOGLEVEL`, `SLEEP`, `ATTEST`, `SERIAL`, `TOTP_*` |
| USB HID | FIDO2 / OATH / ENTERBOOT — see [docs/HID_HOST.md](docs/HID_HOST.md) |
| USB CCID | PIV smart-card applet; written and host-tested, **CCID enumeration unverified on real hardware** — see [docs/MAC_LOGIN.md](docs/MAC_LOGIN.md) |
| BLE GATT | FIDO2 (`0xFFFD`), PIV (`FBF6EB90-…`), and a daemon bridge service (`FBF6EB80-…`) on one NimBLE server; **written, unverified on real hardware** — see [docs/BLE_FIDO.md](docs/BLE_FIDO.md) |
| macOS port | `/dev/cu.usbmodem*` (the product CDC, not a CH340 `usbserial`) |

Web Serial needs 115200 **and** DTR asserted — TinyUSB only routes the CDC data
interface once the host raises DTR, so a port opened without it stays silent.

BLE and USB CCID are both compiled into the default product build (not an
opt-in lab flag) — see the `[cryptick] ble` / `ccid` fragments in
`platformio.ini`.

## PCB pins

| Function | GPIO |
| -------- | ---- |
| RIGHT / DOWN / UP / LEFT / CENTER | **5 / 4 / 7 / 6 / 15** (active-low) |
| SW2 rotary encoder CW / CCW | 40 / 41 (rotation only — the encoder's pushbutton is wired to GND on this PCB rev, not a GPIO) |
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
| `esp32-s3-n16r8` | Product (default): TinyUSB CDC + FIDO HID + CCID, BLE on, verbose logs |
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
drivers/       fingerprint_r558s, usb_device (CDC+HID), usb_ccid (PIV/CCID transport)
core/          totp, secret_crypto, cryptick_log, crypto_esp32
core/fido2/    vendored Solo CTAP stack + Cryptick ESP32 HAL
core/piv/      PIV applet (piv.c) + ESP32 HAL — compiled into the product build,
               host-tested; CCID/BLE binding unverified on hardware (MAC_LOGIN.md)
core/ble_fido/ BLE GATT transports: FIDO (0xFFFD), PIV, daemon bridge, HID keyboard
src/systems/   input (5-way + encoder), nav, display, fp, auth, battery, event_bus
src/host/      serial console, totp_storage, OATH-over-HID, credential_store
test/          L1 Unity suites (run on the board; test_nav also runs host-side)
tests/         L0 host pytest, L2 device pytest, BLE fuzz, shared support helpers
scripts/       flashing, post-flash smoke, test runners
```

**Security:** TOTP secrets are AES-256-GCM encrypted on LittleFS with a wrap key
in NVS. HID OATH management, FIDO2 credential management, and PIV private-key
operations all require a fingerprint once any template is enrolled, funneled
through the same presence gate (`core/fido2/hal_esp32.cpp`) — see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#subsystem-map). The NVS wrap key is
**not** eFuse-locked yet — see [docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md)
for the honest threat model.
