# Cryptick Token — agent guide

This file orients **agents and humans** working on the Cryptick Token firmware.

Primary path: `esp32-s3-n16r8` only (PCB v0.1.0, ESP32-S3-WROOM-1 N16R8).

---

## Why Serial was empty (root cause, fixed in source)

The PlatformIO board profile **`esp32-s3-devkitc-1` forces `-DARDUINO_USB_MODE=1`** (Espressif USB Serial/JTAG, VID `303A`). That wins over Adafruit TinyUSB unless you:

```ini
build_unflags = -DARDUINO_USB_MODE=1
build_flags = -DARDUINO_USB_MODE=0 -DARDUINO_USB_CDC_ON_BOOT=1
```

(Do **not** fight `-DCFG_TUD_CDC=1` against the Adafruit port default.)

When MODE=1, Windows only shows **COM with VID 303A** and the app CDC/FIDO composite never appears → **nothing useful on serial**.

When MODE=0 works, open the COM with **VID `1209` PID `BEEE` "Cryptick Token"**, not the 303A port.

**Channel model**

| Channel | Role |
|---------|------|
| USB HID CTAPHID | FIDO2 + OATH (TOTP secrets) + ENTERBOOT |
| USB CDC | Logs only (optional debug CLI if `CRYPTICK_SERIAL_DEBUG_CMDS`) |
| USB CCID | Future PIV / Mac login (scaffold only) |

See `docs/HID_HOST.md`.

---

## Product goal

Battery-powered **hardware security token**:

| Area | Goal |
| ---- | ---- |
| **TOTP** | OLED codes after FP; secrets via **HID OATH**, stored LittleFS |
| **FIDO2** | USB HID CTAPHID security key; fingerprint = user presence |
| **Fingerprint** | Gate TOTP UI; enroll 2-place R557; clear templates |
| **USB-C** | One cable: logs CDC + FIDO HID + firmware programming |
| **No BOOT buttons** | Enter ROM download via HID ENTERBOOT, 1200 bps, or `BOOTLOADER` |

Brand: VID `0x1209`, PID `0xBEEE`, product **Cryptick Token**.

---

## Architecture (layers)

```text
board_config → drivers (USB, R557) → core (TOTP, Solo FIDO) → systems + host → main
  host: serial (logs), totp_storage, cryptick_oath_hid
```

**Ownership rules**

- Only `input_system` reads button GPIOs.
- Only `display_system` draws the OLED.
- Cross-system communication: `event_bus` (or FIDO `_fido_ui_request` / `ctaphid_confirm_*`).
- Do not reintroduce full product BLE without enabling scaffold deliberately; no SSD1306 stubs / Super Mini / ESP8266 envs.

---

## PCB pin map (product)

| Function | GPIO |
| -------- | ---- |
| RIGHT | **5** |
| DOWN | **4** |
| UP | **7** |
| LEFT | **6** |
| CENTER | **15** |
| OLED SDA / SCL | 8 / 9 |
| FP ESP_RX / ESP_TX / IRQ | 17 / 18 / 16 (boot auto-swaps UART if needed) |
| STAT1 / STAT2 | 38 / 39 |

Buttons are **active-low** (pull-up, press → GND).

**Verify after every flash:** serial line  
`[IN] map  RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15`  
Press each key once; log must show the **physical** direction, e.g. physical UP → `[IN] UP (GPIO7)`.

If directions are wrong, change the **pin numbers** in `include/board_config.h` only (never soft-remap keys in nav).

---

## Build, flash, test

```bash
# Order: unit tests → product flash (hard_reset exits ROM) → product smoke
pio test -e test_event_bus --upload-port COMxx
pio test -e test_totp --upload-port COMxx
pio test -e test_fp_enroll --upload-port COMxx
pio run -e esp32-s3-n16r8 -t upload --upload-port COMxx
python scripts/post_flash_check.py COMxx
# expect map RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15
```

UART CH340 TX/RX: `default_reset` + **`hard_reset` after flash** (leaves download).  
USB: type `BOOTLOADER`, upload, esptool must hard-reset when done.

---

## Fingerprint enroll (correct flow)

1. Settings → Enroll **or** serial `FINGER_ENROLL` (non-blocking).
2. Hold finger firmly until step advances.
3. **Lift completely** when serial/OLED says remove.
4. Place **same** finger again until stored.
5. Abort: LEFT or `FINGER_ABORT`.

Watch serial: `[FP] enroll place…` / `remove…` / `enrolled id=…`.

Do **not** use long blocking `enrollFingerprint` on the main loop (freezes USB).

---

## Known gaps / backlog for agents

Work these in order unless the user prioritizes otherwise:

### P0 — hardware bring-up (must be solid before feature work)

- [ ] Confirm button map with serial after flash; fix `board_config.h` pins only if wrong
- [ ] Stable enroll 2-step on UI + serial; no hang at free-id
- [ ] Reliable USB re-flash (1200bps / `BOOTLOADER`)
- [ ] FP UART orientation auto-detect stays correct

### P1 — correctness & tests

- [ ] TOTP RFC 6238 golden vectors (exact code at fixed timestamps)
- [ ] totp_storage JSON round-trip test
- [ ] enrollPoll state machine unit test (mock Stream)
- [ ] nav state transitions tested without GPIO (bus inject)

### P2 — FIDO product completeness

- [ ] WebAuthn register/assert smoke
- [ ] Decide: PIN / resident keys / attestation cert strategy (`core/FEATURES_TODO.md`)
- [x] Wire `UI_FIDO_SUCCESS` (post-presence flash)

### P3 — security / ship

- [ ] Encrypt TOTP secrets at rest (today: plaintext LittleFS) — `docs/SECURITY_ROADMAP.md`
- [ ] Optional FP-gate sensitive OATH HID ops
- [x] CI: `pio run` + host `pytest` (`.github/workflows/ci.yml`)

### Mac login (PIV)

- [ ] USB CCID composite + full PIV 9a/9d — scaffold in `core/piv` + `docs/MAC_LOGIN.md`

### Do not do by default

- BLE (stubs removed; not in product MVP)
- ESP8266 / Super Mini ports
- Soft key remapping tables; change GPIO numbers only

---

## Coding conventions

1. Pins and product timeouts live only in `board_config.h`.
2. New sources must be listed in `platformio.ini` `build_src_filter`.
3. Prefer minimal diffs; match existing `*_system_*` naming.
4. Preserve USB bootloader path (`--wrap=TinyUSB_Port_EnterDFU`, `usb_device_enter_bootloader`).
5. FIDO user presence = **fingerprint only**, not nav keys.
6. No WiFi time — set clock via `SETTIME` / `DATE`.
7. Document honestly: secrets not encrypted unless implemented.

---

## Tree map (keep vs gone)

| Path | Role |
| ---- | ---- |
| `include/board_config.h` | Pins + constants |
| `drivers/fingerprint_r558s.*` | R557 protocol |
| `drivers/usb_device.*` | CDC + FIDO HID + bootloader |
| `src/systems/*` | App systems |
| `src/host/*` | Serial CLI + storage |
| `core/totp.*` | TOTP algo |
| `core/fido2/*` | CTAP stack |
| `test/test_totp.cpp` | Unity TOTP tests |
| `docs/ARCHITECTURE.md` | Layer diagram detail |
| `README.md` | User-facing |

**Removed:** Super Mini / ESP8266 envs, `display_ssd1306`, `ble`, empty `usb_hid` stubs, `fido_bridge`, `EspSoftwareSerial`, `device_hal` shim under `src/`.

---

## When something “doesn’t work”

| Symptom | Likely cause |
| ------- | ------------ |
| Buttons swapped like always | **Old firmware still running** — look for outdated `[IN] map` line |
| Enroll appears dead | Free-id hang (fixed: no slow LoadChar scan); or finger never fully lifted |
| Upload COM busy | Serial mon open, or Windows USB glitch — re-plug |
| Wrong `[IN] NAME` for physical press | Edit pin `#define`s in `board_config.h`, flash again |

---

## How agents should multitask

Parallelize safely:

1. One agent: bring-up (buttons/FP/USB) + flash  
2. One agent: tests (`test_totp` golden + storage)  
3. One agent: FIDO/docs only if not stepping on bring-up files  

Do not two agents rewrite `board_config.h` / `fingerprint_r558s.cpp` / `usb_device.cpp` / `input_system.cpp` at once.
