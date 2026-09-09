# Cryptick Token — agent guide

This file orients **agents and humans** working on the Cryptick Token firmware.

Primary path: `esp32-s3-n16r8` only (PCB v0.1.0, ESP32-S3-WROOM-1 N16R8).

---

## Console & flash (product USB)

**Default product env = TinyUSB CDC+HID** (`CRYPTICK_USB_STACK=1`, `ARDUINO_USB_MODE=0`).
Host console is **device USB-C**: VID `0x1209` PID `0xBEEE` “Cryptick Token”.

**Lab fallback env** `esp32-s3-n16r8-jtag`: Serial/JTAG only (VID `303A`) — logs, no FIDO HID.

macOS ports:
- Product CDC: typically `/dev/cu.usbmodem*` (not COM)
- ROM download after 1200bps / `BOOTLOADER`: often same class, Espressif bootloader
- Optional UART programmer: `/dev/cu.usbserial-*` (CH340)

```bash
# Product (default) — MODE=0 CDC+HID 1209:BEEE
pio run -e esp32-s3-n16r8 -t upload
# or: python3 scripts/flash_product_usb.py

# Lab Serial/JTAG if product USB does not appear
pio run -e esp32-s3-n16r8-jtag -t upload

pio device monitor -b 115200 --port /dev/cu.usbmodemXXXX
ls /dev/cu.*
```

**Reflash without BOOT pads (MODE=0):**
1. PlatformIO `use_1200bps_touch` (open CDC @ 1200 → ROM), or
2. Serial `BOOTLOADER` / `DFU` / `DOWNLOAD`, or
3. HID `CTAPHID_ENTERBOOT`, or
4. CH340 UART esptool + hard_reset

Upload product: `use_1200bps_touch = true`, `--after=hard_reset`. Soft app restart: `REBOOT`.
Stuck download: `esptool.py --port /dev/cu.… run --after hard_reset` or power-cycle.

| Channel | Role |
|---------|------|
| USB CDC | Logs @ 115200 + console (`HELP`, `LOGLEVEL`, `SLEEP`, `ATTEST`, `TOTP_*`, `OATH`) |
| USB HID | FIDO2 / OATH / ENTERBOOT |
| CH340 | Programming only if used; leave unplugged for product use |

See `docs/HID_HOST.md`. `docs/index.html` is a browser dashboard over the same
two channels — WebHID for OATH, Web Serial (115200 + DTR) for the console and
the Device Settings tab.

---

## Product goal

Battery-powered **hardware security token**:

| Area | Goal |
| ---- | ---- |
| **TOTP** | OLED codes after FP; secrets via **HID OATH**, stored LittleFS |
| **FIDO2** | USB HID CTAPHID security key; fingerprint = user presence |
| **Fingerprint** | Gate TOTP UI; 2-place enroll on the R558-S (`docs/datasheets/R558S-fingerprint-module-manual-v1.1.pdf`); clear templates |
| **USB-C** | One cable later: logs CDC + FIDO HID + programming |
| **No BOOT buttons** | UART esptool now; later HID ENTERBOOT / 1200 bps / `BOOTLOADER` |

Brand: VID `0x1209`, PID `0xBEEE`, product **Cryptick Token**.

---

## Architecture (layers)

```text
board_config → drivers (USB gated, R558-S) → core (TOTP, Solo FIDO, BLE FIDO) → systems + host → main
  host: serial (CDC logs + console), totp_storage, cryptick_oath_hid
```

**Ownership rules**

- Only `input_system` reads button GPIOs.
- Only `display_system` draws the OLED.
- Only `nav_system` changes `UiState`; `event_bus.h`'s enum is append-only.
- Cross-system communication: `event_bus` (or FIDO `_fido_ui_request` / `ctaphid_confirm_*`).
- BLE is a **product transport**, not a scaffold: `core/ble_fido/` implements the
  FIDO BLE wire format (GATT `0xFFFD`), which is *not* CTAPHID tunnelled over BLE.
  It is a second producer feeding the one FIDO task — never a second caller of
  `ctap_request()`. See [docs/BLE_FIDO.md](docs/BLE_FIDO.md).
- No SSD1306 stubs, Super Mini, or ESP8266 envs.

**Sleep.** `UI_SLEEP` powers the OLED down, stops the fingerprint matcher and
drops the unlock session after `UI_SLEEP_TIMEOUT_SEC`. The MCU and USB stay up —
this is a security key and the host must still reach it for FIDO with the screen
dark, so there is no `esp_sleep` anywhere. CENTER wakes it (the press is consumed
by the wake), and so does any host presence request. Full rules in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#ui-states-and-idle-sleep).

**Threading.** The Arduino loop runs on core 1 and owns every `*_system`; the
FIDO task runs on core 0. The FIDO task must never call `nav_system_*` or
`display_system_*` directly — park a caption with `device_set_ui_label()` and
let the loop drain it. Shared state needs an explicit lock; the full table is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#threading-model). `volatile` is not a
substitute for a critical section on multi-field ring buffers.

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

**Verify after every flash (CH340):**  
`[IN] map  RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15`  
Press each key once; log must show the **physical** direction, e.g. physical UP → `[IN] UP (GPIO7)`.

If directions are wrong, change the **pin numbers** in `include/board_config.h` only (never soft-remap keys in nav).

---

## Build, flash, test

Order: host tests → Unity on board → product flash → post-flash smoke.

```bash
# L0 — no hardware
pip install -r tests/requirements-host.txt && pytest tests/host -q

# L1 — on the board (PORT is a /dev/cu.usbmodem* path on macOS)
for e in test_totp test_event_bus test_fp_enroll test_nav test_secret_crypto; do
  pio test -e "$e" --upload-port "$PORT"
done

# Product flash + smoke
pio run -e esp32-s3-n16r8 -t upload
python3 scripts/post_flash_check.py          # auto-detects 1209:BEEE
# expect [DISP], map RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15, [BOOT] Ready

# L2 — hardware-in-the-loop
./scripts/run_device_tests.sh
```

`./scripts/run_all_tests.sh` runs L0, compiles every L1 suite without a board,
and runs L2 (skipping cleanly if nothing is attached).

---

## On-device UI

```text
CLOCK ──CENTER──▶ MENU ──▶ TOTP (fingerprint-gated)
                    └────▶ SETTINGS ─┬─▶ Enroll finger
                                     ├─▶ Clear FP (n)
                                     ├─▶ Sleep: 45s   (CENTER cycles presets)
                                     └─▶ Device info  (USB / FP / accounts / uptime)
SLEEP ──CENTER──▶ CLOCK        (idle timeout; host request also wakes)
```

The settings list scrolls with a scrollbar once it exceeds three rows — add
entries to `SettingsItem` plus `nav_system_settings_label()`, never to a
hardcoded array in `display_system`.

Screen sleep is configurable three ways, all persisted in NVS:
Settings → Sleep, console `SLEEP <sec|NOW|OFF>` / `WAKE`, or the Device Settings
tab in `docs/index.html`.

---

## Fingerprint enroll (correct flow)

1. Clock **CENTER** → menu → Settings → Enroll.
2. Hold finger firmly until step advances.
3. **Lift completely** when serial/OLED says lift (GenImg `02H` no finger).
4. Place **same** finger again until stored.
5. Abort: LEFT.

Watch serial:
- Buttons: `[IN] UP (GPIO7)` etc.
- Finger TOUCH IRQ: `[IN] TOUCH DOWN (GPIO16)` / `[IN] TOUCH UP (GPIO16)`
- Enroll: `[FP] place finger…` / `lift finger…` / `enrolled PageID=…`

Do **not** use long blocking `enrollFingerprint` on the main loop.

See `docs/datasheets/R558S-fingerprint-module-manual-v1.1.pdf` for
GenImg/Img2Tz/RegModel/Store. (The older R557 manual is kept alongside it; the
fitted part is the R558-S and its manual is authoritative where they differ.)

---

## Known gaps / backlog for agents

Work these in order unless the user prioritizes otherwise:

### P0 — hardware bring-up (must be solid before feature work)

- [x] Confirm button map with serial after flash; fix `board_config.h` pins only if wrong
- [x] Stable enroll 2-step on UI + serial (AutoEnroll 31H)
- [x] On-demand FP: GenImg/Search only during TOTP-auth / FIDO-presence / enroll (idle quiet)
- [ ] TOUCH GPIO16 idle HIGH + edges (PCB net stuck LOW — deferred)
- [ ] Optional later: power-gate FP module when idle (always powered today)
- [x] Product USB MODE=0 TinyUSB CDC+HID (code + install env + `scripts/flash_product_usb.sh`)
- [x] Verify product USB **0x1209:0xBEEE** + CDC (DTR) + FIDO HID smoke via `tests/device`
- [x] Multi-layer test framework: L0 host / L1 Unity / L2 device (`test/README.md`, `pytest.ini`)
- [x] FP UART orientation auto-detect stays correct
- [ ] Recover if host only sees Serial/JTAG or silent COM: power-cycle → `esp32-s3-n16r8-install` / flash script

### P1 — correctness & tests

- [x] TOTP RFC 6238 golden vectors (host + board tests; uint32 timestamps)
- [x] totp_storage JSON schema round-trip (host `test_totp_storage_json.py`)
- [x] enrollPoll AutoEnroll state machine unit test (mock Stream)
- [x] nav state transitions tested without GPIO (bus inject)
- [x] Idle sleep / CENTER wake / host wake covered in `test/test_nav`
- [x] Device L2: USB identity, CDC HELP, CTAPHID_INIT, OATH LIST + lifecycle (`tests/device/`)
- [ ] L2 coverage for `SLEEP` / `WAKE` over CDC (needs a board)

### P2 — FIDO product completeness

- [x] CTAPHID_INIT smoke (host `tests/device/test_hid_fido_init.py`)
- [x] CTAP2 GetInfo L2 + host MakeCredential/GetAssertion (`docs/WEBAUTHN_L3.md`)
- [x] FIDO Place-finger latch (cross-core `_is_processing` + U2F/CTAP UP timeout + GetInfo `uv`)
- [x] Chrome path: **no NMSG**, GetInfo `U2F_V2`+`FIDO_2_0`, CTAPHID_MSG/U2F_REGISTER enabled (retest browser UI)
- [ ] Full browser WebAuthn demo (manual OS UI) — flash + webauthn.io after U2F restore
- [x] Product batch attestation (self-signed) + AAGUID — `docs/ATTESTATION.md` (MDS/public CA still open)
- [ ] PIN / resident-key UX polish
- [x] Wire `UI_FIDO_SUCCESS` (post-presence flash)

### P3 — security / ship

- [x] Encrypt TOTP secrets at rest (AES-256-GCM + NVS wrap key) — `docs/SECURITY_ROADMAP.md`
- [x] FP-gate OATH PUT/DELETE/CALCULATE (`CRYPTICK_OATH_REQUIRE_FP` default **1**; UV wait; bootstrap if no FP templates)
- [x] CI: L0 pytest + all four `pio run` envs + L1 Unity compile (`.github/workflows/ci.yml`)
- [ ] eFuse-backed wrap key + flash encryption — today a full flash dump yields
      both key and ciphertext (`docs/SECURITY_ROADMAP.md`)

### P4 — UX / power

- [x] Idle screen sleep + CENTER wake, configurable and persisted (`UI_SLEEP`)
- [x] Boot animation, on-device settings list with scroll, Device info screen
- [x] `docs/index.html`: Device Settings tab, serial path fixed to 115200 + DTR
- [ ] Measure actual idle current with the panel off; decide whether the FP
      module is worth power-gating (P0 item above)
- [ ] Dim before blanking (SSD1306 `setContrast`) as a softer warning

### Mac login (PIV)

- [ ] USB CCID composite + full PIV 9a/9d — scaffold in `core/piv` + `docs/MAC_LOGIN.md`

### Do not do by default

- ESP8266 / Super Mini ports
- Soft key remapping tables; change GPIO numbers only

---

## Coding conventions

1. Pins and product timeouts live only in `board_config.h`.
2. New sources must be listed in `platformio.ini` `build_src_filter`, or they are
   silently not compiled. Shared include paths belong in the `[cryptick]`
   section, not copy-pasted per env.
3. Prefer minimal diffs; match existing `*_system_*` naming.
4. Flashing always ends in `hard_reset`. The product USB bootloader path
   (`usb_device_enter_bootloader`) exists only under `CRYPTICK_USB_STACK`.
5. FIDO user presence = **fingerprint only**, not nav keys.
6. No WiFi time — set the clock via `SETTIME` / `DATE` / OATH SET_TIME.
7. Never call `exit()` or `abort()` in firmware. Return an error code, or
   `device_reboot()` when the state is unrecoverable.
8. Respect the core split (see Architecture above): systems belong to the
   Arduino loop, and shared state needs a documented lock.
9. Test helpers live in `tests/support/`. Do not fork a second copy of the
   CTAPHID framing or CDC discovery into a script.
10. Document honestly: secrets are AES-GCM encrypted at rest, but the NVS wrap
    key is not eFuse-locked, so a full flash dump still reveals them.

---

## Tree map (keep vs gone)

| Path | Role |
| ---- | ---- |
| `include/board_config.h` | Pins + constants (the only place pins may change) |
| `include/cryptick_log.h` | `CLOG_*` levels and macros |
| `drivers/fingerprint_r558s.*` | R558-S UART protocol |
| `drivers/usb_device.*` | CDC + FIDO HID + bootloader entry |
| `drivers/usb_ccid.*` | TinyUSB descriptors for CCID — **not written**; the last gap before login |
| `src/systems/*` | App systems, all owned by the Arduino loop |
| `src/host/*` | Console, storage, OATH-over-HID, credential lock |
| `core/secret_crypto.*` | AES-GCM wrap key + secret blobs |
| `core/cryptick_log.cpp` | Unified CDC log sink (mutex-guarded) |
| `core/totp.*` | TOTP + strict base32 decode |
| `core/fido2/*` | Vendored Solo CTAP stack + `hal_esp32.cpp` |
| `core/ble_fido/*` | FIDO BLE transport: framing (host-testable) + NimBLE GATT |
| `core/piv/*` | PIV applet (SP 800-73-4) + ESP32 hooks |
| `drivers/ccid_proto.*` | CCID bulk protocol; host-tested, no USB interface yet |
| `test/test_*/test_main.cpp` | L1 Unity suites |
| `tests/{host,device,support}` | L0/L2 pytest and shared transport helpers |
| `scripts/syntax_check_scaffolds.sh` | Compile-checks sources outside `build_src_filter` |
| `docs/datasheets/` | R558-S + R557 manuals, PCB schematic |

**Removed:** Super Mini / ESP8266 envs, `display_ssd1306`, the original
`core/ble_fido` no-op scaffold (replaced by the real transport, not deleted),
empty `usb_hid` stubs, `fido_bridge`,
`EspSoftwareSerial`, and the `hal/device_hal.h` shim (its declarations live in
`core/fido2/device.h`).

---

## When something “doesn’t work”

| Symptom | Likely cause |
| ------- | ------------ |
| Buttons swapped like always | **Old firmware still running** — look for outdated `[IN] map` line |
| Enroll appears dead | Finger never fully lifted (need GenImg=no-finger); or free-id probes slow |
| Upload COM busy | Serial mon open, or Windows USB glitch — re-plug |
| Silent / only VID 303A | Stuck in ROM download — `esptool.py --port … run --after hard_reset` or power-cycle |
| Wrong `[IN] NAME` for physical press | Edit pin `#define`s in `board_config.h`, flash again |
| Empty CH340 log | Monitor wrong port, or old TinyUSB firmware still running |


---

## How agents should multitask

Parallelize safely:

1. One agent: bring-up (buttons/FP/USB) + flash  
2. One agent: tests (`test_totp` golden + storage)  
3. One agent: FIDO/docs only if not stepping on bring-up files  

Do not two agents rewrite `board_config.h` / `fingerprint_r558s.cpp` / `usb_device.cpp` / `input_system.cpp` at once.
