# Cryptick console logging

## Levels

| N | Name | What you see |
|---|------|----------------|
| 0 | NONE | Silence |
| 1 | ERROR | Failures only (**ship compile default**) |
| 2 | WARN | Recoverable issues |
| 3 | INFO | Boot, ready, enroll/match, OATH milestones |
| 4 | DEBUG | Subsystem actions (buttons, nav state, FP steps, OATH APDU) — **lab default** |
| 5 | TRACE | High volume: bus events, display redraw, heartbeats, HID/FIDO chatter |

Format: `[L][TAG] message` e.g. `[D][IN] UP (GPIO7)`.

CDC: `HELP` · `LOGLEVEL 0..5` · `ATTEST` · `SLEEP [sec|NOW|OFF]` · `WAKE`

Level is **saved in NVS** (`cryptick` / `loglvl`) and restored on reboot after `LOGLEVEL` is set.
The screen sleep timeout lives in the same namespace as `sleepsec`.

Output is plain ASCII with no ANSI colour, including the Solo FIDO tags, so the
stream can be parsed by `scripts/post_flash_check.py` and the L2 tests.

Both cores log. `cryptick_log.cpp` serialises writes to the CDC sink behind a
mutex, so a line from the FIDO task cannot interleave mid-character with one
from the Arduino loop. Every line is terminated with exactly one newline even
when the formatted text was truncated.

## Compile-time ship vs lab

| Build env | Solo `DEBUG_LEVEL` | Default runtime level |
|-----------|--------------------|------------------------|
| `esp32-s3-n16r8` (lab) | 1 (FIDO `printf1` enabled) | **4 DEBUG** |
| `esp32-s3-n16r8-ship` | 0 (FIDO compile-stripped) | **1 ERROR** |

```bash
# Lab / development (full action logs)
pio run -e esp32-s3-n16r8 -t upload

# Distribution-ish quiet build
pio run -e esp32-s3-n16r8-ship -t upload
```

Override any env: `-DCRYPTICK_LOG_LEVEL_DEFAULT=0` through `5`.

## What is covered

| Tag | Origin |
|-----|--------|
| BOOT/USB/HB | main, USB stack |
| IN | button map + presses |
| DISP/I2C | OLED path |
| BAT | charger STAT pins |
| FP / FP-TX | R558 match/enroll (+ UART hex at TRACE if debug on) |
| AUTH/NAV | unlock session, UI state machines |
| BUS | event_bus publish/pop (TRACE) |
| STOR | encrypted TOTP load/save |
| OATH | APDU INS/UV/result |
| FIDO/HAL/CTAP… | Solo tags via `fido_log_print` when runtime ≥ DEBUG and `DEBUG_LEVEL>0` |

## Manual verification after flash

```bash
# Lab binary (default logs at DEBUG, Solo FIDO logs on)
pio run -e esp32-s3-n16r8 -t upload

# Or quiet ship binary
pio run -e esp32-s3-n16r8-ship -t upload

# On CDC @115200:
HELP
LOGLEVEL 5          # full action trace
LOGLEVEL            # show level (persisted in NVS)
ATTEST              # product AAGUID + cert size
LOGLEVEL 1          # quiet again

# Host
pytest tests/device -v --device
# expects: AAGUID c7a5e1e0-7c4b-4f0a-9d2e-55c41c710001 in GetInfo
```

If product USB shows up but CDC is silent and 1200bps/BOOTLOADER fail: **unplug USB, wait 3s, replug**, then flash via `esp32-s3-n16r8-install` if you only see Espressif 303A.
