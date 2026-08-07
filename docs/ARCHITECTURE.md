# Architecture — Cryptick Token (S3 PCB)

See **[AGENTS.md](../AGENTS.md)** for product goal, backlog, and agent rules.

## Layers

```text
USB host ── CDC CLI ── src/host/serial_comm
        └── HID FIDO ── drivers/usb_device ── core/fido2

R557 UART ── drivers/fingerprint_r558s ── src/systems/fp_system
5-way GPIO ── input_system ── event_bus ── nav_system ── display_system
BQ25185 STAT ── battery_system ───────────────────────── display_system
DS3231 I2C ── main / serial time set ── TOTP (core/totp)
```

## Event bus

`EVT_INPUT`, `EVT_FP`, `EVT_BATTERY`, `EVT_AUTH`, `EVT_UI_STATE`, `EVT_CMD`.

Only `input_system` touches button pins. Only `display_system` draws OLED.

## USB (no BOOT pads)

1. App CDC → host 1200 bps touch / DTR drop → `__wrap_TinyUSB_Port_EnterDFU` → `usb_persist_restart(RESTART_BOOTLOADER)`
2. CLI `BOOTLOADER` same path
3. esptool `write_flash` on USB-Serial/JTAG ROM port (`--before=no_reset`)

## Fingerprint enroll

Non-blocking `enrollStart` / `enrollPoll` in driver; `fp_system` polls while `_enrolling`. Free template id must **not** LoadChar-scan (timeout hang).

## Build

Single env: `esp32-s3-n16r8` in `platformio.ini`.
