# Cryptick Token Firmware — Project & Architecture Reference

Hardware, the USB composite descriptor, the PIV smart-card object model, and
real boot order. For the software layers, threading model, event bus, and a
full subsystem diagram (nav/display, fingerprint, FIDO2/CTAP, PIV/CCID, BLE
GATT), see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the two pages
are complementary, not duplicates.

## 1. Overview & Hardware
- **Target**: ESP32-S3-WROOM-1 N16R8 (16MB Flash, 8MB Octal PSRAM).
- **Vendor / Product ID**: `0x1209:0xBEEE` ("Cryptick Token").
- **Physical Peripherals**:
  - OLED display (SSD1306/SH1106 I2C).
  - Capacitive navigation buttons.
  - R558-S Optical/Capacitive Fingerprint sensor on UART.
  - Hardware RTC (DS3231) on I2C.
  - LiPo battery fuel gauge on ADC.

## 2. USB Composite Stack (`drivers/usb_device.cpp`)
The product firmware operates with TinyUSB in native USB mode (`ARDUINO_USB_MODE=0`, `CRYPTICK_USB_STACK=1`):
1. **Interface 0: CTAPHID / FIDO2** (Endpoint 0x81 IN, 0x01 OUT, 64-byte packets). Usage Page `0xF1D0`, Usage `0x01`. Supports CTAP2.0/2.1, U2F, and custom extensions.
2. **Interface 1 & 2: USB CDC (Serial)** (Communication + Data). Management console at 115200 bps, logging, and 1200-bps bootloader trigger.
3. **Interface 3: CCID Smart Card** (Endpoint 0x82 IN, 0x02 OUT, 64-byte bulk). Smart Card Class `0x0B`, bulk transfer, T=1 protocol, compliant with NIST SP 800-73-4 (PIV).

## 3. PIV Smart Card Subsystem (`core/piv/`)
- **Applet**: NIST SP 800-73-4 compliant PIV applet in `core/piv/piv.c`.
- **Objects**:
  - CCC (Card Capability Container): `0x5FC107` (Synthesized).
  - CHUID (Cardholder Unique Identifier): `0x5FC102` (Synthesized GUID).
  - Slot 9A Authentication Certificate: `0x5FC105` (Stored in LittleFS `/piv_5fc105.bin`, seeded with paired macOS certificate).
  - Slot 9C Digital Signature Certificate: `0x5FC10A`.
  - Slot 9D Key Management Certificate: `0x5FC10B`.
  - Slot 9E Card Authentication Certificate: `0x5FC101`.
- **Key Derivation**: Keys are derived from the master device secret using HMAC with per-slot generation counters stored in NVS (`piv` namespace).
- **Execution Architecture**:
  - Fast, non-blocking CCID commands (Slot status, Power on/off, Parameters, Select AID, Get Data, Verify PIN) execute synchronously on the USB task with microsecond latency.
  - Private key signing (`PIV_INS_GENERAL_AUTHENTICATE`) is dispatched to the FIDO FreeRTOS task, gating signature generation on user presence (fingerprint/touch).

## 4. Boot Sequencing (`src/main.cpp`)
To prevent host smart card reader daemons (such as macOS `usbsmartcardreaderd` or Linux `pcscd`) from seeing an unready slot or uninitialized descriptors, USB attach is held until last. The actual order in `setup()` (verified against source, not the order this section previously claimed):
1. Console/logging (`Serial.begin`, `cryptick_log_init`), the I2C mutex, `credential_store_init()`, the event bus.
2. Display init + boot animation, then input (buttons + encoder) — before storage, so a blank-screen boot is still visible on the OLED.
3. Storage (`LittleFS.begin(true)`), then the DS3231 RTC probe.
4. Battery, auth, and nav systems.
5. **FIDO core HAL** (`device_hal_init()`) — this runs *before* crypto/PIV init below, not after, because the FIDO task and its presence-ceremony mutex (`core/fido2/hal_esp32.cpp`) must exist before anything can queue work onto it.
6. `ble_fido_gatt_init()` when `CRYPTICK_BLE_FIDO=1` — creates the NimBLE GATT server the FIDO task's queue callback posts into.
7. Load TOTP credentials, then fingerprint init (`fp_system_init()`).
8. Crypto primitives (`crypto_ecc256_init()`).
9. PIV HAL (`piv_hal_init()`) — after crypto, since slot keys derive from the master secret.
10. `ble_piv_gatt_init()`, then (when `CRYPTICK_BLE_FIDO=1`) `ble_daemon_gatt_init()`, `ble_hid_keyboard_init()`, and `ble_fido_start_advertising()`.
11. CCID driver structure allocation (`usb_ccid_init()`, when `CRYPTICK_USB_CCID=1`) — after `piv_hal_init()`, since the first CCID message can arrive as soon as the host powers the card.
12. **USB attach**: `usb_device_init()` enables interfaces and attaches D+/D- pullups, last, so the host's immediate enumeration probes (e.g. `PC_to_RDR_GetSlotStatus`) find every endpoint and data structure already instantiated.

Both BLE and USB-CCID are compiled into the default product environment
(`[cryptick] ble` and `ccid` fragments in `platformio.ini`), so this order
applies to the firmware every unit ships, not an opt-in variant.

## 5. Testing & Verification
- Unit & integration tests in `tests/host/` run under pytest:
  ```bash
  python3 -m pytest tests/host/
  ```
- Firmware compilation and flash:
  ```bash
  ~/.platformio/penv/bin/pio run
  export PATH="$HOME/.platformio/penv/bin:$PATH"
  python3 scripts/flash_product_usb.py --port /dev/cu.usbmodemCRYPTICK2
  ```
