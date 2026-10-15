# Cryptick Token Firmware — Project & Architecture Reference

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
To prevent host smart card reader daemons (such as macOS `usbsmartcardreaderd` or Linux `pcscd`) from seeing an unready slot or uninitialized descriptors, the boot sequence strictly adheres to:
1. Console and logging init.
2. Storage (`LittleFS.begin(true)`).
3. Display and input systems.
4. Cryptographic primitives (`crypto_ecc256_init()`).
5. PIV HAL and default certificate verification (`piv_hal_init()`).
6. CCID driver structure allocation (`usb_ccid_init()`).
7. FIDO core HAL (`device_hal_init()`).
8. BLE GATT services initialization.
9. **USB attach**: `usb_device_init()` enables interfaces and attaches D+/D- pullups.

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
