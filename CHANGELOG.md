# Changelog — Cryptick Token Firmware

All notable changes to the Cryptick Token firmware are documented in this file.

## [2026-09-27] - Production-Grade PIV Smart Card & Concurrent USB CTAPHID

### Fixed
- **macOS Smart Card Unlock (CryptoTokenKit `usbsmartcardreaderd` Integration)**:
  - **Synchronous CCID Execution Model**: Fixed `drivers/usb_ccid.cpp` where all CCID messages previously queued to the FIDO FreeRTOS task through a size-1 queue. Non-blocking commands (`PC_to_RDR_GetSlotStatus`, `PC_to_RDR_IccPowerOn`, `PC_to_RDR_IccPowerOff`, `PC_to_RDR_GetParameters`, `SELECT AID`, `GET DATA`, `VERIFY PIN`) are now answered synchronously and immediately on the USB task.
  - **Blocking Separation**: Only `PIV_INS_GENERAL_AUTHENTICATE` (0x87) dispatches to the FIDO task queue to wait on physical user presence (fingerprint/touch).
  - **Boot Initialization Sequence**: Reordered `src/main.cpp` so that `LittleFS.begin()`, `crypto_ecc256_init()`, `piv_hal_init()`, and `usb_ccid_init()` are initialized *before* `usb_device_init()`. When the host USB stack mounts the device, all endpoints and state machines are immediately ready.
  - **Enumeration Latch**: Increased `CCID_FAIL_LIMIT` from 2 to 10 in `drivers/usb_ccid.cpp` to prevent transient reboots during flashing from latching the CCID interface off in NVS.
  - **Permanent Paired Certificate Recovery**: Embedded the 436-byte paired certificate container in `core/piv/piv_hal_esp32.cpp`. If `/piv_5fc105.bin` is absent from LittleFS, it is automatically restored on boot.
  - **Extended APDU Support**: Added ISO 7816-4 extended-length APDU parsing to `core/piv/piv.c` (`cmd[4] == 0 && cmd_len >= 7`) to prevent `0x6700` length errors from modern smart card drivers.

### Verified
- `system_profiler SPSmartCardsDataType` confirms `Ucaselabs Cryptick Token (ATR: 0x3b800181)` bound to `com.apple.CryptoTokenKit.pivtoken`.
- `sc_auth identities` confirms user `aurelius` paired to SHA-1 `70F43A7963168DE966C2E60DC1291C170542C4B5`.
- Full pytest test suite (303 tests) passing with 100% success.
