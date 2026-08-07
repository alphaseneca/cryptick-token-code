# Features TODO

- [x] TOTP (SHA1 / 6–8 digits; product OATH MVP = 6 dig / 30s)
- [x] FIDO2 / CTAP2 over USB HID (Solo1-class stack under `core/fido2/`)
- [x] OATH management over CTAPHID (`CTAPHID_CRYPTICK_OATH`, see docs/HID_HOST.md)
- [x] CDC logs-only (credential CLI gated / removed)
- [x] ENTERBOOT → `cryptick_enter_bootloader` → ROM USB download
- [ ] U2F polish / broader CTAP1 host coverage
- [ ] Product attestation key + cert (currently test material)
- [ ] PIN policy polish / resident-key UX
- [ ] Encrypt TOTP secrets at rest (docs/SECURITY_ROADMAP.md)
- [ ] FP-gate OATH PUT/DELETE for ship
- [ ] BLE FIDO/OATH transport scaffolding → full GATT reassembly (`core/ble_fido/`)
- [ ] USB CCID + PIV 9a/9d for Mac login (`docs/MAC_LOGIN.md` — stub only)
