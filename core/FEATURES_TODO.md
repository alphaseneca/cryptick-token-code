# Features TODO

- [x] TOTP (SHA1 / 6–8 digits; product OATH MVP = 6 dig / 30s)
- [x] FIDO2 / CTAP2 over USB HID (Solo1-class stack under `core/fido2/`)
- [x] OATH management over CTAPHID (`CTAPHID_CRYPTICK_OATH`, see docs/HID_HOST.md)
- [x] CDC logs-only (credential CLI gated / removed)
- [x] ENTERBOOT → `cryptick_enter_bootloader` → ROM USB download
- [x] Multi-layer tests: L0 pytest / L1 Unity / L2 device (`tests/device`, `test/README.md`)
- [x] Encrypt TOTP secrets at rest (AES-GCM + NVS wrap key — `docs/SECURITY_ROADMAP.md`)
- [x] FP-gate OATH PUT/DELETE/CALCULATE (default on; UV wait + bootstrap if no templates)
- [x] L2 OATH lifecycle PUT→LIST→CALCULATE→DELETE (`tests/device/test_hid_oath_lifecycle.py`)
- [x] Product batch attestation key + self-signed cert + AAGUID (`docs/ATTESTATION.md`; ATTEST; L2 AAGUID check)
- [x] Unified CDC log levels 0–5 + ship env + NVS persist (`docs/LOGGING.md`)
- [x] WebAuthn Place-finger UI latched (cross-core processing + U2F UP timeout + FP UV flags)
- [x] Browser Chrome path: re-enable CTAPHID_MSG/U2F (no NMSG); GetInfo U2F_V2+FIDO_2_0
- [x] Idle screen sleep + CENTER/host wake, configurable and NVS-persisted (`UI_SLEEP`)
- [x] OLED opening animation, scrolling settings list, Device info screen
- [x] `docs/index.html` Device Settings tab (sleep, clock, log level, attestation, recovery)
- [ ] FIDO MDS / public root trust + factory key injection
- [ ] Manual browser WebAuthn demo site sign-off (human / OS UI; see docs/WEBAUTHN_L3.md)
- [ ] U2F polish / broader CTAP1 host coverage
- [ ] PIN policy polish / resident-key UX
- [ ] USB CCID + PIV 9a/9d for Mac login (`docs/MAC_LOGIN.md` — stub only)
- [ ] eFuse-backed wrap key + flash encryption (`docs/SECURITY_ROADMAP.md`)

Explicitly out of scope: BLE transport (the no-op `core/ble_fido/` scaffold was
removed), ESP8266 / Super Mini ports.
