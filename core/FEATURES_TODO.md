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
- [x] PIV applet: SELECT/GET DATA/PUT DATA/VERIFY/GENERAL AUTHENTICATE, response
      chaining, PIN retry counter, keys derived per slot (`core/piv/`)
- [x] PIV PIN change + key generation (`CHANGE REFERENCE DATA`, `GENERATE`)
- [x] CCID bulk protocol layer (`drivers/ccid_proto.c`, host-tested against the applet)
- [ ] CCID USB descriptors + endpoints — the last gap before Mac/Linux login
- [x] CCC + CHUID synthesised on demand from a derived per-device GUID
- [ ] Host tooling to issue a certificate against a `GENERATE` public key
- [ ] PIV over BLE via a host-side virtual reader
- [ ] PIV provisioning: publish slot public keys so a cert can be issued
- [ ] eFuse-backed wrap key + flash encryption (`docs/SECURITY_ROADMAP.md`)
- [x] FIDO2 over BLE (GATT `0xFFFD`, LESC+MITM passkey on the OLED — `docs/BLE_FIDO.md`)
- [ ] BLE bench sign-off: pair from Windows/Chrome native BLE stack and `libfido2`
- [ ] PIV over BLE via a host-side virtual reader (`docs/MAC_LOGIN.md`)

Explicitly out of scope: ESP8266 / Super Mini ports.
