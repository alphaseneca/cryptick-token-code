# Cryptick — Mac login (PIV / smart card)

## Status (honest)

| Item | State |
|------|--------|
| USB HID FIDO + OATH | Product path (see `docs/HID_HOST.md`) |
| USB **CCID** interface | **Skeleton** — not full CTK enumeration yet |
| PIV applet (SELECT, 9a/9d) | **Stub** — SELECT PIV AID returns a fixed SW; no key ops |
| Mac `sc_auth` pair / unlock | **Not done** — do not claim finished Mac login |
| Fingerprint gate for PIV | Design-ready; wired to FIDO presence today |

Apple login / screensaver unlock with a hardware token is **PIV over USB CCID**, consumed by CryptoTokenKit — **not** FIDO HID and **not** BLE.

## Target architecture

```text
Mac CTK ── USB CCID ── drivers/usb_ccid + core/piv APDU router
                            │
                            ▼
                     SELECT AID → VERIFY (PIN or session after FP)
                     AUTHENTICATE 9a / key mgmt 9d
                            │
                            ▼
                     FP match required before private-key use
```

## Checklist (when PIV lands)

1. Plug Cryptick → Mac sees a **smart card reader** + PIV token  
2. `sc_auth identities` lists certificate hash  
3. Pair identity to user (`sc_auth accept` / System Settings)  
4. Unplug/replug → unlock login after **fingerprint** on-token  
5. Without FP, key op times out / fails  

Reference: [Yubico macOS PIV login](https://developers.yubico.com/PIV/Guides/Smart_card-only_authentication_on_macOS.html).

## Current code

- `drivers/usb_ccid.*` — composite CCID **scaffolding** (not enabled in product composite by default until endpoint budget + CTK smoke pass)
- `core/piv/*` — SELECT AID stub + TODO for GENERATE/IMPORT/AUTHENTICATE  
- Enable path will extend `usb_device` composite after HID/CDC stable  

Until CCID is enabled in the product build, use this doc as the roadmap only.
