# Cryptick — Mac login (PIV / smart card)

## Status (honest)

| Item | State |
|------|--------|
| USB HID FIDO + OATH | Product path (see `docs/HID_HOST.md`) |
| PIV applet | **Done** — SELECT/GET DATA/PUT DATA/VERIFY/CHANGE REFERENCE/GENERATE/GENERAL AUTHENTICATE, response chaining. 81 host tests |
| CCID **protocol layer** | **Done** — `drivers/ccid_proto.c`, 25 host tests, drives the applet end to end |
| CCID **USB interface** | **Not done** — no descriptors, no endpoints, `usb_ccid_enabled()` is false |
| CCC / CHUID objects | **Done** — synthesised on demand from a derived per-device GUID |
| Certificate provisioning | Device side done (`GENERATE` publishes the public key); **no host tooling** |
| Mac `sc_auth` pair / unlock | **Not done** — do not claim finished Mac login |
| Fingerprint gate for PIV | **Done** — routed through the shared presence gate, not a second flag |
| Hardware verification | **None.** Nothing here has run on a device |

**What still blocks a login,** in the order it bites: the CCID interface does
not enumerate, so nothing can reach the applet; and no certificate exists,
because nothing yet turns a `GENERATE` public key into an issued cert.

### Card identity

CCC and CHUID are **synthesised on demand** rather than written at first boot,
so nothing is spent in flash unless a real one is provisioned, and `PUT DATA`
still overrides — a stored object always wins.

The GUID they share is derived from the master secret: per-device because the
secret is, stable across reboots and reflashes, and costing no storage. It is
deliberately **not** the AAGUID, which identifies the model — every Cryptick
would otherwise present as the same card and a host could not tell two apart.
It is shaped as an RFC 4122 v4 UUID because hosts display and log it.

The FASC-N is a fixed non-federal placeholder. A real one is a BCD-encoded
federal credential number and this device issues no such credential; hosts key
on the GUID and the certificate instead. The CHUID's issuer signature (`0x3E`)
is emitted **empty** rather than forged — this card is not part of a federal
PKI, and saying so is the honest answer.

Certificates are never synthesised. An invented empty one would look like a
provisioned card that simply cannot authenticate, which is harder to diagnose
than an absent object.

Apple login / screensaver unlock with a hardware token is **PIV**, consumed by
CryptoTokenKit — **not** FIDO. That is about the applet, not the wire: the
transport underneath is USB CCID today, and BLE-backed PIV through a host-side
virtual reader is a real path once the CCID applet exists. The FIDO BLE
transport in `core/ble_fido/` does not carry PIV; see [BLE_FIDO.md](BLE_FIDO.md).

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

| File | Role | Tested |
|------|------|--------|
| `core/piv/piv.c` | The applet: APDUs in, APDUs out, transport-independent | host, 81 cases |
| `core/piv/piv_hal_esp32.cpp` | Key derivation, LittleFS objects, PIN in NVS, presence | compiles only |
| `drivers/ccid_proto.c` | CCID bulk messages (PC/SC, pcscd, CryptoTokenKit speak this) | host, 25 cases |
| `drivers/usb_ccid.cpp` | TinyUSB descriptors and endpoints | **not written** |

The split mirrors `core/ble_fido/`: protocol logic is freestanding and host
tested, and the part that needs a device is kept as small as possible. Every
defect found in this project so far has been in platform glue, not in protocol
logic, which is the argument for shrinking the glue rather than trusting it.

### Keys and PIN

Slot keys are **derived** from the device master secret plus a per-slot
generation counter, never stored. `GENERATE ASYMMETRIC KEY PAIR` bumps that
counter and returns the new public key, so rolling a key persists across reboots
with nothing new written to flash — and correctly invalidates any certificate
issued against the old one.

Real PIV gates `GENERATE` behind the card management key (9B). This device has
no 9B key, so the gate is a verified PIN plus a fingerprint. That is a
deliberate substitution and should be revisited before anyone calls this
standards-conformant.

The PIN lives in NVS as a hash salted with the master secret, so a flash dump
alone does not permit an offline guess of six digits. With no PIN set it falls
back to the SP 800-73 default `123456` and logs a warning; `CHANGE REFERENCE
DATA` is implemented, so there is now a way off it.

### What to build next

1. **CCID descriptors** — class `0x0B`, the 54-byte functional descriptor with
   `dwProtocols` advertising T=1 to match the ATR, and two bulk endpoints.
   Check the endpoint budget against CDC+HID *first*; that is where adding a
   third interface to a working composite usually fails.
2. **Bulk reassembly** — a CCID message can span several 64-byte packets, and
   `ccid_handle_message()` requires a complete one.
3. **CCC and CHUID** — small identity objects a card is expected to have from
   the factory. Synthesise them at first boot from the device identity.
4. **Provisioning tooling** — read the public key via `GENERATE`, issue a
   certificate, write it back with `PUT DATA`.
