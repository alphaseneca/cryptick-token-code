# Cryptick — Mac login (PIV / smart card)

## Status (honest)

| Item | State |
|------|--------|
| USB HID FIDO + OATH | Product path (see `docs/HID_HOST.md`) |
| PIV applet | **Done** — SELECT/GET DATA/PUT DATA/VERIFY/CHANGE REFERENCE/GENERATE/GENERAL AUTHENTICATE, response chaining. 81 host tests |
| CCID **protocol layer** | **Done** — `drivers/ccid_proto.c`, 25 host tests, drives the applet end to end |
| CCID **USB interface** | **Written, unverified on hardware** — descriptors, two bulk endpoints and a TinyUSB class driver. Descriptor bytes asserted off-device; *binding* is not |
| CCC / CHUID objects | **Done** — synthesised on demand from a derived per-device GUID |
| Certificate provisioning | Device side done (`GENERATE` publishes the public key, chained `PUT DATA` writes the cert back). Host tooling is the daemon's, and the wire format is pinned by `tests/host/test_piv_provisioning.py` |
| PIV over BLE | **Written, unverified on hardware** — service `FBF6EB90-…`, framing shared with `0xFFFD`, not advertised |
| Mac `sc_auth` pair / unlock | **Not done** — do not claim finished Mac login |
| Fingerprint gate for PIV | **Done** — routed through the shared presence gate, not a second flag |
| Hardware verification | **None.** Nothing here has run on a device |

**What still blocks a login,** in the order it bites: nobody has confirmed the
CCID interface binds to a host class driver, and no certificate exists, because
the tool that issues one lives in the daemon and is not written yet.

The first of those is a hardware question and cannot be closed from the test
suite. If a descriptor field is wrong, the class driver silently does not bind,
which looks exactly like the device being absent — so treat "PIV did not show
up" as unexplained until the descriptors have been read off a real host.

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
| `drivers/ccid_descriptors.c` | The descriptor bytes, freestanding so they can be asserted | host, 9 cases |
| `drivers/usb_ccid.cpp` | TinyUSB class driver, endpoints, hand-off to the FIDO task | compiles only |
| `core/ble_fido/ble_piv_gatt_esp32.cpp` | PIV over BLE: GATT service and write callback | compiles only |

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

Everything above is written. What is left needs a device and a host:

1. **Confirm the class driver binds** on macOS, Linux and Windows. The
   descriptor bytes are asserted in `tests/host/test_ccid_descriptors.py`,
   including the ones that tie the descriptor to code elsewhere — the declared
   exchange level against what `piv.c` can parse, `dwProtocols` against the ATR
   and its checksum, `dwMaxCCIDMessageLength` against the reassembly buffer.
   None of that proves a host will bind to it.
2. **Certificate issuance**, in the daemon.
3. **`sc_auth pair`** against a provisioned 9A, then FileVault via 9D.

#### If the CCID interface does not enumerate

The device has no BOOT pads, so the only reflash paths run over a composite
that enumerates, and adding an interface is how that stops being true. The
interface therefore latches itself off after two boots that never reach the
configured state, and the latch is tied to the firmware image that set it, so a
new build gets a clean slate — without that, a device latched off would stay
off across the very reflash meant to recover it.

So a descriptor bug costs two reboots, not the device. If CCID is missing and
the log says `latched off`, that is this mechanism working; fix the descriptors
and reflash, and the new image re-arms on its own.

`dwFeatures` declares **short APDU level** (`0x00020000`), not the
short-and-extended `0x00040000` that comparable devices ship. `piv.c` decodes
short APDUs only and refuses extended with `6700`, so claiming extended would
invite a 3-byte `Lc` read as a one-byte zero. If a host stack turns out to
require `0x00040000` to bind, that is the first field to revisit — and the
applet has to grow extended decoding in the same change, not after it.
