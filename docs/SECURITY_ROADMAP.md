# Encryption / security roadmap

## Today (product path)

| Asset | At rest | Gate |
|-------|---------|------|
| TOTP secrets | **AES-256-GCM** blobs in LittleFS JSON v2 (`sec` field; wrap key in NVS `cryptick/wrapk`) | OLED TOTP UI behind fingerprint; HID PUT/DELETE/CALCULATE require UV when any FP is enrolled |
| FIDO RK / PIN state | NVS / LittleFS RK blob | UV = fingerprint for presence |
| Attestation key + cert | **Cryptick batch** self-signed in flash (`docs/ATTESTATION.md`) | Not public-CA / MDS |

LittleFS is never a plaintext credential dump. Schema v1 (`"secret": "BASE32..."`) is **read once** and rewritten encrypted on next load/save.

## Architecture

1. **Device wrap key** — 256-bit random in NVS namespace `cryptick` key `wrapk` (created on first boot).  
2. **AES-256-GCM** — raw TOTP key bytes (base32-decoded) → `base64(0x01 ‖ nonce12 ‖ ct ‖ tag16)` as JSON `sec`.  
3. Host OATH PUT stores plaintext only on the wire during the session; save path always encrypts.  
4. **UV policy** (`CRYPTICK_OATH_REQUIRE_FP`, **default 1**):  
   - No enrolled FP templates → host may manage (bootstrap).  
   - Templates present → PUT/DELETE/PUT_OTPAUTH/CALCULATE wait for finger (or active OLED auth session).  
   - LIST / SET_TIME remain unauthenticated (names only / clock).  
5. Lab builds may set `-DCRYPTICK_OATH_REQUIRE_FP=0`.

## What this does and does not protect against

Be precise about the claim, because "encrypted at rest" is easy to overread.

**Protected.** Someone who reads the LittleFS partition alone — by pulling the
JSON off a mounted filesystem, recovering a backup, or dumping only the data
partition — gets ciphertext. There are no plaintext secrets in the filesystem,
and the GCM tag means a tampered blob fails to unwrap rather than decoding to
garbage.

**Not protected.** The wrap key sits in NVS on the same flash chip, and flash
encryption is not enabled. Anyone who can read the *whole* flash — physical
access with a programmer, or an `esptool read_flash` over the exposed USB path —
recovers both the key and the ciphertext, and the encryption buys nothing. Until
the key is bound to an eFuse-derived secret, treat this as protection against
casual filesystem inspection, not against an attacker holding the board.

Erasing NVS (a full-chip erase during flashing) destroys the wrap key and makes
every stored secret permanently unrecoverable. That is the intended failure
mode, but it means users must keep their own backup of enrolment secrets.

## Still open before a full product security claim

- eFuse-backed wrap key + ESP32 flash encryption (the gap described above) —
  implementation plan: [SECURE_BOOT_FLASH_ENCRYPTION.md](SECURE_BOOT_FLASH_ENCRYPTION.md)
- FIDO MDS / public attestation root (a batch self-signed cert already ships — [ATTESTATION.md](ATTESTATION.md))
- PIN / resident-key UX polish
- Full WebAuthn browser OS UI acceptance

## CI

Every push and PR runs the L0 host suite (AES-GCM blob format, JSON schema
round-trip, TOTP vectors), builds all four firmware environments, and
compile-checks the five L1 Unity suites. See `.github/workflows/ci.yml`.
