# Cryptick OATH / FIDO / ENTERBOOT over USB HID

Brand: **VID `0x1209` PID `0xBEEE`** product string **Cryptick Token**.

| Channel | Role |
|---------|------|
| **FIDO HID (CTAPHID)** | FIDO2/U2F, Cryptick OATH, ENTERBOOT |
| **USB CDC** | Logs only (no product credential CLI) |
| **1200 bps / `BOOTLOADER` CDC** | ROM download backup |

Host tools must open the FIDO HID interface, not a serial/COM port, for TOTP secret management.

## CTAPHID framing

Standard Solo/CTAPHID 64-byte reports (`CID` + init/cont). After `CTAPHID_INIT`, custom product opcodes:

| CMD | Code | Purpose |
|-----|------|---------|
| `CTAPHID_ENTERBOOT` | `0xD1` (`TYPE_INIT\|0x51`) | Enter ESP ROM USB download via `cryptick_enter_bootloader()` → `usb_device_enter_bootloader()` |
| `CTAPHID_CRYPTICK_OATH` | `0xE3` (`TYPE_INIT\|0x63`) | OATH/TOTP APDU-lite body |

## OATH body (`CTAPHID_CRYPTICK_OATH`)

YKOATH-inspired. Not CCID OATH class.

### Request

```text
CLA (0x00) | INS | P1 (0x00) | P2 (0x00) | Lc | TLV…
```

### Response

```text
[TLV…] | SW1 | SW2
```

`SW = 0x9000` success. Common errors: `6A80` wrong data, `6A82` not found, `6D00` INS, `6985` conditions (UV required / timeout), `6700` length.

### Instructions (product)

| INS | Name | Request | Response | UV |
|-----|------|---------|----------|----|
| `0x01` | PUT | Tag `0x71` name, `0x73` key | SW | Yes if FP enrolled |
| `0x02` | DELETE | Tag `0x71` name | SW | Yes if FP enrolled |
| `0xa1` | LIST | empty | name TLVs + SW | No |
| `0xa2` | CALCULATE | `0x71` name + `0x74` 8-byte counter BE | `0x75` response + SW | Yes if FP enrolled |
| `0x04` | SET_TIME | 4-byte UTC unix BE (not TLV) | SW | No |
| `0x40` | PUT_OTPAUTH | UTF-8 `otpauth://totp/…` | SW | Yes if FP enrolled |

**UV policy (`CRYPTICK_OATH_REQUIRE_FP`, default 1):** if the sensor has zero templates, management is allowed without touch (first-time setup). After enroll, OLED shows **Manage** / **Code** and waits up to 25s for fingerprint (same path as FIDO). Active unlock session from OLED TOTP also satisfies UV. Lab: `-DCRYPTICK_OATH_REQUIRE_FP=0`.

Secrets on device are stored encrypted (AES-GCM); see `docs/SECURITY_ROADMAP.md`.

### Tag `0x73` (key) for PUT

```text
type_algo (1) | digits (1) | secret_bytes…
type_algo = 0x21  // high nibble TOTP 0x20, low nibble SHA1 0x01
digits    = 6      // product fixed for now
```

Host base32-decodes secrets before PUT. Rejects non-SHA1, non-6-digit, non-30s period in PUT_OTPAUTH.

### CALCULATE challenge

8-byte big-endian **time-step counter** `floor(unix / 30)`. Response TLV:

```text
0x75 0x05  digits(1=6)  code_u32_BE
```

### Example put (conceptual hex of APDU only)

Name `Example:user`, secret raw after base32 decode of `JBSWY3DPEHPK3PXP`:

```text
00 01 00 00 Lc
  71 0C 45 78 61 6D 70 6C 65 3A 75 73 65 72   # name "Example:user"
  73 0C 21 06 <10-byte secret>
```

### Host flow

1. Open FIDO HID VID:PID `1209:BEEE`
2. `CTAPHID_INIT`
3. `CTAPHID_CRYPTICK_OATH` + PUT or PUT_OTPAUTH
4. Optional CALCULATE / SET_TIME
5. OLED still shows codes after fingerprint unlock

Python L2 helpers: `scripts/tests/hid_oath_smoke.py`, `scripts/tests/hid_fido_init.py` (skip without hardware).
