# WebAuthn L3 acceptance (browser + host CTAP2)

Product FIDO path is CTAPHID **CTAP2 + CTAP1/U2F MSG** (Solo-class under `core/fido2/`). UV = **fingerprint**.

macOS Chrome often does `INIT → GetInfo → WINK → CTAPHID_MSG (U2F_REGISTER)` as **GetTouch**, then CTAP2 `MakeCredential` for passkeys. Older non-rk creates may stay on U2F. Product capabilities therefore **re-enable MSG/U2F** (do **not** set `CAPABILITY_NMSG`) and advertise both `U2F_V2` and `FIDO_2_0`.

## Automated / host (no browser)

```bash
# L2: GetInfo only (no finger)
pytest tests/device/test_hid_ctap2_getinfo.py -v --device

# L3 host: MakeCredential + GetAssertion via python-fido2
pip install fido2
python scripts/tests/webauthn_ctap2_smoke.py
# OLED: place enrolled finger when prompted (Confirm / Place finger)
```

Pass criteria (verified on product hardware):

| Step | Pass |
|------|------|
| GetInfo status `0x00` | versions include **`U2F_V2` and `FIDO_2_0`**; INIT caps = **WINK\|CBOR** (bit0+bit2; **no NMSG**) |
| MakeCredential (host/script) | completes after finger (`CTAPHID_CBOR`) |
| Browser create (Chrome) | finger prompt via **U2F_REGISTER GetTouch** and/or CTAP2 MC; OLED success only after CTAP2 MC/GA or a **non-bogus** U2F create (not GetInfo, not Chrome GetTouch) |
| GetAssertion | completes after finger; UP/UV flags set |

Note: use `Ctap2(..., strict_cbor=False)` (baked into the smoke script). Solo encoder key order is accepted by browsers; newer python-fido2 defaults to strict canonical CBOR. GetInfo options/algorithms use lex key order where practical (`clientPin`? `credMgmt` `plat` `rk` `up` `uv`; alg map `alg` then `type`).

## Manual browser smoke

1. Flash product: `pio run -e esp32-s3-n16r8 -t upload` (or `scripts/flash_product_usb.py`).
2. Plug Cryptick (product USB `1209:BEEE`). Enroll at least one fingerprint if not already.
3. Open Chromium/Chrome (or Safari) that lists **external** USB security keys.
4. Visit a known demo:
   - [webauthn.io](https://webauthn.io)
   - [webauthn.me](https://webauthn.me)
5. **Register**
   - Authenticator: **cross-platform / USB security key** (not only platform/iCloud)
   - Prefer **no resident key required** first
   - Attestation: **none** is fine (`CRYPTICK_ATTEST_FMT_NONE=1` default → CTAP2 `fmt: "none"` for small HID replies)
6. When OS/browser shows “touch security key”, place **enrolled finger** on Cryptick (**Place finger** on OLED).
7. Expect success toast; credential stored for that RP.
8. **Authenticate** on the same site → finger again → success.

### CDC log checklist (during Register)

| Log | Meaning |
|-----|---------|
| `CTAPHID_INIT` / `CTAPHID_CBOR` GetInfo | Normal probe — **no** OLED Working/OK |
| `CTAPHID_WINK` | Optional blink |
| `CTAPHID_MSG` + `U2F_REGISTER` | Chrome **GetTouch** (bogus app `0x41…` / chal `0x42…`) **or** CTAP1 create. Finger required. GetTouch must **not** toast Success |
| `CTAPHID_CBOR` MakeCredential | CTAP2 create after GetTouch. Same finger reused once (`CRYPTICK_FIDO_UV_CACHE_MS`). **GetAssertion / U2F_AUTHENTICATE always need a new finger** |
| `[FP] MATCH` then success toast | UV completed for a real create/get |

### Failures to record

| Symptom | Likely cause |
|---------|----------------|
| Key never listed | still Serial/JTAG firmware, or only HID broken |
| `NMSG: U2F/CTAPHID_MSG disabled` | **old build** still advertising NMSG — reflash product env without `CAPABILITY_NMSG` |
| Place finger then OLED OK but browser still “Create a passkey…” | **False success UI** — GetInfo/GetTouch must not toast; success only on CTAP2 MC/GA `0x00` or a real (non-bogus) U2F body+`0x9000`. Also: stay awake `CRYPTICK_FIDO_CEREMONY_HOLD_MS` so MakeCredential is not raced by idle sleep |
| Place finger then browser “timed out or was not allowed” | **clientPin:false** in GetInfo (fixed: omit `clientPin` until PIN set); or empty `pinAuth` after outdated GetInfo |
| Register hangs until browser timeout, no match log | no enrolled template / wrong finger (`[FP] MATCH` on CDC) |
| Invalid attestation / untrusted | expected with self-signed product batch cert until MDS |
| Resident-key required fails | RK/PIN polish not product-complete — use non-RK first |

## Product honesty

- Protocol: **CTAP2.0 + U2F/MSG** over HID (`CAPABILITY_WINK \| CAPABILITY_CBOR`, GetInfo versions **`FIDO_2_0` first**, then `U2F_V2`). Finger UV. No PIN required for demos.
- macOS Chrome often does `GetInfo → WINK → U2F_REGISTER` as **GetTouch** (bogus challenge `0x42…` / app `0x41…`), then CTAP2 **MakeCredential**. GetInfo and GetTouch must not toast OLED success. That fingerprint is a **one-shot credit for MakeCredential only** (`CRYPTICK_FIDO_UV_CACHE_MS`). Login (`GetAssertion` / `U2F_AUTHENTICATE`) always prompts again.
- U2F_REGISTER multi-frame writeback must keep `is_processing` latched until IN completes (no mid-write IDLE) so 750ms CID timeouts cannot corrupt ~670B replies. MSG APDUs are decoded as short **or** extended (Chrome's 73-byte register is extended + Le).
- Do **not** set `CAPABILITY_NMSG`: Chrome still sends MSG after GetInfo and will fail create if MSG is refused.
- CTAP 2.2 extras (PPUAT, pin complexity) are not implemented and not required for webauthn.io.
- Attestation for browser demos defaults to CTAP2 `fmt: "none"` (empty attStmt). Packed batch cert is used on U2F_REGISTER and available for CTAP2 packed via `-DCRYPTICK_ATTEST_FMT_NONE=0`.

## PIN (optional, not needed for webauthn.io)

Cryptick Token uses **fingerprint** as user verification. A FIDO client PIN is optional and only advertised in GetInfo after you set one (not required for create/get passkey on demos).

If you later want a client PIN (enterprise / multi-user policy): use a native tool such as:

```bash
# After product PIN support is polished and GetInfo lists clientPin
fido2-token -S /dev/hidrawN   # set PIN (linux/libfido2)
```

Product path today: enroll finger → browser create/get without PIN UI.

## Related

- L2 HID: `tests/device/test_hid_fido_init.py`, `test_hid_ctap2_getinfo.py`
- OATH UV: `tests/device/test_hid_oath_lifecycle.py`
- Security: `docs/SECURITY_ROADMAP.md`
- Yubico CTAP 2.2 overview (not required for product demos): https://developers.yubico.com/CTAP/CTAP2.2.html
