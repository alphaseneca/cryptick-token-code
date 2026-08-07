# Encryption / security roadmap

## Today

| Asset | At rest | Gate |
|-------|---------|------|
| TOTP secrets | **Plaintext JSON** on LittleFS (`CONFIG_FILE`) | OLED UI behind fingerprint; HID PUT not yet FP-gated |
| FIDO RK / PIN state | NVS / LittleFS RK blob | UV = fingerprint for presence |
| Attestation key | Flash constant (dev cert) | Swap for product before ship |

**Do not claim secrets are encrypted** until the encrypt path below ships and is tested.

## Target

1. **Device secret key** in eFuse/NVS (factory or first boot RNG)  
2. **AES-GCM** (or AES-SIV) wrap each TOTP secret field before `storage_save_config`  
3. Host PUT via OATH HID stores ciphertext only  
4. **FP gate** sensitive OATH ops (PUT/DELETE/LIST secrets metadata OK; CALCULATE optional policy)  
5. Optional: refuse CDC debug CLI if `CRYPTICK_SERIAL_DEBUG_CMDS` off (default)  
6. L1 Unity: storage encrypt/decrypt round-trip  

## OATH FP policy note

Product intent: same fingerprint stack as FIDO (presence). MVP ships management over HID without FP for lab convenience; ship checklist should turn on FP for PUT/DELETE before external distribution.

## CI

Every PR: product `pio run` + host `pytest tests/host` (see `.github/workflows/ci.yml`).
