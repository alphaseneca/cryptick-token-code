# Product attestation (FIDO2)

## Status (honest)

| Item | Done? |
|------|--------|
| Dedicated Cryptick P-256 **attestation private key** in firmware | **Yes** — `core/fido2/cryptick_attestation.inc` |
| Matching **X.509 cert DER** (self-signed batch) | **Yes** — CN=`Cryptick Token`, O=`Ucaselabs` |
| Stable product **AAGUID** | **Yes** — `c7a5e1e0-7c4b-4f0a-9d2e-55c41c710001` |
| Wired into Solo HAL (`device_get_attestation_key` / cert DER / AAGUID) | **Yes** |
| Public CA / FIDO **MDS** metadata published | **No** |
| Factory HSM / per-device key injection | **No** |
| Browser “trusted manufacturer” without local trust | **No** (self-signed by design) |

So: **not Solo test material anymore** — this is a **Cryptick Token batch attestation package**.  
It is **not** “finished commercial FIDO certification / MDS” identity.

Regenerate (new batch) only when you intentionally rotate:

```bash
pip install cryptography
python3 scripts/generate_attestation.py
# commit updated cryptick_attestation.inc; flash product
```

WebAuthn demos: use `attestation: none` for pure protocol smoke, or `direct` to exercise the package (host/RP may still flag untrusted root).

## Product AAGUID (must match GetInfo / ATTEST)

```
c7a5e1e0-7c4b-4f0a-9d2e-55c41c710001
```

CDC: type `ATTEST` for cert size + AAGUID.
