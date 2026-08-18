"""L3 host CTAP2 smoke using python-fido2 (optional): MakeCredential + GetAssertion.

Uses Ctap2 directly with strict_cbor=False — Solo/Cryptick Token GetInfo CBOR is
accepted by browsers but is not always canonical for modern python-fido2.

  pip install fido2
  python scripts/tests/webauthn_ctap2_smoke.py

Place enrolled finger when OLED shows Confirm / Place finger.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sys
from typing import Any


def find_cryptick_token():
    from fido2.hid import CtapHidDevice

    found = []
    for d in CtapHidDevice.list_devices():
        desc = getattr(d, "descriptor", None)
        vid = pid = None
        if desc is not None:
            vid = getattr(desc, "vid", None) or (desc.get("vendor_id") if isinstance(desc, dict) else None)
            pid = getattr(desc, "pid", None) or (desc.get("product_id") if isinstance(desc, dict) else None)
        if vid == 0x1209 and pid == 0xBEEE:
            found.append(d)
    if found:
        return found[0]
    all_d = list(CtapHidDevice.list_devices())
    if len(all_d) == 1:
        print("Using sole FIDO HID (VID/PID filter miss)")
        return all_d[0]
    return None


def client_data_hash(typ: str, challenge: bytes, origin: str) -> tuple[bytes, bytes]:
    """Return (clientDataJSON, SHA-256 hash) for CTAP clientDataHash."""
    # WebAuthn clientDataJSON — challenge is base64url without padding
    import base64

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    cdata = {
        "type": typ,
        "challenge": b64u(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    raw = json.dumps(cdata, separators=(",", ":")).encode("utf-8")
    return raw, hashlib.sha256(raw).digest()


def main() -> int:
    try:
        from fido2.ctap2 import Ctap2
        from fido2.ctap import STATUS
    except ImportError:
        print("Install:  pip install fido2")
        return 2

    device = find_cryptick_token()
    if not device:
        print("No Cryptick Token FIDO HID 1209:BEEE found")
        return 1

    print("Device open:", getattr(device, "product_name", "Cryptick Token"))

    # Solo tinycbor map key order is not always canonical — disable strict decode
    ctap = Ctap2(device, strict_cbor=False)
    info = ctap.get_info()
    print("GetInfo versions:", list(info.versions))
    print("GetInfo options:", dict(info.options) if info.options else {})
    aaguid = bytes(info.aaguid) if info.aaguid is not None else b""
    want = bytes.fromhex("c7a5e1e07c4b4f0a9d2e55c41c710001")
    print("AAGUID:", aaguid.hex() if aaguid else "?")
    if aaguid == want:
        print("AAGUID matches product batch (docs/ATTESTATION.md)")
    else:
        print("WARN: AAGUID is not product Cryptick Token batch", want.hex())
    if "FIDO_2_0" not in info.versions and "FIDO_2_1_PRE" not in info.versions:
        print("WARN: no FIDO_2_0 in versions:", info.versions)

    def on_keepalive(status: int) -> None:
        if status == STATUS.UPNEEDED:
            print(">>> PLACE ENROLLED FINGER (OLED: Confirm / Place finger)")
        elif status == STATUS.PROCESSING:
            print("   (device processing…)")

    origin = "https://example.com"
    rp_id = "example.com"
    user_id = secrets.token_bytes(16)
    chal = secrets.token_bytes(32)
    _, cdh = client_data_hash("webauthn.create", chal, origin)

    print("MakeCredential…")
    try:
        att = ctap.make_credential(
            client_data_hash=cdh,
            rp={"id": rp_id, "name": "Cryptick Token"},
            user={
                "id": user_id,
                "name": "cryptick-token-user",
                "displayName": "Cryptick Token User",
            },
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
            on_keepalive=on_keepalive,
        )
    except Exception as e:
        print("MakeCredential failed:", type(e).__name__, e)
        return 1

    print("MakeCredential OK")
    auth_data = att.auth_data
    if not auth_data.credential_data:
        print("No credential_data in response")
        return 1
    cred_id = auth_data.credential_data.credential_id
    print("credential_id len:", len(cred_id))

    chal2 = secrets.token_bytes(32)
    _, cdh2 = client_data_hash("webauthn.get", chal2, origin)

    print("GetAssertion…")
    try:
        assertion = ctap.get_assertion(
            rp_id=rp_id,
            client_data_hash=cdh2,
            allow_list=[{"type": "public-key", "id": cred_id}],
            options={"up": True, "uv": False},
            on_keepalive=on_keepalive,
        )
    except Exception as e:
        print("GetAssertion failed:", type(e).__name__, e)
        return 1

    print("GetAssertion OK, user_present=", getattr(assertion.auth_data, "flags", None))
    print("L3 host CTAP2 smoke PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
