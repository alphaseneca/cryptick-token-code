#!/usr/bin/env python3
"""Pass/fail smoke check of the product firmware right after upload.

Usage:
  python3 scripts/post_flash_check.py                        # auto-detect
  python3 scripts/post_flash_check.py /dev/cu.usbmodemXXXX   # force a port

Exit code 0 means the board booted far enough to print the button map.

Port discovery and DTR handling live in tests/support/cryptick_usb.py, shared
with serial_smoke.py and the L2 pytest suite.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from support.cryptick_usb import (  # noqa: E402
    find_product_cdc,
    list_serial_ports,
    open_cdc,
    pyserial_available,
)

EXPECTED_MAP = "RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15"

# Fallbacks when the product CDC is not up: a still-cabled CH340, or the
# ROM/Serial-JTAG device that means the board never left download mode.
FALLBACK_VID_PID = (
    (0x1A86, 0x7523),  # CH340 bring-up adapter
    (0x303A, 0x1001),  # Espressif ROM / Serial-JTAG
)


def pick_port(forced: str | None) -> str:
    if forced:
        return forced
    port = find_product_cdc()
    if port:
        return port
    ports = list_serial_ports()
    for vid, pid in FALLBACK_VID_PID:
        for p in ports:
            if p.vid == vid and p.pid == pid:
                print(f"[check] WARN product CDC absent — falling back to {p.device} "
                      f"({vid:04X}:{pid:04X})")
                return p.device
    if not ports:
        raise SystemExit("No serial ports found")
    return ports[0].device


def main() -> int:
    if not pyserial_available():
        print("pip install -r tests/requirements.txt")
        return 2

    forced = sys.argv[1] if len(sys.argv) > 1 else None
    dev = pick_port(forced)
    print(f"[check] open {dev} @115200 (DTR=on for TinyUSB DATA)")
    ser = open_cdc(dev)

    ser.write(b"\r\nHELP\r\n")
    ser.flush()
    deadline = time.time() + 12.0
    buf = ""
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk.decode("utf-8", errors="replace")
            if "[BOOT] Ready" in buf or "cryptick>" in buf or "[IN] map" in buf:
                break
        time.sleep(0.05)

    if "[BOOT] Ready" not in buf:
        time.sleep(1.0)
        extra = ser.read(8192)
        if extra:
            buf += extra.decode("utf-8", errors="replace")

    print("--- capture ---")
    print(buf[-4000:] if len(buf) > 4000 else buf)
    print("--- end ---")

    ok = True
    if EXPECTED_MAP not in buf and "RIGHT=5" not in buf:
        print(f"[check] FAIL: expected button map containing {EXPECTED_MAP}")
        print("[check] open the Cryptick CDC (1209:BEEE), not CH340, after unplugging the adapter")
        ok = False
    else:
        print(f"[check] OK button map: {EXPECTED_MAP}")

    for needle in ("[DISP]", "[FP]", "[BOOT] Ready", "Cryptick", "[USB]"):
        print(f"[check] {'saw' if needle.lower() in buf.lower() else 'missing'} {needle!r}")

    ser.write(b"HELP\r\n")
    ser.flush()
    time.sleep(0.3)
    more = ser.read(4096).decode("utf-8", errors="replace")
    if more.strip():
        print(more[-500:])

    ser.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
