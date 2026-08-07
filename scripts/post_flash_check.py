#!/usr/bin/env python3
"""Smoke-check product firmware over UART (CH340) or TinyUSB CDC after upload.

Usage:
  python scripts/post_flash_check.py
  python scripts/post_flash_check.py COM10
"""
from __future__ import annotations

import re
import sys
import time

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    print("pip install pyserial")
    sys.exit(2)

# Prefer product CDC, then CH340 UART (bring-up adapter)
PREFERRED = (
    ("1209", "BEEE"),  # Cryptick TinyUSB
    ("1A86", "7523"),  # CH340
    ("303A", "1001"),  # USB Serial/JTAG (MODE=1 tests / ROM)
)

EXPECTED_MAP = "RIGHT=5 DOWN=4 UP=7 LEFT=6 CENTER=15"


def pick_port(forced: str | None) -> str:
    if forced:
        return forced
    ports = list(list_ports.comports())
    for vid, pid in PREFERRED:
        for p in ports:
            h = (p.hwid or "").upper()
            if f"VID:PID={vid}:{pid}" in h.replace(" ", ""):
                return p.device
    if not ports:
        raise SystemExit("No serial ports found")
    return ports[0].device


def main() -> int:
    forced = sys.argv[1] if len(sys.argv) > 1 else None
    dev = pick_port(forced)
    print(f"[check] open {dev} @115200")
    ser = serial.Serial(dev, 115200, timeout=0.2)
    time.sleep(0.4)
    ser.reset_input_buffer()

    # Wake / dump banner
    ser.write(b"\r\nHELP\r\n")
    ser.flush()
    deadline = time.time() + 8.0
    buf = ""
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk.decode("utf-8", errors="replace")
            if "[BOOT] Ready" in buf or "cryptick>" in buf or "[IN] map" in buf:
                break
        time.sleep(0.05)

    print("--- capture ---")
    print(buf[-4000:] if len(buf) > 4000 else buf)
    print("--- end ---")

    ok = True
    if EXPECTED_MAP not in buf and f"RIGHT=5" not in buf:
        # Try provoke map reprint (input re-init is only on boot)
        print(f"[check] FAIL: expected button map containing {EXPECTED_MAP}")
        ok = False
    else:
        print(f"[check] OK button map: {EXPECTED_MAP}")

    for needle in ("[DISP]", "[FP]", "[BOOT] Ready", "Cryptick"):
        if needle.lower() in buf.lower() or needle in buf:
            print(f"[check] saw {needle!r}")
        else:
            print(f"[check] missing {needle!r} (may need power-cycle + reconnect UART TX/RX)")

    # Soft enroll start (non-blocking) — only checks command accepted
    ser.write(b"FINGER_ENROLL\r\n")
    ser.flush()
    time.sleep(1.5)
    more = ser.read(4096).decode("utf-8", errors="replace")
    print(more)
    if "enroll" in more.lower() or "FINGER" in more or "place" in more.lower():
        print("[check] FINGER_ENROLL got a response")
        ser.write(b"FINGER_ABORT\r\n")
        ser.flush()
        time.sleep(0.3)
    else:
        print("[check] WARN: no enroll serial response (sensor / baud / wiring?)")

    ser.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
