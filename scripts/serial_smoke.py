#!/usr/bin/env python3
"""Stream the Cryptick CDC console for 12 s and summarise what the board said.

Usage:
  python3 scripts/serial_smoke.py                 # auto-detect 1209:BEEE
  python3 scripts/serial_smoke.py /dev/cu.usbmodemXXXX

Use this when you want to *watch* the boot log. For a pass/fail gate after
flashing, use scripts/post_flash_check.py instead.

Port discovery and the DTR handling live in tests/support/cryptick_usb.py so
this script, post_flash_check.py and the L2 pytest suite all agree on what
counts as "the product console".
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


def main() -> int:
    if not pyserial_available():
        print("FAIL: pyserial missing — pip install -r tests/requirements.txt")
        return 2

    preferred = sys.argv[1] if len(sys.argv) > 1 else None

    print("Ports:")
    for p in list_serial_ports():
        print(f"  {p.device}  {p.hwid}  {p.description}")

    port = preferred or find_product_cdc()
    if not port:
        print("FAIL: no Cryptick CDC (1209:BEEE) and no port given")
        return 1

    print(f"\nOpening {port} @115200 for 12 s (DTR asserted)...")
    ser = open_cdc(port)

    deadline = time.time() + 12
    chunks: list[bytes] = []
    help_sent = False
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            chunks.append(chunk)
            sys.stdout.write(chunk.decode("utf-8", errors="replace"))
            sys.stdout.flush()
        if not help_sent and time.time() > deadline - 10:
            ser.write(b"HELP\r\n")
            help_sent = True
    ser.close()

    text = b"".join(chunks).decode("utf-8", errors="replace")
    print("\n--- summary ---")
    checks = [
        ("banner", "cryptick" in text.lower()),
        ("input_map", "[IN] map" in text or "RIGHT=" in text),
        ("boot_ready", "Ready" in text or "LittleFS" in text or "[HB]" in text),
        ("fp", "[FP]" in text),
    ]
    ok = 0
    for name, passed in checks:
        print(f"  {name}: {'OK' if passed else 'MISS'}")
        ok += int(passed)

    if ok == 0:
        print("FAIL: no Cryptick traffic — wrong port (ROM 303A?) or USB CDC broken")
        return 2
    print(f"PASS partial {ok}/{len(checks)}")
    return 0 if ok >= 2 else 3


if __name__ == "__main__":
    raise SystemExit(main())
