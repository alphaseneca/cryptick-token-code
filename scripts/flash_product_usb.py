#!/usr/bin/env python3
"""Flash Cryptick product firmware over USB-C (esptool).

Handles:
  - App running as Serial/JTAG (VID 303A) — usb_reset
  - App running as TinyUSB product (VID 1209/BEEE) — 1200 bps touch → ROM
  - Already in ROM download mode

Usage:
  python3 scripts/flash_product_usb.py
  python3 scripts/flash_product_usb.py --port /dev/cu.usbmodem12301
  python3 scripts/flash_product_usb.py --env esp32-s3-n16r8-jtag
"""
from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
import time


def list_ports() -> list[str]:
    if sys.platform == "darwin":
        return sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/cu.usbserial*"))
    if sys.platform.startswith("linux"):
        return sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
    return []


def try_1200_touch(port: str) -> None:
    try:
        import serial  # type: ignore
    except ImportError:
        print("note: pyserial not installed; 1200 touch skipped (esptool may still work)")
        return
    print(f"1200bps touch on {port}…")
    try:
        ser = serial.Serial(port, 1200)
        time.sleep(0.05)
        ser.close()
    except Exception as e:
        print(f"  1200 touch: {e}")
    time.sleep(1.2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="serial port (default: first cu.usbmodem*)")
    ap.add_argument("--env", default="esp32-s3-n16r8", help="PlatformIO env")
    ap.add_argument("--build-only", action="store_true")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)

    env = args.env
    r = subprocess.call(["pio", "run", "-e", env])
    if r != 0:
        return r
    if args.build_only:
        return 0

    port = args.port
    if not port:
        ports = list_ports()
        if not ports:
            print("No USB serial ports found. Plug device or pass --port.")
            return 2
        port = ports[0]
        print(f"using port {port}")

    is_jtag_or_rom = False
    try:
        from serial.tools import list_ports as lp
        for p in lp.comports():
            if p.device == port and p.vid == 0x303A:
                is_jtag_or_rom = True
                break
    except Exception:
        pass

    if is_jtag_or_rom:
        print(f"Port {port} is Espressif VID 303A (Serial/JTAG or ROM) — skipping 1200bps touch")
        env = "esp32-s3-n16r8-install"
    else:
        # Product TinyUSB / most CDC apps need 1200 → ROM before esptool
        try_1200_touch(port)

    ports_after = list_ports()
    upload_port = ports_after[0] if ports_after else port
    if upload_port != port:
        print(f"ROM / new port: {upload_port}")

    cmd = [
        "pio",
        "run",
        "-e",
        env,
        "-t",
        "upload",
        "--upload-port",
        upload_port,
    ]
    print(" ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
