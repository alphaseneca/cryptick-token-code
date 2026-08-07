#!/usr/bin/env python3
"""Serial smoke test after Cryptick flash.
Looks for Cryptick (1209:BEEE) COM or given COMx.
"""
import sys
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyserial", "-q"])
    import serial
    import serial.tools.list_ports

TARGET_VID = 0x1209
TARGET_PID = 0xBEEE


def find_port(preferred=None):
    if preferred:
        return preferred
    for p in serial.tools.list_ports.comports():
        h = (p.hwid or "").upper()
        if "VID:PID=1209:BEEE" in h or "VID_1209" in h and "PID_BEEE" in h:
            return p.device
        if "CRYPTICK" in (p.description or "").upper():
            return p.device
    # fallback first COM
    ports = list(serial.tools.list_ports.comports())
    return ports[0].device if ports else None


def main():
    pref = sys.argv[1] if len(sys.argv) > 1 else None
    print("Ports:")
    for p in serial.tools.list_ports.comports():
        print(f"  {p.device}  {p.hwid}  {p.description}")

    port = find_port(pref)
    if not port:
        print("FAIL: no serial ports")
        return 1
    print(f"\nOpening {port} @ 115200 for 12s...")
    ser = serial.Serial(port, 115200, timeout=0.5)
    time.sleep(0.3)
    # soft re-open kick for some stacks
    ser.dtr = False
    time.sleep(0.05)
    ser.dtr = True
    deadline = time.time() + 12
    buf = b""
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            sys.stdout.write(chunk.decode("utf-8", errors="replace"))
            sys.stdout.flush()
        # try HELP once after 2s
        if time.time() > deadline - 9 and b"cryptick" not in buf.lower() and b"HELP" not in buf:
            ser.write(b"HELP\r\n")
    ser.close()
    print("\n--- summary ---")
    text = buf.decode("utf-8", errors="replace")
    checks = [
        ("banner", "Cryptick" in text or "CRYPTICK" in text or "cryptick" in text.lower()),
        ("input_map", "[IN] map" in text or "RIGHT=" in text),
        ("boot_ready", "Ready" in text or "LittleFS" in text or "[HB]" in text),
        ("fp", "[FP]" in text),
    ]
    ok = 0
    for name, pass_ in checks:
        print(f"  {name}: {'OK' if pass_ else 'MISS'}")
        if pass_:
            ok += 1
    if ok == 0:
        print("FAIL: no Cryptick firmware traffic — wrong COM (ROM 303A?) or USB CDC broken")
        return 2
    print(f"PASS partial {ok}/{len(checks)}")
    return 0 if ok >= 2 else 3


if __name__ == "__main__":
    raise SystemExit(main())
