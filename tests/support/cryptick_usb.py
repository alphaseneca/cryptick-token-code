"""Shared helpers for Cryptick device (L2) and tooling."""
from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Iterable, Optional

VID_PRODUCT = 0x1209
PID_PRODUCT = 0xBEEE
VID_JTAG = 0x303A
PID_JTAG = 0x1001


@dataclass
class UsbDeviceInfo:
    vid: int
    pid: int
    product: str
    manufacturer: str
    serial_path: Optional[str]


def pyserial_available() -> bool:
    try:
        import serial  # noqa: F401
    except ImportError:
        return False
    return True


def list_serial_ports():
    """Enumerate serial ports, or return [] when pyserial is not installed.

    Discovery must degrade to "no device found" rather than raising: the L2
    fixtures call this before deciding whether to skip, so raising here turned
    a missing optional dependency into 14 collection errors instead of skips.
    Callers that genuinely need pyserial (open_cdc) report it themselves.
    """
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    return list(list_ports.comports())


def find_product_cdc(preferred: Optional[str] = None) -> Optional[str]:
    if preferred:
        return preferred
    for p in list_serial_ports():
        # pyserial vid/pid ints are reliable on macOS (hwid string can lag)
        if p.vid == VID_PRODUCT and p.pid == PID_PRODUCT:
            return p.device
        h = (p.hwid or "").upper().replace(" ", "")
        if f"VID:PID={VID_PRODUCT:04X}:{PID_PRODUCT:04X}" in h:
            return p.device
        if "CRYPTICK" in (p.device or "").upper() or "CRYPTICK" in (p.description or "").upper():
            if p.vid in (None, VID_PRODUCT) or f"VID:PID={VID_PRODUCT:04X}" in h or "1209" in h:
                return p.device
    for p in list_serial_ports():
        if "CRYPTICK" in (p.device or "").upper():
            return p.device
    return None


def open_cdc(port: Optional[str] = None, baud: int = 115200, settle_s: float = 1.0):
    """Open Cryptick CDC. Assert DTR for TinyUSB DATA on macOS; avoid DTR drop (bootloader)."""
    try:
        import serial
    except ImportError as e:
        raise RuntimeError("pyserial required: pip install -r tests/requirements.txt") from e

    path = find_product_cdc(port)
    if not path:
        raise FileNotFoundError("No Cryptick CDC (1209:BEEE / usbmodemCRYPTICK*)")

    last_err: Optional[Exception] = None
    for attempt in range(3):
        try:
            ser = serial.Serial()
            ser.port = path
            ser.baudrate = baud
            ser.timeout = 0.3
            ser.write_timeout = 1.0
            # Do not toggle DTR low: with enableReboot some stacks interpret that as reset/bootloader
            ser.dsrdtr = True
            ser.rtscts = False
            ser.open()
            try:
                ser.setDTR(True)
                ser.setRTS(False)
            except Exception:
                pass
            time.sleep(settle_s + attempt * 0.3)
            # Kick the console once so app path is exercised
            ser.write(b"\r\n")
            ser.flush()
            time.sleep(0.15)
            ser.reset_input_buffer()
            return ser
        except Exception as e:  # pragma: no cover
            last_err = e
            time.sleep(0.4)
    raise RuntimeError(f"CDC open failed: {last_err}")


def cdc_read_for(ser, seconds: float = 2.0) -> str:
    end = time.time() + seconds
    chunks: list[bytes] = []
    while time.time() < end:
        b = ser.read(4096)
        if b:
            chunks.append(b)
    return b"".join(chunks).decode("utf-8", errors="replace")


def cdc_command(ser, cmd: str, wait_s: float = 1.0) -> str:
    ser.reset_input_buffer()
    line = (cmd.strip() + "\r\n").encode("ascii")
    ser.write(line)
    ser.flush()
    return cdc_read_for(ser, wait_s)


def macos_usb_product_ids() -> list[tuple[int, int, str]]:
    """Return [(vid, pid, name), ...] for Cryptick / Espressif S3 USB."""
    import subprocess

    try:
        text = subprocess.check_output(
            ["ioreg", "-p", "IOUSB", "-l", "-w0"], text=True, errors="replace"
        )
    except Exception:
        return []
    out: list[tuple[int, int, str]] = []
    # Match vendor/product anywhere in each device subtree
    for block in text.split("+-o "):
        v = re.search(r'"idVendor"\s*=\s*(\d+)', block)
        p = re.search(r'"idProduct"\s*=\s*(\d+)', block)
        n = re.search(r'"USB Product Name"\s*=\s*"([^"]*)"', block)
        if not v or not p:
            continue
        vid, pid = int(v.group(1)), int(p.group(1))
        name = n.group(1) if n else ""
        if vid in (VID_PRODUCT, VID_JTAG) or "Cryptick" in name or "ryptick" in name:
            out.append((vid, pid, name))
    # Also accept serial.tools brand match as a logical entry
    for port in list_serial_ports():
        h = (port.hwid or "").upper().replace(" ", "")
        if f"VID:PID={VID_PRODUCT:04X}:{PID_PRODUCT:04X}" in h:
            out.append((VID_PRODUCT, PID_PRODUCT, port.description or "Cryptick Token"))
    return out


def assert_needles(text: str, needles: Iterable[str]) -> list[str]:
    missing = [n for n in needles if n.lower() not in text.lower()]
    return missing
