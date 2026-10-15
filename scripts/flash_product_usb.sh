#!/usr/bin/env bash
# Flash product MODE=0 (TinyUSB CDC+HID, VID 0x1209 / PID 0xBEEE) over USB.
#
# Paths:
#   1) Device still on Serial/JTAG (303A) or stuck → this script / env -install
#   2) Device already product (1209:BEEE) →: pio run -e esp32-s3-n16r8 -t upload
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.platformio/penv/bin:${PATH}"

echo "[flash] building product MODE=0 → install env"
pio run -e esp32-s3-n16r8-install

PORT="${1:-}"
if [[ -z "${PORT}" ]]; then
  # Prefer usbmodem (S3 Serial/JTAG or TinyUSB CDC)
  PORT="$(ls /dev/cu.usbmodem* 2>/dev/null | head -1 || true)"
fi
if [[ -z "${PORT}" ]]; then
  PORT="$(ls /dev/cu.usbserial* 2>/dev/null | head -1 || true)"
fi
if [[ -z "${PORT}" ]]; then
  echo "[flash] no /dev/cu.usbmodem* or usbserial* — unplug/replug device USB-C, then retry"
  exit 1
fi

echo "[flash] port=${PORT}"
# Free port holders (serial monitors)
if command -v lsof >/dev/null 2>&1; then
  for p in $(lsof -t "${PORT}" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
  sleep 0.5
fi

ESPTOOL="$(find "${HOME}/.platformio/packages" -path "*/tool-esptoolpy/esptool.py" 2>/dev/null | head -1)"
if [[ -z "${ESPTOOL}" ]]; then
  ESPTOOL="$(find "${HOME}/.platformio/packages" -name esptool.py 2>/dev/null | head -1)"
fi
BOOT_APP0="${HOME}/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
BUILD=".pio/build/esp32-s3-n16r8-install"

echo "[flash] esptool write (usb_reset → product TinyUSB binary)"
python3 "${ESPTOOL}" --chip esp32s3 -p "${PORT}" -b 460800 \
  --before usb_reset --after hard_reset write_flash \
  0x0 "${BUILD}/bootloader.bin" \
  0x8000 "${BUILD}/partitions.bin" \
  0xe000 "${BOOT_APP0}" \
  0x10000 "${BUILD}/firmware.bin"

echo "[flash] done — expect host: VID 0x1209 PID 0xBEEE Cryptick Token"
echo "[flash]   CDC: /dev/cu.usbmodem* @115200   HID: FIDO usage page"
echo "[flash] later reflash product: pio run -e esp32-s3-n16r8 -t upload  (1200bps)"
