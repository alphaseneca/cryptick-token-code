#include "usb_device.h"
#include "usb_ccid.h"
#include <cryptick_log.h>
#include <string.h>
#include <Arduino.h>
#include "cryptick_console.h"

/*
 * Product USB:
 *  ARDUINO_USB_MODE=0 — ESP32 Arduino TinyUSB (CDC + FIDO HID), VID 0x1209 PID 0xBEEE.
 *  ARDUINO_USB_MODE=1 — USB Serial/JTAG (Espressif VID 303A) lab fallback only.
 *
 * Reflash paths (MODE=0, no BOOT pads):
 *  1) CDC: host 1200 bps open/close (Arduino enableReboot) → ROM USB download
 *  2) CLI: type BOOTLOADER → usb_persist_restart(RESTART_BOOTLOADER)
 *  3) HID: CTAPHID ENTERBOOT → same
 *  4) CH340 UART esptool if wired
 */

#if defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK

#include "USB.h"

#ifndef CRYPTICK_USB_VID
#define CRYPTICK_USB_VID 0x1209
#endif
#ifndef CRYPTICK_USB_PID
#define CRYPTICK_USB_PID 0xBEEE
#endif

#if defined(ARDUINO_USB_MODE) && (ARDUINO_USB_MODE == 0)

#include "USBHID.h"
#include "USBCDC.h"
#include "esp32-hal-tinyusb.h"
#include "tusb.h"

/* FIDO CTAPHID: FIDO Alliance usage page, 64-byte in/out (no Report ID) */
static const uint8_t hid_report_descriptor[] = {
    0x06, 0xD0, 0xF1,
    0x09, 0x01,
    0xA1, 0x01,
    0x09, 0x20,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x81, 0x02,
    0x09, 0x21,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,
    0xC0
};

/*
 * OUT reports arrive on the TinyUSB task and are drained by the Arduino loop,
 * so the ring indices need a spinlock rather than bare `volatile`.
 */
#define HID_RX_QUEUE_SIZE 24
static uint8_t _rx_queue[HID_RX_QUEUE_SIZE][64];
static uint8_t _rx_head = 0;
static uint8_t _rx_tail = 0;
static portMUX_TYPE _rx_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t _rx_drops = 0;
static SemaphoreHandle_t _usb_mutex = NULL;

static USBHID _hid;

class CryptickFidoHid : public USBHIDDevice {
public:
    CryptickFidoHid()
    {
        static bool added = false;
        if (!added) {
            added = true;
            _hid.addDevice(this, sizeof(hid_report_descriptor));
        }
    }

    void begin(void) { _hid.begin(); }
    bool ready(void) { return _hid.ready(); }

    uint16_t _onGetDescriptor(uint8_t *buffer) override
    {
        memcpy(buffer, hid_report_descriptor, sizeof(hid_report_descriptor));
        return sizeof(hid_report_descriptor);
    }

    void _onOutput(uint8_t report_id, const uint8_t *buffer, uint16_t len) override
    {
        (void)report_id;
        if (!buffer || len < 64)
            return;
        portENTER_CRITICAL(&_rx_mux);
        uint8_t next = (uint8_t)((_rx_head + 1) % HID_RX_QUEUE_SIZE);
        if (next == _rx_tail) {
            /* Dropping a CTAPHID frame strands the transaction; make it visible. */
            _rx_drops++;
            portEXIT_CRITICAL(&_rx_mux);
            return;
        }
        memcpy(_rx_queue[_rx_head], buffer, 64);
        _rx_head = next;
        portEXIT_CRITICAL(&_rx_mux);
    }

    /* IN reports go through usb_hid_send_report / _try (ready-gated TinyUSB). */
};

static CryptickFidoHid _fido_hid;
/* Own CDC instance — CDC_ON_BOOT=0 so HID can register before USB.begin(). */
static USBCDC _cdc(0);
Stream &USBLog = _cdc;

static void usb_cdc_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_data;
    if (event_id == ARDUINO_USB_CDC_CONNECTED_EVENT) {
        /* Host open/DTR — re-state product path so tests/monitors catch lines */
        CryptickLog.println();
        CLOG_I("USB", "CDC host connected");
        CLOG_I("USB", "TinyUSB product CDC+HID  VID=0x1209 PID=0xBEEE");
        CLOG_I("USB", "reflash: 1200bps | BOOTLOADER | HID ENTERBOOT");
        CryptickLog.print(F("cryptick> "));
        CryptickLog.flush();
    }
}

void usb_device_init(void)
{
    if (!_usb_mutex)
        _usb_mutex = xSemaphoreCreateMutex();

    /* Variant pins_arduino sets USB_VID/USB_PID before app_main USB defaults. */
    USB.manufacturerName(USB_MANUFACTURER);
    USB.productName(USB_PRODUCT);
    USB.VID(CRYPTICK_USB_VID);
    USB.PID(CRYPTICK_USB_PID);
    USB.serialNumber("CRYPTICK");

    /*
     * Descriptor order for product composite (Arduino-ESP32 TinyUSB):
     *   HID + CDC instances register → USB.begin() binds OTG stack.
     * CDC_ON_BOOT must be 0 so we own the CDC instance (product console).
     */
    /*
     * Before USB.begin() and after the CDC instance exists: CDC reserves its
     * endpoints at construction, and this reserves from what is left. Returns
     * false and changes nothing if the interface is latched off or the budget
     * is gone, so a CCID that cannot be added still leaves a composite that
     * enumerates and can be reflashed.
     */
    usb_ccid_register();

    _fido_hid.begin();
    _cdc.onEvent(usb_cdc_event);
    _cdc.begin(115200);
    _cdc.setTxTimeoutMs(0);
    _cdc.enableReboot(true); /* PlatformIO/esptool 1200 bps → ROM download */
    USB.begin();

    uint32_t t0 = (uint32_t)millis();
    while ((uint32_t)millis() - t0 < 2500) {
        if (tud_inited() && tud_mounted())
            break;
        delay(10);
        yield();
    }
    delay(50);

    /* Reaching the configured state is the only proof the descriptors are
     * acceptable to a host, so it is what clears the CCID failure latch. */
    if (tud_inited() && tud_mounted())
        usb_ccid_mount_ok();

    CLOG_I("USB", "TinyUSB product CDC+HID");
    CLOG_I("USB", "VID=0x%04X PID=0x%04X mounted=%d cdc=%d",
                       CRYPTICK_USB_VID, CRYPTICK_USB_PID,
                       (tud_inited() && tud_mounted()) ? 1 : 0,
                       _cdc ? 1 : 0);
    CLOG_I("USB", "host: 1209:BEEE CDC@115200 + FIDO HID%s",
                       usb_ccid_enabled() ? " + CCID" : "");
    CLOG_I("USB", "reflash: 1200bps | BOOTLOADER | HID ENTERBOOT");
    CryptickLog.flush();
}

bool usb_device_mounted(void)
{
    return tud_inited() && tud_mounted();
}

void usb_device_enter_bootloader(void)
{
    CLOG_I("USB", "→ ROM USB download (CDC+JTAG PHY)");
    CryptickLog.flush();
    delay(80);
    /*
     * Espressif: leave TinyUSB product mode and restart into download so the
     * host sees Espressif Serial/JTAG (303A) for esptool.
     */
    usb_persist_restart(RESTART_BOOTLOADER);
    CLOG_E("USB", "bootloader restart failed");
}

void usb_device_poll_bootloader(void)
{
    /*
     * Bootloader entry is USBCDC enableReboot (host open/close at 1200 bps)
     * or BOOTLOADER CLI / HID ENTERBOOT → usb_device_enter_bootloader().
     *
     * Do not force ROM based on stale line-coding=1200 while still connected:
     * that ejects the product CDC after host monitor probes and stranding
     * the board as 303A:1001 until a JTAG reflash.
     */
}


bool usb_hid_read_report(uint8_t buffer[64])
{
    bool got = false;
    portENTER_CRITICAL(&_rx_mux);
    if (_rx_head != _rx_tail) {
        memcpy(buffer, _rx_queue[_rx_tail], 64);
        _rx_tail = (uint8_t)((_rx_tail + 1) % HID_RX_QUEUE_SIZE);
        got = true;
    }
    portEXIT_CRITICAL(&_rx_mux);

    static uint32_t reported_drops = 0;
    uint32_t drops = _rx_drops;
    if (drops != reported_drops) {
        reported_drops = drops;
        CLOG_W("USB", "HID OUT queue full — dropped %lu report(s)",
               (unsigned long)drops);
    }
    return got;
}

/*
 * HID IN via TinyUSB ready + tud_hid_n_report — not USBHID::SendReport().
 *
 * Arduino SendReport() waits on a completion semaphore; on timeout the xfer is
 * often still in flight, then outer retries re-submit the same 64B when ready()
 * flips → duplicate CONT frames or multi-second nested waits (8×400×250 + 3s).
 * Keepalives using that path starve the ~670B U2F_REGISTER writeback (~12 frames).
 *
 * Model: at most one outstanding IN; next frame waits until ready again.
 */
static bool hid_wait_ready(uint32_t deadline_ms)
{
    while ((uint32_t)millis() < deadline_ms) {
        if (tud_inited() && tud_mounted() && tud_hid_n_ready(0))
            return true;
        vTaskDelay(pdMS_TO_TICKS(1));
        yield();
    }
    return tud_inited() && tud_mounted() && tud_hid_n_ready(0);
}

bool usb_hid_try_send_report(const uint8_t buffer[64])
{
    if (!buffer || !_usb_mutex)
        return false;
    if (!tud_inited() || !tud_mounted() || !tud_hid_n_ready(0))
        return false;
    if (xSemaphoreTake(_usb_mutex, 0) != pdTRUE)
        return false;

    bool ok = false;
    if (tud_hid_n_ready(0))
        ok = tud_hid_n_report(0, 0, buffer, 64);

    xSemaphoreGive(_usb_mutex);
    return ok;
}

bool usb_hid_send_report(const uint8_t buffer[64])
{
    /*
     * The mutex is created once in usb_device_init(), before the FIDO task
     * exists. Creating it lazily here raced two callers into two mutexes.
     */
    if (!buffer || !_usb_mutex)
        return false;

    /*
     * Reliable path: wait free → one submit → wait free again (ordered multi-frame).
     * After successful submit never retransmit this buffer even if host is slow;
     * next call blocks on ready first.
     */
    const uint32_t budget_ms = 600u;
    uint32_t t0 = (uint32_t)millis();

    if (xSemaphoreTake(_usb_mutex, pdMS_TO_TICKS(budget_ms)) != pdTRUE)
        return false;

    if (!hid_wait_ready(t0 + 400u)) {
        xSemaphoreGive(_usb_mutex);
        return false;
    }

    if (!tud_hid_n_report(0, 0, buffer, 64)) {
        xSemaphoreGive(_usb_mutex);
        return false;
    }

    /* Host IN completion (1 ms poll typical). Soft wait — do not re-submit. */
    (void)hid_wait_ready(t0 + budget_ms);

    xSemaphoreGive(_usb_mutex);
    return true;
}

#else /* ARDUINO_USB_MODE == 1: USB Serial/JTAG CDC — lab fallback */

Stream &USBLog = Serial;

void usb_device_init(void)
{
    Serial.begin(115200);
    Serial.setTxTimeoutMs(0);
    uint32_t t0 = (uint32_t)millis();
    while ((uint32_t)millis() - t0 < 1200) {
        if (Serial)
            break;
        delay(10);
        yield();
    }
    delay(50);
    CLOG_I("USB", "Serial/JTAG CDC (MODE=1 lab) — no FIDO HID");
    CLOG_I("USB", "Product path: build esp32-s3-n16r8 (MODE=0)");
    CryptickLog.flush();
}

bool usb_device_mounted(void)
{
    return (bool)Serial;
}

void usb_device_enter_bootloader(void)
{
    CLOG_I("USB", "MODE=1 — restart (use esptool --before usb_reset)");
    CryptickLog.flush();
    delay(30);
    esp_restart();
}

void usb_device_poll_bootloader(void)
{
}

bool usb_hid_read_report(uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

bool usb_hid_send_report(const uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

bool usb_hid_try_send_report(const uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

#endif /* ARDUINO_USB_MODE */

#else /* !CRYPTICK_USB_STACK */

Stream &USBLog = Serial;

void usb_device_init(void)
{
    Serial.begin(115200);
    Serial.setTxTimeoutMs(0);
    delay(200);
}

bool usb_device_mounted(void) { return false; }

void usb_device_enter_bootloader(void)
{
    CLOG_I("USB", "stack off — flash with esptool + hard_reset");
    CryptickLog.flush();
}

void usb_device_poll_bootloader(void) {}

bool usb_hid_read_report(uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

bool usb_hid_send_report(const uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

bool usb_hid_try_send_report(const uint8_t buffer[64])
{
    (void)buffer;
    return false;
}

#endif /* CRYPTICK_USB_STACK */
