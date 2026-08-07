#include "usb_device.h"
#include <string.h>

#ifdef ESP32
#include "USB.h"
#include "esp32-hal-tinyusb.h"
#endif

/*
 * Prefer class headers; keep tusb API from ESP32 core stack.
 * Umbrella Adafruit_TinyUSB.h pulls MSC headers (SdFat dependency) — avoid it.
 */
#include "arduino/Adafruit_USBD_CDC.h"
#include "arduino/hid/Adafruit_USBD_HID.h"
#include "tusb.h"

/*
 * Single CDC + FIDO HID. Product registers one CDC interface at runtime.
 * VID/PID set via USB API (avoid build-flag clash with board pins_arduino).
 */

#ifndef CRYPTICK_USB_VID
#define CRYPTICK_USB_VID 0x1209
#endif
#ifndef CRYPTICK_USB_PID
#define CRYPTICK_USB_PID 0xBEEE
#endif

static Adafruit_USBD_HID _usb_hid;
Stream &USBLog = Serial;

#define HID_RX_QUEUE_SIZE 12
static uint8_t _rx_queue[HID_RX_QUEUE_SIZE][64];
static volatile uint8_t _rx_head = 0;
static volatile uint8_t _rx_tail = 0;

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

static void _hid_report_callback(uint8_t report_id, hid_report_type_t report_type,
                                 uint8_t const *buffer, uint16_t bufsize)
{
    (void)report_id;
    if (report_type == HID_REPORT_TYPE_OUTPUT && bufsize == 64) {
        uint8_t next = (uint8_t)((_rx_head + 1) % HID_RX_QUEUE_SIZE);
        if (next != _rx_tail) {
            memcpy(_rx_queue[_rx_head], buffer, 64);
            _rx_head = next;
        }
    }
}

void usb_device_init(void)
{
#ifdef ESP32
    USB.manufacturerName(USB_MANUFACTURER);
    USB.productName(USB_PRODUCT);
    USB.VID(CRYPTICK_USB_VID);
    USB.PID(CRYPTICK_USB_PID);
#endif

    _usb_hid.setPollInterval(5);
    _usb_hid.setReportDescriptor(hid_report_descriptor, sizeof(hid_report_descriptor));
    _usb_hid.setReportCallback(NULL, _hid_report_callback);
    _usb_hid.begin();

#ifdef ESP32
    USB.begin();
#endif

    Serial.begin(115200);

    /* Short wait only — never block boot (OLED / buttons must still work). */
    uint32_t t0 = (uint32_t)millis();
    while ((uint32_t)millis() - t0 < 800) {
        if (Serial || (tud_inited() && tud_mounted()))
            break;
        delay(10);
        yield();
    }
    delay(30);
}

bool usb_device_mounted(void)
{
    return tud_inited() && tud_mounted();
}

void usb_device_enter_bootloader(void)
{
#ifdef ESP32
    Serial.println(F("[USB] Entering ROM download mode..."));
    Serial.flush();
    delay(50);
    usb_persist_restart(RESTART_BOOTLOADER);
    Serial.println(F("[USB] bootloader restart failed"));
#endif
}

void usb_device_poll_bootloader(void)
{
#ifdef ESP32
    if (!tud_inited() || !tud_mounted())
        return;
    if (!tud_cdc_n_connected(0)) {
        cdc_line_coding_t coding;
        tud_cdc_n_get_line_coding(0, &coding);
        if (coding.bit_rate == 1200)
            usb_persist_restart(RESTART_BOOTLOADER);
    }
#endif
}

extern "C" void __wrap_TinyUSB_Port_EnterDFU(void)
{
#ifdef ESP32
    usb_persist_restart(RESTART_BOOTLOADER);
#endif
}

bool usb_hid_read_report(uint8_t buffer[64])
{
    if (_rx_head != _rx_tail) {
        memcpy(buffer, _rx_queue[_rx_tail], 64);
        _rx_tail = (uint8_t)((_rx_tail + 1) % HID_RX_QUEUE_SIZE);
        return true;
    }
    return false;
}

static SemaphoreHandle_t _usb_mutex = NULL;

bool usb_hid_send_report(const uint8_t buffer[64])
{
    if (!_usb_mutex)
        _usb_mutex = xSemaphoreCreateMutex();

    uint32_t timeout = (uint32_t)millis() + 50;
    while ((uint32_t)millis() < timeout) {
        if (_usb_hid.ready()) {
            if (xSemaphoreTake(_usb_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                bool success = _usb_hid.sendReport(0, buffer, 64);
                xSemaphoreGive(_usb_mutex);
                if (success)
                    return true;
            }
        }
        yield();
    }
    return false;
}
