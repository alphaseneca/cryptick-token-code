#include "usb_hid.h"
#include "Adafruit_TinyUSB.h"
#include <string.h>

extern "C" {
    void i2c_lock();
    void i2c_unlock();
}

/**
 * @brief FIDO HID Report Descriptor.
 * 
 * Required format to be recognized by operating systems and browsers
 * as a FIDO Alliance Authenticator (Usage Page 0xF1D0).
 */
static const uint8_t hid_report_descriptor[] = {
    0x06, 0xD0, 0xF1,   // Usage Page (FIDO Alliance)
    0x09, 0x01,         // Usage (U2FHID)
    0xA1, 0x01,         // Collection (Application)
    0x09, 0x20,         // Usage (Data In)
    0x15, 0x00,         // Logical Minimum (0)
    0x26, 0xFF, 0x00,   // Logical Maximum (255)
    0x75, 0x08,         // Report Size (8)
    0x95, 0x40,         // Report Count (64)
    0x81, 0x02,         // Input (Data, Var, Abs)
    0x09, 0x21,         // Usage (Data Out)
    0x15, 0x00,         // Logical Minimum (0)
    0x26, 0xFF, 0x00,   // Logical Maximum (255)
    0x75, 0x08,         // Report Size (8)
    0x95, 0x40,         // Report Count (64)
    0x91, 0x02,         // Output (Data, Var, Abs)
    0xC0                // End Collection
};

static Adafruit_USBD_HID _usb_hid;

/* Circular buffer for incoming reports (4 deep to handle typical bursts) */
#define HID_RX_QUEUE_SIZE 12
static uint8_t  _rx_queue[HID_RX_QUEUE_SIZE][64];
static volatile uint8_t _rx_head = 0;
static volatile uint8_t _rx_tail = 0;

/*
 * @brief Internal callback for Adafruit_TinyUSB upon receiving a HID report.
 */
static void _hid_report_callback(uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize) {
    (void)report_id;
    if (report_type == HID_REPORT_TYPE_OUTPUT && bufsize == 64) {
        uint8_t next = (_rx_head + 1) % HID_RX_QUEUE_SIZE;
        if (next != _rx_tail) { // Don't overwrite if full
            memcpy(_rx_queue[_rx_head], buffer, 64);
            _rx_head = next;
        }
    }
}

void usb_hid_init(void) {
    _usb_hid.setPollInterval(2);
    _usb_hid.setReportDescriptor(hid_report_descriptor, sizeof(hid_report_descriptor));
    _usb_hid.setReportCallback(NULL, _hid_report_callback);
    _usb_hid.begin();
}

bool usb_hid_read_report(uint8_t buffer[64]) {
    if (_rx_head != _rx_tail) {
        memcpy(buffer, _rx_queue[_rx_tail], 64);
        _rx_tail = (_rx_tail + 1) % HID_RX_QUEUE_SIZE;
        return true;
    }
    return false;
}

static SemaphoreHandle_t _usb_mutex = NULL;

bool usb_hid_send_report(const uint8_t buffer[64]) {
    if (!_usb_mutex) _usb_mutex = xSemaphoreCreateMutex();

    // Simplified log to prevent buffer overflow/stalls.
    // Use [HID] TX: CMD for quick diagnosis without flooding slow Serial.
    Serial.printf("[HID] TX (CMD: 0x%02X)\n", buffer[4]);

    bool success = false;
    uint32_t timeout = millis() + 50; 
    
    while (millis() < timeout) {
        if (_usb_hid.ready()) {
            if (xSemaphoreTake(_usb_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                success = _usb_hid.sendReport(0, buffer, 64);
                xSemaphoreGive(_usb_mutex);
                if (success) return true;
            }
        }
        yield();
    }
    Serial.println("[HID] TX Timeout!");
    return false;
}





