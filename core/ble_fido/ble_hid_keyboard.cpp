#include "ble_hid_keyboard.h"
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>
#include <cryptick_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

static NimBLEHIDDevice *s_hid = nullptr;
static NimBLECharacteristic *s_input_report = nullptr;

/* Standard 1-byte Report ID Keyboard descriptor */
static const uint8_t s_keyboard_report_map[] = {
    0x05, 0x01,                    // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,                    // USAGE (Keyboard)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, 0x01,                    //   REPORT_ID (1)
    0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
    0x19, 0xe0,                    //   USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xe7,                    //   USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //   LOGICAL_MAXIMUM (1)
    0x75, 0x01,                    //   REPORT_SIZE (1)
    0x95, 0x08,                    //   REPORT_COUNT (8)
    0x81, 0x02,                    //   INPUT (Data,Var,Abs)
    0x95, 0x01,                    //   REPORT_COUNT (1)
    0x75, 0x08,                    //   REPORT_SIZE (8)
    0x81, 0x01,                    //   INPUT (Cnst,Ary,Abs)
    0x95, 0x06,                    //   REPORT_COUNT (6)
    0x75, 0x08,                    //   REPORT_SIZE (8)
    0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
    0x25, 0x65,                    //   LOGICAL_MAXIMUM (101)
    0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
    0x19, 0x00,                    //   USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65,                    //   USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00,                    //   INPUT (Data,Ary,Abs)
    0xc0                           // END_COLLECTION
};

#include "totp.h"
#include <vector>

extern std::vector<TOTPCredential> credentials;
extern "C" uint32_t get_synced_utc(void);

void ble_hid_keyboard_init(void)
{
    NimBLEServer *server = NimBLEDevice::getServer();
    if (!server) {
        CLOG_E("BLE_HID", "no GATT server; call ble_fido_gatt_init() first");
        return;
    }

    s_hid = new NimBLEHIDDevice(server);
    s_input_report = s_hid->getInputReport(1);

    s_hid->setManufacturer("Ucaselabs");
    s_hid->setPnp(0x02, 0x1209, 0xBEEE, 0x0100);
    s_hid->setHidInfo(0x00, 0x01);
    s_hid->setReportMap((uint8_t *)s_keyboard_report_map, sizeof(s_keyboard_report_map));
    s_hid->setBatteryLevel(100);

    /* Explicitly start all HID services so they are registered with GATT server */
    if (s_hid->getDeviceInfoService()) {
        s_hid->getDeviceInfoService()->start();
    }
    if (s_hid->getHidService()) {
        s_hid->getHidService()->start();
    }
    if (s_hid->getBatteryService()) {
        s_hid->getBatteryService()->start();
    }

    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    if (adv) {
        adv->setAppearance(HID_KEYBOARD);
        if (s_hid->getHidService()) {
            adv->addServiceUUID(s_hid->getHidService()->getUUID());
        }
    }

    CLOG_I("BLE_HID", "BLE HID Keyboard service ready and started");
}

bool ble_hid_keyboard_is_connected(void)
{
    NimBLEServer *server = NimBLEDevice::getServer();
    return (server && server->getConnectedCount() > 0 && s_input_report != nullptr);
}

static void send_key(uint8_t keycode, uint8_t modifier)
{
    if (!s_input_report) return;

    /* 8-byte standard keyboard input report */
    uint8_t report[8] = { modifier, 0, keycode, 0, 0, 0, 0, 0 };
    s_input_report->setValue(report, sizeof(report));
    s_input_report->notify();
    vTaskDelay(pdMS_TO_TICKS(30));

    /* Key release */
    memset(report, 0, sizeof(report));
    s_input_report->setValue(report, sizeof(report));
    s_input_report->notify();
    vTaskDelay(pdMS_TO_TICKS(30));
}

bool ble_hid_type_string(const char *str)
{
    if (!str || !ble_hid_keyboard_is_connected()) {
        CLOG_W("BLE_HID", "cannot type string: BLE peer not connected");
        return false;
    }

    CLOG_I("BLE_HID", "typing string over BLE HID...");
    for (const char *p = str; *p; p++) {
        uint8_t kc = 0;
        uint8_t mod = 0;
        char c = *p;
        if (c >= '1' && c <= '9') {
            kc = 0x1E + (c - '1'); // '1' = 0x1E, '2' = 0x1F, ..., '9' = 0x26
        } else if (c == '0') {
            kc = 0x27;             // '0' = 0x27
        } else if (c >= 'a' && c <= 'z') {
            kc = 0x04 + (c - 'a'); // 'a' = 0x04 ... 'z' = 0x1D
        } else if (c >= 'A' && c <= 'Z') {
            kc = 0x04 + (c - 'A');
            mod = 0x02;            // Left Shift
        } else if (c == '\n' || c == '\r') {
            kc = 0x28;             // Enter = 0x28
        } else if (c == '\t') {
            kc = 0x2B;             // Tab = 0x2B
        } else if (c == ' ') {
            kc = 0x2C;             // Space = 0x2C
        } else if (c == '-') {
            kc = 0x2D;
        } else if (c == '_') {
            kc = 0x2D;
            mod = 0x02;
        }
        if (kc) {
            send_key(kc, mod);
        }
    }
    return true;
}

bool ble_hid_type_pin(const char *pin)
{
    if (!pin || !ble_hid_keyboard_is_connected()) {
        CLOG_W("BLE_HID", "cannot type PIN: BLE peer not connected");
        return false;
    }

    if (!ble_hid_type_string(pin))
        return false;

    /* Send Return key to submit */
    send_key(0x28, 0);
    CLOG_I("BLE_HID", "PIN sent successfully");
    return true;
}

bool ble_hid_type_piv_pin(void)
{
    return ble_hid_type_pin("123456");
}

bool ble_hid_type_current_totp(int account_idx)
{
    if (credentials.empty()) {
        CLOG_W("BLE_HID", "no TOTP accounts configured");
        return false;
    }
    int idx = account_idx;
    if (idx < 0 || idx >= (int)credentials.size()) {
        idx = 0;
    }
    uint32_t now_utc = get_synced_utc();
    String code = totp_generate(credentials[idx], now_utc);
    if (code.length() == 0 || code == "Bad Key" || code == "Bad Algo") {
        CLOG_W("BLE_HID", "TOTP generate failed");
        return false;
    }
    CLOG_I("BLE_HID", "typing TOTP code for account %s...", credentials[idx].label.c_str());
    return ble_hid_type_pin(code.c_str());
}
