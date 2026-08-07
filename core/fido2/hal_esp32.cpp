#include "device.h"
#include "ctaphid.h"
#include "log.h"
#include <Arduino.h>
#include <nvs.h>
#include <nvs_flash.h>
#include "esp_random.h"
#include "LittleFS.h"
#include <board_config.h>
#include <RTClib.h>
#include "usb_device.h"

extern "C" {

#define HID_QUEUE_LEN 16
static bool _up_disabled = false;
static bool _is_processing = false;
static bool _user_confirmed = false;
static bool _request_cancelled = false;
volatile int8_t _fido_ui_request = 0; // 0=Idle, 1=Prompt, 2=Processing
QueueHandle_t volatile _hid_queue = NULL; // Volatile for cross-core safety
static TaskHandle_t  _fido_task_handle = NULL;
SemaphoreHandle_t _i2c_mutex = NULL;
#define FIDO_STACK_SIZE (32 * 1024)

/* Button ISRs removed — InputSystem owns all navigation pins. */

void i2c_mutex_init() {
    if (!_i2c_mutex) {
        _i2c_mutex = xSemaphoreCreateRecursiveMutex();
    }
}

void i2c_lock() {
    if (!_i2c_mutex) i2c_mutex_init();
    xSemaphoreTakeRecursive(_i2c_mutex, portMAX_DELAY);
}

void i2c_unlock() {
    if (_i2c_mutex) xSemaphoreGiveRecursive(_i2c_mutex);
}

void usbhid_send(uint8_t *msg) {
    if (msg) {
        usb_hid_send_report(msg);
    }
}

void ctaphid_push_report(const uint8_t *report) {
    if (!report) return;
    if (!_hid_queue) {
        Serial.println("[FIDO] ERR: Bridge Queue not initialized!");
        return;
    }

    if (xQueueSend(_hid_queue, report, 0) != pdTRUE) {
        Serial.println("[FIDO] Bridge FULL! Recovering...");
        Serial.flush();
        xQueueReset(_hid_queue);
        xQueueSend(_hid_queue, report, 0); 
    } else {
        Serial.println("[FIDO] Bridge: Packet Queued.");
    }
}

void ctaphid_confirm_user_presence() {
    _user_confirmed = true;
}

void ctaphid_cancel_request() {
    _request_cancelled = true;
}

uint8_t ctaphid_is_processing() {
    return _is_processing;
}

static unsigned long _last_status_1_or_2_ms = 0;

void device_hal_heartbeat() {
    unsigned long now = millis();
    // Persist UI states 1 and 2 for at least 1500ms 
    // to prevent flickering during protocol segmenting.
    if (_fido_ui_request != 0 && !_is_processing) {
        if (now - _last_status_1_or_2_ms > 1500) {
            _fido_ui_request = 0;
        }
    }
}

void device_set_status(uint32_t status) {
    unsigned long now = millis();
    if (status == CTAPHID_STATUS_PROCESSING) {
        _is_processing = true;
        _fido_ui_request = 2; // Processing
        _last_status_1_or_2_ms = now;
    } else if (status == CTAPHID_STATUS_UPNEEDED) {
        _is_processing = true;
        _fido_ui_request = 1; // Prompt
        _last_status_1_or_2_ms = now;
    } else if (status == CTAPHID_STATUS_IDLE) {
        _is_processing = false;
        // Don't clear immediately; let the heartbeat handled it once 1500ms has passed.
    }
    Serial.printf("[HAL] Status: %d | UI Req: %d\n", status, _fido_ui_request);
}

int device_button_pressed(int btn) {
    (void)btn;
    return 0; /* InputSystem owns buttons; FIDO UV is fingerprint only */
}

int device_is_button_pressed(void) {
    return 0;
}

uint32_t device_get_time_utc() {
    extern uint32_t get_synced_utc();
    return get_synced_utc();
}

uint32_t device_millis() {
    return (uint32_t)millis();
}

void device_reboot() {
    ESP.restart();
}

int ctap_user_presence_test(uint32_t delay_ms) {
    if (_up_disabled) {
        Serial.println("[HAL] UP Warning: UP is disabled, auto-confirming.");
        return 1; // Success
    }

    uint32_t start = millis();
    uint32_t last_keepalive = 0;
    _fido_ui_request = 1; // Request Prompt UI → fingerprint match on main core
    _user_confirmed = false;
    _request_cancelled = false;

    Serial.println("[HAL] UP Wait: place enrolled finger to confirm");

    while (millis() - start < delay_ms) {
        uint32_t now = millis();

        /* FIDO user presence is fingerprint only (bridge from FpSystem/NavSystem) */
        if (_user_confirmed) {
            Serial.println("[HAL] UP Success (fingerprint)");
            _fido_ui_request = 2; // Request Processing UI
            return 1;
        }

        if (now - last_keepalive >= 100) {
            extern void ctaphid_update_status(int8_t status);
            ctaphid_update_status(CTAPHID_STATUS_UPNEEDED);
            last_keepalive = now;
        }

        if (_request_cancelled) {
            Serial.println("[HAL] UP Cancelled by User");
            _fido_ui_request = 0;
            return -1;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
        yield();
    }

    Serial.println("[HAL] UP Timeout");
    _fido_ui_request = 0;
    return 0;
}

void _fido_task_loop(void *pvParameters) {
    Serial.println("[FIDO] Starting Task on Core 0...");
    ctap_init();
    Serial.println("[FIDO] Protocol Stack Ready.");
    
    uint8_t pkt[64];
    uint32_t last_heartbeat = 0;
    while(true) {
        if (_hid_queue && xQueueReceive(_hid_queue, pkt, pdMS_TO_TICKS(10)) == pdTRUE) {
            Serial.printf("[FIDO] RX Packet: CMD 0x%02X\n", pkt[4]);
            ctaphid_handle_packet(pkt);
        }
        ctaphid_check_timeouts();
        
        vTaskDelay(pdMS_TO_TICKS(5)); 
    }
}

void device_init_esp32() {
    static bool _initialized = false;
    if (_initialized) {
        Serial.println("[FIDO] HAL Already Active. Skipping Re-init.");
        return;
    }
    _initialized = true;

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    /* Navigation pins owned by InputSystem — do not attach ISRs here. */

    if (_hid_queue == NULL) {
        _hid_queue = xQueueCreate(HID_QUEUE_LEN, 64);
        Serial.println("[FIDO] Bridge Queue Initialized.");
    }
    i2c_mutex_init();
    
    if (_fido_task_handle == NULL) {
        xTaskCreatePinnedToCore(
            _fido_task_loop,
            "fido2_task",
            FIDO_STACK_SIZE,
            NULL,
            4,          // Priority 4 (High)
            &_fido_task_handle,
            0
        );
        Serial.println("[FIDO] Task Created.");
    }
}

void device_hal_init() {
    device_init_esp32();
}

uint32_t millis_esp32() {
    return millis();
}

int authenticator_read_state(AuthenticatorState *s) {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open("fido2", NVS_READONLY, &my_handle);
    if (err != ESP_OK) return 0;
    size_t required_size = sizeof(AuthenticatorState);
    err = nvs_get_blob(my_handle, "state", s, &required_size);
    nvs_close(my_handle);
    return (err == ESP_OK && s->is_initialized == INITIALIZED_MARKER);
}

void authenticator_write_state(AuthenticatorState *s) {
    nvs_handle_t my_handle;
    if (nvs_open("fido2", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_blob(my_handle, "state", s, sizeof(AuthenticatorState));
        nvs_commit(my_handle);
        nvs_close(my_handle);
    }
}

void device_disable_up(bool disable) {
    _up_disabled = disable;
}

int ctap_generate_rng(uint8_t *dst, size_t num) {
    esp_fill_random(dst, num);
    return 1;
}

uint32_t ctap_atomic_count(uint32_t amount) {
    nvs_handle_t my_handle;
    uint32_t counter = 0;
    esp_err_t err = nvs_open("fido2", NVS_READWRITE, &my_handle);
    if (err == ESP_OK) {
        nvs_get_u32(my_handle, "counter", &counter);
        counter += amount;
        nvs_set_u32(my_handle, "counter", counter);
        nvs_commit(my_handle);
        nvs_close(my_handle);
    }
    return counter;
}

#define RK_FILENAME "/fido2_rk.bin"

void ctap_reset_rk() {
    LittleFS.remove(RK_FILENAME);
}

uint32_t ctap_rk_size() {
    return 50; 
}

void ctap_store_rk(int index, CTAP_residentKey *rk) {
    File f = LittleFS.open(RK_FILENAME, "r+");
    if (!f) f = LittleFS.open(RK_FILENAME, "w");
    if (f) {
        f.seek(index * sizeof(CTAP_residentKey));
        f.write((uint8_t*)rk, sizeof(CTAP_residentKey));
        f.close();
    }
}

void ctap_load_rk(int index, CTAP_residentKey * rk) {
    memset(rk, 0xff, sizeof(CTAP_residentKey));
    File f = LittleFS.open(RK_FILENAME, "r");
    if (f) {
        f.seek(index * sizeof(CTAP_residentKey));
        size_t read_bytes = f.read((uint8_t*)rk, sizeof(CTAP_residentKey));
        if (read_bytes < sizeof(CTAP_residentKey)) {
            // Partial read: likely end of file reached. 
            // The buffer was already 0xff initialized, so the rest remains 0xff (invalid).
        }
        f.close();
    }
}

void ctap_delete_rk(int index) {
    CTAP_residentKey empty;
    memset(&empty, 0xff, sizeof(CTAP_residentKey));
    ctap_store_rk(index, &empty);
}

void ctap_overwrite_rk(int index, CTAP_residentKey *rk) {
    ctap_store_rk(index, rk);
}

void device_wink() {
    Serial.println("WINK!");
}

void device_set_clock_rate(DEVICE_CLOCK_RATE param) {}
int device_is_nfc() { return 0; }
void usbhid_close() {}
void device_init() {}

void cryptick_enter_bootloader(void) {
    usb_device_enter_bootloader();
}

void cryptick_lock_if_not_already(void) {}
uint8_t cryptick_is_locked(void) { return 0; }

static const uint8_t _attestation_cert_der[] =
"\x30\x82\x01\xfb\x30\x82\x01\xa1\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38"
"\x30\x35\x31\x30\x30\x33\x30\x36\x32\x30\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32"
"\x37\x30\x33\x30\x36\x32\x30\x5a\x30\x7c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x0f\x30\x0d"
"\x06\x03\x55\x04\x07\x0c\x06\x4c\x61\x75\x72\x65\x6c\x31\x15\x30\x13\x06\x03\x55"
"\x04\x0a\x0c\x0c\x54\x45\x53\x54\x20\x43\x4f\x4d\x50\x41\x4e\x59\x31\x22\x30\x20"
"\x06\x03\x55\x04\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
"\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04"
"\x03\x0c\x0b\x63\x6f\x6e\x6f\x72\x70\x70\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf"
"\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d\x70\x3f\xb4\x02\xa4\x97\xf4\x83"
"\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a\x3e\x14\x48\x92\xef\x08\xf8\xca"
"\xea\xfb\x32\xab\x20\xa3\x62\x30\x60\x30\x46\x06\x03\x55\x1d\x23\x04\x3f\x30\x3d"
"\xa1\x30\xa4\x2e\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04"
"\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x82\x09\x00\xf7\xc9\xec\x89\xf2\x63\x94"
"\xd9\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04"
"\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00"
"\x30\x45\x02\x20\x18\x38\xb0\x45\x03\x69\xaa\xa7\xb7\x38\x62\x01\xaf\x24\x97\x5e"
"\x7e\x74\x64\x1b\xa3\x7b\xf7\xe6\xd3\xaf\x79\x28\xdb\xdc\xa5\x88\x02\x21\x00\xcd"
"\x06\xf1\xe3\xab\x16\x21\x8e\xd8\xc0\x14\xaf\x09\x4f\x5b\x73\xef\x5e\x9e\x4b\xe7"
"\x35\xeb\xdd\x9b\x6d\x8f\x7d\xf3\xc4\x3a\xd7";

void device_attestation_read_cert_der(uint8_t * dst) {
    memmove(dst, _attestation_cert_der, sizeof(_attestation_cert_der) - 1);
}

int device_attestation_cert_der_get_size() {
    return sizeof(_attestation_cert_der) - 1;
}

static uint8_t _attestation_key[32] = {0xcd, 0x67, 0xaa, 0x31, 0x0d, 0x09, 0x1e, 0xd1, 0x6e, 0x7e, 0x98, 0x92, 0xaa, 0x07, 0x0e, 0x19, 0x94, 0xfc, 0xd7, 0x14, 0xae, 0x7c, 0x40, 0x8f, 0xb9, 0x46, 0xb7, 0x2e, 0x5f, 0xe7, 0x5d, 0x30};

uint8_t *device_get_attestation_key() {
    return _attestation_key;
}

void device_read_aaguid(uint8_t * dst){
    // "UCASELABS" based AAGUID
    static const uint8_t aaguid[16] = {
        0x00, 0x55, 0x43, 0x41, 0x53, 0x45, 0x4c, 0x41, 
        0x42, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    memmove(dst, aaguid, 16);
}

} // extern C
