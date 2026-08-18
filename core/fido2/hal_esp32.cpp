#include "device.h"
#include "ctaphid.h"
#include "log.h"
#include <Arduino.h>
#include <nvs.h>
#include <nvs_flash.h>
#include "esp_random.h"
#include "LittleFS.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <RTClib.h>
#include "usb_device.h"

extern "C" {

#define HID_QUEUE_LEN 16
static bool _up_disabled = false;
/*
 * Cross-core (FIDO task core0 ↔ Arduino loop): all must be volatile so main
 * never sees UI prompt without processing, which used to clear Place-finger
 * after 1.5s and stop MATCH_FIDO while CTAP still waited.
 */
static volatile bool _is_processing = false;
static volatile bool _user_confirmed = false;
static volatile bool _request_cancelled = false;
volatile int8_t _fido_ui_request = 0; // 0=Idle, 1=Prompt, 2=Processing, 3=Success
static volatile unsigned long _last_status_1_or_2_ms = 0;
/* One-shot GetTouch → MakeCredential credit. Never used for assert/auth. */
static volatile uint32_t _uv_cache_until_ms = 0;
QueueHandle_t volatile _hid_queue = NULL; // Volatile for cross-core safety
static TaskHandle_t  _fido_task_handle = NULL;
SemaphoreHandle_t _i2c_mutex = NULL;
#define FIDO_STACK_SIZE (32 * 1024)

/* CTAPHID packet[4] = type|cmd; CANCEL is TYPE_INIT|0x11 */
static bool hid_pkt_is_cancel(const uint8_t *pkt)
{
    if (!pkt) return false;
    uint8_t type_cmd = pkt[4];
    return (type_cmd & TYPE_INIT) && ((type_cmd & 0x7f) == 0x11);
}

/** Drop queued CTAPHID_CANCEL while blocked in UP (FIDO task cannot handle). */
static void poll_queued_cancel(void)
{
    if (!_hid_queue) return;
    uint8_t pkt[64];
    if (xQueuePeek((QueueHandle_t)_hid_queue, pkt, 0) != pdTRUE)
        return;
    if (!hid_pkt_is_cancel(pkt))
        return;
    if (xQueueReceive((QueueHandle_t)_hid_queue, pkt, 0) == pdTRUE) {
        _request_cancelled = true;
        CLOG_I("HAL", "UP: host CTAPHID_CANCEL");
    }
}

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
    if (!msg)
        return;
    /*
     * Reliable multi-frame CTAPHID (U2F_REGISTER ~12 × 64B after UV).
     * usb_hid_send_report is ready-gated (~500ms budget, no retransmit-after-submit).
     * One short outer retry if endpoint was briefly busy (keepalive just submitted).
     */
    if (usb_hid_send_report(msg))
        return;
    vTaskDelay(pdMS_TO_TICKS(2));
    if (usb_hid_send_report(msg))
        return;
    CLOG_E("USB", "HID TX FAILED (IN not accepted)");
}

void usbhid_send_besteffort(uint8_t *msg) {
    if (!msg)
        return;
    /*
     * Keepalives must never stack 3s failure waits during place-finger —
     * that delayed MSG writeback by ~12 × 3s (~38s) and froze the browser dialog.
     */
    static uint16_t drops;
    if (usb_hid_try_send_report(msg)) {
        drops = 0;
        return;
    }
    drops++;
    if ((drops % 20u) == 0u)
        CLOG_D("USB", "HID keepalive drop x%u (IN busy/unread)", (unsigned)drops);
}

void ctaphid_push_report(const uint8_t *report) {
    if (!report) return;
    if (!_hid_queue) {
        CLOG_E("FIDO", "ERR: Bridge Queue not initialized!");
        return;
    }

    if (xQueueSend(_hid_queue, report, 0) != pdTRUE) {
        CLOG_D("FIDO", "Bridge FULL! Recovering...");
        CryptickLog.flush();
        xQueueReset(_hid_queue);
        xQueueSend(_hid_queue, report, 0); 
    } else {
        CLOG_D("FIDO", "Bridge: Packet Queued.");
    }
}

void ctaphid_confirm_user_presence() {
    _user_confirmed = true;
}

void ctaphid_cancel_request() {
    _request_cancelled = true;
    _uv_cache_until_ms = 0;
}

uint8_t ctaphid_is_processing() {
    return _is_processing ? 1 : 0;
}

void device_hal_heartbeat() {
    unsigned long now = millis();
    /*
     * Auto-clear residual UI:
     *  - req 1/2 only after !_is_processing (legacy latch)
     *  - req 3 (success) held ~1.5s then clock
     * Never invent success from clearing processing.
     */
    if (_fido_ui_request == 3) {
        if (now - _last_status_1_or_2_ms > 1500) {
            _fido_ui_request = 0;
        }
        return;
    }
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
        /*
         * PROCESSING latches the CID timeout, not the OLED. GetInfo used to
         * flash "Working…" and wake from sleep before any user gesture.
         * Only promote UI when we were already in a presence ceremony.
         */
        if (_fido_ui_request == 1 || _fido_ui_request == 2 || _fido_ui_request == 3)
            _fido_ui_request = 2;
        _last_status_1_or_2_ms = now;
    } else if (status == CTAPHID_STATUS_UPNEEDED) {
        _is_processing = true;
        _fido_ui_request = 1; // Prompt
        _last_status_1_or_2_ms = now;
    } else if (status == CTAPHID_STATUS_IDLE) {
        _is_processing = false;
        /* Do not map IDLE→Success; see device_ctap_finished(). */
        _last_status_1_or_2_ms = now;
    }
    CLOG_D("HAL", "Status: %d | UI Req: %d proc=%d",
           (int)status, (int)_fido_ui_request, _is_processing ? 1 : 0);
}

/** After CTAPHID has fully written the CBOR reply (or error status byte). */
void device_ctap_finished(uint8_t ctap_status, int allow_success_ui) {
    _is_processing = false;
    if (allow_success_ui && ctap_status == 0) {
        _fido_ui_request = 3; /* real create/get success only */
        CLOG_I("HAL", "CTAP OK → UI success");
    } else {
        /* GetInfo / ClientPin / errors: no success toast */
        if (_fido_ui_request == 1 || _fido_ui_request == 2 || _fido_ui_request == 3)
            _fido_ui_request = 0;
        if (ctap_status != 0)
            CLOG_W("HAL", "CTAP status=0x%02x toast=%d → UI idle",
                   ctap_status, allow_success_ui);
    }
    _last_status_1_or_2_ms = millis();
}

void device_delay_ms(uint32_t ms) {
    if (ms == 0)
        return;
    vTaskDelay(pdMS_TO_TICKS(ms));
}

int device_button_pressed(int btn) {
    (void)btn;
    return 0; /* InputSystem owns buttons; FIDO UV is fingerprint only */
}

int device_is_button_pressed(void) {
    return 0;
}

uint32_t device_get_time_utc() {
    extern uint32_t get_synced_utc(void);
    return get_synced_utc();
}

void device_set_time_utc(uint32_t utc) {
    extern void set_synced_utc(uint32_t);
    set_synced_utc(utc);
}

uint32_t device_millis() {
    return (uint32_t)millis();
}

void device_reboot() {
    ESP.restart();
}

void ctap_uv_cache_arm_gettouch(void)
{
    uint32_t now = (uint32_t)millis();
    _uv_cache_until_ms = now + (uint32_t)CRYPTICK_FIDO_UV_CACHE_MS;
    CLOG_I("HAL", "UP cache armed %u ms (GetTouch→MakeCredential only)",
           (unsigned)CRYPTICK_FIDO_UV_CACHE_MS);
}

int ctap_user_presence_test(uint32_t delay_ms) {
    return ctap_user_presence_test_ex(delay_ms, 0);
}

int ctap_user_presence_test_ex(uint32_t delay_ms, int allow_uv_cache) {
    if (_up_disabled) {
        CLOG_W("HAL", "UP Warning: UP is disabled, auto-confirming.");
        return 1; // Success
    }

    uint32_t now0 = (uint32_t)millis();
    if (allow_uv_cache && _uv_cache_until_ms != 0 &&
        (int32_t)(_uv_cache_until_ms - now0) > 0) {
        /*
         * Chrome GetTouch already took a fingerprint. MakeCredential may
         * consume that credit once. Authenticate / GetAssertion never do.
         */
        CLOG_I("HAL", "UP cached GetTouch→MC (%lu ms left)",
               (unsigned long)(_uv_cache_until_ms - now0));
        _uv_cache_until_ms = 0;
        _is_processing = true;
        if (_fido_ui_request == 1)
            _fido_ui_request = 2;
        _last_status_1_or_2_ms = now0;
        return 1;
    }

    /* A new finger wait is a new ceremony — drop a leftover GetTouch credit. */
    if (_uv_cache_until_ms != 0) {
        CLOG_D("HAL", "UP cache dropped (assert/auth needs finger)");
        _uv_cache_until_ms = 0;
    }

    if (delay_ms < 2000)
        delay_ms = CRYPTICK_FIDO_UP_TIMEOUT_MS;

    uint32_t start = millis();
    uint32_t last_keepalive = 0;
    /*
     * Hold UI + FP match for the whole delay_ms. Heartbeat may only clear
     * UI when !_is_processing — latch processing for the full wait.
     *
     * FIDO task (core 0): main loop arms MATCH_FIDO via nav _fido_ui_request.
     * Main-core callers (CDC OATH UV, SETTIME path): loop is blocked, so we
     * self-service GenImg/Search via device_presence_fp_* (no FP on core 0).
     */
    _user_confirmed = false;
    _request_cancelled = false;
    _is_processing = true;
    _fido_ui_request = 1; /* Prompt UI → fingerprint match on main core */
    _last_status_1_or_2_ms = millis();

    const bool self_service = !device_on_fido_task();
    if (self_service)
        device_presence_fp_begin();

    CLOG_I("HAL", "UP Wait: place enrolled finger (%lu ms) self_svc=%d",
           (unsigned long)delay_ms, self_service ? 1 : 0);

    while (millis() - start < delay_ms) {
        uint32_t now = millis();

        poll_queued_cancel();

        if (self_service && device_presence_fp_poll() == 1) {
            _user_confirmed = true;
        }

        /* FIDO user presence is fingerprint only (bridge from FpSystem/NavSystem) */
        if (_user_confirmed) {
            CLOG_I("HAL", "UP Success (fingerprint%s)",
                   self_service ? " self-service" : "");
            _fido_ui_request = 2; /* Processing UI */
            _last_status_1_or_2_ms = now;
            /* Do not arm cache here — only GetTouch (u2f.c) may. */
            if (self_service)
                device_presence_fp_end();
            /* Keep processing true until device_set_status(IDLE) after CTAP */
            return 1;
        }

        if (_request_cancelled) {
            CLOG_I("HAL", "UP Cancelled");
            _fido_ui_request = 0;
            _is_processing = false;
            _uv_cache_until_ms = 0;
            if (self_service)
                device_presence_fp_end();
            return -1;
        }

        /*
         * CTAP keepalive ~100 ms. Best-effort only (usbhid_send_besteffort);
         * if host is not reading IN, we drop instead of 3s blocking.
         * For self-service (CDC), keepalive is harmless no-op if no active CID.
         */
        if (now - last_keepalive >= 100) {
            extern void ctaphid_update_status(int8_t status);
            ctaphid_update_status(CTAPHID_STATUS_UPNEEDED);
            last_keepalive = now;
            /* Re-latch in case of any stray IDLE / non-volatile race */
            _fido_ui_request = 1;
            _is_processing = true;
            _last_status_1_or_2_ms = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
        yield();
    }

    CLOG_E("HAL", "UP Timeout");
    _fido_ui_request = 0;
    _is_processing = false;
    _uv_cache_until_ms = 0;
    if (self_service)
        device_presence_fp_end();
    return 0;
}

void _fido_task_loop(void *pvParameters) {
    CLOG_I("FIDO", "Starting Task on Core 0...");
    ctap_init();
    CLOG_I("FIDO", "Protocol Stack Ready.");
    
    uint8_t pkt[64];
    uint32_t last_heartbeat = 0;
    while(true) {
        if (_hid_queue && xQueueReceive(_hid_queue, pkt, pdMS_TO_TICKS(10)) == pdTRUE) {
            CLOG_D("FIDO", "RX Packet: CMD 0x%02X", pkt[4]);
            ctaphid_handle_packet(pkt);
        }
        ctaphid_check_timeouts();
        
        vTaskDelay(pdMS_TO_TICKS(5)); 
    }
}

void device_init_esp32() {
    static bool _initialized = false;
    if (_initialized) {
        CLOG_I("FIDO", "HAL Already Active. Skipping Re-init.");
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
        CLOG_I("FIDO", "Bridge Queue Initialized.");
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
        CLOG_D("FIDO", "Task Created.");
    }
}

void device_hal_init() {
    device_init_esp32();
    /* Product attestation identity (always log at INFO once at boot) */
    uint8_t aaguid[16];
    device_read_aaguid(aaguid);
    CLOG_I("ATTEST",
           "AAGUID=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x "
           "cert_der=%d batch=self-signed CN=Cryptick Token",
           aaguid[0], aaguid[1], aaguid[2], aaguid[3], aaguid[4], aaguid[5],
           aaguid[6], aaguid[7], aaguid[8], aaguid[9], aaguid[10], aaguid[11],
           aaguid[12], aaguid[13], aaguid[14], aaguid[15],
           device_attestation_cert_der_get_size());
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

int device_on_fido_task(void) {
    return (_fido_task_handle != NULL &&
            xTaskGetCurrentTaskHandle() == _fido_task_handle) ? 1 : 0;
}

/*
 * Prompt caption handoff. The FIDO task writes, the Arduino loop reads; the
 * spinlock keeps a caption from being half-overwritten while being copied out.
 */
static char _ui_label[64];
static bool _ui_label_pending = false;
static portMUX_TYPE _ui_label_mux = portMUX_INITIALIZER_UNLOCKED;

void device_set_ui_label(const char *label) {
    if (!label || !label[0])
        return;
    portENTER_CRITICAL(&_ui_label_mux);
    strncpy(_ui_label, label, sizeof(_ui_label) - 1);
    _ui_label[sizeof(_ui_label) - 1] = 0;
    _ui_label_pending = true;
    portEXIT_CRITICAL(&_ui_label_mux);
}

int device_take_ui_label(char *out, size_t cap) {
    if (!out || cap == 0)
        return 0;
    int taken = 0;
    portENTER_CRITICAL(&_ui_label_mux);
    if (_ui_label_pending) {
        strncpy(out, _ui_label, cap - 1);
        out[cap - 1] = 0;
        _ui_label_pending = false;
        taken = 1;
    }
    portEXIT_CRITICAL(&_ui_label_mux);
    return taken;
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
    CLOG_I("HAL", "WINK");
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

/* Product batch attestation — Cryptick Token (self-signed batch; mfr Ucaselabs). */
#include "cryptick_attestation.inc"

void device_attestation_read_cert_der(uint8_t * dst) {
    if (!dst)
        return;
    memmove(dst, kCryptickTokenAttestCertDer, sizeof(kCryptickTokenAttestCertDer));
}

int device_attestation_cert_der_get_size() {
    return (int)sizeof(kCryptickTokenAttestCertDer);
}

uint8_t *device_get_attestation_key() {
    /* Return writable-looking pointer required by Solo API; content is product key */
    static uint8_t key_ram[32];
    static int ready = 0;
    if (!ready) {
        memmove(key_ram, kCryptickTokenAttestKey, 32);
        ready = 1;
    }
    return key_ram;
}

void device_read_aaguid(uint8_t * dst){
    if (!dst)
        return;
    memmove(dst, kCryptickTokenAaguid, 16);
}

} // extern C
