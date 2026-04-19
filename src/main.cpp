#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <LittleFS.h>
#include <RTClib.h>
#include "tusb.h"

#include "app_config.h"
#include "auth_handler.h"
#include "device_hal.h"
#include "display_handler.h"
#include "navigation.h"
#include "totp_storage.h"
#include "serial_comm.h"
#include "../drivers/usb_hid.h"
#include "../core/fido2/ctaphid.h"
#include "../core/fido2/ctap.h"
#include "../core/fido2/crypto.h"

extern "C" {
    void device_init_esp32();
    void ctaphid_push_report(const uint8_t *report);
    extern volatile int8_t _fido_ui_request;

    void nav_set_state_fido_prompt();
    void nav_set_state_fido_processing();
    void nav_set_state_clock();

    // Bridging FIDO logs to Serial
    void fido_log_print(const char* msg) {
        Serial.print(msg);
    }
}

#ifdef ENABLE_FINGERPRINT
#include "../drivers/fingerprint_r558s.h"
#endif

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
RTC_DS3231 rtc;

#ifdef ENABLE_FINGERPRINT
HardwareSerial fingerprintSerial(1); // Use UART1 for fingerprint sensor
R558SFingerprint finger(fingerprintSerial);
bool fingerprintReady = false;
static void auth_led_success(void) { finger.setLedOnFor(FINGERPRINT_LED_MATCH, 1000); }
static void auth_led_fail(void) { finger.setLed(FINGERPRINT_LED_ERROR); }
static void auth_led_clear(void) { finger.setLedOff(); }
#endif

std::vector<TOTPCredential> credentials;
NavContext navCtx;
unsigned long lastDisplayUpdate = 0;

static String currentUsername = "User";
static int batteryLevel = 85;
static bool bluetoothConnected = false;
bool g_setup_finished = false;


/* ── Timing Engine (Zero-I2C Overhead) ── */
extern "C" uint32_t get_synced_utc() {
    static uint32_t baseUtc = 0;
    static unsigned long baseMillis = 0;
    
    if (baseUtc == 0) {
        // Initial sync on first call
        i2c_lock();
        baseUtc = rtc.now().unixtime();
        i2c_unlock();
        baseMillis = millis();
    }
    
    return baseUtc + (millis() - baseMillis) / 1000;
}


/* Menu page labels (indexed by MenuItem enum) */
static const char *menuLabels[] = { "TOTP", "Settings" };

void setup()
{
    delay(300);
    i2c_mutex_init(); // Create hardware lock immediately
    
    Serial.begin(57600);
    while (!Serial && millis() < 1000); 
    Serial.println("\n\n--- Cryptick Token Starting ---");
    
    i2c_lock();
    Wire.begin(OLED_SDA, OLED_SCL);
    Wire.setClock(400000); 
    i2c_unlock();

    
    yield();


    if (!display_handler_init(display))
    {
        Serial.println("Display failed!");
        while (1)
            delay(10);
    }
    yield();

    Serial.println("[BOOT] Starting Cryptick Firmware...");
    Serial.flush();

    Serial.println("[BOOT] Initializing LittleFS...");
    if (!LittleFS.begin(true)) 
    {
        Serial.println("[BOOT] LittleFS FAIL!");
    } else {
        Serial.println("[BOOT] LittleFS OK");
    }
    yield();

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Checking Boot...");
    display.display();

    Serial.println("[BOOT] Initializing I2C/RTC...");
    i2c_lock();
    if (!rtc.begin())
    {
        i2c_unlock();
        Serial.println("[BOOT] RTC Not Found!");
    }
    else {
        i2c_unlock();
        Serial.println("[BOOT] RTC OK");
    }

    /* Initialize HAL (buttons with ISR, RTC access, rng) */
    Serial.println("[BOOT] Starting FIDO HAL...");
    device_hal_init();
    Serial.println("[BOOT] FIDO HAL Ready");

    Serial.println("[SETUP] Loading Config...");
    loadConfiguration(credentials);
    yield(); 
    Serial.println("[SETUP] Config OK");

    Serial.println("\n[SETUP] Entering Main Loop. System Ready.");
    Serial.print("cryptick> ");
    Serial.flush();

#ifdef ENABLE_FINGERPRINT

    yield();
    fingerprintSerial.begin(FINGERPRINT_BAUD, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);
    delay(200);
    yield();
    finger.setDebug(false);
    if (finger.begin(FINGERPRINT_BAUD) == FINGERPRINT_OK)
    {
        Serial.println("[BOOT] Fingerprint Sensor OK");
        uint16_t count = 0;
        if (finger.getTemplateCount(&count) == FINGERPRINT_OK) {
            Serial.printf("Sensor contains %d templates\n", count);
        }
#if FINGERPRINT_LED_READY
        finger.setLed(FINGERPRINT_LED_READY); /* green LED while initializing */
        delay(2000);
        finger.setLedOff();
#endif
        fingerprintReady = true;
    }
    else
    {
        fingerprintReady = false;
        Serial.println("R558-S not found");
    }
    auth_handler_set_fingerprint_enabled(fingerprintReady);
    auth_handler_set_led_callbacks(auth_led_success, auth_led_fail, auth_led_clear);
#else
    auth_handler_set_fingerprint_enabled(false);
#endif

    /* Initialize Crypto and FIDO — Solo1 Port (HAL already initialized) */
    crypto_ecc256_init();

    
    // Low level raw USB init
    usb_hid_init();
    // Protocol task handles initialization and handling internally
    // ctaphid_init(); 


    Serial.println("Solo1 FIDO2 Port Ready!");

    display.clearDisplay();
    display_handler_clock(display, (uint32_t)rtc.now().unixtime(),
                          currentUsername.c_str(), batteryLevel, bluetoothConnected);
    display.display();
    lastDisplayUpdate = millis();
    g_setup_finished = true;
    Serial.print("cryptick> ");
    Serial.flush();
}





void loop()
{
    // ── FIDO UI Bridge (Execution on Core 1) ──
    device_hal_heartbeat(); // Run background UI timer
    
    static int8_t _last_ui_req = 0;
    if (_fido_ui_request != _last_ui_req || _fido_ui_request == 0) {
        if (_fido_ui_request != _last_ui_req) {
            Serial.printf("[UI] Bridge Request: %d -> %d\n", _last_ui_req, _fido_ui_request);
            _last_ui_req = _fido_ui_request;
        }

        if (_fido_ui_request == 1) {
            nav_set_state_fido_prompt();
        } else if (_fido_ui_request == 2) {
            nav_set_state_fido_processing();
        } else if (_fido_ui_request == 0) {
            // FORCE recovery to clock if stuck or finished
            if (navCtx.state == NAV_FIDO_PROMPT || navCtx.state == NAV_FIDO_PROCESSING) {
                navCtx.state = NAV_CLOCK;
                display.clearDisplay();
                display_handler_clock(display, (uint32_t)rtc.now().unixtime(),
                                      currentUsername.c_str(), batteryLevel, bluetoothConnected);
                display.display(); // Force flush
                lastDisplayUpdate = millis();
                Serial.println("[UI] Forcefully returned to Clock.");
            }
        }
    }
    _last_ui_req = _fido_ui_request;

    unsigned long now = millis();



    /* Serial command processing */
    processSerialCommands(Serial, credentials,
#ifdef ENABLE_FINGERPRINT
                          &finger, fingerprintReady
#else
                          nullptr, false
#endif
    );

#ifdef ENABLE_FINGERPRINT
    auth_handler_set_fingerprint_enabled(fingerprintReady);
    finger.ledUpdate();
#else
    auth_handler_set_fingerprint_enabled(false);
#endif

    /* Fingerprint LED and status update */

    /* Run FIDO Transport Layer Pipes — Solo1 Port */
    uint8_t hid_report[64];
    if (usb_hid_read_report(hid_report)) {
        Serial.printf("[HID] RX: %02X%02X%02X%02X...\n", hid_report[0], hid_report[1], hid_report[2], hid_report[3]);
        Serial.flush();
        ctaphid_push_report(hid_report);
    }



    /* Update navigation state machine — snapshot state to detect changes */
    navCtx.accountCount = (int)credentials.size();
    unsigned long loopEntryState = navCtx.state;
    int prevMenu = navCtx.menuIndex;
    int prevAccount = navCtx.accountIndex;
    
    nav_update(navCtx, now);

    /* Render display ── immediately on state change (Bypass limit for FIDO transitions) */
    bool stateChanged = (navCtx.state != loopEntryState ||
                         navCtx.menuIndex != prevMenu ||
                         navCtx.accountIndex != prevAccount);

    const unsigned long MIN_REFRESH_INTERVAL = 100; // Max 10 FPS to prevent I2C starvation
    bool isUrgentState = (navCtx.state == NAV_FIDO_PROMPT || navCtx.state == NAV_FIDO_PROCESSING || navCtx.state == NAV_FIDO_SUCCESS);
    if ((stateChanged && (isUrgentState || (now - lastDisplayUpdate >= MIN_REFRESH_INTERVAL))) || 
        (now - lastDisplayUpdate >= DISPLAY_UPDATE_INTERVAL))
    {
        uint32_t utc = get_synced_utc();
        
        i2c_lock();
        display.clearDisplay();


        
        switch (navCtx.state)
        {
        case NAV_CLOCK:
            display_handler_clock(display, utc, currentUsername.c_str(), batteryLevel, bluetoothConnected);
            break;
        case NAV_MENU:
            display_handler_menu(display, menuLabels, MENU_ITEM_COUNT, navCtx.menuIndex);
            break;
        case NAV_TOTP_VIEW:
            display_handler_totp(display, credentials, (size_t)navCtx.accountIndex);
            break;
        case NAV_SETTINGS:
            display_handler_message(display, "Settings", "Not implemented");
            break;
        case NAV_AUTH_PROMPT:
            display_handler_auth_prompt(display);
            break;
        case NAV_AUTH_ERROR:
            display_handler_auth_error(display);
            break;
        case NAV_FIDO_PROMPT:
            display_handler_fido_prompt(display, navCtx.fidoRpId);
            break;
        case NAV_FIDO_PROCESSING:
            display_handler_fido_processing(display);
            break;
        case NAV_FIDO_SUCCESS:
            display_handler_fido_success(display);
            break;
        default:
            break;
        }

        display.display();
        i2c_unlock();
        lastDisplayUpdate = now;
    }


    /* Fingerprint polling (only when auth prompt is active) */
#ifdef ENABLE_FINGERPRINT
    static unsigned long lastFingerPoll = 0;

    unsigned long fingerInterval = (navCtx.state == NAV_FIDO_PROCESSING || ctaphid_is_processing()) ? 1000 : FINGERPRINT_POLL_INTERVAL_MS;
    if (navCtx.state == NAV_AUTH_PROMPT && fingerprintReady &&
        (now - lastFingerPoll >= fingerInterval))
    {
        lastFingerPoll = now;
        uint16_t id, score;
        int r = finger.getFingerprintID(&id, &score);
        if (r == FINGERPRINT_OK)
        {
            Serial.printf("Finger matched ID=%u score=%u\n", (unsigned)id, (unsigned)score);
            currentUsername = "ID:" + String(id);
            nav_auth_success(navCtx, now);
        }
    }
#endif

    yield();
}
