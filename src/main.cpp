#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <LittleFS.h>
#include <RTClib.h>

#include "config.h"
#include "auth_handler.h"
#include "device_hal.h"
#include "display_handler.h"
#include "navigation.h"
#include "serial_comm.h"
#include "storage.h"

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
PageEnum currentPage = PAGE_CLOCK;
int currentAccountIndex = 0;
unsigned long lastDisplayUpdate = 0;

static String currentUsername = "User";
static int batteryLevel = 85;
static bool bluetoothConnected = false;

void setup()
{
    delay(300);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    delay(100);

    Serial.begin(57600);
    Wire.begin(OLED_SDA, OLED_SCL);
    delay(200);
    yield();

    Serial.println("TOTP Device Starting...");

    if (!display_handler_init(display))
    {
        Serial.println("Display failed!");
        while (1)
            delay(10);
    }
    yield();

    if (!LittleFS.begin())
    {
        Serial.println("LittleFS failed!");
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("LittleFS Error!");
        display.display();
        while (1)
            delay(10);
    }
    yield();

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Checking RTC...");
    display.display();

    if (!rtc.begin())
    {
        Serial.println("RTC not found!");
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("RTC Error!");
        display.display();
        while (1)
            delay(10);
    }

    if (rtc.lostPower())
    {
        Serial.println("RTC lost power, setting compile time");
        rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    }
    yield();

    device_hal_init();
    DateTime now = rtc.now();
    Serial.printf("RTC: %04d-%02d-%02d %02d:%02d:%02d\n",
                  now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("RTC OK!");
    display.display();
    delay(800);
    yield();

    loadConfiguration(credentials);
    yield(); /* Let ESP8266 run background tasks; avoids watchdog reset */
    Serial.println("Config loaded.");

#ifdef ENABLE_FINGERPRINT
    yield();
    fingerprintSerial.begin(FINGERPRINT_BAUD, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);
    delay(200);
    yield();
    finger.setDebug(false);
    if (finger.begin(FINGERPRINT_BAUD) == FINGERPRINT_OK)
    {
        fingerprintReady = true;
        Serial.println("R558-S fingerprint ready");
#if FINGERPRINT_LED_READY
        finger.setLed(FINGERPRINT_LED_READY); /* green LED on while device is initializing */
        delay(2000);
        finger.setLedOff();
#endif
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

    Serial.println("TOTP Device Ready!");

    display.clearDisplay();
    display_handler_clock(display, (uint32_t)rtc.now().unixtime(),
                          currentUsername.c_str(), batteryLevel, bluetoothConnected);
    display.display();
    lastDisplayUpdate = millis();
}

void loop()
{
    unsigned long now = millis();

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
    handleNavigation(currentPage, currentAccountIndex, (int)credentials.size(), now);
    if (auth_handler_check_inactivity(now))
        currentPage = PAGE_CLOCK;

    if (now - lastDisplayUpdate >= DISPLAY_UPDATE_INTERVAL)
    {
        display.clearDisplay();
        uint32_t utc = (uint32_t)rtc.now().unixtime();
        if (currentPage == PAGE_CLOCK)
            display_handler_clock(display, utc, currentUsername.c_str(), batteryLevel, bluetoothConnected);
        else if (currentPage == PAGE_TOTP)
            display_handler_totp(display, credentials, (size_t)currentAccountIndex);
        else if (currentPage == PAGE_SETTINGS)
            display_handler_message(display, "Settings", "Not implemented");
        else if (currentPage == PAGE_AUTH_PROMPT)
            display_handler_auth_prompt(display);
        else if (currentPage == PAGE_AUTH_ERROR)
            display_handler_auth_error(display);
        display.display();
        lastDisplayUpdate = now;
    }

#ifdef ENABLE_FINGERPRINT
    static unsigned long authErrorStartTime = 0;
    static unsigned long lastFingerPoll = 0;

    if (currentPage == PAGE_AUTH_ERROR)
    {
        if (now - authErrorStartTime >= (unsigned long)AUTH_ERROR_DISPLAY_MS)
        {
            currentPage = PAGE_CLOCK;
            authErrorStartTime = 0;
            auth_handler_clear();
        }
    }
    else if (fingerprintReady && (now - lastFingerPoll >= FINGERPRINT_POLL_INTERVAL_MS))
    {
        lastFingerPoll = now;
        uint16_t id, score;
        int r = finger.getFingerprintID(&id, &score);
        if (r == FINGERPRINT_OK)
        {
            Serial.printf("Finger matched ID=%u score=%u\n", (unsigned)id, (unsigned)score);
            currentUsername = "ID:" + String(id);
            if (currentPage == PAGE_AUTH_PROMPT)
            {
                auth_handler_set_authenticated(true);
                currentPage = PAGE_TOTP;
                currentAccountIndex = 0;
                auth_handler_record_activity(now);
            }
            delay(800);
        }
        else if (currentPage == PAGE_AUTH_PROMPT && (r == FINGERPRINT_NOMATCH || r == FINGERPRINT_NOTFOUND))
        {
            currentPage = PAGE_AUTH_ERROR;
            authErrorStartTime = now;
            auth_handler_verify_failed();
        }
    }
#endif
    yield();
}
