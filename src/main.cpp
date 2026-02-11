#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include "config.h"
#ifdef ENABLE_WEBSERVER
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#endif
#ifdef ENABLE_FINGERPRINT
#include <SoftwareSerial.h>
#include "R558SFingerprint.h"
#endif
#include <LittleFS.h>
#include <RTClib.h>
#include "types.h"
#include "display.h"
#include "storage.h"
#include "navigation.h"
#include "web_server.h"
#include "serial_comm.h"

// Hardware objects
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
RTC_DS3231 rtc;
#ifdef ENABLE_WEBSERVER
ESP8266WebServer server(80);
#endif
#ifdef ENABLE_FINGERPRINT
SoftwareSerial fingerprintSerial(FINGERPRINT_RX, FINGERPRINT_TX);
R558SFingerprint finger(fingerprintSerial);
bool fingerprintReady = false;  // true only when sensor is present and init OK
#endif

// Application state
std::vector<TOTPAccount> accounts;
DeviceStatus deviceStatus;
PageType currentPage = PAGE_CLOCK;
int currentAccountIndex = 0;
unsigned long lastDisplayUpdate = 0;

void setup()
{
  // Let 3.3V and I/O settle before any peripherals (helps intermittent boot)
  delay(300);
  pinMode(BUTTON_PIN, INPUT_PULLUP);  // GPIO0: ensure pull-up before anything else
  delay(100);

  Serial.begin(57600);
  Wire.begin(OLED_SDA, OLED_SCL);
  delay(200);  // I2C bus and peripherals power-up
  yield();

  Serial.println("TOTP Device Starting...");

  // Initialize display
  if (!initDisplay(display))
  {
    Serial.println("Display failed!");
    while (1)
      delay(10);
  }
  yield();

  // Initialize filesystem
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

  // Initialize RTC
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
    display.println("Check wiring:");
    display.println("SDA: GPIO14");
    display.println("SCL: GPIO12");
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

  DateTime now = rtc.now();
  Serial.printf("RTC: %04d-%02d-%02d %02d:%02d:%02d\n",
                now.year(), now.month(), now.day(),
                now.hour(), now.minute(), now.second());

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("RTC OK!");
  display.printf("Time: %02d:%02d:%02d", now.hour(), now.minute(), now.second());
  display.display();
  delay(800);
  yield();

  // Load configuration
  loadConfiguration(accounts);
  yield();

  // Setup WiFi AP (only when webserver enabled)
#ifdef ENABLE_WEBSERVER
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("WiFi Setup...");
  display.display();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  yield();  // WiFi causes current spike; let supply settle

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("WiFi AP Ready");
  display.println("SSID: " + String(AP_SSID));
  display.println("Pass: " + String(AP_PASSWORD));
  display.print("IP: ");
  display.println(WiFi.softAPIP());
  display.display();

  Serial.printf("AP: %s / %s @ %s\n", AP_SSID, AP_PASSWORD, WiFi.softAPIP().toString().c_str());
#else
  Serial.println("WiFi/web server disabled by build configuration");
#endif
  // Setup web server (optional at build time)
#ifdef ENABLE_WEBSERVER
  setupWebServer(server, accounts, rtc);
#else
  Serial.println("Web server disabled by build configuration");
#endif
  // Initialize fingerprint only when enabled; use it only when device responds
#ifdef ENABLE_FINGERPRINT
  fingerprintSerial.begin(FINGERPRINT_BAUD);
  finger.setDebug(false);  // set true for R558-S packet debug
  if (finger.begin(FINGERPRINT_BAUD) == FINGERPRINT_OK) {
    fingerprintReady = true;
    Serial.println("R558-S fingerprint ready");
#if FINGERPRINT_LED_READY
    finger.setLed(FINGERPRINT_LED_READY);  // LED from config (e.g. green = ready)
#endif
  } else {
    fingerprintReady = false;
    Serial.println("R558-S not found (skip fingerprint)");
  }
#endif

  // Initialize device status
  deviceStatus.wifiConnected = false;
  deviceStatus.batteryLevel = 85;
  deviceStatus.username = "User";
  deviceStatus.currentTime = rtc.now();
  Serial.println("TOTP Device Ready!");

  // Show home clock immediately (don't leave screen on "RTC OK")
  display.clearDisplay();
  renderClockPage(display, deviceStatus);
  display.display();
  lastDisplayUpdate = millis();
}
void loop()
{
#ifdef ENABLE_WEBSERVER
  server.handleClient();
#endif
  processSerialCommands(Serial, rtc, accounts
#ifdef ENABLE_FINGERPRINT
      , &finger, fingerprintReady
#endif
  );

  deviceStatus.currentTime = rtc.now();
#ifdef ENABLE_WEBSERVER
  deviceStatus.wifiConnected = WiFi.softAPgetStationNum() > 0;
#else
  deviceStatus.wifiConnected = false;
#endif

  // Button and display first so UI stays responsive (no long blocking before these)
  handleNavigation(currentPage, currentAccountIndex, accounts.size(), BUTTON_PIN);

  unsigned long now = millis();
  if (now - lastDisplayUpdate >= DISPLAY_UPDATE_INTERVAL)
  {
    display.clearDisplay();
    if (currentPage == PAGE_CLOCK)
      renderClockPage(display, deviceStatus);
    else
      renderTOTPPage(display, deviceStatus, accounts, currentAccountIndex, rtc);
    display.display();
    lastDisplayUpdate = now;
  }

  // Throttle fingerprint: poll only every FINGERPRINT_POLL_INTERVAL_MS so loop stays fast
#ifdef ENABLE_FINGERPRINT
  static unsigned long lastFingerPoll = 0;
  if (fingerprintReady && (now - lastFingerPoll >= FINGERPRINT_POLL_INTERVAL_MS))
  {
    lastFingerPoll = now;
    uint16_t id, score;
    int r = finger.getFingerprintID(&id, &score);
    if (r == FINGERPRINT_OK)
    {
      Serial.printf("Finger matched ID=%u score=%u\n", (unsigned)id, (unsigned)score);
      deviceStatus.username = "ID:" + String(id);
#if FINGERPRINT_LED_MATCH
      finger.setLed(FINGERPRINT_LED_MATCH);
#endif
      delay(800);
#if FINGERPRINT_LED_READY
      finger.setLed(FINGERPRINT_LED_READY);
#endif
    }
  }
#endif
  yield();  // let ESP8266 run background tasks (WiFi, etc.) for smoother UI
}