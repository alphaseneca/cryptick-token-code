#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#ifdef ENABLE_WEBSERVER
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#endif
#include <LittleFS.h>
#include <RTClib.h>

#include "config.h"
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

// Application state
std::vector<TOTPAccount> accounts;
DeviceStatus deviceStatus;
PageType currentPage = PAGE_CLOCK;
int currentAccountIndex = 0;
unsigned long lastDisplayUpdate = 0;

void setup()
{
  Serial.begin(57600);
  Wire.begin(OLED_SDA, OLED_SCL);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  delay(1000);

  Serial.println("TOTP Device Starting...");

  // Initialize display
  if (!initDisplay(display))
  {
    Serial.println("Display failed!");
    while (1)
      delay(10);
  }

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

  DateTime now = rtc.now();
  Serial.printf("RTC: %04d-%02d-%02d %02d:%02d:%02d\n",
                now.year(), now.month(), now.day(),
                now.hour(), now.minute(), now.second());

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("RTC OK!");
  display.printf("Time: %02d:%02d:%02d", now.hour(), now.minute(), now.second());
  display.display();
  delay(1000);

  // Load configuration
  loadConfiguration(accounts);

  // Setup WiFi AP (only when webserver enabled)
#ifdef ENABLE_WEBSERVER
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("WiFi Setup...");
  display.display();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASSWORD);

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
  // Initialize device status
  deviceStatus.wifiConnected = false;
  deviceStatus.batteryLevel = 85;
  deviceStatus.username = "User";
  deviceStatus.currentTime = rtc.now();
  Serial.println("TOTP Device Ready!");
}
void loop()
{
#ifdef ENABLE_WEBSERVER
  server.handleClient();
#endif
  processSerialCommands(Serial, rtc, accounts);
  // Update status
  deviceStatus.currentTime = rtc.now();
#ifdef ENABLE_WEBSERVER
  deviceStatus.wifiConnected = WiFi.softAPgetStationNum() > 0;
#else
  deviceStatus.wifiConnected = false;
#endif
  // Handle navigation
  handleNavigation(currentPage, currentAccountIndex, accounts.size(), BUTTON_PIN);
  // Update display
  if (millis() - lastDisplayUpdate >= DISPLAY_UPDATE_INTERVAL)
  {
    display.clearDisplay();
    if (currentPage == PAGE_CLOCK)
      renderClockPage(display, deviceStatus);
    else
      renderTOTPPage(display, deviceStatus, accounts, currentAccountIndex, rtc);

    display.display();
    lastDisplayUpdate = millis();
  }
}