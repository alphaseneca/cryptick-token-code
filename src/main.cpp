// ============================================================================
// TOTP Hardware Device - Main Application
// ============================================================================

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <TOTP.h>
#include "Config.h"
#include <RTClib.h>

// Inlined from include/Types.h
struct TOTPAccount
{
  String name;
  String secret;
  String issuer;
  int digits;
  int period;
  String algorithm;
};

struct DeviceStatus
{
  bool wifiConnected;
  int batteryLevel;
  String username;
  DateTime currentTime;
};

enum PageType
{
  PAGE_CLOCK = 0,
  PAGE_TOTP = 1,
  PAGE_COUNT = 2
};

#include "../lib/drivers/RTC_Driver/RTC_Driver.h"
#include "../lib/drivers/OLED_Driver/OLED_Driver.h"

// ============================================================================
// Global Objects
// ============================================================================

OLED_Driver display(OLED_WIDTH, OLED_HEIGHT, OLED_SDA, OLED_SCL, OLED_RESET, OLED_ADDRESS);
RTC_Driver rtc;
ESP8266WebServer server(80);

// ============================================================================
// Global Variables
// ============================================================================

std::vector<TOTPAccount> accounts;
DeviceStatus deviceStatus;
int currentAccountIndex = 0;
PageType currentPage = PAGE_CLOCK;
unsigned long lastUpdate = 0;
unsigned long lastDisplayUpdate = 0;
unsigned long lastButtonPress = 0;

// Forward declarations
void saveConfiguration();

// ============================================================================
// TOTP Functions
// ============================================================================

int base32_decode(const char *encoded, uint8_t *result, int bufSize)
{
  const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  int buffer = 0, bitsLeft = 0, count = 0;
  for (const char *ptr = encoded; *ptr && count < bufSize; ++ptr)
  {
    char ch = toupper(*ptr);
    if (ch == '=')
      break;
    const char *p = strchr(base32_chars, ch);
    if (!p)
      continue;
    buffer <<= 5;
    buffer |= (p - base32_chars);
    bitsLeft += 5;
    if (bitsLeft >= 8)
    {
      result[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
      bitsLeft -= 8;
    }
  }
  return count;
}

String generateTOTP(const TOTPAccount &account)
{
  time_t rtcTime = rtc.unixtime();
  if (rtcTime == 0)
    return "RTC Error";

  uint8_t key[32];
  int keyLen = base32_decode(account.secret.c_str(), key, sizeof(key));
  if (keyLen == 0)
    return "Invalid Secret";

  TOTP totp(key, keyLen);
  char *code = totp.getCode(rtcTime);
  return String(code);
}

// ============================================================================
// Configuration Management
// ============================================================================

void loadConfiguration()
{
  if (!LittleFS.exists(CONFIG_FILE))
  {
    saveConfiguration();
    return;
  }

  File file = LittleFS.open(CONFIG_FILE, "r");
  if (!file)
  {
    Serial.println("Failed to open config file");
    return;
  }

  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, file);
  file.close();

  if (error)
  {
    Serial.println("Failed to parse config file");
    return;
  }

  accounts.clear();
  JsonArray accountsArray = doc["accounts"];
  for (JsonObject accountObj : accountsArray)
  {
    TOTPAccount account;
    account.name = accountObj["name"].as<String>();
    account.secret = accountObj["secret"].as<String>();
    account.issuer = accountObj["issuer"].as<String>();
    account.digits = accountObj["digits"] | 6;
    account.period = accountObj["period"] | 30;
    account.algorithm = "SHA1";
    accounts.push_back(account);
  }

  Serial.printf("Loaded %d accounts\n", accounts.size());
}

void saveConfiguration()
{
  DynamicJsonDocument doc(2048);
  JsonArray accountsArray = doc.createNestedArray("accounts");

  for (const TOTPAccount &account : accounts)
  {
    JsonObject accountObj = accountsArray.createNestedObject();
    accountObj["name"] = account.name;
    accountObj["secret"] = account.secret;
    accountObj["issuer"] = account.issuer;
    accountObj["digits"] = account.digits;
    accountObj["period"] = account.period;
    accountObj["algorithm"] = "SHA1";
  }

  File file = LittleFS.open(CONFIG_FILE, "w");
  if (!file)
  {
    Serial.println("Failed to open config file for writing");
    return;
  }

  serializeJson(doc, file);
  file.close();
  Serial.println("Configuration saved");
}

// ============================================================================
// Display Functions
// ============================================================================

void drawBatteryIndicator(int x, int y)
{
  int batteryWidth = 16;
  int batteryHeight = 6;
  display.drawRect(x, y, batteryWidth, batteryHeight, SSD1306_WHITE);
  display.drawRect(x + batteryWidth, y + 2, 2, 2, SSD1306_WHITE);
  int levelWidth = (deviceStatus.batteryLevel * (batteryWidth - 2)) / 100;
  if (levelWidth > 0)
  {
    display.fillRect(x + 1, y + 1, levelWidth, batteryHeight - 2, SSD1306_WHITE);
  }
}

void drawWiFiIcon(int x, int y)
{
  if (deviceStatus.wifiConnected)
  {
    display.drawCircle(x + 8, y + 8, 7, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 5, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 3, SSD1306_WHITE);
    display.fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);
  }
  else
  {
    display.drawCircle(x + 8, y + 8, 7, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 5, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 3, SSD1306_WHITE);
    display.fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);
    display.drawLine(x + 2, y + 2, x + 14, y + 14, SSD1306_WHITE);
    display.drawLine(x + 14, y + 2, x + 2, y + 14, SSD1306_WHITE);
  }
}

void renderClockPage()
{
  drawWiFiIcon(0, 0);

  DateTime now = deviceStatus.currentTime;
  char dateTimeStr[20];
  sprintf(dateTimeStr, "%02d/%02d/%04d", now.day(), now.month(), now.year());

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  int16_t x1, y1;
  uint16_t w, h;
  display.getTextBounds(dateTimeStr, 0, 0, &x1, &y1, &w, &h);
  display.setCursor(OLED_WIDTH - w, 0);
  display.print(dateTimeStr);

  char timeStr[9];
  sprintf(timeStr, "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

  display.setTextSize(2);
  display.getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
  int timeX = (OLED_WIDTH - w) / 2;
  int timeY = (OLED_HEIGHT - h) / 2;
  display.setCursor(timeX, timeY);
  display.print(timeStr);

  display.setTextSize(1);
  display.setCursor(0, OLED_HEIGHT - 8);
  display.print(deviceStatus.username);

  drawBatteryIndicator(OLED_WIDTH - 20, OLED_HEIGHT - 8);
}

void renderTOTPPage()
{
  if (accounts.empty())
  {
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, OLED_HEIGHT / 2 - 8);
    display.print("No TOTP accounts");
    display.setCursor(0, OLED_HEIGHT / 2);
    display.print("Configure via web");
    return;
  }

  const TOTPAccount &account = accounts[currentAccountIndex];
  DateTime now = deviceStatus.currentTime;
  char timeStr[9];
  snprintf(timeStr, sizeof(timeStr), "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print(account.name);

  int16_t x1, y1;
  uint16_t w, h;
  display.getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
  display.setCursor(OLED_WIDTH - w, 0);
  display.print(timeStr);

  String totpCode = generateTOTP(account);
  display.setTextSize(3);
  display.getTextBounds(totpCode.c_str(), 0, 0, &x1, &y1, &w, &h);
  int codeX = (OLED_WIDTH - w) / 2;
  int codeY = (OLED_HEIGHT - h) / 2;
  display.setCursor(codeX, codeY);
  display.print(totpCode);

  display.setTextSize(1);
  display.setCursor(0, OLED_HEIGHT - 8);
  display.print(account.issuer);

  time_t rtcTime = rtc.unixtime();
  unsigned long timeRemaining = (rtcTime > 0) ? (TOTP_PERIOD - (rtcTime % TOTP_PERIOD)) : 0;
  char countdownStr[8];
  sprintf(countdownStr, "%2lus", timeRemaining);

  display.getTextBounds(countdownStr, 0, 0, &x1, &y1, &w, &h);
  int padding = 4;
  int rectX = OLED_WIDTH - w - padding;
  int rectY = OLED_HEIGHT - h - padding;
  display.fillRect(rectX, rectY, w + 2 * padding, h + 2 * padding, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  display.setCursor(rectX + padding, rectY + padding);
  display.print(countdownStr);
}

void renderCurrentPage()
{
  display.clear();
  switch (currentPage)
  {
  case PAGE_CLOCK:
    renderClockPage();
    break;
  case PAGE_TOTP:
    renderTOTPPage();
    break;

  default:
    renderClockPage();
    break;
  }
  display.display();
}

// ============================================================================
// Page Navigation
// ============================================================================

void updateDeviceStatus()
{
  deviceStatus.currentTime = rtc.now();
  deviceStatus.wifiConnected = WiFi.softAPgetStationNum() > 0;
}

void handlePageNavigation()
{
  static bool lastButtonState = HIGH;
  bool currentButtonState = digitalRead(BUTTON_PIN);

  if (lastButtonState == HIGH && currentButtonState == LOW)
  {
    if (millis() - lastButtonPress > BUTTON_DEBOUNCE_MS)
    {
      lastButtonPress = millis();

      if (currentPage == PAGE_CLOCK)
      {
        currentPage = PAGE_TOTP;
        currentAccountIndex = 0;
      }
      else if (currentPage == PAGE_TOTP)
      {
        if (accounts.size() > 1)
        {
          currentAccountIndex++;
          if (currentAccountIndex >= static_cast<int>(accounts.size()))
          {
            currentPage = PAGE_CLOCK;
            currentAccountIndex = 0;
          }
        }
        else
        {
          currentPage = PAGE_CLOCK;
          currentAccountIndex = 0;
        }
      }
    }
  }
  lastButtonState = currentButtonState;
}

// ============================================================================
// Web Server Handlers
// ============================================================================

String readHTMLFile()
{
  File file = LittleFS.open("/index.html", "r");
  if (!file)
    return "";
  String content = file.readString();
  file.close();
  return content;
}

void handleRoot()
{
  String htmlContent = readHTMLFile();
  if (htmlContent.length() == 0)
  {
    server.send(200, "text/html", "<html><body><h1>Error</h1><p>HTML file not found. Upload index.html to LittleFS.</p></body></html>");
  }
  else
  {
    server.send(200, "text/html", htmlContent);
  }
}

void handleAddAccount()
{
  if (server.hasArg("plain"))
  {
    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, server.arg("plain"));
    if (!error)
    {
      TOTPAccount account;
      account.name = doc["name"].as<String>();
      account.issuer = doc["issuer"].as<String>();
      account.secret = doc["secret"].as<String>();
      account.digits = doc["digits"] | 6;
      account.algorithm = "SHA1";
      account.period = 30;
      accounts.push_back(account);
      saveConfiguration();
      server.send(200, "application/json", "{\"status\":\"success\"}");
      return;
    }
  }
  server.send(400, "application/json", "{\"status\":\"error\"}");
}

void handleDeleteAccount()
{
  if (server.hasArg("plain"))
  {
    DynamicJsonDocument doc(256);
    DeserializationError error = deserializeJson(doc, server.arg("plain"));
    if (!error)
    {
      unsigned int index = doc["index"];
      if (index < accounts.size())
      {
        accounts.erase(accounts.begin() + index);
        saveConfiguration();
        server.send(200, "application/json", "{\"status\":\"success\"}");
        return;
      }
    }
  }
  server.send(400, "application/json", "{\"status\":\"error\"}");
}

void handleListAccounts()
{
  DynamicJsonDocument doc(2048);
  JsonArray accountsArray = doc.createNestedArray("accounts");
  for (const TOTPAccount &account : accounts)
  {
    JsonObject accountObj = accountsArray.createNestedObject();
    accountObj["name"] = account.name;
    accountObj["issuer"] = account.issuer;
    accountObj["digits"] = account.digits;
    accountObj["algorithm"] = account.algorithm;
  }
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleGetTOTP()
{
  if (accounts.empty())
  {
    server.send(404, "application/json", "{\"error\":\"No accounts configured\"}");
    return;
  }
  String accountName = server.hasArg("account") ? server.arg("account") : "";
  unsigned int accountIndex = 0;
  if (accountName.length() > 0)
  {
    for (unsigned int i = 0; i < accounts.size(); i++)
    {
      if (accounts[i].name == accountName)
      {
        accountIndex = i;
        break;
      }
    }
  }
  const TOTPAccount &account = accounts[accountIndex];
  String totpCode = generateTOTP(account);
  DynamicJsonDocument doc(256);
  doc["account"] = account.name;
  doc["issuer"] = account.issuer;
  doc["code"] = totpCode;
  doc["timeRemaining"] = TOTP_PERIOD - ((millis() - lastUpdate) / 1000);
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleSetTime()
{
  if (server.hasArg("timestamp"))
  {
    time_t timestamp = server.arg("timestamp").toInt();
    rtc.adjust(DateTime(timestamp));
    server.send(200, "text/plain", "RTC time set successfully");
  }
  else
  {
    server.send(400, "text/plain", "Missing timestamp parameter");
  }
}

void setupWebServer()
{
  server.on("/", HTTP_GET, handleRoot);
  server.on("/add", HTTP_POST, handleAddAccount);
  server.on("/delete", HTTP_POST, handleDeleteAccount);
  server.on("/list", HTTP_GET, handleListAccounts);
  server.on("/totp", HTTP_GET, handleGetTOTP);
  server.on("/settime", HTTP_POST, handleSetTime);
  server.begin();
  Serial.println("Web server started");
}

// ============================================================================
// Setup & Loop
// ============================================================================

void setup()
{
  Serial.begin(57600);
  delay(1000);

  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Serial.println("TOTP Hardware Device Starting...");

  // Initialize display
  if (!display.begin())
  {
    Serial.println("Display initialization failed!");
    while (1)
      delay(10);
  }
  display.clear();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("TOTP Device");
  display.println("Initializing...");
  display.display();
  delay(2000);

  // Initialize filesystem
  if (!LittleFS.begin())
  {
    Serial.println("LittleFS initialization failed!");
    display.clear();
    display.setCursor(0, 0);
    display.println("LittleFS Error!");
    display.display();
    while (1)
      delay(10);
  }

  // Initialize RTC
  display.clear();
  display.setCursor(0, 0);
  display.println("Checking RTC...");
  display.display();

  if (!rtc.begin())
  {
    Serial.println("RTC not found!");
    display.clear();
    display.setCursor(0, 0);
    display.println("RTC Error!");
    display.println("Check wiring:");
    display.println("SDA: GPIO14");
    display.println("SCL: GPIO12");
    display.display();
    while (1)
      delay(10);
  }

  DateTime now = rtc.now();
  Serial.printf("RTC Time: %04d-%02d-%02d %02d:%02d:%02d\n",
                now.year(), now.month(), now.day(),
                now.hour(), now.minute(), now.second());

  display.clear();
  display.setCursor(0, 0);
  display.println("RTC OK!");
  display.printf("Time: %02d:%02d:%02d", now.hour(), now.minute(), now.second());
  display.display();
  delay(1000);

  // Load configuration
  loadConfiguration();

  // Setup WiFi
  display.clear();
  display.setCursor(0, 0);
  display.println("WiFi Setup");
  display.println("Starting AP...");
  display.display();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASSWORD);

  display.clear();
  display.setCursor(0, 0);
  display.println("WiFi AP Ready");
  display.println("SSID: " + String(AP_SSID));
  display.println("Pass: " + String(AP_PASSWORD));
  display.print("IP: ");
  display.println(WiFi.softAPIP().toString());
  display.display();

  Serial.print("SSID: " + String(AP_SSID) + ", Password: " + String(AP_PASSWORD) + ", IP: ");
  Serial.println(WiFi.softAPIP());

  // Setup web server
  setupWebServer();

  // Initialize device status
  deviceStatus.wifiConnected = false;
  deviceStatus.batteryLevel = 85;
  deviceStatus.username = "User";
  deviceStatus.currentTime = rtc.now();

  Serial.println("TOTP Device Ready!");
}

void loop()
{
  server.handleClient();
  updateDeviceStatus();
  handlePageNavigation();

  unsigned long currentTime = millis();
  if (currentTime - lastUpdate >= TOTP_PERIOD * 1000)
  {
    lastUpdate = currentTime;
  }

  if (currentTime - lastDisplayUpdate >= DISPLAY_UPDATE_INTERVAL)
  {
    renderCurrentPage();
    lastDisplayUpdate = currentTime;
  }
}
