#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <WiFiManager.h>
#include <FS.h>
#include <LittleFS.h>
#include <time.h>
#include <RTClib.h>
#include <TOTP.h> // lucadentella TOTP library (SHA1 only)

// Declare SPIFFS for ESP8266
extern FS SPIFFS;

// OLED Display Configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C
#define OLED_SDA 14 // D6
#define OLED_SCL 12 // D5

// Button Configuration
#define BUTTON_PIN 0 // GPIO0 (Flash button on most ESP8266 boards)

Adafruit_SSD1306 *display;
RTC_DS3231 rtc;

// Web Server for configuration
ESP8266WebServer server(80);
WiFiManager wifiManager;

// TOTP Configuration
const char *CONFIG_FILE = "/totp_config.json";
const int TOTP_PERIOD = 30;               // 30 seconds
const int DISPLAY_UPDATE_INTERVAL = 1000; // 1 second

// Page System Configuration
enum PageType
{
  PAGE_CLOCK = 0,
  PAGE_TOTP = 1,
  PAGE_COUNT = 2
};

// Device Status Structure
struct DeviceStatus
{
  bool wifiConnected;
  int batteryLevel; // Placeholder for future battery monitoring
  String username;  // Placeholder for user identification
  DateTime currentTime;
};

// Structure to hold TOTP account information
struct TOTPAccount
{
  String name;
  String secret;
  String issuer;
  int digits;
  int period;
  String algorithm; // "SHA1" (only supported algorithm)
};

// Global variables
std::vector<TOTPAccount> accounts;
int currentAccountIndex = 0;
int currentPage = PAGE_CLOCK;
unsigned long lastUpdate = 0;
unsigned long lastDisplayUpdate = 0;
unsigned long lastButtonPress = 0;
bool buttonPressed = false;
bool displayNeedsUpdate = true;

DeviceStatus deviceStatus;

// Page System Function Declarations
void initializePageSystem();
void updateDeviceStatus();
void handlePageNavigation();
void renderCurrentPage();
void renderClockPage();
void renderTOTPPage();
void drawStatusBar();
void drawBatteryIndicator(int x, int y);
void drawWiFiIcon(int x, int y);

// Function declarations
void setupDisplay();
void setupRTC();
void setupWiFiSimple();
void setupWebServer();
void loadConfiguration();
void saveConfiguration();
String generateTOTP(const TOTPAccount &account);
time_t getRTCTimestamp();
String getCurrentTime();
void handleRoot();
void handleAddAccount();
void handleDeleteAccount();
void handleListAccounts();
void handleGetTOTP();
void handleSetTime();
void handleSerialSetTime();
void compareWithAuthenticator();

// Page System Implementation
void initializePageSystem()
{
  deviceStatus.wifiConnected = false;
  deviceStatus.batteryLevel = 85; // Placeholder
  deviceStatus.username = "User"; // Placeholder
  deviceStatus.currentTime = rtc.now();
}

void updateDeviceStatus()
{
  deviceStatus.currentTime = rtc.now();
  deviceStatus.wifiConnected = WiFi.softAPgetStationNum() > 0;
  // Future: Add battery monitoring
}

void handlePageNavigation()
{
  static bool lastButtonState = HIGH;
  bool currentButtonState = digitalRead(BUTTON_PIN);

  if (lastButtonState == HIGH && currentButtonState == LOW)
  {
    // Button pressed
    if (millis() - lastButtonPress > 200) // Debounce
    {
      lastButtonPress = millis();

      if (currentPage == PAGE_CLOCK)
      {
        currentPage = PAGE_TOTP;
        currentAccountIndex = 0; // Reset to first account when entering TOTP page
      }
      else if (currentPage == PAGE_TOTP)
      {
        if (accounts.size() > 1)
        {
          // If multiple accounts, cycle through them
          currentAccountIndex++;
          if (currentAccountIndex >= static_cast<int>(accounts.size()))
          {
            // After showing the last account, go back to clock
            currentPage = PAGE_CLOCK;
            currentAccountIndex = 0; // Reset for next time
          }
        }
        else
        {
          // If only one account or no accounts, go back to clock
          currentPage = PAGE_CLOCK;
          currentAccountIndex = 0;
        }
      }

      displayNeedsUpdate = true; // Force immediate update
    }
  }

  lastButtonState = currentButtonState;
}

void renderCurrentPage()
{
  display->clearDisplay();

  switch (currentPage)
  {
  case PAGE_CLOCK:
    renderClockPage();
    break;
  case PAGE_TOTP:
    renderTOTPPage();
    break;
  }

  display->display();
}

void renderClockPage()
{
  // Top left: WiFi icon
  drawWiFiIcon(0, 0);

  // Top right: Full date and time
  DateTime now = deviceStatus.currentTime;
  char dateTimeStr[20];
  sprintf(dateTimeStr, "%02d/%02d/%04d", now.day(), now.month(), now.year());

  display->setTextSize(1);
  display->setTextColor(SSD1306_WHITE);

  // Calculate position for right-aligned text
  int16_t x1, y1;
  uint16_t w, h;
  display->getTextBounds(dateTimeStr, 0, 0, &x1, &y1, &w, &h);
  display->setCursor(SCREEN_WIDTH - w, 0);
  display->print(dateTimeStr);

  // Center: Large time display
  char timeStr[9];
  sprintf(timeStr, "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

  display->setTextSize(2);
  display->getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
  int timeX = (SCREEN_WIDTH - w) / 2;
  int timeY = (SCREEN_HEIGHT - h) / 2;
  display->setCursor(timeX, timeY);
  display->print(timeStr);

  // Bottom left: Username
  display->setTextSize(1);
  display->setCursor(0, SCREEN_HEIGHT - 8);
  display->print(deviceStatus.username);

  // Bottom right: Battery indicator
  drawBatteryIndicator(SCREEN_WIDTH - 20, SCREEN_HEIGHT - 8);
}

void renderTOTPPage()
{
  if (accounts.empty())
  {
    // No accounts configured
    display->setTextSize(1);
    display->setTextColor(SSD1306_WHITE);
    display->setCursor(0, SCREEN_HEIGHT / 2 - 8);
    display->print("No TOTP accounts");
    display->setCursor(0, SCREEN_HEIGHT / 2);
    display->print("Configure via web");
    return;
  }

  const TOTPAccount &account = accounts[currentAccountIndex];

  // Get current time
  DateTime now = deviceStatus.currentTime;
  char timeStr[9];
  snprintf(timeStr, sizeof(timeStr), "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

  // Top left: Account name
  display->setTextSize(1);
  display->setTextColor(SSD1306_WHITE);
  display->setCursor(0, 0);
  display->print(account.name);

  // Top right: Current time
  int16_t x1, y1;
  uint16_t w, h;
  display->getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
  display->setCursor(SCREEN_WIDTH - w, 0);
  display->print(timeStr);

  // TOTP Code: Large, centered, no label
  String totpCode = generateTOTP(account);
  display->setTextSize(3); // Large text
  display->getTextBounds(totpCode, 0, 0, &x1, &y1, &w, &h);
  int codeX = (SCREEN_WIDTH - w) / 2;
  int codeY = (SCREEN_HEIGHT - h) / 2;
  display->setCursor(codeX, codeY);
  display->print(totpCode);

  // Bottom left: Issuer (provider)
  display->setTextSize(1);
  display->setTextColor(SSD1306_WHITE);
  display->setCursor(0, SCREEN_HEIGHT - 8); // 8px high for text size 1
  display->print(account.issuer);

  // Bottom right: Countdown timer
  time_t rtcTime = getRTCTimestamp();
  unsigned long timeRemaining = (rtcTime > 0) ? (TOTP_PERIOD - (rtcTime % TOTP_PERIOD)) : 0;
  char countdownStr[8];
  sprintf(countdownStr, "%2lus", timeRemaining);

  display->getTextBounds(countdownStr, 0, 0, &x1, &y1, &w, &h);
  int padding = 4;
  int rectX = SCREEN_WIDTH - w - padding;
  int rectY = SCREEN_HEIGHT - h - padding;
  int rectW = w + 2 * padding;
  int rectH = h + 2 * padding;

  // Draw filled rectangle for inverted effect
  display->fillRect(rectX, rectY, rectW, rectH, SSD1306_WHITE);
  display->setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  display->setCursor(rectX + padding, rectY + padding);
  display->print(countdownStr);
}

void drawStatusBar()
{
  // Draw a thin line at the top for status indicators
  display->drawLine(0, 8, SCREEN_WIDTH, 8, SSD1306_WHITE);
}

void drawBatteryIndicator(int x, int y)
{
  int batteryWidth = 16;
  int batteryHeight = 6;

  // Battery outline
  display->drawRect(x, y, batteryWidth, batteryHeight, SSD1306_WHITE);
  display->drawRect(x + batteryWidth, y + 2, 2, 2, SSD1306_WHITE);

  // Battery level
  int levelWidth = (deviceStatus.batteryLevel * (batteryWidth - 2)) / 100;
  if (levelWidth > 0)
  {
    display->fillRect(x + 1, y + 1, levelWidth, batteryHeight - 2, SSD1306_WHITE);
  }
}

void drawWiFiIcon(int x, int y)
{
  if (deviceStatus.wifiConnected)
  {
    // Connected WiFi icon - proper WiFi symbol with arcs and dot
    // Draw the arcs (semicircles) from bottom to top
    display->drawCircle(x + 8, y + 8, 7, SSD1306_WHITE); // Outer arc
    display->drawCircle(x + 8, y + 8, 5, SSD1306_WHITE); // Middle arc
    display->drawCircle(x + 8, y + 8, 3, SSD1306_WHITE); // Inner arc
    // Draw the dot at the bottom
    display->fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);
  }
  else
  {
    // Disconnected WiFi icon - same arcs but with X through it
    display->drawCircle(x + 8, y + 8, 7, SSD1306_WHITE); // Outer arc
    display->drawCircle(x + 8, y + 8, 5, SSD1306_WHITE); // Middle arc
    display->drawCircle(x + 8, y + 8, 3, SSD1306_WHITE); // Inner arc
    // Draw the dot at the bottom
    display->fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);
    // Draw X to indicate disconnected
    display->drawLine(x + 2, y + 2, x + 14, y + 14, SSD1306_WHITE);
    display->drawLine(x + 14, y + 2, x + 2, y + 14, SSD1306_WHITE);
  }
}

void setup()
{
  Serial.begin(57600);
  Wire.begin(OLED_SDA, OLED_SCL);
  delay(1000);

  // Setup button pin
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Serial.println("TOTP Hardware Device Starting...");

  // Initialize display FIRST
  setupDisplay();

  if (!LittleFS.begin())
  {
    Serial.println("LittleFS initialization failed!");
    display->clearDisplay();
    display->setCursor(0, 0);
    display->println("LittleFS Error!");
    display->display();
    return;
  }

  // Now check RTC and show status on display
  setupRTC();
  loadConfiguration();
  setupWiFiSimple();
  setupWebServer();
  initializePageSystem();

  Serial.println("TOTP Device Ready!");
}

void loop()
{
  // Handle web server
  server.handleClient();

  // Update device status
  updateDeviceStatus();

  // Handle page navigation
  handlePageNavigation();

  // Update TOTP codes
  unsigned long currentTime = millis();
  if (currentTime - lastUpdate >= TOTP_PERIOD * 1000)
  {
    lastUpdate = currentTime;
  }

  // Update display every second
  if (currentTime - lastDisplayUpdate >= 1000)
  {
    renderCurrentPage();
    lastDisplayUpdate = currentTime;
  }

  // Handle serial time set
  handleSerialSetTime();
}

void setupDisplay()
{
  display = new Adafruit_SSD1306(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

  if (!display->begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS))
  {
    Serial.println(F("SSD1306 allocation failed - check wiring/address!"));
    // Can't show error on display if display itself failed
    return;
  }

  display->clearDisplay();
  display->setTextSize(1);
  display->setTextColor(SSD1306_WHITE);
  display->setCursor(0, 0);
  display->println(F("TOTP Device"));
  display->println(F("Initializing..."));
  display->display();
  delay(2000);
}

void setupRTC()
{
  Serial.println("Initializing RTC...");

  // Show RTC status on display
  display->clearDisplay();
  display->setCursor(0, 0);
  display->println("Checking RTC...");
  display->display();

  if (!rtc.begin())
  {
    Serial.println("Couldn't find RTC! Check wiring.");
    display->clearDisplay();
    display->setCursor(0, 0);
    display->println("RTC Error!");
    display->println("Check wiring:");
    display->println("SDA: GPIO14");
    display->println("SCL: GPIO12");
    display->println("VCC: 3.3V");
    display->println("GND: GND");
    display->display();
    Serial.flush();
    while (1)
      delay(10); // Halt if RTC not found
  }

  if (rtc.lostPower())
  {
    Serial.println("RTC lost power, setting time to compile time!");
    display->clearDisplay();
    display->setCursor(0, 0);
    display->println("RTC lost power!");
    display->println("Setting to compile time...");
    display->display();
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    delay(2000);
  }

  DateTime now = rtc.now();
  Serial.printf("RTC Time: %04d-%02d-%02d %02d:%02d:%02d\n",
                now.year(), now.month(), now.day(),
                now.hour(), now.minute(), now.second());

  // Show successful RTC initialization
  display->clearDisplay();
  display->setCursor(0, 0);
  display->println("RTC OK!");
  display->printf("Time: %02d:%02d:%02d", now.hour(), now.minute(), now.second());
  display->display();
  delay(1000);
}

void setupWiFiSimple()
{
  display->clearDisplay();
  display->setCursor(0, 0);
  display->println(F("WiFi Setup"));
  display->println(F("Starting AP..."));
  display->display();

  // Start Access Point
  WiFi.mode(WIFI_AP);
  WiFi.softAP("TOTP-Device", "12345678");

  display->clearDisplay();
  display->setCursor(0, 0);
  display->println(F("WiFi AP Ready"));
  display->println(F("SSID: TOTP-Device"));
  display->println(F("Pass: 12345678"));
  display->print(F("IP: "));
  display->println(WiFi.softAPIP());
  display->display();

  Serial.println("Access Point started");
  Serial.print("SSID: TOTP-Device, Password: 12345678, IP: ");
  Serial.println(WiFi.softAPIP());
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

void loadConfiguration()
{
  if (!LittleFS.exists(CONFIG_FILE))
  {
    Serial.println("No configuration file found, creating default");
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
    account.algorithm = "SHA1"; // Force SHA1 for this implementation
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
    accountObj["algorithm"] = "SHA1"; // Force SHA1
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

// Base32 decode function for TOTP secrets
int base32_decode(const char* encoded, uint8_t* result, int bufSize) {
    const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int buffer = 0, bitsLeft = 0, count = 0;
    
    for (const char* ptr = encoded; *ptr && count < bufSize; ++ptr) {
        char ch = toupper(*ptr);
        if (ch == '=') break;
        
        const char* p = strchr(base32_chars, ch);
        if (!p) continue;
        
        buffer <<= 5;
        buffer |= (p - base32_chars);
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            result[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    return count;
}

// Get Unix timestamp from RTC
time_t getRTCTimestamp()
{
  DateTime now = rtc.now();
  if (now.year() < 2020 || now.year() > 2100)
  {
    Serial.println("Invalid RTC values detected!");
    return 0;
  }
  return now.unixtime();
}

String getCurrentTime()
{
  DateTime now = rtc.now();
  char timeString[9];
  sprintf(timeString, "%02d:%02d:%02d", now.hour(), now.minute(), now.second());
  return String(timeString);
}

String generateTOTP(const TOTPAccount &account)
{
    time_t rtcTime = getRTCTimestamp();
    if (rtcTime == 0)
        return "RTC Error";

    // Decode base32 secret to bytes
    uint8_t key[32]; // Adjust size as needed
    int keyLen = base32_decode(account.secret.c_str(), key, sizeof(key));
    
    if (keyLen == 0) {
        return "Invalid Secret";
    }

    // Create TOTP object (this library only supports SHA1)
    TOTP totp(key, keyLen);
    
    // Get the code
    char* code = totp.getCode(rtcTime);
    return String(code);
}

void handleRoot()
{
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");

  server.sendContent("<!DOCTYPE html><html><head>");
  server.sendContent("<title>TOTP Device Configuration</title>");
  server.sendContent("<meta name='viewport' content='width=device-width, initial-scale=1'>");
  server.sendContent("<style>");
  server.sendContent("body { font-family: Arial, sans-serif; margin: 20px; }");
  server.sendContent(".container { max-width: 600px; margin: 0 auto; }");
  server.sendContent(".form-group { margin-bottom: 15px; }");
  server.sendContent("label { display: block; margin-bottom: 5px; }");
  server.sendContent("input, select { width: 100%; padding: 8px; box-sizing: border-box; }");
  server.sendContent("button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 5px; }");
  server.sendContent(".account { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }");
  server.sendContent(".time-sync { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }");
  server.sendContent(".status { padding: 10px; margin: 10px 0; border-radius: 5px; }");
  server.sendContent(".success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }");
  server.sendContent(".error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }");
  server.sendContent("</style></head><body>");
  server.sendContent("<div class='container'>");
  server.sendContent("<h1>TOTP Device Configuration</h1>");
  server.sendContent("<div class='time-sync'>");
  server.sendContent("<h3>Time Synchronization</h3>");
  server.sendContent("<p>Current browser time: <span id='browserTime'>Loading...</span></p>");
  server.sendContent("<button onclick='syncTime()'>Sync Device Time with Browser</button>");
  server.sendContent("<div id='timeStatus'></div>");
  server.sendContent("</div>");
  server.sendContent("<h2>Add New Account</h2>");
  server.sendContent("<form id='addForm'>");
  server.sendContent("<div class='form-group'><label>Account Name:</label><input type='text' id='name' required></div>");
  server.sendContent("<div class='form-group'><label>Issuer:</label><input type='text' id='issuer' required></div>");
  server.sendContent("<div class='form-group'><label>Secret Key (Base32):</label><input type='text' id='secret' required></div>");
  server.sendContent("<div class='form-group'><label>Digits:</label><select id='digits'><option value='6'>6</option><option value='8'>8</option></select></div>");
  server.sendContent("<div class='form-group'><label>Algorithm:</label><select id='algorithm'><option value='SHA1'>SHA1</option></select></div>");
  server.sendContent("<button type='submit'>Add Account</button></form>");
  server.sendContent("<h2>Current Accounts</h2><div id='accounts'></div></div>");
  server.sendContent("<script>");
  server.sendContent("function updateBrowserTime() { const now = new Date(); const timeString = now.toLocaleString(); document.getElementById('browserTime').textContent = timeString; }");
  server.sendContent("function syncTime() { const now = new Date(); const timestamp = Math.floor(now.getTime() / 1000); const statusDiv = document.getElementById('timeStatus'); statusDiv.innerHTML = '<div class=\"status\">Syncing time...</div>'; fetch('/settime', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'timestamp=' + timestamp }).then(response => response.text()).then(data => { statusDiv.innerHTML = '<div class=\"status success\">Time synchronized successfully!</div>'; setTimeout(() => { statusDiv.innerHTML = ''; }, 3000); }).catch(error => { statusDiv.innerHTML = '<div class=\"status error\">Failed to sync time: ' + error + '</div>'; }); }");
  server.sendContent("function loadAccounts() { fetch('/list').then(response => response.json()).then(data => { const accountsDiv = document.getElementById('accounts'); accountsDiv.innerHTML = ''; if (data.accounts && data.accounts.length > 0) { data.accounts.forEach((account, index) => { const accountDiv = document.createElement('div'); accountDiv.className = 'account'; accountDiv.innerHTML = `<strong>${account.name}</strong> (${account.issuer})<br>Digits: ${account.digits}, Algorithm: ${account.algorithm}<br><button onclick='deleteAccount(${index})'>Delete</button>`; accountsDiv.appendChild(accountDiv); }); } else { accountsDiv.innerHTML = '<p>No accounts configured yet.</p>'; } }).catch(error => { console.error('Error loading accounts:', error); document.getElementById('accounts').innerHTML = '<p>Error loading accounts.</p>'; }); }");
  server.sendContent("function deleteAccount(index) { fetch('/delete', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({index: index}) }).then(response => response.json()).then(data => { if(data.status === 'success') { loadAccounts(); } }); }");
  server.sendContent("document.getElementById('addForm').addEventListener('submit', function(e) { e.preventDefault(); const formData = { name: document.getElementById('name').value, issuer: document.getElementById('issuer').value, secret: document.getElementById('secret').value, digits: parseInt(document.getElementById('digits').value), algorithm: document.getElementById('algorithm').value }; fetch('/add', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(formData) }).then(response => response.json()).then(data => { if(data.status === 'success') { document.getElementById('addForm').reset(); loadAccounts(); } }); });");
  server.sendContent("window.addEventListener('load', function() { updateBrowserTime(); setInterval(updateBrowserTime, 1000); loadAccounts(); setTimeout(syncTime, 2000); });");
  server.sendContent("</script></body></html>");
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
      account.algorithm = "SHA1"; // Force SHA1
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
      if (index >= 0 && index < accounts.size())
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
    String timestampStr = server.arg("timestamp");
    time_t timestamp = timestampStr.toInt();
    rtc.adjust(DateTime(timestamp));
    server.send(200, "text/plain", "RTC time set successfully");
    Serial.printf("RTC time set to: %s", getCurrentTime().c_str());
  }
  else
  {
    server.send(400, "text/plain", "Missing timestamp parameter");
  }
}

void handleSerialSetTime()
{
  if (Serial.available())
  {
    String input = Serial.readStringUntil('\n');
    input.trim();
    
    if (input.startsWith("SETTIME "))
    {
      String tsStr = input.substring(8);
      time_t timestamp = tsStr.toInt();
      if (timestamp > 1000000000) // Basic sanity check for UNIX time
      { 
        rtc.adjust(DateTime(timestamp));
        Serial.printf("Time set to: %lu\n", timestamp);
        
        DateTime now = rtc.now();
        Serial.printf("RTC Time: %04d-%02d-%02d %02d:%02d:%02d\n",
                    now.year(), now.month(), now.day(),
                    now.hour(), now.minute(), now.second());
        Serial.printf("Epoch: %u\n", (unsigned int)now.unixtime());
      }
      else
      {
        Serial.println("Invalid timestamp!");
      }
    }
    else if (input == "TIME")
    {
      DateTime now = rtc.now();
      Serial.printf("RTC Time: %04d-%02d-%02d %02d:%02d:%02d\n",
                  now.year(), now.month(), now.day(),
                  now.hour(), now.minute(), now.second());
      Serial.printf("Epoch: %u\n", (unsigned int)now.unixtime());
    }
    else if (input.equals("ACCOUNTS") || input.equals("accounts"))
    {
      // Show all configured accounts
      Serial.printf("Total accounts: %d\n", accounts.size());
      for (unsigned int i = 0; i < accounts.size(); i++)
      {
        Serial.printf("%d: %s (%s) - %d digits, %s\n",
                      i + 1,
                      accounts[i].name.c_str(),
                      accounts[i].issuer.c_str(),
                      accounts[i].digits,
                      accounts[i].algorithm.c_str());
      }
    }
    else if (input.equals("COMPARE") || input.equals("compare"))
    {
      // Compare with authenticator
      compareWithAuthenticator();
    }
  }
}

void compareWithAuthenticator()
{
  if (accounts.empty())
  {
    Serial.println("No accounts configured");
    return;
  }

  const TOTPAccount &account = accounts[0];
  Serial.println("=== Comparing with Authenticator ===");
  Serial.printf("Account: %s (%s)\n", account.name.c_str(), account.issuer.c_str());
  Serial.printf("Secret: %s\n", account.secret.c_str());
  Serial.printf("Algorithm: %s\n", account.algorithm.c_str());
  Serial.printf("Digits: %d\n", account.digits);

  time_t rtcTime = getRTCTimestamp();
  uint64_t counter = rtcTime / account.period;

  Serial.printf("Current RTC time: %lu\n", rtcTime);
  Serial.printf("Counter: %llu\n", counter);

  String deviceTOTP = generateTOTP(account);
  Serial.printf("Device TOTP: %s\n", deviceTOTP.c_str());

  Serial.println("What does your authenticator app show?");
  Serial.println("================================");
}