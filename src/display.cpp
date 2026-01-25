#include "display.h"
#include "config.h"
#include "totp_core.h"

bool initDisplay(Adafruit_SSD1306 &display)
{
    if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS))
    {
        Serial.println("Display init failed!");
        return false;
    }

    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println("TOTP Device");
    display.println("Initializing...");
    display.display();
    delay(2000);
    return true;
}

void drawBatteryIndicator(Adafruit_SSD1306 &display, int x, int y, int level)
{
    const int w = 16, h = 6;
    display.drawRect(x, y, w, h, SSD1306_WHITE);
    display.drawRect(x + w, y + 2, 2, 2, SSD1306_WHITE);

    int fill = (level * (w - 2)) / 100;
    if (fill > 0)
        display.fillRect(x + 1, y + 1, fill, h - 2, SSD1306_WHITE);
}

void drawWiFiIcon(Adafruit_SSD1306 &display, int x, int y, bool connected)
{
    display.drawCircle(x + 8, y + 8, 7, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 5, SSD1306_WHITE);
    display.drawCircle(x + 8, y + 8, 3, SSD1306_WHITE);
    display.fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);

    if (!connected)
    {
        display.drawLine(x + 2, y + 2, x + 14, y + 14, SSD1306_WHITE);
        display.drawLine(x + 14, y + 2, x + 2, y + 14, SSD1306_WHITE);
    }
}

void renderClockPage(Adafruit_SSD1306 &display, const DeviceStatus &status)
{
    drawWiFiIcon(display, 0, 0, status.wifiConnected);

    DateTime now = status.currentTime;
    char dateStr[20];
    sprintf(dateStr, "%02d/%02d/%04d", now.day(), now.month(), now.year());

    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);

    int16_t x1, y1;
    uint16_t w, h;
    display.getTextBounds(dateStr, 0, 0, &x1, &y1, &w, &h);
    display.setCursor(SCREEN_WIDTH - w, 0);
    display.print(dateStr);

    char timeStr[9];
    sprintf(timeStr, "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

    display.setTextSize(2);
    display.getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
    display.setCursor((SCREEN_WIDTH - w) / 2, (SCREEN_HEIGHT - h) / 2);
    display.print(timeStr);

    display.setTextSize(1);
    display.setCursor(0, SCREEN_HEIGHT - 8);
    display.print(status.username);

    drawBatteryIndicator(display, SCREEN_WIDTH - 20, SCREEN_HEIGHT - 8, status.batteryLevel);
}

void renderTOTPPage(Adafruit_SSD1306 &display, const DeviceStatus &status,
                    const std::vector<TOTPAccount> &accounts, int accountIndex,
                    RTC_DS3231 &rtc)
{
    if (accounts.empty())
    {
        display.setTextSize(1);
        display.setTextColor(SSD1306_WHITE);
        display.setCursor(0, SCREEN_HEIGHT / 2 - 8);
        display.print("No TOTP accounts");
        display.setCursor(0, SCREEN_HEIGHT / 2);
        display.print("Configure via web");
        return;
    }

    const TOTPAccount &account = accounts[accountIndex];
    DateTime now = status.currentTime;

    char timeStr[9];
    sprintf(timeStr, "%02d:%02d:%02d", now.hour(), now.minute(), now.second());

    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.print(account.name);

    int16_t x1, y1;
    uint16_t w, h;
    display.getTextBounds(timeStr, 0, 0, &x1, &y1, &w, &h);
    display.setCursor(SCREEN_WIDTH - w, 0);
    display.print(timeStr);

    time_t timestamp = now.unixtime();
    String code = generateTOTP(account, timestamp);

    display.setTextSize(3);
    display.getTextBounds(code.c_str(), 0, 0, &x1, &y1, &w, &h);
    display.setCursor((SCREEN_WIDTH - w) / 2, (SCREEN_HEIGHT - h) / 2);
    display.print(code);

    display.setTextSize(1);
    display.setCursor(0, SCREEN_HEIGHT - 8);
    display.print(account.issuer);

    unsigned long remaining = TOTP_PERIOD - (timestamp % TOTP_PERIOD);
    char countdown[8];
    sprintf(countdown, "%2lus", remaining);

    display.getTextBounds(countdown, 0, 0, &x1, &y1, &w, &h);
    int padding = 4;
    int rectX = SCREEN_WIDTH - w - padding;
    int rectY = SCREEN_HEIGHT - h - padding;

    display.fillRect(rectX, rectY, w + 2 * padding, h + 2 * padding, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    display.setCursor(rectX + padding, rectY + padding);
    display.print(countdown);
}