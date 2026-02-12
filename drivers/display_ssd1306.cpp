#include "display_ssd1306.h"
#include <Adafruit_GFX.h>

static void draw_battery(Adafruit_SSD1306 &d, int x, int y, int level)
{
    const int w = 16, h = 6;
    d.drawRect(x, y, w, h, SSD1306_WHITE);
    d.drawRect(x + w, y + 2, 2, 2, SSD1306_WHITE);
    int fill = (level * (w - 2)) / 100;
    if (fill > 0)
        d.fillRect(x + 1, y + 1, fill, h - 2, SSD1306_WHITE);
}

static void draw_wifi_icon(Adafruit_SSD1306 &d, int x, int y, bool connected)
{
    d.drawCircle(x + 8, y + 8, 7, SSD1306_WHITE);
    d.drawCircle(x + 8, y + 8, 5, SSD1306_WHITE);
    d.drawCircle(x + 8, y + 8, 3, SSD1306_WHITE);
    d.fillCircle(x + 8, y + 12, 1, SSD1306_WHITE);
    if (!connected)
    {
        d.drawLine(x + 2, y + 2, x + 14, y + 14, SSD1306_WHITE);
        d.drawLine(x + 14, y + 2, x + 2, y + 14, SSD1306_WHITE);
    }
}

bool display_ssd1306_init(Adafruit_SSD1306 &display, uint8_t i2c_addr, int width, int height)
{
    if (!display.begin(SSD1306_SWITCHCAPVCC, i2c_addr))
        return false;
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

void display_ssd1306_clock(Adafruit_SSD1306 &display, int width, int height,
    const char *date_str, const char *time_str, const char *username, int battery_pct, bool link_connected)
{
    draw_wifi_icon(display, 0, 0, link_connected);
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    int16_t x1, y1;
    uint16_t w, h;
    display.getTextBounds(date_str, 0, 0, &x1, &y1, &w, &h);
    display.setCursor(width - w, 0);
    display.print(date_str);
    display.setTextSize(2);
    display.getTextBounds(time_str, 0, 0, &x1, &y1, &w, &h);
    display.setCursor((width - w) / 2, (height - h) / 2);
    display.print(time_str);
    display.setTextSize(1);
    display.setCursor(0, height - 8);
    if (username)
        display.print(username);
    draw_battery(display, width - 20, height - 8, battery_pct);
}

void display_ssd1306_totp(Adafruit_SSD1306 &display, int width, int height,
    const char *account_name, const char *time_str, const char *code_6,
    const char *issuer, const char *countdown_str)
{
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.print(account_name);
    int16_t x1, y1;
    uint16_t w, h;
    display.getTextBounds(time_str, 0, 0, &x1, &y1, &w, &h);
    display.setCursor(width - w, 0);
    display.print(time_str);
    display.setTextSize(3);
    display.getTextBounds(code_6, 0, 0, &x1, &y1, &w, &h);
    display.setCursor((width - w) / 2, (height - h) / 2);
    display.print(code_6);
    display.setTextSize(1);
    display.setCursor(0, height - 8);
    if (issuer)
        display.print(issuer);
    display.getTextBounds(countdown_str, 0, 0, &x1, &y1, &w, &h);
    int padding = 4;
    int rectX = width - w - padding;
    int rectY = height - h - padding;
    display.fillRect(rectX, rectY, w + 2 * padding, h + 2 * padding, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    display.setCursor(rectX + padding, rectY + padding);
    display.print(countdown_str);
}

void display_ssd1306_message(Adafruit_SSD1306 &display, int width, int height,
    const char *line1, const char *line2)
{
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, height / 2 - 8);
    display.print(line1);
    display.setCursor(0, height / 2);
    display.print(line2);
}
