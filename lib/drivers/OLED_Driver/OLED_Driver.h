#ifndef OLED_DRIVER_H
#define OLED_DRIVER_H

#include <Arduino.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_GFX.h>
#include <Wire.h>

class OLED_Driver
{
public:
  OLED_Driver(int width, int height, int sda, int scl, int reset, uint8_t address);
  bool begin();
  void clear();
  void display();
  void setTextSize(uint8_t size);
  void setTextColor(uint16_t color);
  void setTextColor(uint16_t color, uint16_t background);
  void setCursor(int16_t x, int16_t y);
  void print(const String &text);
  void println(const String &text);
  // REMOVED: void print(const String &ip);
  // REMOVED: void println(const String &ip);
  void printf(const char *format, ...);
  void getTextBounds(const char *string, int16_t x, int16_t y, int16_t *x1, int16_t *y1, uint16_t *w, uint16_t *h);
  void drawLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t color);
  void drawRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);
  void drawCircle(int16_t x0, int16_t y0, int16_t r, uint16_t color);
  void fillCircle(int16_t x0, int16_t y0, int16_t r, uint16_t color);

  int getWidth() const { return width; }
  int getHeight() const { return height; }
  bool isInitialized() const { return initialized; }

private:
  Adafruit_SSD1306 *displayImpl;
  int width;
  int height;
  int sda;
  int scl;
  int reset;
  uint8_t address;
  bool initialized;
};

#endif