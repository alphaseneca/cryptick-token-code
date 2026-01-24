#include "OLED_Driver.h"
#include <Arduino.h>
#include <stdarg.h>

OLED_Driver::OLED_Driver(int w, int h, int sdapin, int sclpin, int resetpin, uint8_t addr)
    : width(w), height(h), sda(sdapin), scl(sclpin), reset(resetpin), address(addr), initialized(false)
{
  displayImpl = nullptr;
}

bool OLED_Driver::begin()
{
  if (initialized)
    return true;

  Wire.begin(sda, scl);
  displayImpl = new Adafruit_SSD1306(width, height, &Wire, reset);

  if (!displayImpl->begin(SSD1306_SWITCHCAPVCC, address))
  {
    Serial.println("OLED: Init failed!");
    delete displayImpl;
    displayImpl = nullptr;
    return false;
  }

  initialized = true;
  clear();
  display();
  return true;
}

void OLED_Driver::clear()
{
  if (displayImpl)
    displayImpl->clearDisplay();
}

void OLED_Driver::display()
{
  if (displayImpl)
    displayImpl->display();
}

void OLED_Driver::setTextSize(uint8_t size)
{
  if (displayImpl)
    displayImpl->setTextSize(size);
}

void OLED_Driver::setTextColor(uint16_t color)
{
  if (displayImpl)
    displayImpl->setTextColor(color);
}

void OLED_Driver::setTextColor(uint16_t color, uint16_t background)
{
  if (displayImpl)
    displayImpl->setTextColor(color, background);
}

void OLED_Driver::setCursor(int16_t x, int16_t y)
{
  if (displayImpl)
    displayImpl->setCursor(x, y);
}

void OLED_Driver::print(const String &text)
{
  if (displayImpl)
    displayImpl->print(text);
}

void OLED_Driver::println(const String &text)
{
  if (displayImpl)
    displayImpl->println(text);
}

void OLED_Driver::printf(const char *format, ...)
{
  if (!displayImpl)
    return;
  char buffer[128];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  displayImpl->print(buffer);
}

void OLED_Driver::getTextBounds(const char *string, int16_t x, int16_t y, int16_t *x1, int16_t *y1, uint16_t *w, uint16_t *h)
{
  if (displayImpl)
    displayImpl->getTextBounds(string, x, y, x1, y1, w, h);
}

void OLED_Driver::drawLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t color)
{
  if (displayImpl)
    displayImpl->drawLine(x0, y0, x1, y1, color);
}

void OLED_Driver::drawRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color)
{
  if (displayImpl)
    displayImpl->drawRect(x, y, w, h, color);
}

void OLED_Driver::fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color)
{
  if (displayImpl)
    displayImpl->fillRect(x, y, w, h, color);
}

void OLED_Driver::drawCircle(int16_t x0, int16_t y0, int16_t r, uint16_t color)
{
  if (displayImpl)
    displayImpl->drawCircle(x0, y0, r, color);
}

void OLED_Driver::fillCircle(int16_t x0, int16_t y0, int16_t r, uint16_t color)
{
  if (displayImpl)
    displayImpl->fillCircle(x0, y0, r, color);
}