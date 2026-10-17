#include "display_driver_u8g2.h"
#include "device.h"
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <Wire.h>

/*
 * Everything in this file used to live directly inside display_system.cpp
 * (as the free functions oled_try_begin()/display_bring_up() and the raw
 * u8g2.* calls scattered through the screen-drawing functions). None of it
 * is UI logic — it is this one backend's hardware bring-up and its mapping
 * from the generic DisplayDriver primitives onto U8g2's own API — so it
 * moved here unchanged, primitive-for-primitive and byte-for-byte on the
 * wire, when display_system.cpp was refactored onto the DisplayDriver
 * interface.
 */

bool U8g2DisplayDriver::oledTryBegin(uint8_t addr7)
{
    CLOG_D("DISP", "begin SSD1306 @0x%02X…", addr7);
    CryptickLog.flush();
    _u8g2.setI2CAddress(addr7 << 1);
    _u8g2.setBusClock(100000);
    for (int attempt = 0; attempt < 3; attempt++) {
        CLOG_D("DISP", "u8g2.begin attempt %d", attempt + 1);
        CryptickLog.flush();
        if (_u8g2.begin()) {
            _u8g2.setPowerSave(0);
            _u8g2.setContrast(255);
            _u8g2.clearBuffer();
            _u8g2.sendBuffer();
            _addr = addr7;
            CLOG_I("DISP", "u8g2.begin OK");
            CryptickLog.flush();
            return true;
        }
        CLOG_D("DISP", "u8g2.begin returned false");
        CryptickLog.flush();
        delay(40);
        Wire.begin(OLED_SDA, OLED_SCL);
        Wire.setClock(100000);
        Wire.setTimeOut(100);
        yield();
    }
    return false;
}

bool U8g2DisplayDriver::begin(bool selfTest)
{
    i2c_lock();
    /* Soft bus recovery (do not leave pins as hard GPIO after) */
    pinMode(OLED_SCL, OUTPUT_OPEN_DRAIN);
    pinMode(OLED_SDA, INPUT_PULLUP);
    for (int i = 0; i < 9; i++) {
        digitalWrite(OLED_SCL, HIGH);
        delayMicroseconds(5);
        digitalWrite(OLED_SCL, LOW);
        delayMicroseconds(5);
    }
    digitalWrite(OLED_SCL, HIGH);
    delayMicroseconds(5);

    Wire.begin(OLED_SDA, OLED_SCL);
    Wire.setTimeOut(100);
    Wire.setClock(100000);
    delay(20);

    uint8_t found = 0;
    bool saw_3c = false, saw_3d = false;
    bool saw_68 = false;
    for (uint8_t a = 1; a < 127; a++) {
        Wire.beginTransmission(a);
        uint8_t err = Wire.endTransmission();
        if (err == 0) {
            CLOG_D("I2C", "device 0x%02X", a);
            found++;
            if (a == 0x3C) saw_3c = true;
            if (a == 0x3D) saw_3d = true;
            if (a == 0x68) saw_68 = true;
        }
        if ((a & 0x1f) == 0)
            yield();
    }
    CryptickLog.flush();
    if (!found)
        CLOG_D("I2C", "no devices — check SDA/SCL / 3V3 / OLED solder");
    else
        CLOG_D("I2C", "%u device(s) OLED3C=%d OLED3D=%d RTC68=%d",
               (unsigned)found, (int)saw_3c, (int)saw_3d, (int)saw_68);
    CryptickLog.flush();

    /* Release mutex for u8g2 init (Wire calls can yield); re-take after */
    i2c_unlock();

    bool ok = false;
    if (saw_3c && oledTryBegin(0x3C))
        ok = true;
    else if (saw_3d && oledTryBegin(0x3D))
        ok = true;
    else if (oledTryBegin(0x3C))
        ok = true;
    else if (oledTryBegin(0x3D))
        ok = true;

    if (!ok) {
        CLOG_E("DISP", "FAIL SDA=%d SCL=%d (no SSD1306 ACK)", OLED_SDA, OLED_SCL);
        CryptickLog.flush();
        return false;
    }

    i2c_lock();
    Wire.setClock(100000);
    _u8g2.setBusClock(100000);
    _u8g2.setPowerSave(0);
    _u8g2.setContrast(255);
    if (selfTest) {
        /*
         * Brief all-white frame. This is a panel test, not decoration: if the
         * glass is alive but the content is wrong you still see this flash.
         * The actual intro is display_system_boot_animation().
         */
        _u8g2.clearBuffer();
        _u8g2.drawBox(0, 0, 128, 64);
        _u8g2.sendBuffer();
        delay(60);
        _u8g2.clearBuffer();
        _u8g2.sendBuffer();
    }
    i2c_unlock();

    CLOG_I("DISP", "OK  SSD1306 @0x%02X  SDA=%d SCL=%d", _addr, OLED_SDA, OLED_SCL);
    CryptickLog.flush();
    return true;
}

void U8g2DisplayDriver::sleep(bool asleep)
{
    _u8g2.setPowerSave(asleep ? 1 : 0);
}

void U8g2DisplayDriver::clear()
{
    _u8g2.clearBuffer();
}

void U8g2DisplayDriver::flush()
{
    _u8g2.sendBuffer();
}

void U8g2DisplayDriver::setFont(DisplayFont font)
{
    switch (font) {
    case DisplayFont::Small:       _u8g2.setFont(u8g2_font_5x7_tr); break;
    case DisplayFont::Medium:      _u8g2.setFont(u8g2_font_6x12_tr); break;
    case DisplayFont::LargeDigits: _u8g2.setFont(u8g2_font_logisoso22_tn); break;
    case DisplayFont::Bold:        _u8g2.setFont(u8g2_font_7x14B_tr); break;
    }
}

int U8g2DisplayDriver::textWidth(const char *s)
{
    return _u8g2.getStrWidth(s);
}

void U8g2DisplayDriver::drawText(int x, int y, const char *s)
{
    _u8g2.drawStr(x, y, s);
}

void U8g2DisplayDriver::fillRect(int x, int y, int w, int h)
{
    _u8g2.drawBox(x, y, w, h);
}

void U8g2DisplayDriver::drawRect(int x, int y, int w, int h)
{
    _u8g2.drawFrame(x, y, w, h);
}

void U8g2DisplayDriver::drawHLine(int x, int y, int w)
{
    _u8g2.drawHLine(x, y, w);
}

void U8g2DisplayDriver::drawVLine(int x, int y, int h)
{
    _u8g2.drawVLine(x, y, h);
}

void U8g2DisplayDriver::drawLine(int x0, int y0, int x1, int y1)
{
    _u8g2.drawLine(x0, y0, x1, y1);
}

void U8g2DisplayDriver::drawBitmap(int x, int y, int w, int h, const unsigned char *bits)
{
    _u8g2.drawXBMP(x, y, w, h, bits);
}

void U8g2DisplayDriver::setInverted(bool inverted)
{
    _u8g2.setDrawColor(inverted ? 0 : 1);
}

void U8g2DisplayDriver::setClip(int x0, int y0, int x1, int y1)
{
    _u8g2.setClipWindow(x0, y0, x1, y1);
}

void U8g2DisplayDriver::clearClip()
{
    _u8g2.setMaxClipWindow();
}
