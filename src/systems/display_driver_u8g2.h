#ifndef CRYPTICK_DISPLAY_DRIVER_U8G2_H
#define CRYPTICK_DISPLAY_DRIVER_U8G2_H

#include "display_driver.h"
#include <U8g2lib.h>
#include <board_config.h>

/**
 * First DisplayDriver backend: the shipping 128x64 SSD1306 OLED over HW
 * I2C. Owns the U8g2 object and all of its bring-up details (I2C bus
 * recovery, address scan/retry, contrast, the panel self-test flash) —
 * none of that is specific to the UI, so none of it is in the interface;
 * it is entirely private to this class. See display_system.cpp for the
 * system-level orchestration (retry backoff, sleep/wake, dirty-rect
 * timing) that calls this driver through the DisplayDriver interface only.
 */
class U8g2DisplayDriver : public DisplayDriver {
public:
    bool begin(bool selfTest) override;
    void sleep(bool asleep) override;

    void clear() override;
    void flush() override;

    void setFont(DisplayFont font) override;
    int textWidth(const char *s) override;
    void drawText(int x, int y, const char *s) override;

    void fillRect(int x, int y, int w, int h) override;
    void drawRect(int x, int y, int w, int h) override;
    void drawHLine(int x, int y, int w) override;
    void drawVLine(int x, int y, int h) override;
    void drawLine(int x0, int y0, int x1, int y1) override;
    void drawBitmap(int x, int y, int w, int h, const unsigned char *bits) override;

    void setInverted(bool inverted) override;

    void setClip(int x0, int y0, int x1, int y1) override;
    void clearClip() override;

private:
    bool oledTryBegin(uint8_t addr7);

    U8G2_SSD1306_128X64_NONAME_F_HW_I2C _u8g2{U8G2_R0, /* reset=*/U8X8_PIN_NONE};
    uint8_t _addr = OLED_ADDRESS;
};

#endif
