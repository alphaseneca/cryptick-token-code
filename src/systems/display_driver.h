#ifndef CRYPTICK_DISPLAY_DRIVER_H
#define CRYPTICK_DISPLAY_DRIVER_H

/**
 * Hardware-agnostic drawing surface for the UI layer.
 *
 * display_system.cpp's screen-drawing functions (draw_home, draw_totp,
 * draw_settings, etc.) used to call U8g2's own API (u8g2.drawStr /
 * u8g2.drawBox / u8g2.setFont / ...) directly, which meant the only way to
 * ever support a different physical display (the product's planned move to
 * a larger TFT panel driven by LVGL/EEZ Studio) would have been to
 * rewrite every screen. This interface is the seam: one abstract surface,
 * multiple possible backends. `U8g2DisplayDriver` (display_driver_u8g2.h)
 * is the first and, for now, only implementation — it wraps exactly the
 * current 128x64 SSD1306/U8g2 setup, pixel-for-pixel unchanged. A future
 * LVGL-backed TFT driver is a second class implementing this same
 * interface, added alongside it — see NOTES.md for what that would need.
 *
 * This only covers primitives display_system.cpp actually calls today
 * (surveyed call-by-call, not guessed). Nothing speculative was added: see
 * NOTES.md for what is deliberately NOT here yet (icons/bitmaps) and why.
 */

enum class DisplayFont {
    Small,       /* u8g2_font_5x7_tr      — status bar, labels, hints */
    Medium,      /* u8g2_font_6x12_tr     — titles, menu/list rows, body text */
    LargeDigits, /* u8g2_font_logisoso22_tn — clock time / TOTP code (digits only) */
    Bold,        /* u8g2_font_7x14B_tr    — boot animation wordmark only */
};

class DisplayDriver {
public:
    virtual ~DisplayDriver() {}

    /**
     * Bring the display hardware up. `selfTest` requests a brief visible
     * panel check on first bring-up (the main-loop retry path passes
     * false so repeated retries against an absent panel stay cheap).
     * Returns false if the panel could not be reached.
     */
    virtual bool begin(bool selfTest) = 0;

    /** Panel sleep/wake (power-save mode). */
    virtual void sleep(bool asleep) = 0;

    /** Start and finish a frame. */
    virtual void clear() = 0;
    virtual void flush() = 0;

    /** Text, using whichever font was last selected. */
    virtual void setFont(DisplayFont font) = 0;
    virtual int textWidth(const char *s) = 0;
    virtual void drawText(int x, int y, const char *s) = 0;

    /** Shapes. */
    virtual void fillRect(int x, int y, int w, int h) = 0;
    virtual void drawRect(int x, int y, int w, int h) = 0; /* outline only */
    virtual void drawHLine(int x, int y, int w) = 0;
    virtual void drawVLine(int x, int y, int h) = 0;
    virtual void drawLine(int x0, int y0, int x1, int y1) = 0;

    /** 1bpp XBM-format glyph, MSB-first within each row-byte (U8g2's own
     *  XBM convention) — the icon set in display_icons.h. */
    virtual void drawBitmap(int x, int y, int w, int h, const unsigned char *bits) = 0;

    /**
     * Selection/erase color. true switches subsequent drawing to the
     * "background" color — used both to cut inverted text into an
     * already-filled selection bar, and to erase a region before drawing a
     * dialog frame on top of it. false restores normal foreground drawing.
     * This is an inherently monochrome, XOR-style concept — see NOTES.md
     * for how a color backend would need to replace it.
     */
    virtual void setInverted(bool inverted) = 0;

    /**
     * Clip subsequent drawing to this window; clearClip() lifts it. Used
     * only by the boot animation's wordmark wipe-in reveal — see NOTES.md.
     */
    virtual void setClip(int x0, int y0, int x1, int y1) = 0;
    virtual void clearClip() = 0;
};

#endif
