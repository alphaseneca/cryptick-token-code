#ifndef CRYPTICK_DISPLAY_ICONS_H
#define CRYPTICK_DISPLAY_ICONS_H

#include <stdint.h>

/*
 * Status glyphs, as real XBM bitmaps rather than text standing in for an
 * icon (the OLED overhaul explicitly replaces things like `drawStr(x,y,"FP")`
 * / `drawStr(x,y,"-")` and English sentences like "BLE: Connected to Mac").
 *
 * Hand-authored at the small size the 128x64 title/status row actually has
 * room for (11x11 / 12x11 — see each glyph's comment), generated and
 * visually checked with a throwaway Python+Pillow script rather than typed
 * blind; see each bitmap's dimensions below. XBM packing: LSB-first per
 * byte, each row padded to a whole byte, exactly what U8G2's drawXBMP()
 * expects. ESP32's U8X8_PGM_READ is a plain dereference (no Harvard-
 * architecture split like AVR), so these are ordinary const data — no
 * PROGMEM / pgm_read_byte needed.
 *
 * Connected/disconnected and ready/absent states reuse one glyph each and
 * are told apart by icon_draw_state() drawing a diagonal strike through the
 * "off" state, rather than doubling the bitmap count — one shape per
 * concept, consistently struck-through for its negative, the same way a
 * crossed-out icon reads everywhere else.
 */

/** Bluetooth rune. 11x11, 2 bytes/row. */
static const uint8_t ICON_BLE_W = 11, ICON_BLE_H = 11;
static const unsigned char icon_ble_bits[] = {
    0x18, 0x00, 0x28, 0x00, 0x48, 0x00, 0x8E, 0x00, 0x28, 0x01, 0x88, 0x00,
    0x28, 0x01, 0x8E, 0x00, 0x48, 0x00, 0x28, 0x00, 0x18, 0x00
};

/** Fingerprint / biometric sensor (concentric scan rings). 11x11, 2 bytes/row. */
static const uint8_t ICON_FINGERPRINT_W = 11, ICON_FINGERPRINT_H = 11;
static const unsigned char icon_fingerprint_bits[] = {
    0xF8, 0x00, 0x04, 0x01, 0x02, 0x02, 0x21, 0x04, 0x71, 0x04, 0x89, 0x04,
    0x71, 0x04, 0x21, 0x04, 0x02, 0x02, 0x04, 0x01, 0xF8, 0x00
};

/** Padlock (PIN / secure-slot screens). 12x11, 2 bytes/row. */
static const uint8_t ICON_LOCK_W = 12, ICON_LOCK_H = 11;
static const unsigned char icon_lock_bits[] = {
    0xF8, 0x00, 0x04, 0x01, 0x04, 0x01, 0xFE, 0x0F, 0x02, 0x08, 0xF2, 0x09,
    0x12, 0x09, 0xF2, 0x09, 0x42, 0x08, 0x42, 0x08, 0xFE, 0x0F
};

/** Warning triangle (fault / error states). 12x11, 2 bytes/row. */
static const uint8_t ICON_WARNING_W = 12, ICON_WARNING_H = 11;
static const unsigned char icon_warning_bits[] = {
    0x20, 0x00, 0x20, 0x00, 0x70, 0x00, 0x50, 0x00, 0x88, 0x00, 0xA8, 0x00,
    0x24, 0x01, 0x24, 0x01, 0x22, 0x02, 0x02, 0x02, 0xFE, 0x0F
};

/** USB trident. 11x11, 2 bytes/row. */
static const uint8_t ICON_USB_W = 11, ICON_USB_H = 11;
static const unsigned char icon_usb_bits[] = {
    0x20, 0x00, 0x20, 0x00, 0x70, 0x00, 0x20, 0x00, 0x20, 0x00, 0xAC, 0x01,
    0x52, 0x02, 0x72, 0x02, 0xAC, 0x01, 0x20, 0x00, 0x70, 0x00
};

/**
 * Battery shell (outline + terminal nub only). 22x9, 3 bytes/row.
 *
 * The charge *level* this hardware can report is not a fuel-gauge percentage
 * — there is no battery ADC on this board (see board_config.h / README) — it
 * is the BQ25185's two-pin digital charge state (idle/charging/done/fault,
 * see battery_system.h). So the fill is drawn at render time as a plain box
 * inside this shell sized/animated from that state (see draw_battery() in
 * display_system.cpp), rather than this bitmap pretending to show a level
 * the hardware cannot actually measure.
 */
static const uint8_t ICON_BATTERY_W = 22, ICON_BATTERY_H = 9;
static const unsigned char icon_battery_shell_bits[] = {
    0xFF, 0xFF, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00, 0x06, 0x01, 0x00, 0x06,
    0x01, 0x00, 0x06, 0x01, 0x00, 0x06, 0x01, 0x00, 0x06, 0x01, 0x00, 0x02,
    0xFF, 0xFF, 0x03
};

#endif
