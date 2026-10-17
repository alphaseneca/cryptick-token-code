#ifndef CRYPTICK_EVENT_BUS_H
#define CRYPTICK_EVENT_BUS_H

#include <stdint.h>

/** Typed lightweight events between systems (main-loop ring buffer). */
enum BusEventType : uint8_t {
    EVT_INPUT = 1,
    EVT_FP,
    EVT_BATTERY,
    EVT_AUTH,
    EVT_UI_STATE,
    EVT_CMD
};

enum InputKey : uint8_t {
    KEY_CENTER = 0,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_UP,
    KEY_DOWN,
    /*
     * SW2 quadrature rotary encoder (GPIO40/41, see board_config.h). Raised
     * one per detent, not per quadrature edge. nav_system treats these as
     * KEY_DOWN/KEY_UP for scrolling, but input_system reports the distinct
     * source so logs can tell a rotation tick from a 5-way press.
     */
    KEY_ENCODER_CW,
    KEY_ENCODER_CCW
};

enum ChargeState : uint8_t {
    CHARGE_IDLE = 0,
    CHARGE_CHARGING,
    CHARGE_DONE,
    CHARGE_FAULT
};

/* Appended to, never reordered: the numeric value shows up in [NAV] logs. */
enum UiState : uint8_t {
    UI_CLOCK = 0,
    UI_MENU,
    UI_TOTP,
    UI_SETTINGS,
    UI_AUTH_PROMPT,
    UI_AUTH_ERROR,
    UI_FP_ENROLL,
    UI_FP_CLEAR_CONFIRM,
    UI_FIDO_PROMPT,
    UI_FIDO_PROCESSING,
    UI_FIDO_SUCCESS,
    UI_SLEEP,        /* panel off; CENTER or a host request wakes it */
    UI_DEVICE_INFO,  /* Settings → Info */
    UI_BLE_PAIRING,  /* 6-digit LESC passkey; typed on the host, not a finger */
    UI_BLE_MENU,     /* Top-level Bluetooth status and controls */
    /*
     * PIV PIN entry: the encoder (remapped to KEY_UP/KEY_DOWN, see
     * nav_system.cpp) scrolls the highlighted digit 0-9, CENTER advances to
     * the next one and, on the last, starts a fresh-touch confirm
     * (UI_AUTH_PROMPT) before the PIN is auto-typed over BLE HID — see
     * nav_system.cpp's enter_piv_pin_entry()/require_fresh_touch(). Used to
     * be a static "PIN: 123456" display typed on a single CENTER press with
     * no confirmation; replaced so a typed PIN always costs a real touch.
     */
    UI_PIV_PIN_ENTRY
};

enum FpEventKind : uint8_t {
    FP_READY = 0,
    FP_MATCHED,
    FP_NO_MATCH,
    FP_ENROLL_STEP,   /* data = 1..2 capture done, 0 = remove finger prompt */
    FP_ENROLL_DONE,
    FP_ENROLL_FAIL,
    FP_COUNT
};

enum AuthEventKind : uint8_t {
    AUTH_CLEARED = 0,
    AUTH_OK,
    AUTH_FAIL
};

enum CmdKind : uint8_t {
    CMD_FP_MATCH_AUTH = 1,   /* gate TOTP */
    CMD_FP_MATCH_FIDO,       /* FIDO user presence */
    CMD_FP_MATCH_STOP,
    CMD_FP_ENROLL_START,
    CMD_FP_ENROLL_ABORT,
    CMD_FP_CLEAR_ALL
};

struct BusEvent {
    BusEventType type;
    uint8_t kind;     /* subtype */
    uint16_t a;       /* id / index / flags */
    uint16_t b;       /* score / step / extra */
};

void bus_init(void);
bool bus_publish(const BusEvent &e);
bool bus_pop(BusEvent &out);
void bus_clear(void);

#endif
