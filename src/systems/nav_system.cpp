#include "nav_system.h"
#include "auth_system.h"
#include "fp_system.h"
#include <board_config.h>
#include "device.h"
#include <string.h>
#include <Arduino.h>

enum MenuItem { MENU_TOTP = 0, MENU_SETTINGS = 1, MENU_COUNT = 2 };
enum SettingsItem {
    SET_ENROLL = 0,
    SET_CLEAR = 1,
    SET_COUNT_INFO = 2,
    SET_ITEM_COUNT = 3
};

static UiState _state = UI_CLOCK;
static int _menuIdx = 0;
static int _settingsIdx = 0;
static int _accountIdx = 0;
static int _accountCount = 0;
static unsigned long _authErrorStart = 0;
static unsigned long _fidoSuccessStart = 0;
static uint8_t _enrollStep = 1;
static bool _enrollRemove = false;
static char _fidoLabel[64] = "FIDO2";
static int8_t _lastFidoReq = 0;

static void publish_ui(void)
{
    BusEvent e{};
    e.type = EVT_UI_STATE;
    e.kind = (uint8_t)_state;
    e.a = (uint16_t)_menuIdx;
    e.b = (uint16_t)_accountIdx;
    bus_publish(e);
}

static void set_state(UiState s)
{
    if (_state == s) return;
    _state = s;
    publish_ui();
}

static void cmd_fp(uint8_t kind)
{
    BusEvent e{};
    e.type = EVT_CMD;
    e.kind = kind;
    bus_publish(e);
}

void nav_system_init(void)
{
    _state = UI_CLOCK;
    _menuIdx = 0;
    _settingsIdx = 0;
    _accountIdx = 0;
    publish_ui();
}

void nav_system_set_account_count(int n)
{
    _accountCount = n;
    if (_accountIdx >= n && n > 0) _accountIdx = n - 1;
    if (n == 0) _accountIdx = 0;
}

UiState nav_system_state(void) { return _state; }
int nav_system_menu_index(void) { return _menuIdx; }
int nav_system_settings_index(void) { return _settingsIdx; }
int nav_system_account_index(void) { return _accountIdx; }
int nav_system_account_count(void) { return _accountCount; }
uint8_t nav_system_enroll_step(void) { return _enrollStep; }
bool nav_system_enroll_remove(void) { return _enrollRemove; }
const char *nav_system_fido_label(void) { return _fidoLabel; }

void nav_system_set_fido_ui(int8_t req)
{
    if (req == _lastFidoReq && req != 0) return;
    _lastFidoReq = req;
    if (req == 1) {
        set_state(UI_FIDO_PROMPT);
        cmd_fp(CMD_FP_MATCH_FIDO);
    } else if (req == 2) {
        cmd_fp(CMD_FP_MATCH_STOP);
        set_state(UI_FIDO_PROCESSING);
    } else if (req == 0) {
        cmd_fp(CMD_FP_MATCH_STOP);
        if (_state == UI_FIDO_PROMPT || _state == UI_FIDO_PROCESSING) {
            set_state(UI_CLOCK);
        }
    }
}

static void enter_menu(void)
{
    _menuIdx = 0;
    set_state(UI_MENU);
    auth_system_record_activity(millis());
}

static void enter_totp(unsigned long now)
{
    if (auth_system_needs_auth()) {
        set_state(UI_AUTH_PROMPT);
        cmd_fp(CMD_FP_MATCH_AUTH);
    } else {
        _accountIdx = 0;
        set_state(UI_TOTP);
        auth_system_record_activity(now);
    }
}

static void enter_settings(unsigned long now)
{
    _settingsIdx = 0;
    set_state(UI_SETTINGS);
    auth_system_record_activity(now);
}

static void start_enroll(void)
{
    if (!fp_system_ready()) return;
    _enrollStep = 1;
    _enrollRemove = false;
    set_state(UI_FP_ENROLL);
    cmd_fp(CMD_FP_ENROLL_START);
}

void nav_system_on_event(const BusEvent &e)
{
    unsigned long now = millis();

    if (e.type == EVT_FP) {
        if (e.kind == FP_MATCHED) {
            if (_state == UI_AUTH_PROMPT) {
                auth_system_on_match();
                auth_system_record_activity(now);
                cmd_fp(CMD_FP_MATCH_STOP);
                _accountIdx = 0;
                set_state(UI_TOTP);
            } else if (_state == UI_FIDO_PROMPT) {
                /* Fingerprint confirms FIDO user presence */
                ctaphid_confirm_user_presence();
                cmd_fp(CMD_FP_MATCH_STOP);
                set_state(UI_FIDO_PROCESSING);
            }
        } else if (e.kind == FP_NO_MATCH) {
            if (_state == UI_AUTH_PROMPT) {
                auth_system_on_fail();
                cmd_fp(CMD_FP_MATCH_STOP);
                _authErrorStart = now;
                set_state(UI_AUTH_ERROR);
            }
            /* FIDO wrong finger: stay on prompt and keep matching */
            if (_state == UI_FIDO_PROMPT) {
                cmd_fp(CMD_FP_MATCH_FIDO);
            }
        } else if (e.kind == FP_ENROLL_STEP) {
            if (_state == UI_FP_ENROLL) {
                _enrollStep = (uint8_t)e.a;
                _enrollRemove = (e.b != 0);
                publish_ui();
            }
        } else if (e.kind == FP_ENROLL_DONE) {
            if (_state == UI_FP_ENROLL) {
                set_state(UI_SETTINGS);
            }
        } else if (e.kind == FP_ENROLL_FAIL) {
            if (_state == UI_FP_ENROLL) {
                set_state(UI_SETTINGS);
            }
        }
        return;
    }

    if (e.type == EVT_AUTH && e.kind == AUTH_CLEARED) {
        /* Do not abort enroll mid-way due to idle timeout */
        if (_state == UI_TOTP || _state == UI_SETTINGS) {
            cmd_fp(CMD_FP_MATCH_STOP);
            set_state(UI_CLOCK);
        } else if (_state == UI_FP_CLEAR_CONFIRM) {
            set_state(UI_CLOCK);
        }
        return;
    }

    if (e.type != EVT_INPUT) return;
    InputKey key = (InputKey)e.kind;

    /* Auto-return overlays */
    if (_state == UI_AUTH_ERROR || _state == UI_FIDO_SUCCESS)
        return;

    switch (_state) {
    case UI_CLOCK:
        /* Any of the 5 keys opens the menu (enroll is Settings → Enroll) */
        if (key == KEY_CENTER || key == KEY_LEFT || key == KEY_RIGHT ||
            key == KEY_UP || key == KEY_DOWN || key == KEY_CW || key == KEY_CCW) {
            enter_menu();
        }
        break;

    case UI_MENU:
        if (key == KEY_UP || key == KEY_CW) {
            _menuIdx = (_menuIdx + MENU_COUNT - 1) % MENU_COUNT;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_CCW || key == KEY_RIGHT) {
            _menuIdx = (_menuIdx + 1) % MENU_COUNT;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_CLOCK);
        } else if (key == KEY_CENTER) {
            if (_menuIdx == MENU_TOTP) enter_totp(now);
            else if (_menuIdx == MENU_SETTINGS) enter_settings(now);
        }
        break;

    case UI_TOTP:
        auth_system_record_activity(now);
        if (key == KEY_UP || key == KEY_CW) {
            if (_accountCount > 0)
                _accountIdx = (_accountIdx + _accountCount - 1) % _accountCount;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_CCW || key == KEY_RIGHT) {
            if (_accountCount > 0)
                _accountIdx = (_accountIdx + 1) % _accountCount;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_MENU);
        }
        break;

    case UI_SETTINGS:
        auth_system_record_activity(now);
        if (key == KEY_UP || key == KEY_CW) {
            _settingsIdx = (_settingsIdx + SET_ITEM_COUNT - 1) % SET_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_CCW || key == KEY_RIGHT) {
            _settingsIdx = (_settingsIdx + 1) % SET_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_MENU);
        } else if (key == KEY_CENTER) {
            if (_settingsIdx == SET_ENROLL) {
                start_enroll();
            } else if (_settingsIdx == SET_CLEAR) {
                set_state(UI_FP_CLEAR_CONFIRM);
            }
            /* SET_COUNT_INFO: display only */
        }
        break;

    case UI_FP_CLEAR_CONFIRM:
        if (key == KEY_LEFT) {
            set_state(UI_SETTINGS);
        } else if (key == KEY_CENTER) {
            cmd_fp(CMD_FP_CLEAR_ALL);
            auth_system_clear();
            set_state(UI_SETTINGS);
        }
        break;

    case UI_FP_ENROLL:
        /* LEFT cancels only — CENTER must not abort enroll (common "OK" press) */
        if (key == KEY_LEFT) {
            cmd_fp(CMD_FP_ENROLL_ABORT);
            set_state(UI_SETTINGS);
        }
        break;

    case UI_AUTH_PROMPT:
        if (key == KEY_LEFT || key == KEY_CENTER) {
            cmd_fp(CMD_FP_MATCH_STOP);
            auth_system_clear();
            set_state(UI_CLOCK);
        }
        break;

    case UI_FIDO_PROMPT:
        /* Fingerprint confirms FIDO; any nav key cancels so UI is not a trap */
        if (key == KEY_LEFT || key == KEY_CENTER || key == KEY_RIGHT ||
            key == KEY_UP || key == KEY_DOWN) {
            ctaphid_cancel_request();
            cmd_fp(CMD_FP_MATCH_STOP);
            set_state(UI_CLOCK);
        }
        break;

    default:
        break;
    }
}

void nav_system_tick(unsigned long nowMs)
{
    if (_state == UI_AUTH_ERROR) {
        if (nowMs - _authErrorStart >= (unsigned long)AUTH_ERROR_DISPLAY_MS) {
            auth_system_clear();
            set_state(UI_CLOCK);
        }
        return;
    }
    if (_state == UI_FIDO_SUCCESS) {
        if (nowMs - _fidoSuccessStart >= 2000UL) {
            set_state(UI_CLOCK);
        }
        return;
    }

    /* Inactivity on protected pages — never kick out of enroll mid-flow */
    if (_state == UI_TOTP || _state == UI_SETTINGS ||
        _state == UI_FP_CLEAR_CONFIRM) {
        auth_system_tick(nowMs);
        if (!auth_system_is_authenticated() && _state == UI_TOTP && fp_system_ready()) {
            set_state(UI_CLOCK);
        }
    }
}
