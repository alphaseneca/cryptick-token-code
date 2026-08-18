#include "nav_system.h"
#include "auth_system.h"
#include "fp_system.h"
#include <board_config.h>
#include <cryptick_log.h>
#include <string.h>
#include <stdio.h>
#include <Arduino.h>
#include <Preferences.h>

extern "C" {
void ctaphid_confirm_user_presence(void);
void ctaphid_cancel_request(void);
}

enum MenuItem { MENU_TOTP = 0, MENU_SETTINGS = 1, MENU_COUNT = 2 };

enum SettingsItem {
    SET_ENROLL = 0,
    SET_CLEAR,
    SET_SLEEP,
    SET_INFO,
    SET_ITEM_COUNT
};

static UiState _state = UI_CLOCK;
static int _menuIdx = 0;
static int _settingsIdx = 0;
static int _accountIdx = 0;
static int _accountCount = 0;
static unsigned long _authErrorStart = 0;
static unsigned long _fidoSuccessStart = 0;
static unsigned long _enrollMsgStart = 0;
static uint8_t _enrollStep = 1;
static bool _enrollRemove = false;
static char _fidoLabel[64] = "FIDO";
static char _enrollMsg[24] = "";
static int8_t _lastFidoReq = 0;
static bool _pending_clear = false;

/*
 * UI idle clock. Deliberately separate from the auth session in auth_system:
 * that one guards *access* to codes, this one guards *power*. They have
 * different durations and one must not silently reset the other.
 */
static unsigned long _lastActivityMs = 0;
static unsigned long _fidoHoldUntilMs = 0;
static uint16_t _sleepTimeoutSec = UI_SLEEP_TIMEOUT_SEC;

/** Values the Settings → Sleep item cycles through. 0 = never sleep. */
static const uint16_t SLEEP_PRESETS[] = { 15, 30, 45, 60, 120, 300, 0 };
#define SLEEP_PRESET_COUNT ((int)(sizeof(SLEEP_PRESETS) / sizeof(SLEEP_PRESETS[0])))

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
    CLOG_D("NAV", "state %u → %u", (unsigned)_state, (unsigned)s);
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

static void sleep_timeout_persist(uint16_t sec)
{
    Preferences p;
    if (!p.begin("cryptick", false))
        return;
    p.putUShort("sleepsec", sec);
    p.end();
}

static uint16_t sleep_timeout_restore(void)
{
    Preferences p;
    uint16_t v = UI_SLEEP_TIMEOUT_SEC;
    if (p.begin("cryptick", true)) {
        v = p.getUShort("sleepsec", UI_SLEEP_TIMEOUT_SEC);
        p.end();
    }
    return (v > UI_SLEEP_MAX_SEC) ? (uint16_t)UI_SLEEP_MAX_SEC : v;
}

uint16_t nav_system_sleep_timeout_sec(void) { return _sleepTimeoutSec; }

void nav_system_set_sleep_timeout_sec(uint16_t sec, bool persist)
{
    if (sec > UI_SLEEP_MAX_SEC)
        sec = UI_SLEEP_MAX_SEC;
    _sleepTimeoutSec = sec;
    if (persist)
        sleep_timeout_persist(sec);
    CLOG_I("NAV", "sleep timeout %us%s", (unsigned)sec, sec ? "" : " (never)");
}

void nav_system_note_activity(unsigned long nowMs)
{
    _lastActivityMs = nowMs;
}

/*
 * Sleeping mid-operation would blank the very prompt the user is being asked
 * to respond to, so every state that is waiting on a human or on the host
 * holds the display awake.
 */
static bool sleep_allowed(void)
{
    switch (_state) {
    case UI_AUTH_PROMPT:
    case UI_FP_ENROLL:
    case UI_FIDO_PROMPT:
    case UI_FIDO_PROCESSING:
    case UI_FIDO_SUCCESS:
    case UI_AUTH_ERROR:
    case UI_SLEEP:
        return false;
    default:
        break;
    }
    /* Host WebAuthn GetTouch → MakeCredential: keep the panel on after UV. */
    if ((long)(_fidoHoldUntilMs - millis()) > 0)
        return false;
    /* A host OATH/UV wait runs the matcher without owning a UI state. */
    return !fp_system_match_active();
}

static void enter_sleep(void)
{
    if (_state == UI_SLEEP)
        return;
    CLOG_I("NAV", "idle %us — sleeping (panel off)", (unsigned)_sleepTimeoutSec);
    /* Drop anything privileged before the screen goes dark. */
    cmd_fp(CMD_FP_MATCH_STOP);
    auth_system_clear();
    _menuIdx = 0;
    _settingsIdx = 0;
    _accountIdx = 0;
    _enrollMsg[0] = 0;
    set_state(UI_SLEEP);
}

void nav_system_wake(void)
{
    _lastActivityMs = millis();
    if (_state != UI_SLEEP)
        return;
    CLOG_I("NAV", "wake");
    set_state(UI_CLOCK);
}

void nav_system_sleep_now(void)
{
    _lastActivityMs = millis();
    enter_sleep();
}

bool nav_system_is_asleep(void) { return _state == UI_SLEEP; }

void nav_system_init(void)
{
    _state = UI_CLOCK;
    _menuIdx = 0;
    _settingsIdx = 0;
    _accountIdx = 0;
    _enrollMsg[0] = 0;
    _lastActivityMs = millis();
    _fidoHoldUntilMs = 0;
    _sleepTimeoutSec = sleep_timeout_restore();
    CLOG_I("NAV", "sleep timeout %us%s", (unsigned)_sleepTimeoutSec,
           _sleepTimeoutSec ? "" : " (never)");
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
int nav_system_settings_count(void) { return SET_ITEM_COUNT; }

void nav_system_settings_label(int idx, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    switch (idx) {
    case SET_ENROLL:
        snprintf(out, cap, "Enroll finger");
        break;
    case SET_CLEAR:
        snprintf(out, cap, "Clear FP (%u)", (unsigned)fp_system_template_count());
        break;
    case SET_SLEEP:
        if (_sleepTimeoutSec == 0)
            snprintf(out, cap, "Sleep: never");
        else if (_sleepTimeoutSec % 60 == 0)
            snprintf(out, cap, "Sleep: %um", (unsigned)(_sleepTimeoutSec / 60));
        else
            snprintf(out, cap, "Sleep: %us", (unsigned)_sleepTimeoutSec);
        break;
    case SET_INFO:
        snprintf(out, cap, "Device info");
        break;
    default:
        out[0] = 0;
        break;
    }
}
int nav_system_account_index(void) { return _accountIdx; }
int nav_system_account_count(void) { return _accountCount; }
uint8_t nav_system_enroll_step(void) { return _enrollStep; }
bool nav_system_enroll_remove(void) { return _enrollRemove; }
const char *nav_system_fido_label(void) { return _fidoLabel; }

void nav_system_set_fido_label(const char *label)
{
    if (!label || !label[0]) {
        strncpy(_fidoLabel, "Confirm", sizeof(_fidoLabel) - 1);
        _fidoLabel[sizeof(_fidoLabel) - 1] = 0;
        return;
    }
    strncpy(_fidoLabel, label, sizeof(_fidoLabel) - 1);
    _fidoLabel[sizeof(_fidoLabel) - 1] = 0;
}
const char *nav_system_enroll_message(void) { return _enrollMsg; }

void nav_system_set_fido_ui(int8_t req)
{
    CLOG_D("NAV", "fido_ui req=%d (was %d state=%u)", (int)req, (int)_lastFidoReq,
           (unsigned)_state);
    /*
     * The host can ask for user presence while the screen is dark. Waking here
     * is what makes "Place finger" visible — without it the token would look
     * dead while silently waiting on a fingerprint.
     */
    if (req != 0) {
        nav_system_wake();
        _fidoHoldUntilMs = millis() + (unsigned long)CRYPTICK_FIDO_CEREMONY_HOLD_MS;
    } else
        _lastActivityMs = millis();

    int8_t prev = _lastFidoReq;
    if (req == 1) {
        /*
         * Always re-enter prompt + MATCH_FIDO when host re-asserts UP.
         * Early-return on req==1 previously left MATCH stopped after a
         * premature UI clear (heartbeat race) while CTAP still waited.
         */
        _lastFidoReq = 1;
        if (_state != UI_FIDO_PROMPT) {
            set_state(UI_FIDO_PROMPT);
            cmd_fp(CMD_FP_MATCH_FIDO);
        } else if (prev != 1) {
            cmd_fp(CMD_FP_MATCH_FIDO);
        }
        return;
    }
    if (req == 3) {
        /* Explicit success after CTAP status 0x00 writeback */
        _lastFidoReq = 3;
        cmd_fp(CMD_FP_MATCH_STOP);
        _fidoSuccessStart = millis();
        set_state(UI_FIDO_SUCCESS);
        return;
    }
    if (req == _lastFidoReq && req != 0)
        return;
    _lastFidoReq = req;
    if (req == 2) {
        cmd_fp(CMD_FP_MATCH_STOP);
        set_state(UI_FIDO_PROCESSING);
    } else if (req == 0) {
        cmd_fp(CMD_FP_MATCH_STOP);
        /*
         * Idle/error clear — NOT success. (Previously any processing→0
         * flashed OK even when the host got CTAP errors.)
         */
        if (_state == UI_FIDO_PROCESSING || _state == UI_FIDO_PROMPT || prev == 2 || prev == 1) {
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
    if (!fp_system_ready()) {
        strncpy(_enrollMsg, "No sensor", sizeof(_enrollMsg) - 1);
        _authErrorStart = millis();
        set_state(UI_AUTH_ERROR);
        return;
    }
    _enrollStep = 1;
    _enrollRemove = false;
    _enrollMsg[0] = 0;
    set_state(UI_FP_ENROLL);
    cmd_fp(CMD_FP_ENROLL_START);
}

static void cycle_sleep_preset(void)
{
    int i = 0;
    for (; i < SLEEP_PRESET_COUNT; i++) {
        if (SLEEP_PRESETS[i] == _sleepTimeoutSec)
            break;
    }
    /* An out-of-band value set over the console lands on the first preset. */
    int next = (i >= SLEEP_PRESET_COUNT) ? 0 : (i + 1) % SLEEP_PRESET_COUNT;
    nav_system_set_sleep_timeout_sec(SLEEP_PRESETS[next], true);
    publish_ui();
}

static void start_clear(void)
{
    if (fp_system_template_count() > 0 && auth_system_needs_auth()) {
        _pending_clear = true;
        set_state(UI_AUTH_PROMPT);
        cmd_fp(CMD_FP_MATCH_AUTH);
        return;
    }
    _pending_clear = false;
    set_state(UI_FP_CLEAR_CONFIRM);
}

void nav_system_on_event(const BusEvent &e)
{
    unsigned long now = millis();

    if (e.type == EVT_FP) {
        /* A finger on the sensor is user activity even though it is not a key. */
        if (e.kind == FP_MATCHED || e.kind == FP_ENROLL_STEP)
            _lastActivityMs = now;
        if (e.kind == FP_MATCHED) {
            if (_state == UI_AUTH_PROMPT) {
                auth_system_on_match();
                auth_system_record_activity(now);
                cmd_fp(CMD_FP_MATCH_STOP);
                if (_pending_clear) {
                    _pending_clear = false;
                    set_state(UI_FP_CLEAR_CONFIRM);
                } else {
                    _accountIdx = 0;
                    set_state(UI_TOTP);
                }
            } else if (_state == UI_FIDO_PROMPT) {
                ctaphid_confirm_user_presence();
                cmd_fp(CMD_FP_MATCH_STOP);
                set_state(UI_FIDO_PROCESSING);
            }
        } else if (e.kind == FP_NO_MATCH) {
            if (_state == UI_AUTH_PROMPT) {
                auth_system_on_fail();
                cmd_fp(CMD_FP_MATCH_STOP);
                _authErrorStart = now;
                strncpy(_enrollMsg, "No match", sizeof(_enrollMsg) - 1);
                set_state(UI_AUTH_ERROR);
            }
            if (_state == UI_FIDO_PROMPT) {
                cmd_fp(CMD_FP_MATCH_FIDO);
            }
        } else if (e.kind == FP_ENROLL_STEP) {
            if (_state == UI_FP_ENROLL) {
                _enrollStep = (uint8_t)e.a;
                _enrollRemove = (e.b != 0);
                _enrollMsg[0] = 0;
                publish_ui();
            }
        } else if (e.kind == FP_ENROLL_DONE) {
            if (_state == UI_FP_ENROLL) {
                strncpy(_enrollMsg, "Stored", sizeof(_enrollMsg) - 1);
                _enrollMsgStart = now;
                set_state(UI_SETTINGS);
            }
        } else if (e.kind == FP_ENROLL_FAIL) {
            if (_state == UI_FP_ENROLL || e.a == 0xFE) {
                if (e.a == 0x0A || e.a == 0x08)
                    strncpy(_enrollMsg, "Mismatch", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x1F)
                    strncpy(_enrollMsg, "Lib full", sizeof(_enrollMsg) - 1);
                else if (e.a == 0xFE)
                    strncpy(_enrollMsg, "Aborted", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x17)
                    strncpy(_enrollMsg, "Lift fully", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x35 || e.a == 0x3B)
                    strncpy(_enrollMsg, "Bad image", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x03 || e.a == 0x06 || e.a == 0x07 || e.a == 0x15)
                    strncpy(_enrollMsg, "Bad image", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x18)
                    strncpy(_enrollMsg, "Flash err", sizeof(_enrollMsg) - 1);
                else if (e.a == 0x27)
                    strncpy(_enrollMsg, "Already in", sizeof(_enrollMsg) - 1);
                else
                    strncpy(_enrollMsg, "Enroll fail", sizeof(_enrollMsg) - 1);
                _enrollMsgStart = now;
                set_state(UI_SETTINGS);
            }
        }
        return;
    }

    if (e.type == EVT_AUTH && e.kind == AUTH_CLEARED) {
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

    /*
     * Asleep: only CENTER wakes, and that press is consumed by the wake itself
     * so the user never lands somewhere unexpected from a pocket press. Other
     * keys are swallowed without even resetting the idle clock.
     */
    if (_state == UI_SLEEP) {
        if (key == KEY_CENTER)
            nav_system_wake();
        return;
    }

    _lastActivityMs = now;

    if (_state == UI_AUTH_ERROR || _state == UI_FIDO_SUCCESS)
        return;

    switch (_state) {
    case UI_CLOCK:
        /* CENTER enters menu; LEFT stays idle (back semantics on other screens) */
        if (key == KEY_CENTER) {
            enter_menu();
        }
        break;

    case UI_MENU:
        if (key == KEY_UP) {
            _menuIdx = (_menuIdx + MENU_COUNT - 1) % MENU_COUNT;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_RIGHT) {
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
        if (key == KEY_UP) {
            if (_accountCount > 0)
                _accountIdx = (_accountIdx + _accountCount - 1) % _accountCount;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_RIGHT) {
            if (_accountCount > 0)
                _accountIdx = (_accountIdx + 1) % _accountCount;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_MENU);
        }
        break;

    case UI_SETTINGS:
        auth_system_record_activity(now);
        if (key == KEY_UP) {
            _settingsIdx = (_settingsIdx + SET_ITEM_COUNT - 1) % SET_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_RIGHT) {
            _settingsIdx = (_settingsIdx + 1) % SET_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_MENU);
        } else if (key == KEY_CENTER) {
            if (_settingsIdx == SET_ENROLL) {
                start_enroll();
            } else if (_settingsIdx == SET_CLEAR) {
                start_clear();
            } else if (_settingsIdx == SET_SLEEP) {
                cycle_sleep_preset();
            } else if (_settingsIdx == SET_INFO) {
                set_state(UI_DEVICE_INFO);
            }
        }
        break;

    case UI_DEVICE_INFO:
        if (key == KEY_LEFT || key == KEY_CENTER)
            set_state(UI_SETTINGS);
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
        if (key == KEY_LEFT) {
            cmd_fp(CMD_FP_ENROLL_ABORT);
            set_state(UI_SETTINGS);
        }
        break;

    case UI_AUTH_PROMPT:
        if (key == KEY_LEFT) {
            cmd_fp(CMD_FP_MATCH_STOP);
            auth_system_clear();
            set_state(UI_CLOCK);
        }
        break;

    case UI_FIDO_PROMPT:
        if (key == KEY_LEFT) {
            ctaphid_cancel_request();
            cmd_fp(CMD_FP_MATCH_STOP);
            _lastFidoReq = 0;
            set_state(UI_CLOCK);
        }
        break;

    default:
        break;
    }
}

void nav_system_tick(unsigned long nowMs)
{
    if (_state == UI_SLEEP)
        return;

    if (_state == UI_AUTH_ERROR) {
        if (nowMs - _authErrorStart >= (unsigned long)AUTH_ERROR_DISPLAY_MS) {
            /*
             * "No sensor" is raised from Settings → Enroll, so go back there.
             * Every other error came from an unlock attempt: drop the session
             * and fall back to the clock.
             */
            if (strcmp(_enrollMsg, "No sensor") == 0) {
                set_state(UI_SETTINGS);
            } else {
                auth_system_clear();
                set_state(UI_CLOCK);
            }
            _enrollMsg[0] = 0;
        }
        return;
    }
    if (_state == UI_FIDO_SUCCESS) {
        if (nowMs - _fidoSuccessStart >= 1500UL) {
            set_state(UI_CLOCK);
        }
        return;
    }
    /* Keep MATCH_FIDO live for the whole Place finger window. */
    if (_state == UI_FIDO_PROMPT) {
        static unsigned long lastRematch = 0;
        if (!fp_system_match_active() && (nowMs - lastRematch) >= 500UL) {
            lastRematch = nowMs;
            cmd_fp(CMD_FP_MATCH_FIDO);
        }
    }
    /* Clear brief enroll status on settings */
    if (_state == UI_SETTINGS && _enrollMsg[0] &&
        nowMs - _enrollMsgStart >= 2000UL) {
        _enrollMsg[0] = 0;
        publish_ui();
    }

    if (_state == UI_TOTP || _state == UI_SETTINGS ||
        _state == UI_FP_CLEAR_CONFIRM) {
        auth_system_tick(nowMs);
        if (!auth_system_is_authenticated() && _state == UI_TOTP && fp_system_ready()) {
            set_state(UI_CLOCK);
        }
    }

    /*
     * Idle → sleep. Checked last so a state change made earlier in this tick
     * (a FIDO prompt arriving, say) is already visible to sleep_allowed().
     */
    if (_sleepTimeoutSec > 0 && sleep_allowed() &&
        (nowMs - _lastActivityMs) >= (unsigned long)_sleepTimeoutSec * 1000UL) {
        enter_sleep();
    }
}
