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
#if CRYPTICK_BLE_FIDO
void ble_fido_clear_all_bonds(void);
void ble_fido_restart_advertising(void);
void ble_fido_cancel_pairing(void);
bool ble_hid_type_piv_pin(void);
bool ble_hid_type_current_totp(int account_idx);
#else
static inline void ble_fido_clear_all_bonds(void) {}
static inline void ble_fido_restart_advertising(void) {}
static inline void ble_fido_cancel_pairing(void) {}
static inline bool ble_hid_type_piv_pin(void) { return false; }
static inline bool ble_hid_type_current_totp(int account_idx) { (void)account_idx; return false; }
#endif
}

enum MenuItem { MENU_TOTP = 0, MENU_PIV = 1, MENU_BLE = 2, MENU_SETTINGS = 3, MENU_COUNT = 4 };

/*
 * SET_TIME used to be its own row ("Clock: RTC OK" / "Clock: Soft (Sync!)")
 * but pointed at draw_device_info(), which has never shown date/time/RTC
 * content — there is no on-device clock-sync flow, only the USB-console
 * SETTIME / OATH SET_TIME commands (see src/host/serial_comm.cpp). Rather
 * than build a from-scratch date/time entry UI for the 5-way nav just to
 * give that row somewhere honest to go, the clock status is folded into
 * Device Info (see draw_device_info()) and the row is dropped.
 */
enum SettingsItem {
    SET_ENROLL = 0,
    SET_CLEAR,
    SET_SLEEP,
    SET_INFO,
    SET_ITEM_COUNT
};

enum BleMenuItem {
    BLE_ACT_UNPAIR = 0,
    BLE_ACT_RESTART_ADV,
    BLE_ITEM_COUNT
};

/*
 * What UI_AUTH_PROMPT is being asked to authorize. TOTP viewing is the
 * original, low-stakes case: a session (auth_system_is_authenticated())
 * is enough, so enter_totp() only routes here when there is no session yet.
 * The other three are trust-state changes (new fingerprint template, wiping
 * every template, wiping every BLE bond) and must NOT be satisfiable by an
 * existing session — see require_fresh_touch() below.
 */
enum PendingAction : uint8_t {
    PENDING_NONE = 0,
    PENDING_TOTP,
    PENDING_CLEAR_CONFIRM,
    PENDING_ENROLL,
    PENDING_BLE_UNPAIR,
};

static UiState _state = UI_CLOCK;
static int _homeCard = 0; // 0 = Clock, 1 = Quick PIV, 2 = Quick TOTP
static int _menuIdx = 0;
static int _settingsIdx = 0;
static int _bleMenuIdx = 0;
static int _accountIdx = 0;
static int _accountCount = 0;
static unsigned long _authErrorStart = 0;
/*
 * Which UI_AUTH_ERROR this is, independent of _enrollMsg: set_state()
 * (below) unconditionally zeroes _enrollMsg on every transition, including
 * the one that enters UI_AUTH_ERROR itself — so the "did we get here via
 * 'No sensor'?" check has to live in its own flag, not the message text,
 * or it always reads back empty by the time leave_auth_error() runs. See
 * NOTES.md: this also silently broke the "No sensor" message from ever
 * being drawn at all (same root cause, left unfixed — out of scope here).
 */
static bool _authErrorNoSensor = false;
static unsigned long _fidoSuccessStart = 0;
static unsigned long _enrollMsgStart = 0;
static uint8_t _enrollStep = 1;
static bool _enrollRemove = false;
static char _fidoLabel[64] = "FIDO";
static char _enrollMsg[24] = "";
static int8_t _lastFidoReq = 0;
static PendingAction _pendingAction = PENDING_NONE;

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
    _enrollMsg[0] = 0;
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
    case UI_BLE_PAIRING:
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
    _pendingAction = PENDING_NONE;
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
    _lastFidoReq = 0;
    _menuIdx = 0;
    _settingsIdx = 0;
    _accountIdx = 0;
    _pendingAction = PENDING_NONE;
    _authErrorNoSensor = false;
    _enrollMsg[0] = 0;
    _lastActivityMs = millis();
    _fidoHoldUntilMs = 0;
    nav_system_set_fido_label("FIDO");
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
int nav_system_home_card(void) { return _homeCard; }
void nav_system_set_home_card(int card) { _homeCard = card; publish_ui(); }
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

int nav_system_ble_menu_index(void) { return _bleMenuIdx; }
int nav_system_ble_menu_count(void) { return BLE_ITEM_COUNT; }

void nav_system_ble_menu_label(int idx, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    switch (idx) {
    case BLE_ACT_UNPAIR:
        snprintf(out, cap, "Unpair / Wipe Bonds");
        break;
    case BLE_ACT_RESTART_ADV:
        snprintf(out, cap, "Restart Adv");
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
        strncpy(_fidoLabel, "FIDO", sizeof(_fidoLabel) - 1);
        _fidoLabel[sizeof(_fidoLabel) - 1] = 0;
        return;
    }
    strncpy(_fidoLabel, label, sizeof(_fidoLabel) - 1);
    _fidoLabel[sizeof(_fidoLabel) - 1] = 0;
}
const char *nav_system_enroll_message(void) { return _enrollMsg; }

/*
 * True while nav_system itself is mid-ceremony for a fresh touch it started
 * for its own reason — on-device TOTP unlock (UI_AUTH_PROMPT), an enroll in
 * progress (UI_FP_ENROLL), or the Clear-FP confirmation (UI_FP_CLEAR_CONFIRM).
 * See nav_system_set_fido_ui()'s guard below for why this matters.
 */
static bool nav_owns_ceremony(void)
{
    return _state == UI_AUTH_PROMPT || _state == UI_FP_ENROLL ||
           _state == UI_FP_CLEAR_CONFIRM;
}

void nav_system_set_fido_ui(int8_t req)
{
    CLOG_D("NAV", "fido_ui req=%d (was %d state=%u)", (int)req, (int)_lastFidoReq,
           (unsigned)_state);

    /*
     * Race: this function is the HAL's only way to ask nav for a touch-prompt
     * (via the host FIDO/OATH ceremony in core/fido2/hal_esp32.cpp's
     * up_test_locked(), bridged through _fido_ui_request in src/main.cpp's
     * loop()), but nav_system can *already* be mid-ceremony for a reason
     * entirely its own — see nav_owns_ceremony() above. Before this guard,
     * an incoming req unconditionally overwrote whatever nav was already
     * waiting on: req==1 replaced it with UI_FIDO_PROMPT and restarted the
     * match as CMD_FP_MATCH_FIDO (see fp_system.cpp's MatchOwner comment —
     * this is the nav-vs-nav-via-FIDO-task side of that same sensor-sharing
     * problem), and req==0's unconditional cmd_fp(CMD_FP_MATCH_STOP) could
     * kill nav's own in-progress match outright. Either way, the single
     * physical touch the user was about to give *their* prompt would
     * instead resolve — or silently drop — an unrelated host ceremony, with
     * nothing on screen to show two different things had been conflated.
     *
     * Deferring costs nothing the host ceremony doesn't already pay:
     * up_test_locked() bounds its own wait with CRYPTICK_FIDO_UP_TIMEOUT_MS
     * regardless of whether the token ever shows a prompt for it, exactly
     * as if the user had simply not been looking at the device — which, as
     * far as that host ceremony is concerned, they were not: they were
     * looking at nav's own prompt instead. This mirrors how hal_esp32.cpp's
     * own _up_mutex already refuses a second concurrent
     * ctap_user_presence_test_ex() caller rather than letting it piggyback
     * on the first one's touch.
     */
    if (nav_owns_ceremony()) {
        CLOG_W("NAV", "fido_ui req=%d deferred: nav owns ceremony state=%u",
               (int)req, (unsigned)_state);
        return;
    }

    /*
     * The host can ask for user presence while the screen is dark. Waking here
     * is what makes "Place finger" visible — without it the token would look
     * dead while silently waiting on a fingerprint.
     */
    if (req != 0) {
        nav_system_wake();
        _fidoHoldUntilMs = millis() + (unsigned long)CRYPTICK_FIDO_CEREMONY_HOLD_MS;
    } else {
        _lastActivityMs = millis();
    }

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
    if (req == 4) {
        /*
         * BLE pairing passkey. Deliberately NOT UI_FIDO_PROMPT: that screen
         * says "Place finger" and starts MATCH_FIDO, which would tell the user
         * to do the wrong thing — the passkey is typed on the host, and no
         * fingerprint is involved in pairing.
         */
        _lastFidoReq = 4;
        cmd_fp(CMD_FP_MATCH_STOP);
        set_state(UI_BLE_PAIRING);
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
        if (_state == UI_FIDO_PROCESSING || _state == UI_FIDO_PROMPT ||
            _state == UI_BLE_PAIRING || prev == 2 || prev == 1 || prev == 4) {
            set_state(UI_CLOCK);
        }
        if (prev == 4 || _state == UI_BLE_PAIRING) {
            nav_system_set_fido_label("FIDO");
        }
    }
}

static void enter_menu(void)
{
    _menuIdx = 0;
    set_state(UI_MENU);
    auth_system_record_activity(millis());
}

/*
 * Security gate for destructive/trust-changing actions (new enrollment,
 * wiping all fingerprints, wiping all BLE bonds): always demands a brand
 * new sensor match, never an existing auth_system session.
 *
 * CMD_FP_MATCH_AUTH resets fp_system's poll window (_lastMatchPoll = 0,
 * see fp_system.cpp), so this always requires a finger placed *after* this
 * call — there is no cached/stale state that can satisfy it. Callers resume
 * their action from the FP_MATCHED handler in nav_system_on_event, keyed on
 * _pendingAction; a failed/aborted attempt must clear _pendingAction so a
 * later, unrelated match can't be misattributed (see the FP_NO_MATCH and
 * UI_AUTH_PROMPT/KEY_LEFT handling below).
 */
static void require_fresh_touch(PendingAction action)
{
    _pendingAction = action;
    set_state(UI_AUTH_PROMPT);
    cmd_fp(CMD_FP_MATCH_AUTH);
}

static void enter_totp(unsigned long now)
{
    if (auth_system_needs_auth()) {
        require_fresh_touch(PENDING_TOTP);
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

static void enter_ble(unsigned long now)
{
    _bleMenuIdx = 0;
    set_state(UI_BLE_MENU);
    auth_system_record_activity(now);
}

static void begin_enroll_now(void)
{
    /*
     * start_enroll() already gates this on fp_system_ready() for its own
     * call path, but the PENDING_ENROLL fresh-touch-confirm dispatch calls
     * here directly with no prior check — if the sensor dropped out between
     * the touch confirming and this running, that path needs the same
     * no-sensor fallback instead of blindly issuing CMD_FP_ENROLL_START.
     */
    if (!fp_system_ready()) {
        set_state(UI_AUTH_ERROR);
        strncpy(_enrollMsg, "No sensor", sizeof(_enrollMsg) - 1);
        _authErrorStart = millis();
        _authErrorNoSensor = true;
        return;
    }
    _enrollStep = 1;
    _enrollRemove = false;
    _enrollMsg[0] = 0;
    set_state(UI_FP_ENROLL);
    cmd_fp(CMD_FP_ENROLL_START);
}

static void start_enroll(void)
{
    if (!fp_system_ready()) {
        /*
         * set_state() clears _enrollMsg and _authErrorNoSensor on every
         * transition (so stale state from the previous screen never bleeds
         * into the next one), so both the "No sensor" banner and the
         * no-sensor flag must be written *after* the transition, not
         * before, or set_state() wipes them before leave_auth_error() (the
         * AUTH_ERROR_DISPLAY_MS timeout, and the early CENTER/LEFT dismiss)
         * ever reads _authErrorNoSensor to decide whether to return to
         * Settings or drop the session back to the clock.
         */
        set_state(UI_AUTH_ERROR);
        strncpy(_enrollMsg, "No sensor", sizeof(_enrollMsg) - 1);
        _authErrorStart = millis();
        _authErrorNoSensor = true;
        return;
    }
    /*
     * Security gap closed: this used to be reachable from Settings with no
     * gate at all beyond "is the sensor present" — anyone with brief
     * physical access could add their own fingerprint as a standing
     * credential alongside the owner's. Enrolling only ever appends a
     * template (fp_system CMD_FP_ENROLL_START / AutoEnroll), it never
     * replaces one, so this was the easy path even when Clear-FP had some
     * gate.
     *
     * Bootstrap case stays open: with zero templates there is nothing yet
     * to prove ownership of, and first-time setup must still work.
     */
    if (fp_system_template_count() > 0) {
        require_fresh_touch(PENDING_ENROLL);
        return;
    }
    begin_enroll_now();
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
    /*
     * Security gap closed: this used to skip straight to the double-press
     * confirm screen whenever auth_system already had a live session (e.g.
     * the owner viewed a TOTP code a minute ago and walked away) — that
     * confirm press is a fat-finger safety net, not authentication, and
     * proves nothing about who is holding the device right now. A
     * destructive action always demands a fresh touch, regardless of
     * session state; only the template-count==0 bootstrap case (nothing to
     * clear/prove ownership of) skips the gate.
     */
    if (fp_system_template_count() > 0) {
        require_fresh_touch(PENDING_CLEAR_CONFIRM);
        return;
    }
    set_state(UI_FP_CLEAR_CONFIRM);
}

/*
 * Shared by the UI_AUTH_ERROR timeout (nav_system_tick()) and its early
 * LEFT/CENTER dismiss (nav_system_on_event()) so the two paths can't drift:
 * "No sensor" came from Settings → Enroll, so return there; every other
 * error came from an unlock attempt, so drop the session and go to the clock.
 */
static void leave_auth_error(void)
{
    if (_authErrorNoSensor) {
        set_state(UI_SETTINGS);
    } else {
        auth_system_clear();
        set_state(UI_CLOCK);
    }
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
                /*
                 * Dispatch on what this particular fresh touch was for. Each
                 * branch clears _pendingAction before acting so a repeat or
                 * stray FP_MATCHED (there should not be one — MATCH_STOP was
                 * just issued above — but see the fp_system/HAL concurrency
                 * note in the branch's own history) cannot replay the action.
                 */
                PendingAction action = _pendingAction;
                _pendingAction = PENDING_NONE;
                switch (action) {
                case PENDING_CLEAR_CONFIRM:
                    set_state(UI_FP_CLEAR_CONFIRM);
                    break;
                case PENDING_ENROLL:
                    begin_enroll_now();
                    break;
                case PENDING_BLE_UNPAIR:
#if CRYPTICK_BLE_FIDO
                    ble_fido_clear_all_bonds();
                    strncpy(_enrollMsg, "Bonds Wiped", sizeof(_enrollMsg) - 1);
                    _enrollMsgStart = now;
#endif
                    set_state(UI_BLE_MENU);
                    break;
                case PENDING_TOTP:
                default:
                    _accountIdx = 0;
                    set_state(UI_TOTP);
                    break;
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
                /* A failed fresh-touch attempt must not leave a pending
                 * destructive action armed for some later, unrelated match. */
                _pendingAction = PENDING_NONE;
                _authErrorStart = now;
                _authErrorNoSensor = false;
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
                /*
                 * set_state() clears _enrollMsg on every transition, so the
                 * "Stored" banner the Settings screen is about to show has
                 * to be written after the transition, not before, or it is
                 * wiped before nav_system_tick()'s 2s banner timer ever
                 * gets to display it.
                 */
                set_state(UI_SETTINGS);
                strncpy(_enrollMsg, "Stored", sizeof(_enrollMsg) - 1);
                _enrollMsgStart = now;
            }
        } else if (e.kind == FP_ENROLL_FAIL) {
            if (_state == UI_FP_ENROLL || e.a == 0xFE) {
                /* Same ordering fix as FP_ENROLL_DONE above: transition
                 * first, then write the banner the new screen should show. */
                set_state(UI_SETTINGS);
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
     * SW2 rotary encoder (GPIO40/41 — see board_config.h): one tick feeds
     * exactly the same scroll semantics as a 5-way UP/DOWN press, so every
     * list in the firmware (top menu, BLE menu, Settings, TOTP accounts,
     * Home quick cards) becomes encoder-scrollable for free, with no
     * per-state duplication and no change to what the 5-way does on its
     * own. The encoder's integral pushbutton is wired to GND on this PCB
     * rev, not to a GPIO (see input_system.cpp), so CENTER stays the only
     * confirm/select action — there is no separate "encoder click" to wire.
     */
    if (key == KEY_ENCODER_CW) key = KEY_DOWN;
    else if (key == KEY_ENCODER_CCW) key = KEY_UP;

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

    if (_state == UI_AUTH_ERROR) {
        /* Same early-dismiss courtesy as UI_FIDO_SUCCESS below, instead of
         * forcing the user to sit through the full AUTH_ERROR_DISPLAY_MS. */
        if (key == KEY_CENTER || key == KEY_LEFT)
            leave_auth_error();
        return;
    }

    if (_state == UI_FIDO_SUCCESS) {
        if (key == KEY_CENTER || key == KEY_LEFT) {
            set_state(UI_CLOCK);
            nav_system_set_fido_label("FIDO");
        }
        return;
    }

    switch (_state) {
    case UI_CLOCK:
        /*
         * RIGHT always means "next card", same as DOWN — it used to also
         * cycle _accountIdx while parked on the Quick-TOTP card (card 2),
         * with no on-screen sign that RIGHT had changed jobs. Account
         * cycling now lives only on the full TOTP list screen (UI_TOTP),
         * where UP/DOWN already do it and have no competing meaning.
         * The encoder (KEY_ENCODER_CW/CCW, remapped to UP/DOWN before this
         * switch) already walks the cards here for free.
         */
        if (key == KEY_CENTER) {
            if (_homeCard == 0) {
                enter_menu();
            } else if (_homeCard == 1) {
                /* Quick PIV PIN typing */
                if (ble_hid_type_piv_pin()) {
                    strncpy(_enrollMsg, "PIN Typed!", sizeof(_enrollMsg) - 1);
                } else {
                    strncpy(_enrollMsg, "BLE Offline", sizeof(_enrollMsg) - 1);
                }
                _enrollMsgStart = now;
                publish_ui();
            } else if (_homeCard == 2) {
                /* Quick TOTP code typing */
                if (ble_hid_type_current_totp(_accountIdx)) {
                    strncpy(_enrollMsg, "Code Typed!", sizeof(_enrollMsg) - 1);
                } else {
                    strncpy(_enrollMsg, "BLE Offline", sizeof(_enrollMsg) - 1);
                }
                _enrollMsgStart = now;
                publish_ui();
            }
        } else if (key == KEY_DOWN || key == KEY_RIGHT) {
            _homeCard = (_homeCard + 1) % 3;
            publish_ui();
        } else if (key == KEY_UP) {
            _homeCard = (_homeCard + 2) % 3;
            publish_ui();
        } else if (key == KEY_LEFT) {
            if (_homeCard != 0) {
                _homeCard = 0;
                publish_ui();
            }
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
            else if (_menuIdx == MENU_PIV) set_state(UI_PIV_PIN);
            else if (_menuIdx == MENU_BLE) enter_ble(now);
            else if (_menuIdx == MENU_SETTINGS) enter_settings(now);
        }
        break;

    case UI_BLE_MENU:
        auth_system_record_activity(now);
        if (key == KEY_UP) {
            _bleMenuIdx = (_bleMenuIdx + BLE_ITEM_COUNT - 1) % BLE_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_DOWN || key == KEY_RIGHT) {
            _bleMenuIdx = (_bleMenuIdx + 1) % BLE_ITEM_COUNT;
            publish_ui();
        } else if (key == KEY_LEFT) {
            set_state(UI_MENU);
        } else if (key == KEY_CENTER) {
            if (_bleMenuIdx == BLE_ACT_UNPAIR) {
                /*
                 * Security gap closed: this used to wipe every BLE bond on
                 * a single CENTER press with no confirmation and no
                 * authentication at all — the least-gated of the three
                 * destructive actions found in this file. Standing pairings
                 * are trust state exactly like fingerprint templates, so the
                 * same fresh-touch gate applies; bootstrap (no fingerprints
                 * enrolled yet) still allows unpairing with no gate, same as
                 * the other two actions, so a factory-fresh unit with no FP
                 * set up yet isn't locked out of its own BLE menu. The gate
                 * itself is not behind CRYPTICK_BLE_FIDO — it is nav_system
                 * policy, independent of whether the BLE stack is compiled
                 * in, and test_nav exercises it on the host build where that
                 * stack is absent.
                 */
                if (fp_system_template_count() > 0) {
                    require_fresh_touch(PENDING_BLE_UNPAIR);
                    return;
                }
#if CRYPTICK_BLE_FIDO
                ble_fido_clear_all_bonds();
                strncpy(_enrollMsg, "Bonds Wiped", sizeof(_enrollMsg) - 1);
                _enrollMsgStart = now;
#endif
            } else if (_bleMenuIdx == BLE_ACT_RESTART_ADV) {
#if CRYPTICK_BLE_FIDO
                ble_fido_restart_advertising();
                strncpy(_enrollMsg, "Adv Restarted", sizeof(_enrollMsg) - 1);
                _enrollMsgStart = now;
#endif
            }
            publish_ui();
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
        } else if (key == KEY_CENTER) {
            if (ble_hid_type_current_totp(_accountIdx)) {
                strncpy(_enrollMsg, "Code Typed!", sizeof(_enrollMsg) - 1);
            } else {
                strncpy(_enrollMsg, "BLE Offline", sizeof(_enrollMsg) - 1);
            }
            _enrollMsgStart = now;
            publish_ui();
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

    case UI_PIV_PIN:
        if (key == KEY_LEFT) {
            set_state(UI_MENU);
        } else if (key == KEY_CENTER) {
            if (ble_hid_type_piv_pin()) {
                strncpy(_enrollMsg, "PIN Typed!", sizeof(_enrollMsg) - 1);
            } else {
                strncpy(_enrollMsg, "BLE Offline", sizeof(_enrollMsg) - 1);
            }
            _enrollMsgStart = now;
            publish_ui();
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
        if (key == KEY_LEFT) {
            cmd_fp(CMD_FP_ENROLL_ABORT);
            set_state(UI_SETTINGS);
        }
        break;

    case UI_AUTH_PROMPT:
        if (key == KEY_LEFT) {
            cmd_fp(CMD_FP_MATCH_STOP);
            auth_system_clear();
            /*
             * Cancel returns to whichever screen asked for this unlock,
             * not a hardcoded UI_CLOCK — see PendingAction above. Mirrors
             * the FP_MATCHED success dispatch's per-action routing.
             */
            PendingAction pending = _pendingAction;
            _pendingAction = PENDING_NONE;
            switch (pending) {
            case PENDING_CLEAR_CONFIRM:
            case PENDING_ENROLL:
                set_state(UI_SETTINGS);
                break;
            case PENDING_BLE_UNPAIR:
                set_state(UI_BLE_MENU);
                break;
            case PENDING_TOTP:
            default:
                set_state(UI_MENU);
                break;
            }
        }
        break;

    case UI_FIDO_PROMPT:
        if (key == KEY_LEFT) {
            ctaphid_cancel_request();
            cmd_fp(CMD_FP_MATCH_STOP);
            _lastFidoReq = 0;
            set_state(UI_CLOCK);
        } else if (key == KEY_CENTER) {
            /* Button-press presence, same ceremony FP_MATCHED triggers —
             * gives the "OK = Confirm" hint in draw_fido_prompt() a real
             * action instead of leaving CENTER unlabeled and inert. */
            ctaphid_confirm_user_presence();
            cmd_fp(CMD_FP_MATCH_STOP);
            set_state(UI_FIDO_PROCESSING);
        }
        break;

    case UI_FIDO_PROCESSING:
        /* Same manual escape hatch as UI_FIDO_PROMPT: this state is usually
         * brief (CTAP keepalive/timeout clears it), but a hung host should
         * not leave the user with no way out. */
        if (key == KEY_LEFT) {
            ctaphid_cancel_request();
            cmd_fp(CMD_FP_MATCH_STOP);
            _lastFidoReq = 0;
            set_state(UI_CLOCK);
        }
        break;

    case UI_BLE_PAIRING:
        /* Every other waiting/prompt screen lets LEFT back out; this one
         * declines the in-progress pairing instead of leaving the user
         * stuck looking at a passkey with no cancel. */
        if (key == KEY_LEFT) {
            ble_fido_cancel_pairing();
            cmd_fp(CMD_FP_MATCH_STOP);
            _lastFidoReq = 0;
            nav_system_set_fido_label("FIDO");
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
        if (nowMs - _authErrorStart >= (unsigned long)AUTH_ERROR_DISPLAY_MS)
            leave_auth_error();
        return;
    }
    if (_state == UI_FIDO_SUCCESS) {
        if (nowMs - _fidoSuccessStart >= 2500UL) {
            set_state(UI_CLOCK);
            nav_system_set_fido_label("FIDO");
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
    /* Clear brief enroll/alert status */
    if (_enrollMsg[0] && (nowMs - _enrollMsgStart) >= 2000UL) {
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
