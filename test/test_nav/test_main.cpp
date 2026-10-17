#include <Arduino.h>
#include <unity.h>
#include "event_bus.h"
#include "nav_system.h"
#include "auth_system.h"

/* Stubs — nav links FIDO confirms and FP readiness without full product */
extern "C" {
void ctaphid_confirm_user_presence(void) {}
void ctaphid_cancel_request(void) {}
}

static bool g_fp_ready = true;
static uint16_t g_fp_count = 0;
static bool g_fp_match_active = false;

bool fp_system_ready(void) { return g_fp_ready; }
uint16_t fp_system_template_count(void) { return g_fp_count; }
bool fp_system_match_active(void) { return g_fp_match_active; }

static void inject_key(uint8_t key)
{
    BusEvent e{};
    e.type = EVT_INPUT;
    e.kind = key;
    nav_system_on_event(e);
}

static void inject_fp(uint8_t kind, uint16_t a = 0, uint16_t b = 0)
{
    BusEvent e{};
    e.type = EVT_FP;
    e.kind = kind;
    e.a = a;
    e.b = b;
    nav_system_on_event(e);
}

/*
 * Common reset. nav_system_init() restores the sleep timeout from NVS, so every
 * sleep test sets its own value with persist=false — otherwise a device that
 * had "never" saved would silently pass tests that should fail.
 */
static void reset_nav(void)
{
    bus_init();
    auth_system_init();
    nav_system_set_fido_ui(0);
    nav_system_init();
    g_fp_ready = true;
    g_fp_count = 0;
    g_fp_match_active = false;
}

/** Run one tick exactly `sec` after the last activity, on the real clock. */
static void tick_after_idle(uint16_t sec)
{
    unsigned long t0 = millis();
    nav_system_note_activity(t0);
    auth_system_record_activity(t0);
    nav_system_tick(t0 + (unsigned long)sec * 1000UL);
}

void test_center_opens_menu_left_stays_clock(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());

    inject_key(KEY_LEFT);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());

    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_MENU, nav_system_state());

    inject_key(KEY_LEFT);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
}

void test_menu_to_settings(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();

    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_MENU, nav_system_state());

    /*
     * Off-by-one (really off-by-two once you count it out): this was written
     * when MenuItem was just { MENU_TOTP = 0, MENU_SETTINGS = 1 }, so one
     * KEY_DOWN from TOTP landed on Settings. MENU_PIV and MENU_BLE were
     * later inserted ahead of MENU_SETTINGS (now index 3, not 1), so a single
     * KEY_DOWN now lands on PIV instead — nothing caught that because
     * test_nav had never actually been executed (see [env:test_nav_native]
     * in platformio.ini). Three presses walk TOTP → PIV → BLE → Settings.
     */
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN); /* Settings */
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_SETTINGS, nav_system_state());
}

void test_settings_enroll_flow_via_bus(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    g_fp_ready = true;
    g_fp_count = 0;

    inject_key(KEY_CENTER);
    /* Same off-by-one as test_menu_to_settings: Settings is index 3 now that
     * MENU_PIV and MENU_BLE sit between it and TOTP, not index 1. */
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN); /* Settings */
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_SETTINGS, nav_system_state());

    /* SET_ENROLL is index 0 */
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_FP_ENROLL, nav_system_state());

    inject_fp(FP_ENROLL_STEP, 1, 0);
    TEST_ASSERT_EQUAL(1, nav_system_enroll_step());
    TEST_ASSERT_FALSE(nav_system_enroll_remove());

    inject_fp(FP_ENROLL_STEP, 1, 1);
    TEST_ASSERT_TRUE(nav_system_enroll_remove());

    inject_fp(FP_ENROLL_DONE, 3, 1);
    TEST_ASSERT_EQUAL(UI_SETTINGS, nav_system_state());
    TEST_ASSERT_EQUAL_STRING("Stored", nav_system_enroll_message());
}

void test_auth_prompt_match_opens_totp(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    nav_system_set_account_count(1);
    auth_system_set_fingerprint_enabled(true);
    auth_system_clear();

    inject_key(KEY_CENTER);
    /* MENU_TOTP at index 0 */
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());

    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_TOTP, nav_system_state());
}

/*
 * Regression for the nav/HAL fingerprint-ceremony race: a host FIDO/OATH
 * request (nav_system_set_fido_ui(1), normally bridged from
 * core/fido2/hal_esp32.cpp's up_test_locked() via _fido_ui_request in
 * src/main.cpp's loop()) arriving while the on-device TOTP-unlock prompt is
 * already open used to silently replace UI_AUTH_PROMPT with UI_FIDO_PROMPT
 * and restart the match as CMD_FP_MATCH_FIDO — so the very next touch, which
 * the user believed was approving the on-device TOTP view, would instead
 * confirm the unrelated host ceremony (or vice versa). nav_owns_ceremony()
 * in nav_system.cpp now defers any incoming request while a nav-owned
 * ceremony (UI_AUTH_PROMPT / UI_FP_ENROLL / UI_FP_CLEAR_CONFIRM) is open, so
 * the state and the eventual match must both stay with the original prompt.
 */
void test_fido_ui_request_deferred_during_auth_prompt(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    nav_system_set_account_count(1);
    auth_system_set_fingerprint_enabled(true);
    auth_system_clear();

    inject_key(KEY_CENTER);
    inject_key(KEY_CENTER); /* MENU_TOTP at index 0 */
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());

    /* A host ceremony's presence request must not steal this prompt. */
    nav_system_set_fido_ui(1);
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());

    /* The touch the user actually gives must still resolve the ORIGINAL
     * (TOTP-unlock) ceremony, not an unrelated one that hijacked the UI. */
    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_TOTP, nav_system_state());
    TEST_ASSERT_TRUE(auth_system_is_authenticated());
}

void test_enroll_no_sensor(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    g_fp_ready = false;

    inject_key(KEY_CENTER);
    /* Same off-by-one as test_menu_to_settings: Settings is index 3 now that
     * MENU_PIV and MENU_BLE sit between it and TOTP, not index 1. */
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN);
    inject_key(KEY_DOWN); /* Settings */
    inject_key(KEY_CENTER);
    inject_key(KEY_CENTER); /* Enroll */
    TEST_ASSERT_EQUAL(UI_AUTH_ERROR, nav_system_state());

    g_fp_ready = true;
}

void test_idle_enters_sleep(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(10, false);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());

    tick_after_idle(9);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
    TEST_ASSERT_FALSE(nav_system_is_asleep());

    tick_after_idle(10);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());
    TEST_ASSERT_TRUE(nav_system_is_asleep());
}

void test_only_center_wakes_and_press_is_consumed(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);
    tick_after_idle(5);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());

    inject_key(KEY_LEFT);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());
    inject_key(KEY_UP);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());
    inject_key(KEY_DOWN);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());

    /* CENTER wakes to the clock — it must NOT also open the menu. */
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
    TEST_ASSERT_FALSE(nav_system_is_asleep());
}

void test_sleep_timeout_zero_never_sleeps(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(0, false);
    tick_after_idle(3600);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
}

void test_no_sleep_while_awaiting_user(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);

    /* A host presence request must hold the screen on however long it waits. */
    nav_system_set_fido_ui(1);
    TEST_ASSERT_EQUAL(UI_FIDO_PROMPT, nav_system_state());
    tick_after_idle(600);
    TEST_ASSERT_EQUAL(UI_FIDO_PROMPT, nav_system_state());

    /* Same for an on-device unlock prompt. */
    nav_system_set_fido_ui(0);
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);
    nav_system_set_account_count(1);
    auth_system_set_fingerprint_enabled(true);
    auth_system_clear();
    inject_key(KEY_CENTER);
    inject_key(KEY_CENTER);
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());
    tick_after_idle(600);
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());
}

void test_host_request_wakes_from_sleep(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);
    tick_after_idle(5);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());

    /* Otherwise "Place finger" would be invisible on a dark screen. */
    nav_system_set_fido_ui(1);
    TEST_ASSERT_EQUAL(UI_FIDO_PROMPT, nav_system_state());
    nav_system_set_fido_ui(0);
}

void test_no_sleep_during_fido_ceremony_hold(void)
{
    /*
     * Chrome GetTouch returns to CLOCK before MakeCredential. Idle sleep
     * must not blank the token under the still-open OS dialog.
     */
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);
    nav_system_set_fido_ui(1);
    nav_system_set_fido_ui(0);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
    tick_after_idle(5);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
    TEST_ASSERT_FALSE(nav_system_is_asleep());
}

void test_sleep_drops_unlock_session(void)
{
    reset_nav();
    nav_system_set_account_count(1);
    auth_system_set_fingerprint_enabled(true);
    auth_system_clear();

    inject_key(KEY_CENTER); /* menu */
    inject_key(KEY_CENTER); /* TOTP → auth prompt */
    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_TOTP, nav_system_state());
    TEST_ASSERT_TRUE(auth_system_is_authenticated());

    /* Well inside INACTIVITY_TIMEOUT_SEC, so sleep is what clears it. */
    nav_system_set_sleep_timeout_sec(5, false);
    tick_after_idle(5);
    TEST_ASSERT_EQUAL(UI_SLEEP, nav_system_state());
    TEST_ASSERT_FALSE(auth_system_is_authenticated());
}

/*
 * Security regression coverage: Enroll / Clear-FP / BLE-unpair must demand a
 * *fresh* fingerprint match whenever a template already exists, never ride
 * on an existing auth_system session, and must stay reachable with no gate
 * at all in the bootstrap case (zero templates).
 */
/*
 * Top menu order is MENU_TOTP=0, MENU_PIV=1, MENU_BLE=2, MENU_SETTINGS=3
 * (nav_system.cpp). enter_menu() always resets _menuIdx to 0, so one KEY_UP
 * wraps straight to Settings (index 3) and two KEY_DOWN reaches BLE
 * (index 2) — used consistently below instead of hand-counting presses
 * inline at each call site.
 */
static void goto_settings(void)
{
    inject_key(KEY_CENTER); /* UI_CLOCK -> UI_MENU, idx 0 (TOTP) */
    inject_key(KEY_UP);     /* idx wraps to 3 (SETTINGS) */
    inject_key(KEY_CENTER); /* UI_MENU -> UI_SETTINGS */
}

static void goto_ble_menu(void)
{
    inject_key(KEY_CENTER); /* UI_CLOCK -> UI_MENU, idx 0 (TOTP) */
    inject_key(KEY_DOWN);   /* idx 1 (PIV) */
    inject_key(KEY_DOWN);   /* idx 2 (BLE) */
    inject_key(KEY_CENTER); /* UI_MENU -> UI_BLE_MENU */
}

void test_enroll_requires_fresh_touch_when_templates_exist(void)
{
    reset_nav();
    g_fp_count = 1;

    goto_settings();
    TEST_ASSERT_EQUAL(UI_SETTINGS, nav_system_state());

    inject_key(KEY_CENTER); /* SET_ENROLL, index 0 */
    TEST_ASSERT_EQUAL_MESSAGE(UI_AUTH_PROMPT, nav_system_state(),
                               "Enroll must gate behind a fresh touch once a template exists");

    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_FP_ENROLL, nav_system_state());
}

void test_enroll_bootstrap_stays_ungated(void)
{
    reset_nav();
    g_fp_count = 0;

    goto_settings();
    inject_key(KEY_CENTER); /* SET_ENROLL */
    TEST_ASSERT_EQUAL_MESSAGE(UI_FP_ENROLL, nav_system_state(),
                               "First-time setup (no templates yet) must stay reachable with no gate");
}

void test_clear_fp_requires_fresh_touch_even_with_live_session(void)
{
    reset_nav();
    g_fp_count = 1;
    /* Simulate an owner who unlocked TOTP a moment ago and is still "in
     * session" — that must NOT be enough to authorize wiping fingerprints. */
    auth_system_set_fingerprint_enabled(true);
    auth_system_on_match();
    TEST_ASSERT_TRUE(auth_system_is_authenticated());

    goto_settings();
    inject_key(KEY_DOWN);
    inject_key(KEY_CENTER); /* SET_CLEAR, index 1 */
    TEST_ASSERT_EQUAL_MESSAGE(UI_AUTH_PROMPT, nav_system_state(),
                               "Clear-FP must not be satisfied by a pre-existing session");

    inject_fp(FP_NO_MATCH);
    TEST_ASSERT_EQUAL_MESSAGE(UI_AUTH_ERROR, nav_system_state(),
                               "A failed fresh-touch attempt must not fall through to the confirm screen");
}

void test_clear_fp_confirm_reached_after_fresh_match(void)
{
    reset_nav();
    g_fp_count = 1;

    goto_settings();
    inject_key(KEY_DOWN);
    inject_key(KEY_CENTER); /* SET_CLEAR */
    TEST_ASSERT_EQUAL(UI_AUTH_PROMPT, nav_system_state());

    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_FP_CLEAR_CONFIRM, nav_system_state());
}

void test_clear_fp_bootstrap_stays_ungated(void)
{
    reset_nav();
    g_fp_count = 0;

    goto_settings();
    inject_key(KEY_DOWN);
    inject_key(KEY_CENTER); /* SET_CLEAR */
    TEST_ASSERT_EQUAL_MESSAGE(UI_FP_CLEAR_CONFIRM, nav_system_state(),
                               "Nothing enrolled yet means nothing to clear/prove ownership of");
}

void test_ble_unpair_requires_fresh_touch_when_templates_exist(void)
{
    reset_nav();
    g_fp_count = 1;

    goto_ble_menu();
    TEST_ASSERT_EQUAL(UI_BLE_MENU, nav_system_state());

    inject_key(KEY_CENTER); /* BLE_ACT_UNPAIR, index 0 */
    TEST_ASSERT_EQUAL_MESSAGE(UI_AUTH_PROMPT, nav_system_state(),
                               "Unpair must gate behind a fresh touch once a template exists");

    inject_fp(FP_MATCHED, 1, 100);
    TEST_ASSERT_EQUAL(UI_BLE_MENU, nav_system_state());
}

void test_ble_unpair_bootstrap_stays_ungated(void)
{
    reset_nav();
    g_fp_count = 0;

    goto_ble_menu();
    inject_key(KEY_CENTER); /* BLE_ACT_UNPAIR */
    TEST_ASSERT_EQUAL_MESSAGE(UI_BLE_MENU, nav_system_state(),
                               "No fingerprints enrolled yet must not lock the owner out of their own BLE menu");
}

void test_settings_labels_cover_every_item(void)
{
    reset_nav();
    int n = nav_system_settings_count();
    TEST_ASSERT_GREATER_THAN(0, n);
    for (int i = 0; i < n; i++) {
        char buf[32];
        buf[0] = 0;
        nav_system_settings_label(i, buf, sizeof(buf));
        TEST_ASSERT_TRUE_MESSAGE(buf[0] != 0, "settings item has no label");
    }
}

void test_ble_pairing_screen_lifecycle(void)
{
    reset_nav();
    nav_system_set_sleep_timeout_sec(5, false);

    /* Pairing request sets state to UI_BLE_PAIRING and displays passkey */
    nav_system_set_fido_label("123456");
    nav_system_set_fido_ui(4);
    TEST_ASSERT_EQUAL(UI_BLE_PAIRING, nav_system_state());
    TEST_ASSERT_EQUAL_STRING("123456", nav_system_fido_label());

    /* Panel must not sleep while pairing passkey is on screen */
    tick_after_idle(600);
    TEST_ASSERT_EQUAL(UI_BLE_PAIRING, nav_system_state());
    TEST_ASSERT_FALSE(nav_system_is_asleep());

    /* Clearing pairing returns to UI_CLOCK and restores default FIDO label */
    nav_system_set_fido_ui(0);
    TEST_ASSERT_EQUAL(UI_CLOCK, nav_system_state());
    TEST_ASSERT_EQUAL_STRING("FIDO", nav_system_fido_label());
}

void setup()
{
    delay(1500);
    UNITY_BEGIN();
    RUN_TEST(test_center_opens_menu_left_stays_clock);
    RUN_TEST(test_menu_to_settings);
    RUN_TEST(test_settings_enroll_flow_via_bus);
    RUN_TEST(test_auth_prompt_match_opens_totp);
    RUN_TEST(test_fido_ui_request_deferred_during_auth_prompt);
    RUN_TEST(test_enroll_no_sensor);
    RUN_TEST(test_idle_enters_sleep);
    RUN_TEST(test_only_center_wakes_and_press_is_consumed);
    RUN_TEST(test_sleep_timeout_zero_never_sleeps);
    RUN_TEST(test_no_sleep_while_awaiting_user);
    RUN_TEST(test_host_request_wakes_from_sleep);
    RUN_TEST(test_no_sleep_during_fido_ceremony_hold);
    RUN_TEST(test_ble_pairing_screen_lifecycle);
    RUN_TEST(test_sleep_drops_unlock_session);
    RUN_TEST(test_settings_labels_cover_every_item);
    UNITY_END();
}

void loop() {}
