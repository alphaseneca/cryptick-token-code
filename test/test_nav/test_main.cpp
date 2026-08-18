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
    inject_key(KEY_DOWN);
    inject_key(KEY_CENTER); /* Settings */
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

void test_enroll_no_sensor(void)
{
    bus_init();
    auth_system_init();
    nav_system_init();
    g_fp_ready = false;

    inject_key(KEY_CENTER);
    inject_key(KEY_DOWN);
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

void setup()
{
    delay(1500);
    UNITY_BEGIN();
    RUN_TEST(test_center_opens_menu_left_stays_clock);
    RUN_TEST(test_menu_to_settings);
    RUN_TEST(test_settings_enroll_flow_via_bus);
    RUN_TEST(test_auth_prompt_match_opens_totp);
    RUN_TEST(test_enroll_no_sensor);
    RUN_TEST(test_idle_enters_sleep);
    RUN_TEST(test_only_center_wakes_and_press_is_consumed);
    RUN_TEST(test_sleep_timeout_zero_never_sleeps);
    RUN_TEST(test_no_sleep_while_awaiting_user);
    RUN_TEST(test_host_request_wakes_from_sleep);
    RUN_TEST(test_no_sleep_during_fido_ceremony_hold);
    RUN_TEST(test_sleep_drops_unlock_session);
    RUN_TEST(test_settings_labels_cover_every_item);
    UNITY_END();
}

void loop() {}
