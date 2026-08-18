#include "fp_system.h"
#include "event_bus.h"
#include "auth_system.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <Arduino.h>

#ifdef ENABLE_FINGERPRINT
#include "fingerprint_r558s.h"

/*
 * R558-S integration (always powered for now; later: power-gate module).
 *
 * Policy:
 *  - Sensor is online after init (VfyPwd / template count) then idle.
 *  - No standing GenImg / TOUCH service in idle.
 *  - Match poll (GenImg→Search) runs only while MATCH_AUTH or MATCH_FIDO
 *    is active (TOTP gate / FIDO user presence).
 *  - Enroll: AutoEnroll status drain only while enrolling.
 *  - TOUCH IRQ deferred (net stuck LOW on current PCB); do not gate match on it.
 */

#ifndef FINGERPRINT_MATCH_POLL_MS
#define FINGERPRINT_MATCH_POLL_MS 280
#endif

static HardwareSerial _fpSerial(1);
static R558SFingerprint _finger(_fpSerial);
static bool _ready = false;
static uint16_t _count = 0;
static int _fp_rx = FINGERPRINT_RX;
static int _fp_tx = FINGERPRINT_TX;

enum MatchMode : uint8_t {
    MATCH_OFF = 0,
    MATCH_AUTH,
    MATCH_FIDO
};

static MatchMode _matchMode = MATCH_OFF;
static bool _enrolling = false;
static unsigned long _lastUiLog = 0;
static unsigned long _lastMatchPoll = 0;
static uint8_t _lastEnrollStep = 0;
static bool _publishedRemove = false;
static EnrollNbState _lastEnrollState = ENROLL_IDLE;

static void publish_fp(uint8_t kind, uint16_t a = 0, uint16_t b = 0)
{
    BusEvent e{};
    e.type = EVT_FP;
    e.kind = kind;
    e.a = a;
    e.b = b;
    bus_publish(e);
}

static void refresh_count(void)
{
    uint16_t n = 0;
    if (_ready && _finger.templateNum(&n) == FINGERPRINT_OK)
        _count = n;
}

static void stop_match(const char *why)
{
    if (_matchMode != MATCH_OFF)
        CLOG_I("FP", "match stop (%s)", why ? why : "-");
    _matchMode = MATCH_OFF;
    _lastMatchPoll = 0;
}

static bool try_sensor_at(int esp_rx, int esp_tx)
{
    _fpSerial.end();
    delay(20);
    _fpSerial.setRxBufferSize(512);
    /* Open UART ASAP so cold-start 0x55 is not lost. Module stays powered. */
    _fpSerial.begin(FINGERPRINT_BAUD, SERIAL_8N1, esp_rx, esp_tx);

    _finger.setDebug(false);
    _finger.setCapacity(FINGERPRINT_CAPACITY);
    _finger.setTimeout(FINGERPRINT_CMD_TIMEOUT_MS);
#if FINGERPRINT_IRQ_PIN >= 0
    /* Touch pin reserved; match does not rely on it until PCB idle is HIGH. */
    _finger.setTouchPin(FINGERPRINT_IRQ_PIN);
#endif

    int r = _finger.begin(FINGERPRINT_BAUD);
    if (r == FINGERPRINT_OK) {
        _fp_rx = esp_rx;
        _fp_tx = esp_tx;
        return true;
    }
    CLOG_E("FP", "try RX=%d TX=%d → fail (%d)", esp_rx, esp_tx, r);
    return false;
}

void fp_system_init(void)
{
    CLOG_D("FP", "R558-S @ %u baud  (on-demand match; idle = no GenImg)",
                       (unsigned)FINGERPRINT_BAUD);

    bool ok = try_sensor_at(FINGERPRINT_RX, FINGERPRINT_TX);
    if (!ok)
        ok = try_sensor_at(FINGERPRINT_TX, FINGERPRINT_RX);

    if (ok) {
        _ready = true;
        _matchMode = MATCH_OFF;
        _enrolling = false;
        refresh_count();
        CLOG_I("FP", "OK  ESP_RX=%d ESP_TX=%d  templates=%u",
                           _fp_rx, _fp_tx, (unsigned)_count);
        CLOG_D("FP", "idle until TOTP-auth / FIDO-presence / enroll");
        publish_fp(FP_READY, _count, 0);
    } else {
        _ready = false;
        CLOG_I("FP", "sensor not found");
    }
}

void fp_system_tick(unsigned long nowMs)
{
    if (!_ready)
        return;

    _finger.ledUpdate();

    /* -------- Enroll session only -------- */
    if (_enrolling) {
        EnrollNbState st;
        uint8_t step = 0;
        int r = _finger.enrollPoll(st, step);
        auth_system_record_activity(nowMs);

        if (st == ENROLL_WAIT_FINGER &&
            (step != _lastEnrollStep || _lastEnrollState != ENROLL_WAIT_FINGER)) {
            _lastEnrollStep = step;
            _lastEnrollState = st;
            _publishedRemove = false;
            publish_fp(FP_ENROLL_STEP, step, 0);
            CLOG_D("FP", "place finger entry %u/2", (unsigned)step);
        }

        if (st == ENROLL_WAIT_REMOVE &&
            (_lastEnrollState != ENROLL_WAIT_REMOVE || !_publishedRemove)) {
            _publishedRemove = true;
            _lastEnrollState = st;
            publish_fp(FP_ENROLL_STEP, step ? step : 1, 1);
            CLOG_D("FP", "lift finger (after entry %u)",
                               (unsigned)(step ? step : 1));
        }

        if (st == ENROLL_BUSY && _lastEnrollState != ENROLL_BUSY) {
            _lastEnrollState = st;
            CLOG_D("FP", "AutoEnroll busy p1=%u p2=%u",
                               _finger.enrollProgressP1(),
                               _finger.enrollProgressP2());
        }

        if (st == ENROLL_DONE) {
            _enrolling = false;
            _lastEnrollState = ENROLL_IDLE;
            refresh_count();
            publish_fp(FP_ENROLL_DONE, _finger.enrollId(), _count);
            CLOG_I("FP", "enrolled PageID=%u total=%u",
                               (unsigned)_finger.enrollId(), (unsigned)_count);
            _finger.setLedOnFor(0x02, 400);
        } else if (st == ENROLL_FAILED) {
            _enrolling = false;
            _lastEnrollState = ENROLL_IDLE;
            publish_fp(FP_ENROLL_FAIL, (uint16_t)((r < 0) ? 0 : r), 0);
            CLOG_E("FP", "enroll FAIL: %s (%d)",
                               R558SFingerprint::getErrorMessage(r), r);
            _finger.setLedOnFor(0x04, 600);
        }

        if (nowMs - _lastUiLog >= 4000UL &&
            (st == ENROLL_WAIT_FINGER || st == ENROLL_WAIT_REMOVE)) {
            _lastUiLog = nowMs;
            CLOG_D("FP", "enroll wait %s",
                               st == ENROLL_WAIT_FINGER ? "place" : "lift");
        }
        (void)r;
        return;
    }

    /* -------- Idle: no UART FP traffic -------- */
    if (_matchMode == MATCH_OFF)
        return;

    /* -------- Active match window (TOTP or FIDO) -------- */
    if (nowMs - _lastMatchPoll < (unsigned long)FINGERPRINT_MATCH_POLL_MS)
        return;
    _lastMatchPoll = nowMs;

    uint16_t id = 0, score = 0;
    int r = _finger.getFingerprintID(&id, &score);

    if (r == FINGERPRINT_OK) {
        CLOG_I("FP", "MATCH id=%u score=%u mode=%u",
                           (unsigned)id, (unsigned)score, (unsigned)_matchMode);
        publish_fp(FP_MATCHED, id, score);
        stop_match("ok");
        _finger.setLedOnFor(0x02, 500);
    } else if (r == FINGERPRINT_NOTFOUND || r == FINGERPRINT_NOMATCH) {
        CLOG_D("FP", "NO_MATCH");
        publish_fp(FP_NO_MATCH, 0, 0);
        stop_match("no_match");
        _finger.setLedOnFor(0x04, 400);
    }
    /* NOFINGER / image fails: keep polling until STOP or success/no_match */
}

bool fp_system_ready(void) { return _ready; }
uint16_t fp_system_template_count(void) { return _count; }
bool fp_system_match_active(void)
{
    return _matchMode == MATCH_AUTH || _matchMode == MATCH_FIDO;
}
void *fp_system_driver(void) { return _ready ? (void *)&_finger : nullptr; }

/*
 * Presence helpers for HAL: when Arduino loop is blocked (CDC OATH UV),
 * ctap_user_presence_test self-services GenImg/Search on the main core.
 * FIDO task must NOT call these (UART would race with main-loop match).
 */
extern "C" void device_presence_fp_begin(void)
{
    if (!_ready || _count == 0)
        return;
    if (_enrolling) {
        _finger.enrollAbort();
        _enrolling = false;
    }
    _matchMode = MATCH_FIDO;
    _lastMatchPoll = 0;
    CLOG_I("FP", "match START (FIDO) — GenImg until match/stop");
    _finger.setLed(0x01);
}

extern "C" void device_presence_fp_end(void)
{
    if (_matchMode != MATCH_OFF)
        _finger.setLedOff();
    stop_match("presence_end");
}

/** 1 = enrolled finger matched, 0 = keep waiting. */
extern "C" int device_presence_fp_poll(void)
{
    if (!_ready || _count == 0)
        return 0;
    if (_matchMode == MATCH_OFF) {
        /* After NO_MATCH path may stop; keep re-arming while UP is open. */
        _matchMode = MATCH_FIDO;
        _lastMatchPoll = 0;
    }

    unsigned long nowMs = millis();
    if (nowMs - _lastMatchPoll < (unsigned long)FINGERPRINT_MATCH_POLL_MS)
        return 0;
    _lastMatchPoll = nowMs;

    uint16_t id = 0, score = 0;
    int r = _finger.getFingerprintID(&id, &score);
    if (r == FINGERPRINT_OK) {
        CLOG_I("FP", "MATCH id=%u score=%u mode=%u",
               (unsigned)id, (unsigned)score, (unsigned)_matchMode);
        publish_fp(FP_MATCHED, id, score);
        stop_match("ok");
        _finger.setLedOnFor(0x02, 500);
        return 1;
    }
    if (r == FINGERPRINT_NOTFOUND || r == FINGERPRINT_NOMATCH) {
        CLOG_D("FP", "NO_MATCH (presence keep trying)");
        /* Stay in MATCH_FIDO — do not abandon UP window. */
        _finger.setLed(0x01);
        return 0;
    }
    return 0;
}

void fp_system_on_cmd(const BusEvent &e)
{
    if (e.type != EVT_CMD)
        return;
    if (!_ready) {
        if (e.kind == CMD_FP_ENROLL_START)
            publish_fp(FP_ENROLL_FAIL, 0, 0);
        return;
    }

    switch (e.kind) {
    case CMD_FP_MATCH_AUTH:
        if (_enrolling) {
            _finger.enrollAbort();
            _enrolling = false;
        }
        _matchMode = MATCH_AUTH;
        _lastMatchPoll = 0; /* first GenImg ASAP */
        CLOG_I("FP", "match START (TOTP auth) — GenImg until match/stop");
        _finger.setLed(0x01);
        break;
    case CMD_FP_MATCH_FIDO:
        if (_enrolling) {
            _finger.enrollAbort();
            _enrolling = false;
        }
        _matchMode = MATCH_FIDO;
        _lastMatchPoll = 0;
        CLOG_I("FP", "match START (FIDO) — GenImg until match/stop");
        _finger.setLed(0x01);
        break;
    case CMD_FP_MATCH_STOP:
        if (_matchMode != MATCH_OFF)
            _finger.setLedOff();
        stop_match("cmd");
        break;
    case CMD_FP_ENROLL_START:
        stop_match("enroll");
        {
            uint16_t slot = (e.a != 0 && e.a != 0xFFFF) ? e.a : 0xFFFF;
            if (_finger.enrollStart(slot) == FINGERPRINT_OK) {
                _enrolling = true;
                _lastEnrollStep = 0;
                _lastEnrollState = ENROLL_IDLE;
                _publishedRemove = false;
                _lastUiLog = 0;
                publish_fp(FP_ENROLL_STEP, 1, 0);
                CLOG_D("FP", "AutoEnroll PageID=%u — place finger",
                                   (unsigned)_finger.enrollId());
                _finger.setLed(0x01);
            } else {
                publish_fp(FP_ENROLL_FAIL, 0, 0);
                CLOG_E("FP", "AutoEnroll start failed");
            }
        }
        break;
    case CMD_FP_ENROLL_ABORT:
        _finger.enrollAbort();
        _enrolling = false;
        _lastEnrollState = ENROLL_IDLE;
        _finger.setLedOff();
        publish_fp(FP_ENROLL_FAIL, 0xFE, 0);
        CLOG_E("FP", "enroll aborted");
        break;
    case CMD_FP_CLEAR_ALL:
        stop_match("clear");
        if (_finger.emptyLibrary() == FINGERPRINT_OK) {
            refresh_count();
            publish_fp(FP_COUNT, _count, 0);
            CLOG_D("FP", "library emptied");
        }
        break;
    default:
        break;
    }
}

#else

void fp_system_init(void) {}
void fp_system_tick(unsigned long) {}
bool fp_system_ready(void) { return false; }
uint16_t fp_system_template_count(void) { return 0; }
bool fp_system_match_active(void) { return false; }
void *fp_system_driver(void) { return nullptr; }
void fp_system_on_cmd(const BusEvent &) {}
extern "C" void device_presence_fp_begin(void) {}
extern "C" void device_presence_fp_end(void) {}
extern "C" int device_presence_fp_poll(void) { return 0; }

#endif
