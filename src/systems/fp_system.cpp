#include "fp_system.h"
#include "event_bus.h"
#include "auth_system.h"
#include <board_config.h>
#include <Arduino.h>

#ifdef ENABLE_FINGERPRINT
#include "fingerprint_r558s.h"

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
static unsigned long _lastPoll = 0;
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
    if (_ready && _finger.getTemplateCount(&n) == FINGERPRINT_OK)
        _count = n;
}

static bool try_sensor_at(int esp_rx, int esp_tx)
{
    _fpSerial.end();
    delay(20);
    _fpSerial.setRxBufferSize(512);
    _fpSerial.begin(FINGERPRINT_BAUD, SERIAL_8N1, esp_rx, esp_tx);
    delay(150);

    _finger.setDebug(false);
    _finger.setCapacity(FINGERPRINT_CAPACITY);
    _finger.setTimeout(FINGERPRINT_UART_TIMEOUT_MS);

    int r = _finger.begin(FINGERPRINT_BAUD);
    if (r == FINGERPRINT_OK) {
        _fp_rx = esp_rx;
        _fp_tx = esp_tx;
        return true;
    }
    Serial.printf("[FP] try RX=%d TX=%d → fail (%d)\n", esp_rx, esp_tx, r);
    return false;
}

void fp_system_init(void)
{
#if FINGERPRINT_IRQ_PIN >= 0
    pinMode(FINGERPRINT_IRQ_PIN, INPUT_PULLUP);
#endif

    Serial.printf("[FP] probing sensor @ %u baud\n", (unsigned)FINGERPRINT_BAUD);

    bool ok = try_sensor_at(FINGERPRINT_RX, FINGERPRINT_TX);
    if (!ok)
        ok = try_sensor_at(FINGERPRINT_TX, FINGERPRINT_RX);

    if (ok) {
        _ready = true;
        refresh_count();
        Serial.printf("[FP] OK  ESP_RX=%d ESP_TX=%d  templates=%u\n",
                      _fp_rx, _fp_tx, (unsigned)_count);
#if FINGERPRINT_LED_READY
        _finger.setLed(FINGERPRINT_LED_READY);
        delay(300);
        _finger.setLedOff();
#endif
        publish_fp(FP_READY, _count, 0);
    } else {
        _ready = false;
        Serial.println(F("[FP] Sensor not found (check wiring / 3V3 / baud)"));
    }
}

void fp_system_tick(unsigned long nowMs)
{
    if (!_ready) return;
    _finger.ledUpdate();

    const unsigned long interval = _enrolling
        ? (unsigned long)FINGERPRINT_ENROLL_POLL_MS
        : (unsigned long)FINGERPRINT_POLL_INTERVAL_MS;
    if (nowMs - _lastPoll < interval) return;
    _lastPoll = nowMs;

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
            Serial.printf("[FP] enroll place finger step %u/2\n", (unsigned)step);
#if FINGERPRINT_LED_ENROLL
            _finger.setLed(FINGERPRINT_LED_ENROLL);
#endif
        }

        if (st == ENROLL_WAIT_REMOVE &&
            (_lastEnrollState != ENROLL_WAIT_REMOVE || !_publishedRemove)) {
            _publishedRemove = true;
            _lastEnrollState = st;
            publish_fp(FP_ENROLL_STEP, step ? step : 1, 1);
            Serial.printf("[FP] enroll remove finger (after step %u)\n",
                          (unsigned)(step ? step : 1));
        }

        if (st == ENROLL_DONE) {
            _enrolling = false;
            _lastEnrollState = ENROLL_IDLE;
            refresh_count();
            publish_fp(FP_ENROLL_DONE, _finger.enrollId(), _count);
            Serial.printf("[FP] enrolled id=%u total=%u\n",
                          (unsigned)_finger.enrollId(), (unsigned)_count);
            _finger.setLedOff();
#if FINGERPRINT_LED_MATCH
            _finger.setLedOnFor(FINGERPRINT_LED_MATCH, 800);
#endif
        } else if (st == ENROLL_FAILED) {
            _enrolling = false;
            _lastEnrollState = ENROLL_IDLE;
            publish_fp(FP_ENROLL_FAIL, (uint16_t)((r < 0) ? 0 : r), 0);
            Serial.printf("[FP] enroll FAIL: %s (%d)\n",
                          R558SFingerprint::getErrorMessage(r), r);
            _finger.setLedOff();
#if FINGERPRINT_LED_ERROR
            _finger.setLedOnFor(FINGERPRINT_LED_ERROR, 800);
#endif
        } else {
            /* keep UI from idling out while waiting on finger */
            (void)0;
        }
        (void)r;
        return;
    }

    if (_matchMode == MATCH_OFF) return;

    uint16_t id = 0, score = 0;
    int r = _finger.getFingerprintID(&id, &score);
    if (r == FINGERPRINT_OK) {
        publish_fp(FP_MATCHED, id, score);
        _matchMode = MATCH_OFF;
#if FINGERPRINT_LED_MATCH
        _finger.setLedOnFor(FINGERPRINT_LED_MATCH, 800);
#endif
    } else if (r == FINGERPRINT_NOTFOUND || r == FINGERPRINT_NOMATCH) {
        publish_fp(FP_NO_MATCH, 0, 0);
#if FINGERPRINT_LED_ERROR
        _finger.setLedOnFor(FINGERPRINT_LED_ERROR, 600);
#endif
    }
}

bool fp_system_ready(void) { return _ready; }
uint16_t fp_system_template_count(void) { return _count; }
void *fp_system_driver(void) { return _ready ? (void *)&_finger : nullptr; }

void fp_system_on_cmd(const BusEvent &e)
{
    if (e.type != EVT_CMD) return;
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
        break;
    case CMD_FP_MATCH_FIDO:
        if (_enrolling) {
            _finger.enrollAbort();
            _enrolling = false;
        }
        _matchMode = MATCH_FIDO;
        break;
    case CMD_FP_MATCH_STOP:
        _matchMode = MATCH_OFF;
        break;
    case CMD_FP_ENROLL_START:
        _matchMode = MATCH_OFF;
        {
            uint16_t slot = (e.a != 0 && e.a != 0xFFFF) ? e.a : 0xFFFF;
            if (_finger.enrollStart(slot) == FINGERPRINT_OK) {
                _enrolling = true;
                _lastEnrollStep = 0;
                _lastEnrollState = ENROLL_IDLE;
                _publishedRemove = false;
                publish_fp(FP_ENROLL_STEP, 1, 0);
                Serial.printf("[FP] enroll started → slot %u — place finger\n",
                              (unsigned)_finger.enrollId());
#if FINGERPRINT_LED_ENROLL
                _finger.setLed(FINGERPRINT_LED_ENROLL);
#endif
            } else {
                publish_fp(FP_ENROLL_FAIL, 0, 0);
                Serial.println(F("[FP] enrollStart failed"));
            }
        }
        break;
    case CMD_FP_ENROLL_ABORT:
        _finger.enrollAbort();
        _enrolling = false;
        _lastEnrollState = ENROLL_IDLE;
        _finger.setLedOff();
        publish_fp(FP_ENROLL_FAIL, 0xFE, 0); /* aborted */
        Serial.println(F("[FP] enroll aborted"));
        break;
    case CMD_FP_CLEAR_ALL:
        if (_finger.emptyDatabase() == FINGERPRINT_OK) {
            refresh_count();
            publish_fp(FP_COUNT, _count, 0);
            Serial.println(F("[FP] database cleared"));
        }
        break;
    default:
        break;
    }
}

#else /* !ENABLE_FINGERPRINT */

void fp_system_init(void) {}
void fp_system_tick(unsigned long) {}
bool fp_system_ready(void) { return false; }
uint16_t fp_system_template_count(void) { return 0; }
void *fp_system_driver(void) { return nullptr; }
void fp_system_on_cmd(const BusEvent &) {}

#endif
