#include "fingerprint_r558s.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#if defined(ESP32)
#include "driver/gpio.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#endif

#ifndef FINGERPRINT_ENROLL_TIMEOUT_MS
#define FINGERPRINT_ENROLL_TIMEOUT_MS 90000
#endif
#ifndef FINGERPRINT_CMD_TIMEOUT_MS
#define FINGERPRINT_CMD_TIMEOUT_MS 1500
#endif
#ifndef FINGERPRINT_AE_POLL_MS
#define FINGERPRINT_AE_POLL_MS 20
#endif

/*
 * Implementation follows:
 *   R558s-fingerprint-module-user-manual-v1-1-1-2-1.pdf  (R558-S Ver 1.1)
 *
 * Primary enroll path = AutoEnroll (31H) with finger leave between captures.
 * TOUCH_OUT (manual, no external R required on MCU pin):
 *   no finger → HIGH; finger → LOW
 * Host uses ESP internal pull-up + CHANGE ISR. Never invert polarity from
 * idle-low (that was floating-wire false auto-detect).
 * Ready byte 0x55 is module power-on only — never required before each command.
 */

#if defined(ESP32)
static portMUX_TYPE s_touch_mux = portMUX_INITIALIZER_UNLOCKED;
#endif

void IRAM_ATTR fingerprint_touch_isr(void *arg)
{
    R558SFingerprint *self = static_cast<R558SFingerprint *>(arg);
    if (!self || self->_touchPin < 0)
        return;
#if defined(ESP32)
    int level = gpio_get_level((gpio_num_t)self->_touchPin);
    /* Datasheet: low = finger present */
    bool present = (level == 0);
    portENTER_CRITICAL_ISR(&s_touch_mux);
    if (present != self->_touchPresent) {
        self->_touchPresent = present;
        if (present) {
            if (self->_touchDownEdges < 255)
                self->_touchDownEdges++;
        } else {
            if (self->_touchUpEdges < 255)
                self->_touchUpEdges++;
        }
    }
    portEXIT_CRITICAL_ISR(&s_touch_mux);
#endif
}

R558SFingerprint::R558SFingerprint(Stream &ss) : _ss(ss) {}

void R558SFingerprint::sampleTouchLevel(void)
{
    if (_touchPin < 0) {
        _touchPresent = false;
        return;
    }
#if defined(ESP32)
    int level = gpio_get_level((gpio_num_t)_touchPin);
#else
    int level = digitalRead(_touchPin);
#endif
    bool present = (level == LOW); /* datasheet */
    _touchPresent = present;
}

void R558SFingerprint::detachTouchIrq(void)
{
#if defined(ESP32)
    if (_touchIrqOn && _touchPin >= 0) {
        gpio_isr_handler_remove((gpio_num_t)_touchPin);
        gpio_set_intr_type((gpio_num_t)_touchPin, GPIO_INTR_DISABLE);
        _touchIrqOn = false;
    }
#endif
}

void R558SFingerprint::attachTouchIrq(void)
{
#if defined(ESP32)
    if (_touchPin < 0)
        return;
    detachTouchIrq();

    /* Datasheet drive: high idle / low touch. Internal pull-up holds HIGH if
     * the net floats (no board pull); do not enable pull-down. */
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << _touchPin;
    io.mode = GPIO_MODE_INPUT;
    io.pull_up_en = GPIO_PULLUP_ENABLE;
    io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io.intr_type = GPIO_INTR_ANYEDGE;
    gpio_config(&io);

    static bool isr_service = false;
    if (!isr_service) {
        esp_err_t e = gpio_install_isr_service(0);
        if (e == ESP_OK || e == ESP_ERR_INVALID_STATE)
            isr_service = true;
    }
    if (isr_service) {
        gpio_isr_handler_add((gpio_num_t)_touchPin, fingerprint_touch_isr, this);
        _touchIrqOn = true;
        delay(2); /* settle pull-up */
        sampleTouchLevel();
        CLOG_D("FP", "TOUCH IRQ GPIO%d ANYEDGE LOW=finger present=%d",
                           _touchPin, _touchPresent ? 1 : 0);
    } else {
        CLOG_E("FP", "TOUCH IRQ install failed — falling back to sample");
    }
#else
    pinMode(_touchPin, INPUT_PULLUP);
    sampleTouchLevel();
#endif
}

void R558SFingerprint::setTouchPin(int pin)
{
    detachTouchIrq();
    _touchPin = pin;
    _touchDownEdges = 0;
    _touchUpEdges = 0;
    if (pin >= 0) {
#if defined(ESP32)
        gpio_reset_pin((gpio_num_t)pin);
        gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
        gpio_set_pull_mode((gpio_num_t)pin, GPIO_PULLUP_ONLY);
#endif
        pinMode(pin, INPUT_PULLUP);
        sampleTouchLevel();
    } else {
        _touchPresent = false;
    }
}

bool R558SFingerprint::fingerPresent(void) const
{
    if (_touchPin < 0)
        return false;
    return _touchPresent;
}

void R558SFingerprint::serviceTouch(void)
{
    if (_touchPin < 0)
        return;
#if defined(ESP32)
    int level = gpio_get_level((gpio_num_t)_touchPin);
#else
    int level = digitalRead(_touchPin);
#endif
    /* Datasheet: high = no finger, low = finger (never auto-invert). */
    bool present = (level == LOW);
#if defined(ESP32)
    portENTER_CRITICAL(&s_touch_mux);
#endif
    if (present != _touchPresent) {
        _touchPresent = present;
        if (present) {
            if (_touchDownEdges < 255)
                _touchDownEdges++;
        } else {
            if (_touchUpEdges < 255)
                _touchUpEdges++;
        }
    }
#if defined(ESP32)
    portEXIT_CRITICAL(&s_touch_mux);
#endif
}

bool R558SFingerprint::takeTouchDown(void)
{
    if (_touchPin < 0)
        return false;
#if defined(ESP32)
    portENTER_CRITICAL(&s_touch_mux);
#endif
    bool hit = _touchDownEdges > 0;
    if (hit)
        _touchDownEdges--;
#if defined(ESP32)
    portEXIT_CRITICAL(&s_touch_mux);
#endif
    return hit;
}

bool R558SFingerprint::takeTouchUp(void)
{
    if (_touchPin < 0)
        return false;
#if defined(ESP32)
    portENTER_CRITICAL(&s_touch_mux);
#endif
    bool hit = _touchUpEdges > 0;
    if (hit)
        _touchUpEdges--;
#if defined(ESP32)
    portEXIT_CRITICAL(&s_touch_mux);
#endif
    return hit;
}

void R558SFingerprint::armTouchEdges(void)
{
    if (_touchPin < 0)
        return;
    if (!_touchIrqOn)
        sampleTouchLevel();
#if defined(ESP32)
    portENTER_CRITICAL(&s_touch_mux);
#endif
    _touchDownEdges = 0;
    _touchUpEdges = 0;
    /* Finger already on pad when match/enroll arms → one synthetic down edge */
    if (_touchPresent)
        _touchDownEdges = 1;
#if defined(ESP32)
    portEXIT_CRITICAL(&s_touch_mux);
#endif
}

void R558SFingerprint::flush()
{
    while (_ss.available())
        (void)_ss.read();
}

uint16_t R558SFingerprint::calcChecksum(const uint8_t *buf, uint16_t len)
{
    uint32_t sum = 0;
    for (uint16_t i = 0; i < len; i++)
        sum += buf[i];
    return (uint16_t)(sum & 0xFFFF);
}

int R558SFingerprint::sendPacket(const uint8_t *data, uint16_t len)
{
    uint16_t dataLen = (uint16_t)(len + 2);
    uint16_t pktLen = (uint16_t)(9 + len + 2);
    if (pktLen > 64 || len > 48)
        return FINGERPRINT_PACKETRECIEVEERR;

    uint8_t packet[64];
    packet[0] = 0xEF;
    packet[1] = 0x01;
    memcpy(packet + 2, _addr, 4);
    packet[6] = 0x01;
    packet[7] = (uint8_t)((dataLen >> 8) & 0xFF);
    packet[8] = (uint8_t)(dataLen & 0xFF);
    memcpy(packet + 9, data, len);

    uint8_t cksBuf[3 + 48];
    cksBuf[0] = 0x01;
    cksBuf[1] = packet[7];
    cksBuf[2] = packet[8];
    memcpy(cksBuf + 3, data, len);
    uint16_t cks = calcChecksum(cksBuf, (uint16_t)(3 + len));
    packet[9 + len] = (uint8_t)((cks >> 8) & 0xFF);
    packet[10 + len] = (uint8_t)(cks & 0xFF);

    if (_debug) {
        cryptick_log_hex(CRYPTICK_LL_TRACE, "FP-TX", packet,
                         pktLen > 24 ? 24 : pktLen);
    }

    flush();
    _ss.write(packet, pktLen);
    _ss.flush();
    return FINGERPRINT_OK;
}

int R558SFingerprint::getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen)
{
    *respLen = 0;
    uint32_t start = millis();
    uint8_t header[9];
    uint8_t idx = 0;

    while (idx < 2) {
        while (_ss.available()) {
            uint8_t b = (uint8_t)_ss.read();
            if (idx == 0 && b == 0xEF) {
                header[0] = b;
                idx = 1;
            } else if (idx == 1 && b == 0x01) {
                header[1] = b;
                idx = 2;
                break;
            } else {
                idx = 0;
            }
        }
        if ((uint32_t)(millis() - start) > _timeout)
            return FINGERPRINT_TIMEOUT;
        if (idx < 2)
            delay(1);
    }
    while (idx < 9) {
        while (_ss.available() && idx < 9)
            header[idx++] = (uint8_t)_ss.read();
        if ((uint32_t)(millis() - start) > _timeout)
            return FINGERPRINT_TIMEOUT;
        delay(1);
    }

    if (header[6] != 0x07)
        return FINGERPRINT_PACKETRECIEVEERR;

    uint16_t pktLen = ((uint16_t)header[7] << 8) | header[8];
    if (pktLen < 2)
        return FINGERPRINT_BADPACKET;
    uint16_t dataLen = (uint16_t)(pktLen - 2);
    if (dataLen > maxLen || dataLen > 256)
        return FINGERPRINT_PACKETRECIEVEERR;

    uint8_t tail[260];
    idx = 0;
    start = millis();
    while (idx < dataLen + 2) {
        while (_ss.available() && idx < dataLen + 2)
            tail[idx++] = (uint8_t)_ss.read();
        if ((uint32_t)(millis() - start) > _timeout)
            return FINGERPRINT_TIMEOUT;
        delay(1);
    }

    uint8_t cksBuf[3 + 256];
    cksBuf[0] = 0x07;
    cksBuf[1] = header[7];
    cksBuf[2] = header[8];
    memcpy(cksBuf + 3, tail, dataLen);
    uint16_t calc = calcChecksum(cksBuf, (uint16_t)(3 + dataLen));
    uint16_t rcv = ((uint16_t)tail[dataLen] << 8) | tail[dataLen + 1];
    if (calc != rcv)
        return FINGERPRINT_BADPACKET;

    memcpy(response, tail, dataLen);
    *respLen = dataLen;
    return FINGERPRINT_OK;
}

int R558SFingerprint::parseAck(uint8_t ack)
{
    switch (ack) {
    case 0x00: return FINGERPRINT_OK;
    case 0x01: return FINGERPRINT_PACKETRECIEVEERR;
    case 0x02: return FINGERPRINT_NOFINGER;
    case 0x03: return FINGERPRINT_IMAGEFAIL;
    case 0x04: return FINGERPRINT_IMAGEDRY;
    case 0x05: return FINGERPRINT_IMAGEWET;
    case 0x06: return FINGERPRINT_IMAGEMESS;
    case 0x07: return FINGERPRINT_FEATUREFAIL;
    case 0x08: return FINGERPRINT_NOMATCH;
    case 0x09: return FINGERPRINT_NOTFOUND;
    case 0x0A: return FINGERPRINT_MERGEFAIL;
    case 0x0B: return FINGERPRINT_BADLOCATION;
    case 0x0C: return FINGERPRINT_INVALIDTEMPLATE;
    case 0x13: return FINGERPRINT_WRONGPASSWORD;
    case 0x15: return FINGERPRINT_INVALIDIMAGE;
    case 0x17: return FINGERPRINT_RESIDUAL;
    case 0x18: return FINGERPRINT_FLASHERR;
    case 0x1F: return FINGERPRINT_LIBFULL;
    case 0x22: return FINGERPRINT_TEMPLATE_EXISTS;
    case 0x24: return FINGERPRINT_LIBEMPTY;
    case 0x25: return FINGERPRINT_ENTRY_COUNT_ERR;
    case 0x26: return FINGERPRINT_CMD_TIMEOUT;
    case 0x27: return FINGERPRINT_ALREADY_ENROLLED;
    case 0x35: return FINGERPRINT_ILLEGALDATA;
    case 0x3B: return FINGERPRINT_POOR_QUALITY;
    default:
        CLOG_D("FP", "conf 0x%02X", ack);
        return (int)ack; /* pass through for AutoEnroll analysis */
    }
}

int R558SFingerprint::simpleCmd(uint8_t code)
{
    uint8_t cmd[] = {code};
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 1);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::begin(uint16_t baud)
{
    (void)baud;
    /*
     * Module power-on only: ~50 ms init then optional single 0x55 ready byte.
     * If the MCU rebooted alone the sensor is already live — do not block for
     * 0x55, and never wait for it before normal commands after begin().
     */
    uint32_t t0 = millis();
    bool saw_ready = false;
    while ((uint32_t)(millis() - t0) < 80) {
        if (_ss.available()) {
            int b = _ss.read();
            if (b == 0x55) {
                saw_ready = true;
                CLOG_I("FP", "ready byte 0x55 (module power-on)");
                break;
            }
            /* discard other boot noise */
        }
        delay(1);
    }
    if (!saw_ready)
        CLOG_I("FP", "no 0x55 (sensor already up) — continue");
    flush();

    _timeout = (uint32_t)FINGERPRINT_CMD_TIMEOUT_MS;

    uint8_t pwdZero[4] = {0, 0, 0, 0};
    int r = vfyPwd(pwdZero);
    if (r != FINGERPRINT_OK) {
        uint8_t pwdFF[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        r = vfyPwd(pwdFF);
    }
    if (r != FINGERPRINT_OK) {
        CLOG_E("FP", "VfyPwd FAIL %d", r);
        return r;
    }
    CLOG_I("FP", "VfyPwd OK");

    r = handShake();
    if (r == FINGERPRINT_OK)
        CLOG_I("FP", "HandShake OK");
    else
        CLOG_E("FP", "HandShake skipped/fail (%d)", r);

    /* ReadSysPara — library size word at offset 2 of 16-byte list */
    {
        uint8_t cmd[] = {0x0F};
        uint8_t resp[32];
        uint16_t len = 0;
        if (sendPacket(cmd, 1) == FINGERPRINT_OK &&
            getPacket(resp, sizeof(resp), &len) == FINGERPRINT_OK &&
            parseAck(resp[0]) == FINGERPRINT_OK && len >= 17) {
            uint16_t lib = ((uint16_t)resp[5] << 8) | resp[6];
            if (lib < 20 || lib > 1000)
                lib = ((uint16_t)resp[6] << 8) | resp[5];
            if (lib >= 20 && lib <= 1000) {
                _capacity = lib;
                CLOG_D("FP", "library size=%u", (unsigned)_capacity);
            }
        }
    }

    uint16_t n = 0;
    if (templateNum(&n) != FINGERPRINT_OK)
        return FINGERPRINT_PACKETRECIEVEERR;

    if (_touchPin >= 0) {
        /* Manual only: high=no finger, low=finger. No auto-invert. */
        _touchActiveLow = true;
        attachTouchIrq();
#if defined(ESP32)
        int raw = gpio_get_level((gpio_num_t)_touchPin);
#else
        int raw = digitalRead(_touchPin);
#endif
        sampleTouchLevel();
        CLOG_D("FP", "TOUCH raw=%s (expect idle HIGH) present=%d irq=%d LOW=finger",
               raw == LOW ? "LOW" : "HIGH",
               _touchPresent ? 1 : 0,
               _touchIrqOn ? 1 : 0);
        if (raw == LOW && !_touchPresent)
            CLOG_D("FP", "TOUCH idle LOW — check wiring to GPIO16");
        else if (raw == LOW)
            CLOG_D("FP", "TOUCH idle LOW with finger sense — lift finger / check net");
    }

    CLOG_I("FP", "templates=%u capacity=%u touch_pin=%d",
                       (unsigned)n, (unsigned)_capacity, _touchPin);
    return FINGERPRINT_OK;
}

int R558SFingerprint::vfyPwd(const uint8_t pwd[4])
{
    uint8_t cmd[] = {0x13, pwd[0], pwd[1], pwd[2], pwd[3]};
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 5);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::handShake()
{
    return simpleCmd(0x35); /* HandShake — not conf 0x35; instruction 35H */
}

int R558SFingerprint::genImg()
{
    return simpleCmd(0x01);
}

int R558SFingerprint::getEnrollImage()
{
    return simpleCmd(0x29);
}

int R558SFingerprint::genChar(uint8_t bufferId)
{
    uint8_t cmd[] = {0x02, bufferId};
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 2);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::matchModel()
{
    return simpleCmd(0x03);
}

int R558SFingerprint::regModel()
{
    return simpleCmd(0x05);
}

int R558SFingerprint::store(uint16_t pageId, uint8_t bufferId)
{
    uint8_t cmd[] = {
        0x06, bufferId,
        (uint8_t)(pageId >> 8), (uint8_t)(pageId & 0xFF)
    };
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 4);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::loadChar(uint16_t pageId, uint8_t bufferId)
{
    uint8_t cmd[] = {
        0x07, bufferId,
        (uint8_t)(pageId >> 8), (uint8_t)(pageId & 0xFF)
    };
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 4);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::search(uint16_t *pageId, uint16_t *score, uint8_t bufferId,
                             uint16_t start, uint16_t count)
{
    *pageId = 0xFFFF;
    *score = 0;
    if (count == 0)
        count = _capacity;
    uint8_t cmd[] = {
        0x04, bufferId,
        (uint8_t)(start >> 8), (uint8_t)(start & 0xFF),
        (uint8_t)(count >> 8), (uint8_t)(count & 0xFF)
    };
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 6);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    int ack = parseAck(resp[0]);
    if (ack == FINGERPRINT_OK && len >= 5) {
        *pageId = ((uint16_t)resp[1] << 8) | resp[2];
        *score = ((uint16_t)resp[3] << 8) | resp[4];
    }
    return ack;
}

int R558SFingerprint::templateNum(uint16_t *count)
{
    *count = 0;
    uint8_t cmd[] = {0x1D};
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 1);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    int ack = parseAck(resp[0]);
    if (ack != FINGERPRINT_OK)
        return ack;
    if (len >= 3)
        *count = ((uint16_t)resp[1] << 8) | resp[2];
    return FINGERPRINT_OK;
}

int R558SFingerprint::readIndexTable(uint8_t page, uint8_t *bitmap32)
{
    /* 1FH ReadIndexTable — page index 0..3 typically, 32-byte bitmap */
    uint8_t cmd[] = {0x1F, page};
    uint8_t resp[40];
    uint16_t len;
    int r = sendPacket(cmd, 2);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    int ack = parseAck(resp[0]);
    if (ack != FINGERPRINT_OK)
        return ack;
    memset(bitmap32, 0, 32);
    uint16_t n = (len > 1) ? (uint16_t)(len - 1) : 0;
    if (n > 32)
        n = 32;
    if (n)
        memcpy(bitmap32, resp + 1, n);
    return FINGERPRINT_OK;
}

int R558SFingerprint::getFreeId(uint16_t &freeId)
{
    freeId = 0xFFFF;
    uint8_t bits[32];
    /* Scan index pages 0..3 (256 bits) or until capacity */
    for (uint8_t page = 0; page < 4; page++) {
        if (readIndexTable(page, bits) != FINGERPRINT_OK)
            break;
        for (uint16_t i = 0; i < 256 && (page * 256u + i) < _capacity; i++) {
            uint16_t id = (uint16_t)(page * 256u + i);
            if ((bits[i / 8] & (1u << (i % 8))) == 0) {
                freeId = id;
                return FINGERPRINT_OK;
            }
        }
    }
    /* Fallback: sequential free after TemplateNum */
    uint16_t n = 0;
    if (templateNum(&n) == FINGERPRINT_OK && n < _capacity) {
        freeId = n;
        return FINGERPRINT_OK;
    }
    return FINGERPRINT_LIBFULL;
}

int R558SFingerprint::deleteChar(uint16_t pageId, uint16_t n)
{
    uint8_t cmd[] = {
        0x0C,
        (uint8_t)(pageId >> 8), (uint8_t)(pageId & 0xFF),
        (uint8_t)(n >> 8), (uint8_t)(n & 0xFF)
    };
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 5);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return r;
    return parseAck(resp[0]);
}

int R558SFingerprint::emptyLibrary()
{
    return simpleCmd(0x0D);
}

int R558SFingerprint::cancel()
{
    return simpleCmd(0x30);
}

int R558SFingerprint::controlBln(uint8_t function, uint8_t startColor,
                                 uint8_t endColor, uint8_t cycles)
{
    uint8_t cmd[] = {0x3C, function, startColor, endColor, cycles};
    uint8_t resp[16];
    uint16_t len;
    int r = sendPacket(cmd, 5);
    if (r != FINGERPRINT_OK)
        return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK)
        return FINGERPRINT_OK; /* soft-fail LED */
    return parseAck(resp[0]) == FINGERPRINT_OK ? FINGERPRINT_OK : FINGERPRINT_OK;
}

int R558SFingerprint::setLed(uint8_t color)
{
    _ledOffAtMs = 0;
    if (color == 0)
        return controlBln(4, 0, 0, 0); /* normally off */
    return controlBln(3, color & 0x07, color & 0x07, 0); /* solid on */
}

int R558SFingerprint::setLedOnFor(uint8_t color, uint32_t durationMs)
{
    int r = setLed(color);
    if (r == FINGERPRINT_OK && durationMs)
        _ledOffAtMs = millis() + durationMs;
    return r;
}

void R558SFingerprint::ledUpdate()
{
    if (_ledOffAtMs && (uint32_t)millis() >= _ledOffAtMs) {
        _ledOffAtMs = 0;
        setLed(0);
    }
}

int R558SFingerprint::getFingerprintID(uint16_t *id, uint16_t *score)
{
    /* Match path: keep UART timeouts tighter so a miss doesn’t freeze UI */
    uint32_t prev = _timeout;
    _timeout = 350;
    int r = genImg();
    if (r != FINGERPRINT_OK) {
        _timeout = prev;
        return r;
    }
    r = genChar(1);
    if (r != FINGERPRINT_OK) {
        _timeout = prev;
        return r;
    }
    r = search(id, score, 1, 0, _capacity);
    _timeout = prev;
    return r;
}

int R558SFingerprint::autoEnrollStart(uint16_t pageId, uint8_t entries, uint16_t params)
{
    /*
     * AutoEnroll 31H (manual):
     *   ID(2 BE) | entries(1) | Params(2 BE)
     * Package length 0008H
     *
     * Params bits (manual):
     *   bit2=0 → return status at key steps
     *   bit3=0 → no overwrite
     *   bit4=0 → allow re-register same print (first enrolling: ok)
     *   bit5=0 → finger must leave between collections
     */
    uint8_t cmd[] = {
        0x31,
        (uint8_t)(pageId >> 8), (uint8_t)(pageId & 0xFF),
        entries,
        (uint8_t)(params >> 8), (uint8_t)(params & 0xFF)
    };
    return sendPacket(cmd, 6);
}

int R558SFingerprint::pollAutoEnrollAck(void)
{
    /*
     * Ack: conf | Parameter1 | Parameter2
     * Non-blocking: only read if a full ack could be present; never sit for 80ms×N.
     */
    if (!_ss.available())
        return FINGERPRINT_TIMEOUT;

    uint32_t prev = _timeout;
    _timeout = 40; /* complete a packet that already started arriving */
    uint8_t resp[16];
    uint16_t len = 0;
    int r = getPacket(resp, sizeof(resp), &len);
    _timeout = prev;
    if (r == FINGERPRINT_TIMEOUT)
        return FINGERPRINT_TIMEOUT;
    if (r != FINGERPRINT_OK)
        return r;
    if (len < 3)
        return FINGERPRINT_BADPACKET;

    uint8_t conf = resp[0];
    _ae_p1 = resp[1];
    _ae_p2 = resp[2];

    if (_debug)
        CLOG_D("FP", "AE conf=%02X p1=%02X p2=%02X",
                           conf, _ae_p1, _ae_p2);

    /* Validity check accepted → start */
    if (conf == 0x00 && _ae_p1 == AE_P1_VALIDITY) {
        _enrollState = ENROLL_WAIT_FINGER;
        _enrollStep = 1;
        return FINGERPRINT_OK;
    }

    /* Collect image success → place finger UI for entry n */
    if (conf == 0x00 && _ae_p1 == AE_P1_GETIMAGE) {
        _enrollStep = (_ae_p2 >= 1) ? _ae_p2 : 1;
        _enrollState = ENROLL_BUSY;
        return FINGERPRINT_OK;
    }

    /* Generate feature success */
    if (conf == 0x00 && _ae_p1 == AE_P1_GENCHAR) {
        _enrollStep = (_ae_p2 >= 1) ? _ae_p2 : _enrollStep;
        _enrollState = ENROLL_BUSY;
        return FINGERPRINT_OK;
    }

    /* Finger leave required after entry n */
    if (conf == 0x00 && _ae_p1 == AE_P1_LEAVE) {
        _enrollStep = (_ae_p2 >= 1) ? _ae_p2 : _enrollStep;
        _enrollState = ENROLL_WAIT_REMOVE;
        return FINGERPRINT_OK;
    }

    /* Merge / dup-check / store phases */
    if (conf == 0x00 && (_ae_p1 == AE_P1_MERGE || _ae_p1 == AE_P1_DUPCHECK)) {
        _enrollState = ENROLL_BUSY;
        return FINGERPRINT_OK;
    }

    /* Store success: conf=00 p1=06 p2=F2 */
    if (conf == 0x00 && _ae_p1 == AE_P1_STORE) {
        _enrollState = ENROLL_DONE;
        _error = FINGERPRINT_OK;
        return FINGERPRINT_OK;
    }

    /*
     * Non-fatal in-progress errors: module waits and retries collection
     * (feature fail, residual, illegal data, poor quality, merge during gen).
     */
    if ((conf == 0x07 || conf == 0x0A || conf == 0x17 || conf == 0x35 ||
         conf == 0x3B || conf == 0x06 || conf == 0x15 || conf == 0x28 ||
         conf == 0x08) &&
        (_ae_p1 == AE_P1_GETIMAGE || _ae_p1 == AE_P1_GENCHAR ||
         _ae_p1 == AE_P1_LEAVE)) {
        CLOG_D("FP", "AE retryable conf=0x%02X stage p1=%u — keep finger / re-place",
                           conf, _ae_p1);
        if (_ae_p1 == AE_P1_LEAVE)
            _enrollState = ENROLL_WAIT_REMOVE;
        else
            _enrollState = ENROLL_WAIT_FINGER;
        return conf;
    }

    /* Terminal failures */
    _error = (int)conf;
    _enrollState = ENROLL_FAILED;
    CLOG_E("FP", "AE FAIL conf=0x%02X p1=%02X p2=%02X %s",
                       conf, _ae_p1, _ae_p2, getErrorMessage(_error));
    return _error;
}

int R558SFingerprint::enrollStart(uint16_t pageId)
{
    enrollAbort(); /* clears any prior auto-enroll */

    _enrollId = pageId;
    if (_enrollId == 0xFFFF) {
        if (getFreeId(_enrollId) != FINGERPRINT_OK)
            return FINGERPRINT_LIBFULL;
    }
    if (_enrollId >= _capacity)
        return FINGERPRINT_BADLOCATION;

    _ae_entries = 2;
    _enrollStep = 1;
    _ae_p1 = 0;
    _ae_p2 = 0;
    _error = FINGERPRINT_OK;
    _enrollDeadline = millis() + (uint32_t)FINGERPRINT_ENROLL_TIMEOUT_MS;
    _enrollState = ENROLL_BUSY;

    /*
     * Params: status replies (bit2=0), no overwrite (bit3=0),
     * allow duplicate enroll (bit4=0), **leave required** (bit5=0).
     */
    const uint16_t params = 0x0000;
    CLOG_I("FP", "AutoEnroll start PageID=%u entries=%u params=0x%04X touch=%d",
                       (unsigned)_enrollId, (unsigned)_ae_entries, params,
                       fingerPresent() ? 1 : 0);

    int r = autoEnrollStart(_enrollId, _ae_entries, params);
    if (r != FINGERPRINT_OK)
        return r;
    _ae_started = true;

    /* First ack (validity) often comes quickly */
    _timeout = 2000;
    r = pollAutoEnrollAck();
    _timeout = (uint32_t)FINGERPRINT_CMD_TIMEOUT_MS;
    if (r == FINGERPRINT_TIMEOUT) {
        /* still waiting — wait finger is fine */
        _enrollState = ENROLL_WAIT_FINGER;
        return FINGERPRINT_OK;
    }
    return (r == FINGERPRINT_OK || r == FINGERPRINT_NOFINGER) ? FINGERPRINT_OK : r;
}

void R558SFingerprint::enrollAbort()
{
    if (_ae_started) {
        cancel();
        _ae_started = false;
    }
    _enrollState = ENROLL_IDLE;
    _enrollStep = 0;
    _error = FINGERPRINT_OK;
}

int R558SFingerprint::enrollPoll(EnrollNbState &state, uint8_t &step)
{
    step = _enrollStep;
    state = _enrollState;

    if (_enrollState == ENROLL_IDLE || _enrollState == ENROLL_DONE ||
        _enrollState == ENROLL_FAILED)
        return (_enrollState == ENROLL_DONE) ? FINGERPRINT_OK : _error;

    if (!_ae_started) {
        _enrollState = ENROLL_FAILED;
        _error = FINGERPRINT_PACKETRECIEVEERR;
        state = _enrollState;
        return _error;
    }

    if ((uint32_t)millis() > _enrollDeadline) {
        cancel();
        _ae_started = false;
        _enrollState = ENROLL_FAILED;
        _error = FINGERPRINT_TIMEOUT;
        state = _enrollState;
        return _error;
    }

    /* Drain at most a few pending AutoEnroll status packets (non-blocking when empty) */
    for (int i = 0; i < 3; i++) {
        int r = pollAutoEnrollAck();
        if (r == FINGERPRINT_TIMEOUT)
            break;
        step = _enrollStep;
        state = _enrollState;
        if (_enrollState == ENROLL_DONE) {
            _ae_started = false;
            return FINGERPRINT_OK;
        }
        if (_enrollState == ENROLL_FAILED) {
            _ae_started = false;
            return _error;
        }
    }

    step = _enrollStep;
    state = _enrollState;
    return FINGERPRINT_OK;
}

int R558SFingerprint::enrollFingerprint(uint16_t id, Stream *feedback)
{
    int r = enrollStart(id);
    if (r != FINGERPRINT_OK)
        return r;
    if (feedback) {
        feedback->println(F("--- R558-S AutoEnroll (manual 31H) ---"));
        feedback->printf("  PageID %u  (place finger 2×, lift between)\n",
                         (unsigned)_enrollId);
    }
    EnrollNbState st;
    uint8_t step;
    EnrollNbState last = ENROLL_IDLE;
    while (true) {
        r = enrollPoll(st, step);
        if (st != last && feedback) {
            last = st;
            if (st == ENROLL_WAIT_FINGER)
                feedback->printf("  Place finger (entry %u)\n", (unsigned)step);
            else if (st == ENROLL_WAIT_REMOVE)
                feedback->println(F("  Lift finger completely"));
            else if (st == ENROLL_BUSY)
                feedback->println(F("  Module processing…"));
        }
        if (st == ENROLL_DONE) {
            if (feedback)
                feedback->printf("  Stored PageID %u\n", (unsigned)_enrollId);
            return FINGERPRINT_OK;
        }
        if (st == ENROLL_FAILED)
            return r;
        delay(20);
        yield();
    }
}

const char *R558SFingerprint::getErrorMessage(int err)
{
    switch (err) {
    case FINGERPRINT_OK: return "OK";
    case FINGERPRINT_PACKETRECIEVEERR: return "Packet error";
    case FINGERPRINT_NOFINGER: return "No finger";
    case FINGERPRINT_IMAGEFAIL: return "Image capture failed";
    case FINGERPRINT_IMAGEDRY: return "Image too dry/faint";
    case FINGERPRINT_IMAGEWET: return "Image too wet";
    case FINGERPRINT_IMAGEMESS: return "Image too messy";
    case FINGERPRINT_FEATUREFAIL: return "Too few feature points";
    case FINGERPRINT_NOMATCH: return "No match";
    case FINGERPRINT_NOTFOUND: return "Not found";
    case FINGERPRINT_MERGEFAIL: return "Merge failed (not same finger)";
    case FINGERPRINT_BADLOCATION: return "PageID out of range";
    case FINGERPRINT_INVALIDTEMPLATE: return "Invalid template";
    case FINGERPRINT_FLASHERR: return "Flash R/W error";
    case FINGERPRINT_WRONGPASSWORD: return "Wrong password";
    case FINGERPRINT_INVALIDIMAGE: return "No valid primary image";
    case FINGERPRINT_RESIDUAL: return "Residual finger — lift fully";
    case FINGERPRINT_LIBFULL: return "Library full";
    case FINGERPRINT_TEMPLATE_EXISTS: return "Template ID not empty";
    case FINGERPRINT_LIBEMPTY: return "Library empty";
    case FINGERPRINT_ENTRY_COUNT_ERR: return "Bad entry count";
    case FINGERPRINT_CMD_TIMEOUT: return "Module timeout";
    case FINGERPRINT_ALREADY_ENROLLED: return "Already enrolled";
    case FINGERPRINT_ILLEGALDATA: return "Illegal data";
    case FINGERPRINT_POOR_QUALITY: return "Poor template quality";
    case FINGERPRINT_TIMEOUT: return "Host timeout";
    case FINGERPRINT_BADPACKET: return "Bad packet";
    default: return "Unknown error";
    }
}
