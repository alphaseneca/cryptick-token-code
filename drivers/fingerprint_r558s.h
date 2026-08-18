#ifndef R558S_FINGERPRINT_H
#define R558S_FINGERPRINT_H

#include <Arduino.h>
#include <Stream.h>

/*
 * Grow R558-S Fingerprint Module — User Manual Ver 1.1 (2024.04)
 * File: R558s-fingerprint-module-user-manual-v1-1-1-2-1.pdf
 *
 * Packet: 0xEF01 | Addr(4) | PID | Len(2) | Content | Sum(2)
 *   Command PID=0x01, Ack PID=0x07
 *   Len = content + checksum (2)
 *   Checksum = sum(PID + Len_H + Len_L + content)
 *
 * TOUCH_OUT (manual II hardware connection):
 *   no finger → high; finger touch → low  (CMOS, ~Vt)
 *
 * Enroll: prefer AutoEnroll (31H); or GenImg/GetEnrollImage + GenChar + RegModel + Store.
 */

/* Confirmation codes — manual IV Check and acknowledgement */
#define FINGERPRINT_OK                0x00
#define FINGERPRINT_PACKETRECIEVEERR  0x01
#define FINGERPRINT_NOFINGER          0x02
#define FINGERPRINT_IMAGEFAIL         0x03
#define FINGERPRINT_IMAGEDRY          0x04
#define FINGERPRINT_IMAGEWET          0x05
#define FINGERPRINT_IMAGEMESS         0x06
#define FINGERPRINT_FEATUREFAIL       0x07
#define FINGERPRINT_NOMATCH           0x08
#define FINGERPRINT_NOTFOUND          0x09
#define FINGERPRINT_MERGEFAIL         0x0A
#define FINGERPRINT_BADLOCATION       0x0B
#define FINGERPRINT_INVALIDTEMPLATE   0x0C
#define FINGERPRINT_FLASHERR          0x18
#define FINGERPRINT_WRONGPASSWORD     0x13
#define FINGERPRINT_INVALIDIMAGE      0x15
#define FINGERPRINT_RESIDUAL          0x17 /* residual FP / finger not moved */
#define FINGERPRINT_LIBFULL           0x1F
#define FINGERPRINT_TEMPLATE_EXISTS   0x22
#define FINGERPRINT_LIBEMPTY          0x24
#define FINGERPRINT_ENTRY_COUNT_ERR   0x25
#define FINGERPRINT_CMD_TIMEOUT       0x26
#define FINGERPRINT_ALREADY_ENROLLED  0x27
#define FINGERPRINT_ILLEGALDATA       0x35 /* documented R558-S conf 35H */
#define FINGERPRINT_POOR_QUALITY      0x3B
#define FINGERPRINT_TIMEOUT           0xFF
#define FINGERPRINT_BADPACKET         0xFE

#define FINGERPRINT_CHARBUFFER1 0x01
#define FINGERPRINT_CHARBUFFER2 0x02

/* AutoEnroll progress Parameter1 (manual table) */
#define AE_P1_VALIDITY   0x00
#define AE_P1_GETIMAGE   0x01
#define AE_P1_GENCHAR    0x02
#define AE_P1_LEAVE      0x03
#define AE_P1_MERGE      0x04
#define AE_P1_DUPCHECK   0x05
#define AE_P1_STORE      0x06

enum EnrollNbState : uint8_t {
    ENROLL_IDLE = 0,
    ENROLL_WAIT_FINGER,  /* UI: place finger (TOUCH low) */
    ENROLL_WAIT_REMOVE,  /* UI: lift finger (TOUCH high) */
    ENROLL_BUSY,         /* module is processing (AutoEnroll intermediate) */
    ENROLL_DONE,
    ENROLL_FAILED
};

class R558SFingerprint {
public:
    R558SFingerprint(Stream &ss);

    /**
     * TOUCH_OUT / IRQ GPIO (manual: high=no finger, low=finger; polarity
     * may auto-flip in begin()). Presence is maintained by a CHANGE ISR —
     * not by polling GenImg or digitalRead every tick.
     */
    void setTouchPin(int pin);
    /** Latched presence from last TOUCH IRQ (sample pin once if ISR not up).
     * Manual: finger present when TOUCH_OUT is LOW. */
    bool fingerPresent(void) const;
    /** Re-sample TOUCH pin on main loop; queue edges if level changed (ISR backup). */
    void serviceTouch(void);
    /** True once per finger-down edge since last call (match path use this). */
    bool takeTouchDown(void);
    /** True once per finger-up edge since last call. */
    bool takeTouchUp(void);
    /** Clear pending edges; if finger already down, schedule one takeTouchDown. */
    void armTouchEdges(void);

    int begin(uint16_t baud = 57600);

    int genImg();                          /* 01H GenImg */
    int getEnrollImage();                  /* 29H GetEnrollImage (prefer for enroll) */
    int genChar(uint8_t bufferId = 1);     /* 02H GenChar */
    int matchModel();                      /* 03H Match */
    int search(uint16_t *pageId, uint16_t *score,
               uint8_t bufferId = 1, uint16_t start = 0, uint16_t count = 0);
    int regModel();                        /* 05H RegModel */
    int store(uint16_t pageId, uint8_t bufferId = 1); /* 06H Store */
    int loadChar(uint16_t pageId, uint8_t bufferId = 1);
    int templateNum(uint16_t *count);      /* 1DH */
    int readIndexTable(uint8_t page, uint8_t *bitmap32); /* 1FH — 32 bytes page */
    int getFreeId(uint16_t &freeId);
    int deleteChar(uint16_t pageId, uint16_t n = 1);
    int emptyLibrary();
    int vfyPwd(const uint8_t pwd[4]);
    int handShake();                       /* 35H */
    int controlBln(uint8_t function, uint8_t startColor, uint8_t endColor, uint8_t cycles);
    int cancel();                          /* 30H Cancel AutoEnroll/AutoIdentify */

    /* LED convenience: Function 3=on, 4=off; color bit0=B bit1=G bit2=R */
    int setLed(uint8_t color); /* 0=off else solid color 1..7 */
    int setLedOff() { return setLed(0); }
    int setLedOnFor(uint8_t color, uint32_t durationMs);
    void ledUpdate();

    int getFingerprintID(uint16_t *id, uint16_t *score);

    /**
     * Non-blocking enroll via AutoEnroll 31H (manual Automatic registration).
     * Host places finger 2 times with leave between; module drives the protocol.
     */
    int enrollStart(uint16_t pageId = 0xFFFF);
    int enrollPoll(EnrollNbState &state, uint8_t &step /* 1..N while placing */);
    void enrollAbort();
    uint16_t enrollId() const { return _enrollId; }
    uint8_t enrollProgressP1() const { return _ae_p1; }
    uint8_t enrollProgressP2() const { return _ae_p2; }

    int enrollFingerprint(uint16_t id, Stream *feedback = nullptr);

    static const char *getErrorMessage(int err);

    void setDebug(bool on) { _debug = on; }
    void setTimeout(uint32_t ms) { _timeout = ms; }
    void setCapacity(uint16_t n) { _capacity = n; }
    int getError() { return _error; }

    /* Aliases used by older call-sites */
    int getImage() { return genImg(); }
    int image2Tz(uint8_t slot = 1) { return genChar(slot); }
    int createModel() { return regModel(); }
    int storeModel(uint16_t pageId, uint8_t buf = 1) { return store(pageId, buf); }
    int loadModel(uint16_t pageId, uint8_t buf = 1) { return loadChar(pageId, buf); }
    int getTemplateCount(uint16_t *c) { return templateNum(c); }
    int emptyDatabase() { return emptyLibrary(); }
    int fingerFastSearch(uint16_t *id, uint16_t *score) { return search(id, score); }

private:
    Stream &_ss;
    int _touchPin = -1;
    bool _touchActiveLow = true; /* R558-S default: low = finger */
    bool _touchIrqOn = false;
    mutable volatile bool _touchPresent = false;
    mutable volatile uint8_t _touchDownEdges = 0;
    mutable volatile uint8_t _touchUpEdges = 0;
    uint32_t _timeout = 1000;
    bool _debug = false;
    int _error = FINGERPRINT_OK;
    uint8_t _addr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t _capacity = 120;
    uint32_t _ledOffAtMs = 0;

    EnrollNbState _enrollState = ENROLL_IDLE;
    uint16_t _enrollId = 0;
    uint8_t _enrollStep = 1; /* current entry n for UI (1..entries) */
    uint8_t _ae_entries = 2;
    uint8_t _ae_p1 = 0;
    uint8_t _ae_p2 = 0;
    uint32_t _enrollDeadline = 0;
    bool _ae_started = false;

    int sendPacket(const uint8_t *data, uint16_t len);
    int getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen);
    uint16_t calcChecksum(const uint8_t *buf, uint16_t len);
    int parseAck(uint8_t ack);
    void flush();
    int simpleCmd(uint8_t code);
    int autoEnrollStart(uint16_t pageId, uint8_t entries, uint16_t params);
    int pollAutoEnrollAck(void); /* 0 = got packet processed, TIMEOUT if none yet */
    void detachTouchIrq(void);
    void attachTouchIrq(void);
    void sampleTouchLevel(void); /* update latch from pin (non-ISR) */
    friend void fingerprint_touch_isr(void *arg);
};

#endif
