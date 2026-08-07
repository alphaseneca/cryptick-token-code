#ifndef R558S_FINGERPRINT_H
#define R558S_FINGERPRINT_H

#include <Arduino.h>
#include <Stream.h>

// R557/R558 packet: Header 0xEF 0x01 | Addr(4) | PID 0x01 | Len(2) | Content | Sum(2).

#define FINGERPRINT_OK                0x00
#define FINGERPRINT_PACKETRECIEVEERR  0x01
#define FINGERPRINT_NOFINGER          0x02
#define FINGERPRINT_IMAGEFAIL         0x03
#define FINGERPRINT_IMAGEMESS         0x06
#define FINGERPRINT_FEATUREFAIL       0x07
#define FINGERPRINT_NOMATCH           0x08
#define FINGERPRINT_NOTFOUND          0x09
#define FINGERPRINT_MERGEFAIL         0x0A
#define FINGERPRINT_BADLOCATION       0x0B
#define FINGERPRINT_DBRANGEFAIL       0x1F
#define FINGERPRINT_WRONGPASSWORD     0x13
#define FINGERPRINT_ILLEGALDATA       0x35
#define FINGERPRINT_TIMEOUT           0xFF
#define FINGERPRINT_BADPACKET         0xFE

#define FINGERPRINT_CHARBUFFER1 0x01
#define FINGERPRINT_CHARBUFFER2 0x02

#define R558_LED_MODE_BREATHE  0x01
#define R558_LED_MODE_BLINK    0x02
#define R558_LED_MODE_ON       0x03
#define R558_LED_MODE_OFF      0x04
#define R558_LED_COLOR_BLUE    0x01
#define R558_LED_COLOR_GREEN   0x02
#define R558_LED_COLOR_RED     0x04

enum EnrollNbState : uint8_t {
    ENROLL_IDLE = 0,
    ENROLL_WAIT_FINGER,
    ENROLL_WAIT_REMOVE,   /* lift after good capture (or before retry) */
    ENROLL_MERGE_STORE,
    ENROLL_DONE,
    ENROLL_FAILED
};

class R558SFingerprint {
public:
  R558SFingerprint(Stream &ss);
  int begin(uint16_t baud = 57600);

  int getImage();
  int image2Tz(uint8_t slot = 1);
  int createModel();
  int storeModel(uint16_t id);
  int loadModel(uint16_t id);
  int fingerFastSearch(uint16_t *id, uint16_t *score);
  int getTemplateCount(uint16_t *count);
  int deleteModel(uint16_t id);
  int emptyDatabase();
  int readSysPara();
  int getFreeId(uint16_t &freeId);
  int vfyPwd(const uint8_t pwd[4]);
  int setPwd(const uint8_t pwd[4]);

  int fingerID(uint16_t *id, uint16_t *score);
  int getFingerprintID(uint16_t *id, uint16_t *score);

  /** Blocking 2-step enroll (R557). */
  int enrollFingerprint(uint16_t id, Stream* feedback = nullptr);

  /** Non-blocking enroll for UI. Call enrollStart then enrollPoll each loop. */
  int enrollStart(uint16_t id = 0xFFFF);
  int enrollPoll(EnrollNbState &state, uint8_t &step /* 1 or 2 when waiting finger */);
  void enrollAbort();
  uint16_t enrollId() const { return _enrollId; }

  static const char* getErrorMessage(int err);

  int setLed(uint8_t color);
  int setLedOff() { return setLed(0); }
  int setLedOnFor(uint8_t color, uint32_t durationMs);
  void ledUpdate();
  int setLedEx(uint8_t mode, uint8_t color, uint8_t cycles = 0);

  void setDebug(bool on) { _debug = on; }
  void setTimeout(uint32_t ms) { _timeout = ms; }
  void setCapacity(uint16_t n) { _capacity = n; }
  int getError() { return _error; }

private:
  Stream &_ss;
  uint32_t _timeout = 5000;
  bool _debug = false;
  int _error = FINGERPRINT_OK;
  uint8_t _addr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  uint32_t _ledOffAtMs = 0;
  uint16_t _capacity = 120;

  EnrollNbState _enrollState = ENROLL_IDLE;
  uint16_t _enrollId = 0;
  uint8_t _enrollStep = 0;
  uint32_t _enrollDeadline = 0;
  uint8_t _nofingerStreak = 0;
  uint8_t _goodImgStreak = 0;
  bool _retryAfterFail = false;

  int sendPacket(uint8_t *data, uint16_t len);
  int getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen);
  uint16_t calcChecksum(uint8_t *buf, uint16_t len);
  int parseAck(uint8_t ack);
  void flush();
  int handshakeOptional();
};

#endif
