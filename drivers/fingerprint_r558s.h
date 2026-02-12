#ifndef R558S_FINGERPRINT_H
#define R558S_FINGERPRINT_H

#include <Arduino.h>
#include <Stream.h>

// -----------------------------------------------------------------------------
// R557/R558 packet: Header 0xEF 0x01 | Addr(4) | PID 0x01 | Len(2) | Content | Sum(2).
// Checksum = PID + Len_Hi + Len_Lo + all Content bytes (16-bit, overflow omitted).
// ACK: PID 0x07, Content[0] = confirmation code.
// -----------------------------------------------------------------------------

// Confirmation codes (manual)
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
#define FINGERPRINT_ILLEGALDATA       0x35  // R558/R557 storeModel etc. "Illegal Data"
#define FINGERPRINT_TIMEOUT           0xFF
#define FINGERPRINT_BADPACKET         0xFE

#define FINGERPRINT_CHARBUFFER1 0x01
#define FINGERPRINT_CHARBUFFER2 0x02

// LED command 0x3C: (mode, startColor, endColor, cycles)
#define R558_LED_MODE_BREATHE  0x01
#define R558_LED_MODE_BLINK    0x02
#define R558_LED_MODE_ON       0x03
#define R558_LED_MODE_OFF      0x04
#define R558_LED_COLOR_BLUE    0x01
#define R558_LED_COLOR_GREEN   0x02
#define R558_LED_COLOR_RED     0x04

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

  // Blocking: waits for finger then identifies (use in simple sketches only)
  int fingerID(uint16_t *id, uint16_t *score);

  // Non-blocking: try once; returns FINGERPRINT_NOFINGER if no finger, OK + id/score on match
  int getFingerprintID(uint16_t *id, uint16_t *score);

  // Enroll: 4 placements (image2Tz 1..4) then RegModel+Store. R558/R557 need 4 to avoid 0x35 Illegal Data.
  // If feedback != nullptr, step-by-step prompts and errors are printed there (e.g. &Serial).
  int enrollFingerprint(uint16_t id, Stream* feedback = nullptr);

  // Human-readable message for error/status (Adafruit-style)
  static const char* getErrorMessage(int err);

  // LED (cmd 0x3C): color 0=off, 1=red(R558_LED_COLOR_RED), 2=green, 3=blue. Uses R558_LED_MODE_ON/OFF.
  int setLed(uint8_t color);
  int setLedOff() { return setLed(0); }
  /** Turn LED on for durationMs, then off. Call ledUpdate() from loop for auto-off. */
  int setLedOnFor(uint8_t color, uint32_t durationMs);
  /** Call from loop; turns LED off when on-time has elapsed. */
  void ledUpdate();
  // Full control: mode R558_LED_MODE_*, color R558_LED_COLOR_*, cycles (0=continuous for blink/breathe).
  int setLedEx(uint8_t mode, uint8_t color, uint8_t cycles = 0);

  void setDebug(bool on) { _debug = on; }
  void setTimeout(uint32_t ms) { _timeout = ms; }
  int getError() { return _error; }

private:
  Stream &_ss;
  uint32_t _timeout = 5000;
  bool _debug = false;
  int _error = FINGERPRINT_OK;
  uint8_t _addr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  uint32_t _ledOffAtMs = 0;  // when non-zero, ledUpdate() turns LED off at this time

  int sendPacket(uint8_t *data, uint16_t len);
  int getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen);
  uint16_t calcChecksum(uint8_t *buf, uint16_t len);
  int parseAck(uint8_t ack);
  void flush();
  int handshake();
};

#endif
