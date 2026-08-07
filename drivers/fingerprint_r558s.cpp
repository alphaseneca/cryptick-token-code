#include "fingerprint_r558s.h"
#include <board_config.h>

#ifndef FINGERPRINT_ENROLL_REMOVE_STREAK
#define FINGERPRINT_ENROLL_REMOVE_STREAK 3
#endif
#ifndef FINGERPRINT_ENROLL_GOOD_IMG
#define FINGERPRINT_ENROLL_GOOD_IMG 2
#endif
#ifndef FINGERPRINT_ENROLL_TIMEOUT_MS
#define FINGERPRINT_ENROLL_TIMEOUT_MS 120000
#endif

R558SFingerprint::R558SFingerprint(Stream &ss) : _ss(ss) {}

int R558SFingerprint::begin(uint16_t baud) {
  (void)baud;
  delay(50);
  flush();
  delay(50);
  flush();

  /* R557 default password is 0x00000000; many modules use 0xFFFFFFFF */
  uint8_t pwdZero[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t pwdFF[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  int pwdR = vfyPwd(pwdZero);
  if (pwdR != FINGERPRINT_OK) {
    pwdR = vfyPwd(pwdFF);
  }
  if (pwdR != FINGERPRINT_OK) {
    if (_debug) Serial.println("VfyPwd failed");
    return pwdR;
  }

  /* Optional wake/link (R558); ignore failure on R557 */
  handshakeOptional();

  uint16_t count;
  if (getTemplateCount(&count) != FINGERPRINT_OK) {
    if (_debug) Serial.println("Get template count failed");
    return FINGERPRINT_PACKETRECIEVEERR;
  }
  if (_debug) Serial.println("R557 ready, templates=" + String(count));
  return FINGERPRINT_OK;
}

int R558SFingerprint::handshakeOptional() {
  uint8_t cmd[] = {0x35};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

void R558SFingerprint::flush() {
  while (_ss.available()) _ss.read();
}

uint16_t R558SFingerprint::calcChecksum(uint8_t *buf, uint16_t len) {
  uint32_t sum = 0;
  for (uint16_t i = 0; i < len; i++) sum += buf[i];
  return (sum & 0xFFFF);
}

int R558SFingerprint::sendPacket(uint8_t *data, uint16_t len) {
  uint8_t packet[64];
  uint16_t pktLen = len + 9 + 2;

  packet[0] = 0xEF;
  packet[1] = 0x01;
  memcpy(packet + 2, _addr, 4);
  packet[6] = 0x01;
  uint16_t dataLen = len + 2;
  packet[7] = (dataLen >> 8) & 0xFF;
  packet[8] = dataLen & 0xFF;
  memcpy(packet + 9, data, len);

  uint8_t cksBuf[3 + len];
  cksBuf[0] = 0x01;
  cksBuf[1] = packet[7];
  cksBuf[2] = packet[8];
  memcpy(cksBuf + 3, data, len);
  uint16_t cks = calcChecksum(cksBuf, 3 + len);
  packet[9 + len] = (cks >> 8) & 0xFF;
  packet[10 + len] = cks & 0xFF;

  if (_debug) {
    Serial.print("TX: ");
    for (uint16_t i = 0; i < pktLen; i++) {
      if (packet[i] < 0x10) Serial.print('0');
      Serial.print(packet[i], HEX);
      Serial.print(' ');
    }
    Serial.println();
  }

  flush();
  _ss.write(packet, pktLen);
  _ss.flush();
  delay(5);
  return FINGERPRINT_OK;
}

int R558SFingerprint::getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen) {
  *respLen = 0;
  uint32_t start = millis();
  uint8_t header[9];
  uint8_t idx = 0;

  while (idx < 2) {
    while (_ss.available()) {
      uint8_t b = _ss.read();
      if (idx == 0 && b == 0xEF) { header[0] = b; idx = 1; }
      else if (idx == 1 && b == 0x01) { header[1] = b; idx = 2; break; }
      else idx = 0;
    }
    if (millis() - start > _timeout) return FINGERPRINT_TIMEOUT;
    if (idx < 2) delay(2);
  }
  while (idx < 9) {
    while (_ss.available() && idx < 9) header[idx++] = _ss.read();
    if (millis() - start > _timeout) return FINGERPRINT_TIMEOUT;
    delay(2);
  }
  if (header[0] != 0xEF || header[1] != 0x01) return FINGERPRINT_BADPACKET;

  uint8_t pid = header[6];
  if (pid != 0x07) return FINGERPRINT_PACKETRECIEVEERR;

  uint16_t pktLen = ((uint16_t)header[7] << 8) | header[8];
  uint16_t dataLen = pktLen - 2;
  if (dataLen > maxLen) return FINGERPRINT_PACKETRECIEVEERR;

  uint8_t tail[258];
  idx = 0;
  start = millis();
  while (idx < dataLen + 2) {
    while (_ss.available() && idx < dataLen + 2) tail[idx++] = _ss.read();
    if (millis() - start > _timeout) return FINGERPRINT_TIMEOUT;
    delay(2);
  }

  uint8_t cksBuf[3 + dataLen];
  cksBuf[0] = pid;
  cksBuf[1] = header[7];
  cksBuf[2] = header[8];
  memcpy(cksBuf + 3, tail, dataLen);
  uint16_t calc = calcChecksum(cksBuf, 3 + dataLen);
  uint16_t rcv = ((uint16_t)tail[dataLen] << 8) | tail[dataLen + 1];
  if (calc != rcv) return FINGERPRINT_BADPACKET;

  memcpy(response, tail, dataLen);
  *respLen = dataLen;
  return FINGERPRINT_OK;
}

int R558SFingerprint::parseAck(uint8_t ack) {
  switch (ack) {
    case 0x00: return FINGERPRINT_OK;
    case 0x01: return FINGERPRINT_PACKETRECIEVEERR;
    case 0x02: return FINGERPRINT_NOFINGER;
    case 0x03: return FINGERPRINT_IMAGEFAIL;
    case 0x06: return FINGERPRINT_IMAGEMESS;
    case 0x07: return FINGERPRINT_FEATUREFAIL;
    case 0x08: return FINGERPRINT_NOMATCH;
    case 0x09: return FINGERPRINT_NOTFOUND;
    case 0x0A: return FINGERPRINT_MERGEFAIL;
    case 0x0B: return FINGERPRINT_BADLOCATION;
    case 0x13: return FINGERPRINT_WRONGPASSWORD;
    case 0x1F: return FINGERPRINT_DBRANGEFAIL;
    case 0x35: return FINGERPRINT_ILLEGALDATA;
    default: return FINGERPRINT_PACKETRECIEVEERR;
  }
}

int R558SFingerprint::setLed(uint8_t color) {
  _ledOffAtMs = 0;
  if (color == 0) return setLedEx(R558_LED_MODE_OFF, 0, 0);
  uint8_t c = (color == 1) ? R558_LED_COLOR_RED : (color == 2) ? R558_LED_COLOR_GREEN : R558_LED_COLOR_BLUE;
  return setLedEx(R558_LED_MODE_ON, c, 0);
}
int R558SFingerprint::setLedOnFor(uint8_t color, uint32_t durationMs) {
  if (color == 0 || durationMs == 0) {
    _ledOffAtMs = 0;
    return setLed(0);
  }
  int r = setLed(color);
  if (r == FINGERPRINT_OK)
    _ledOffAtMs = millis() + durationMs;
  return r;
}
void R558SFingerprint::ledUpdate() {
  if (_ledOffAtMs != 0 && (uint32_t)millis() >= _ledOffAtMs) {
    _ledOffAtMs = 0;
    setLed(0);
  }
}
int R558SFingerprint::setLedEx(uint8_t mode, uint8_t color, uint8_t cycles) {
  /* Soft-fail: R557 may not support Aura LED cmd */
  uint8_t cmd[] = {0x3C, mode, color, color, cycles};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 5);
  if (r != FINGERPRINT_OK) return FINGERPRINT_OK;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return FINGERPRINT_OK;
  return FINGERPRINT_OK;
}

int R558SFingerprint::getImage() {
  uint8_t cmd[] = {0x01};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::image2Tz(uint8_t slot) {
  uint8_t cmd[] = {0x02, slot};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 2);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::createModel() {
  uint8_t cmd[] = {0x05};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::vfyPwd(const uint8_t pwd[4]) {
  uint8_t cmd[] = {0x13, pwd[0], pwd[1], pwd[2], pwd[3]};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 5);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::setPwd(const uint8_t pwd[4]) {
  uint8_t cmd[] = {0x12, pwd[0], pwd[1], pwd[2], pwd[3]};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 5);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::storeModel(uint16_t id) {
  uint8_t cmd[] = {0x06, 0x01, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF)};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 4);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::loadModel(uint16_t id) {
  uint8_t cmd[] = {0x07, 0x01, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF)};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 4);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::fingerFastSearch(uint16_t *id, uint16_t *score) {
  *id = 0xFFFF;
  *score = 0xFFFF;
  uint8_t cmd[] = {0x04, 0x01, 0x00, 0x00, 0x00, 0x64};
  /* PageNum is capacity-limited; use 120 for R557 */
  cmd[4] = (_capacity >> 8) & 0xFF;
  cmd[5] = _capacity & 0xFF;
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 6);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  int ack = parseAck(resp[0]);
  if (ack == FINGERPRINT_OK && len >= 5) {
    *id = ((uint16_t)resp[1] << 8) | resp[2];
    *score = ((uint16_t)resp[3] << 8) | resp[4];
  }
  return ack;
}

int R558SFingerprint::getTemplateCount(uint16_t *count) {
  *count = 0;
  uint8_t cmd[] = {0x1D};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  int ack = parseAck(resp[0]);
  if (ack != FINGERPRINT_OK) return ack;
  if (len >= 3)
    *count = ((uint16_t)resp[1] << 8) | resp[2]; /* big-endian (manual style) */
  else if (len >= 2)
    *count = resp[1];
  /* If big-endian yields absurd, try little-endian */
  if (*count > _capacity && len >= 3)
    *count = (uint16_t)resp[1] | ((uint16_t)resp[2] << 8);
  return FINGERPRINT_OK;
}

int R558SFingerprint::deleteModel(uint16_t id) {
  uint8_t cmd[] = {0x0C, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF), 0x00, 0x01};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 5);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::emptyDatabase() {
  uint8_t cmd[] = {0x0D};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

int R558SFingerprint::readSysPara() {
  uint8_t cmd[] = {0x0F};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 1);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}


int R558SFingerprint::getFreeId(uint16_t &freeId) {
  freeId = 0xFFFF;
  uint16_t capacity = _capacity ? _capacity : 120;

  /* TemplateIndex (0x1F) — short timeout so unsupported modules fail quickly */
  const uint32_t prev = _timeout;
  if (_timeout > 400)
    _timeout = 400;

  uint8_t cmd[] = {0x1F, 0x00};
  uint8_t resp[64];
  uint16_t len;
  int r = sendPacket(cmd, 2);
  if (r == FINGERPRINT_OK)
    r = getPacket(resp, sizeof(resp), &len);
  _timeout = prev;

  if (r == FINGERPRINT_OK && parseAck(resp[0]) == FINGERPRINT_OK) {
    uint8_t *bitmap = resp + 1;
    uint16_t bits = (len > 1) ? (len - 1) * 8 : 0;
    for (uint16_t i = 0; i < bits && i < capacity; i++) {
      if ((bitmap[i / 8] & (1 << (i % 8))) == 0) {
        freeId = i;
        return FINGERPRINT_OK;
      }
    }
    freeId = 0;
    return FINGERPRINT_DBRANGEFAIL;
  }

  /*
   * R557 often has no 0x1F. Do NOT LoadChar-scan (multi-second hangs).
   * Use template count as next sequential id (common module behaviour).
   */
  uint16_t count = 0;
  if (getTemplateCount(&count) == FINGERPRINT_OK) {
    freeId = (count < capacity) ? count : 0;
    return FINGERPRINT_OK;
  }
  freeId = 0;
  return FINGERPRINT_OK;
}

int R558SFingerprint::enrollStart(uint16_t id) {
  _enrollId = id;
  if (_enrollId == 0xFFFF) {
    if (getFreeId(_enrollId) != FINGERPRINT_OK)
      _enrollId = 0;
  }
  _enrollStep = 1;
  _enrollState = ENROLL_WAIT_FINGER;
  _enrollDeadline = millis() + (uint32_t)FINGERPRINT_ENROLL_TIMEOUT_MS;
  _error = FINGERPRINT_OK;
  _nofingerStreak = 0;
  _goodImgStreak = 0;
  _retryAfterFail = false;
  flush();
  return FINGERPRINT_OK;
}

void R558SFingerprint::enrollAbort() {
  _enrollState = ENROLL_IDLE;
  _enrollStep = 0;
  _nofingerStreak = 0;
  _goodImgStreak = 0;
  _retryAfterFail = false;
}

/*
 * R557 / AS608-class enrollment (manual):
 *   GenImg → GenChar(1) → (lift) → GenImg → GenChar(2) → RegModel → StoreChar
 * Non-blocking: one GenImg/GenChar attempt per poll tick.
 */
int R558SFingerprint::enrollPoll(EnrollNbState &state, uint8_t &step) {
  step = _enrollStep;
  state = _enrollState;
  if (_enrollState == ENROLL_IDLE || _enrollState == ENROLL_DONE || _enrollState == ENROLL_FAILED)
    return (_enrollState == ENROLL_DONE) ? FINGERPRINT_OK : _error;

  if (millis() > _enrollDeadline) {
    _enrollState = ENROLL_FAILED;
    _error = FINGERPRINT_TIMEOUT;
    state = _enrollState;
    return _error;
  }

  const uint32_t prevTimeout = _timeout;
  if (_timeout > 600)
    _timeout = 600;

  if (_enrollState == ENROLL_WAIT_FINGER) {
    int r = getImage();
    if (r == FINGERPRINT_NOFINGER || r == FINGERPRINT_TIMEOUT) {
      _goodImgStreak = 0;
      _timeout = prevTimeout;
      return r;
    }
    if (r != FINGERPRINT_OK) {
      _goodImgStreak = 0;
      _timeout = prevTimeout;
      return r;
    }

    if (++_goodImgStreak < (uint8_t)FINGERPRINT_ENROLL_GOOD_IMG) {
      _timeout = prevTimeout;
      return FINGERPRINT_OK;
    }
    _goodImgStreak = 0;

    /* BufferID 1 first capture, 2 second — matches GenChar in manual */
    r = image2Tz(_enrollStep == 1 ? 1 : 2);
    if (r != FINGERPRINT_OK) {
      /* Ask to lift and re-place same step (manual retry) */
      _retryAfterFail = true;
      _nofingerStreak = 0;
      _enrollState = ENROLL_WAIT_REMOVE;
      state = _enrollState;
      _timeout = prevTimeout;
      return r;
    }

    _nofingerStreak = 0;
    _retryAfterFail = false;
    _enrollDeadline = millis() + (uint32_t)FINGERPRINT_ENROLL_TIMEOUT_MS;

    if (_enrollStep == 1) {
      /* Must lift before second GenImg */
      _enrollState = ENROLL_WAIT_REMOVE;
    } else {
      /* After buffer 2, RegModel + Store without requiring lift */
      _enrollState = ENROLL_MERGE_STORE;
    }
    state = _enrollState;
    _timeout = prevTimeout;
    return FINGERPRINT_OK;
  }

  if (_enrollState == ENROLL_WAIT_REMOVE) {
    int r = getImage();
    /* Empty plate: NOFINGER; some R557 builds also return timeout when empty */
    bool empty = (r == FINGERPRINT_NOFINGER || r == FINGERPRINT_TIMEOUT);
    if (empty) {
      if (++_nofingerStreak < (uint8_t)FINGERPRINT_ENROLL_REMOVE_STREAK) {
        _timeout = prevTimeout;
        return FINGERPRINT_NOFINGER;
      }
      _nofingerStreak = 0;
      _goodImgStreak = 0;
      if (_retryAfterFail) {
        _retryAfterFail = false;
        _enrollState = ENROLL_WAIT_FINGER;
        _enrollDeadline = millis() + (uint32_t)FINGERPRINT_ENROLL_TIMEOUT_MS;
        step = _enrollStep;
        state = _enrollState;
        _timeout = prevTimeout;
        return FINGERPRINT_OK;
      }
      /* First capture done → go to second placement */
      _enrollStep = 2;
      _enrollState = ENROLL_WAIT_FINGER;
      _enrollDeadline = millis() + (uint32_t)FINGERPRINT_ENROLL_TIMEOUT_MS;
      step = _enrollStep;
      state = _enrollState;
      _timeout = prevTimeout;
      return FINGERPRINT_OK;
    }
    /* Still seeing a finger (or partial image) — keep asking for lift */
    _nofingerStreak = 0;
    _timeout = prevTimeout;
    return FINGERPRINT_OK;
  }

  if (_enrollState == ENROLL_MERGE_STORE) {
    int r = createModel(); /* RegModel 0x05 */
    if (r != FINGERPRINT_OK) {
      _error = r;
      _enrollState = ENROLL_FAILED;
      state = _enrollState;
      _timeout = prevTimeout;
      return r;
    }
    r = storeModel(_enrollId); /* StoreChar 0x06 */
    if (r != FINGERPRINT_OK) {
      uint16_t alt = 0;
      if (getFreeId(alt) == FINGERPRINT_OK && alt != _enrollId) {
        _enrollId = alt;
        r = storeModel(_enrollId);
      }
    }
    if (r != FINGERPRINT_OK) {
      _error = r;
      _enrollState = ENROLL_FAILED;
      state = _enrollState;
      _timeout = prevTimeout;
      return r;
    }
    _enrollState = ENROLL_DONE;
    state = _enrollState;
    _timeout = prevTimeout;
    return FINGERPRINT_OK;
  }

  _timeout = prevTimeout;
  return FINGERPRINT_OK;
}

int R558SFingerprint::fingerID(uint16_t *id, uint16_t *score) {
  while (getImage() != FINGERPRINT_OK) delay(100);
  image2Tz(1);
  return fingerFastSearch(id, score);
}

int R558SFingerprint::getFingerprintID(uint16_t *id, uint16_t *score) {
  int r = getImage();
  if (r != FINGERPRINT_OK) return r;
  r = image2Tz(1);
  if (r != FINGERPRINT_OK) return r;
  return fingerFastSearch(id, score);
}

int R558SFingerprint::enrollFingerprint(uint16_t id, Stream* feedback) {
  int r = enrollStart(id);
  if (r != FINGERPRINT_OK) {
    if (feedback) feedback->printf("Enroll start fail: %s\n", getErrorMessage(r));
    return r;
  }
  if (feedback) {
    feedback->println(F("--- Enrollment (2 steps) ---"));
    feedback->printf("  Storing at ID %u\n", (unsigned)_enrollId);
    feedback->println(F("  [1/2] Place finger firmly..."));
  }
  EnrollNbState st;
  uint8_t step;
  uint8_t lastStep = 0;
  bool askedRemove = false;
  bool askedPlace = true;
  while (true) {
    r = enrollPoll(st, step);
    if (st == ENROLL_WAIT_FINGER && (step != lastStep || !askedPlace)) {
      lastStep = step;
      askedRemove = false;
      askedPlace = true;
      if (feedback) feedback->printf("  [%u/2] Place finger firmly...\n", (unsigned)step);
    }
    if (st == ENROLL_WAIT_REMOVE && !askedRemove) {
      askedRemove = true;
      askedPlace = false;
      if (feedback) {
        if (_retryAfterFail)
          feedback->printf("  [%u/2] Poor capture — lift finger, try again.\n",
                           (unsigned)step);
        else
          feedback->printf("  [%u/2] OK. Lift finger completely.\n", (unsigned)step);
      }
    }
    if (st == ENROLL_DONE) {
      if (feedback) feedback->printf("  Enrolled at ID %u.\n", (unsigned)_enrollId);
      return FINGERPRINT_OK;
    }
    if (st == ENROLL_FAILED) {
      if (feedback) feedback->printf("  Enroll failed: %s\n", getErrorMessage(r));
      return r;
    }
    delay(40);
    yield();
  }
}

const char* R558SFingerprint::getErrorMessage(int err) {
  switch (err) {
    case FINGERPRINT_OK: return "OK";
    case FINGERPRINT_PACKETRECIEVEERR: return "Packet receive error";
    case FINGERPRINT_NOFINGER: return "No finger";
    case FINGERPRINT_IMAGEFAIL: return "Image capture failed";
    case FINGERPRINT_IMAGEMESS: return "Image too messy";
    case FINGERPRINT_FEATUREFAIL: return "Could not find fingerprint features";
    case FINGERPRINT_NOMATCH: return "Fingerprints do not match";
    case FINGERPRINT_NOTFOUND: return "Fingerprint not found";
    case FINGERPRINT_MERGEFAIL: return "Could not merge fingerprints (try again)";
    case FINGERPRINT_BADLOCATION: return "Invalid template location";
    case FINGERPRINT_DBRANGEFAIL: return "Database full / range error";
    case FINGERPRINT_WRONGPASSWORD: return "Wrong password";
    case FINGERPRINT_ILLEGALDATA: return "Illegal data";
    case FINGERPRINT_TIMEOUT: return "Timeout";
    case FINGERPRINT_BADPACKET: return "Bad packet";
    default: return "Unknown error";
  }
}