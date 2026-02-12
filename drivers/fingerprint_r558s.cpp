#include "fingerprint_r558s.h"

R558SFingerprint::R558SFingerprint(Stream &ss) : _ss(ss) {}

int R558SFingerprint::begin(uint16_t baud) {
  delay(50);
  flush();
  delay(50);
  flush();

  uint8_t defaultPwd[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  int pwdR = vfyPwd(defaultPwd);
  if (pwdR != FINGERPRINT_OK) {
    if (_debug) Serial.println("Pwd wrong (0x21) - Resetting...");
    setPwd(defaultPwd);
    pwdR = vfyPwd(defaultPwd);
  }
  if (pwdR != FINGERPRINT_OK) return pwdR;

  int hsResult = handshake();
  if (hsResult != FINGERPRINT_OK) {
    if (_debug) Serial.println("Handshake FAIL! Check wiring.");
    return hsResult;
  }
  uint16_t count;
  if (getTemplateCount(&count) != FINGERPRINT_OK) {
    if (_debug) Serial.println("Get template count failed");
    return FINGERPRINT_PACKETRECIEVEERR;
  }
  if (_debug) Serial.println("R558-S Ready (baud=" + String(baud) + ", 8N1)");
  return FINGERPRINT_OK;
}

// Handshake 0x35 - wake/link check
int R558SFingerprint::handshake() {
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
  // Give sensor time to process and start replying (reduces Bad packet / Packet receive error)
  delay(80);
  return FINGERPRINT_OK;
}

int R558SFingerprint::getPacket(uint8_t *response, uint16_t maxLen, uint16_t *respLen) {
  *respLen = 0;
  uint32_t start = millis();
  uint8_t header[9];
  uint8_t idx = 0;

  // Sync to packet start (0xEF 0x01) in case of leftover bytes or noise
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
  // Read rest of 9-byte header
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
  if (_debug) {
    Serial.print("RX: ");
    for (uint16_t i = 0; i < dataLen; i++) {
      if (response[i] < 0x10) Serial.print('0');
      Serial.print(response[i], HEX);
      Serial.print(' ');
    }
    Serial.println();
  }
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
    case 0x1F: return FINGERPRINT_DBRANGEFAIL;
    case 0x35: return FINGERPRINT_ILLEGALDATA;  // Illegal Data (e.g. store without 4 enrolls)
    default: return FINGERPRINT_PACKETRECIEVEERR;
  }
}

// LED cmd 0x3C (mode, startColor, endColor, cycles). Colors: 0x01 blue, 0x02 green, 0x04 red.
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
  uint8_t cmd[] = {0x3C, mode, color, color, cycles};
  uint8_t resp[32];
  uint16_t len;
  int r = sendPacket(cmd, 5);
  if (r != FINGERPRINT_OK) return r;
  r = getPacket(resp, sizeof(resp), &len);
  if (r != FINGERPRINT_OK) return r;
  return parseAck(resp[0]);
}

// GenImg 0x01 - collect finger image into ImageBuffer
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

// GenChar 0x02 - generate character from ImageBuffer to CharBuffer1/2
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

// RegModel 0x05 - merge CharBuffer1+2 into template
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

// VfyPwd 0x13 - verify handshake password (default 0xFFFFFFFF or 0x00000000)
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

// SetPwd 0x12
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

// Store 0x06 - store template from buffer to Flash at PageID
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

// LoadChar 0x07 - load template from Flash to buffer
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

// Search 0x04 - search library (BufferID, StartPage, PageNum)
int R558SFingerprint::fingerFastSearch(uint16_t *id, uint16_t *score) {
  *id = 0xFFFF;
  *score = 0xFFFF;
  uint8_t cmd[] = {0x04, 0x01, 0x00, 0x00, 0x00, 0x64};
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

// TempleteNum 0x1D - read valid template count. N may be 1 or 2 bytes; try little-endian 2-byte.
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
    *count = (uint16_t)resp[1] | ((uint16_t)resp[2] << 8);  // little-endian (common on R558)
  else if (len >= 2)
    *count = resp[1];
  return FINGERPRINT_OK;
}

// DeletChar 0x0C - delete N templates from PageID
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

// Empty 0x0D - clear finger library
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

// ReadSysPara 0x0F
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
  uint16_t capacity = 100;
  uint16_t perPage = 256;
  uint16_t pageCount = (capacity + perPage - 1) / perPage;

  for (uint16_t page = 0; page < pageCount; page++) {
    uint8_t cmd[] = {0x1F, (uint8_t)page};
    uint8_t resp[64];
    uint16_t len;
    int r = sendPacket(cmd, 2);
    if (r != FINGERPRINT_OK) return r;
    r = getPacket(resp, sizeof(resp), &len);
    if (r != FINGERPRINT_OK) return r;
    int ack = parseAck(resp[0]);
    if (ack != FINGERPRINT_OK) return ack;

    uint8_t *bitmap = resp + 1;
    for (uint16_t i = 0; i < 256; i++) {
      uint16_t globalId = page * perPage + i;
      if (globalId >= capacity) break;
      uint16_t byteIdx = i / 8;
      uint8_t bitIdx = i % 8;
      if ((bitmap[byteIdx] & (1 << bitIdx)) == 0) {
        freeId = globalId;
        return FINGERPRINT_OK;
      }
    }
  }
  return FINGERPRINT_DBRANGEFAIL;
}

int R558SFingerprint::fingerID(uint16_t *id, uint16_t *score) {
  while (getImage() != FINGERPRINT_OK) delay(100);
  image2Tz(1);
  return fingerFastSearch(id, score);
}

// Non-blocking: one getImage(); if no finger return immediately; else identify
int R558SFingerprint::getFingerprintID(uint16_t *id, uint16_t *score) {
  int r = getImage();
  if (r != FINGERPRINT_OK) return r;  // NOFINGER, IMAGEFAIL, etc.
  r = image2Tz(1);
  if (r != FINGERPRINT_OK) return r;
  return fingerFastSearch(id, score);
}

// R558/R557 require 4 enrollments (image2Tz slots 1..4) before createModel/storeModel (fixes 0x35 Illegal Data).
int R558SFingerprint::enrollFingerprint(uint16_t id, Stream* feedback) {
  uint16_t storeId = id;
  if (storeId == 0xFFFF) {
    if (getFreeId(storeId) != FINGERPRINT_OK) {
      if (feedback) feedback->println(F("Enroll: No free ID (database full)."));
      return FINGERPRINT_DBRANGEFAIL;
    }
  }
  if (feedback) {
    feedback->println(F("--- Enrollment (4 steps) ---"));
    feedback->printf("  Storing at ID %u. Place same finger 4 times when asked.\n", (unsigned)storeId);
  }
  uint32_t savedTimeout = _timeout;
  _timeout = 12000;
  int r;
  for (uint8_t slot = 1; slot <= 4; slot++) {
    if (feedback) feedback->printf("  [%u/4] Place finger on sensor...\n", (unsigned)slot);
    unsigned long start = millis();
    while ((r = getImage()) != FINGERPRINT_OK) {
      if (r != FINGERPRINT_NOFINGER) {
        _timeout = savedTimeout;
        if (feedback) feedback->printf("  Enroll failed: %s\n", getErrorMessage(r));
        return r;
      }
      if (millis() - start > 20000) {
        _timeout = savedTimeout;
        if (feedback) feedback->println(F("  Enroll failed: Timeout (place finger within 20s)."));
        return FINGERPRINT_TIMEOUT;
      }
      delay(200);
    }
    delay(150);
    r = image2Tz(slot);
    if (r != FINGERPRINT_OK) {
      _timeout = savedTimeout;
      if (feedback) feedback->printf("  Enroll failed at step %u: %s\n", (unsigned)slot, getErrorMessage(r));
      return r;
    }
    if (feedback) feedback->printf("  [%u/4] OK. Remove finger.\n", (unsigned)slot);
    delay(150);
    if (slot < 4) {
      for (int i = 0; i < 40; i++) {
        if (getImage() == FINGERPRINT_NOFINGER) break;
        delay(200);
      }
      delay(500);
    }
  }
  if (feedback) feedback->println(F("  Creating template and storing..."));
  delay(150);
  if ((r = createModel()) != FINGERPRINT_OK) {
    _timeout = savedTimeout;
    if (feedback) feedback->printf("  Enroll failed (merge): %s\n", getErrorMessage(r));
    return r;
  }
  delay(150);
  r = storeModel(storeId);
  _timeout = savedTimeout;
  if (r == FINGERPRINT_OK && feedback)
    feedback->printf("  Enrolled at ID %u.\n", (unsigned)storeId);
  else if (r != FINGERPRINT_OK && feedback)
    feedback->printf("  Enroll failed (store): %s\n", getErrorMessage(r));
  return r;
}

const char* R558SFingerprint::getErrorMessage(int err) {
  switch (err) {
    case FINGERPRINT_OK: return "OK";
    case FINGERPRINT_PACKETRECIEVEERR: return "Packet receive error";
    case FINGERPRINT_NOFINGER: return "No finger";
    case FINGERPRINT_IMAGEFAIL: return "Image capture failed";
    case FINGERPRINT_IMAGEMESS: return "Image too messy";
    case FINGERPRINT_FEATUREFAIL: return "Too few features";
    case FINGERPRINT_NOMATCH: return "No match";
    case FINGERPRINT_NOTFOUND: return "Not found";
    case FINGERPRINT_MERGEFAIL: return "Merge failed";
    case FINGERPRINT_BADLOCATION: return "Bad slot/location";
    case FINGERPRINT_DBRANGEFAIL: return "Database full";
    case FINGERPRINT_ILLEGALDATA: return "Illegal data (need 4 enroll steps?)";
    case FINGERPRINT_TIMEOUT: return "Timeout";
    case FINGERPRINT_BADPACKET: return "Bad packet";
    default: return "Unknown error";
  }
}
