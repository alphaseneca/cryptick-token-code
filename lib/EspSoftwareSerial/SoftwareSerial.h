/*
 * SoftwareSerial.h - ESP8266/ESP32 software serial (compatible with Stream)
 * Based on plerup/espsoftwareserial 5.0.0 for ESP8266 compatibility.
 */
#ifndef SoftwareSerial_h
#define SoftwareSerial_h

#include <Arduino.h>
#include <Stream.h>
#include <functional>
#include <atomic>

constexpr int SW_SERIAL_UNUSED_PIN = -1;

enum SoftwareSerialConfig {
  SWSERIAL_5N1 = 0,
  SWSERIAL_6N1,
  SWSERIAL_7N1,
  SWSERIAL_8N1,
};

class SoftwareSerial : public Stream {
public:
  SoftwareSerial(int receivePin, int transmitPin, bool inverse_logic = false, int bufSize = 64, int isrBufSize = 0);
  virtual ~SoftwareSerial();

#if !defined(ESP32)
  bool begin(int32_t baud) { return begin(baud, SWSERIAL_8N1); }
  bool begin(int32_t baud, SoftwareSerialConfig config);
#else
  void begin(int32_t baud) { begin(baud, SWSERIAL_8N1); }
  void begin(int32_t baud, SoftwareSerialConfig config);
#endif

  int32_t baudRate();
  void setTransmitEnablePin(int transmitEnablePin);
  void enableIntTx(bool on);
  bool overflow();

  int available() override;
  int peek() override;
  int read() override;
  void flush() override;
  size_t write(uint8_t byte) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  operator bool() const { return m_rxValid || m_txValid; }

  void enableRx(bool on);
  void enableTx(bool on);
  static void rxRead(SoftwareSerial* self);

  bool listen() { enableRx(true); return true; }
  void end();
  bool isListening() { return m_rxEnabled; }
  bool stopListening() { enableRx(false); return true; }

  void onReceive(std::function<void(int)> handler);
  void perform_work();

  using Print::write;

private:
  void preciseDelay(uint32_t deadline, bool late);
  void writePeriod(uint32_t dutyCycle, uint32_t offCycle, bool withStopBit);
  bool isValidGPIOpin(int pin);
  void rxBits();

  bool m_oneWire;
  int m_rxPin = SW_SERIAL_UNUSED_PIN;
  int m_txPin = SW_SERIAL_UNUSED_PIN;
#if !defined(ESP32)
  int m_swsInstsIdx = -1;
#endif
  int m_txEnablePin = SW_SERIAL_UNUSED_PIN;
  bool m_rxValid = false;
  bool m_rxEnabled = false;
  bool m_txValid = false;
  bool m_txEnableValid = false;
  bool m_invert;
  bool m_overflow = false;
  int8_t m_dataBits;
  int32_t m_bitCycles;
  uint32_t m_periodDeadline;
  bool m_intTxEnabled;
  int m_inPos, m_outPos;
  int m_bufSize = 0;
  uint8_t *m_buffer = nullptr;
  std::atomic<int> m_isrInPos, m_isrOutPos;
  int m_isrBufSize = 0;
  std::atomic<uint32_t> *m_isrBuffer;
  std::atomic<bool> m_isrOverflow;
  std::atomic<uint32_t> m_isrLastCycle;
  int m_rxCurBit;
  uint8_t m_rxCurByte = 0;
  std::function<void(int)> receiveHandler = nullptr;
};

#endif
