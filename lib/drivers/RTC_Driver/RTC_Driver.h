#ifndef RTC_DRIVER_H
#define RTC_DRIVER_H

#include <RTClib.h>

class RTC_Driver {
public:
  RTC_Driver();
  bool begin();
  DateTime now();
  void adjust(const DateTime &dt);
  bool lostPower();
  time_t unixtime();
  String getTimeString();
  bool isValid();

private:
  RTC_DS3231 rtc;
  bool initialized;
};

#endif

