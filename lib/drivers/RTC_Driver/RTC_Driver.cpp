#include "RTC_Driver.h"
#include <Arduino.h>

RTC_Driver::RTC_Driver() : initialized(false)
{
}

bool RTC_Driver::begin()
{
  if (!rtc.begin())
  {
    Serial.println("RTC: Not found!");
    return false;
  }

  initialized = true;

  if (rtc.lostPower())
  {
    Serial.println("RTC: Lost power, setting compile time");
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  }

  return true;
}

DateTime RTC_Driver::now()
{
  return rtc.now();
}

void RTC_Driver::adjust(const DateTime &dt)
{
  rtc.adjust(dt);
}

bool RTC_Driver::lostPower()
{
  return rtc.lostPower();
}

time_t RTC_Driver::unixtime()
{
  DateTime dt = rtc.now();
  if (dt.year() < 2020 || dt.year() > 2100)
  {
    return 0;
  }
  return dt.unixtime();
}

String RTC_Driver::getTimeString()
{
  DateTime dt = rtc.now();
  char timeStr[9];
  sprintf(timeStr, "%02d:%02d:%02d", dt.hour(), dt.minute(), dt.second());
  return String(timeStr);
}

bool RTC_Driver::isValid()
{
  // RTC_DS3231 in some RTClib versions doesn't provide isrunning().
  // Consider RTC valid if it was initialized and returns a sane unix time.
  return initialized && (unixtime() != 0);
}
