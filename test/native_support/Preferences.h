/*
 * Minimal host-side stand-in for the ESP32 Arduino `Preferences` (NVS)
 * wrapper. Used only by the `test_nav_native` PlatformIO environment — see
 * Arduino.h in this directory for why this shim exists.
 *
 * `nav_system.cpp` persists the sleep timeout under key "sleepsec" in
 * namespace "cryptick". This stub keeps values in an in-process map so a
 * `begin()`/`put*()`/`end()` pair is visible to the next `begin()` call
 * within the same test binary — matching real NVS round-trip semantics
 * closely enough for unit tests — but nothing survives past process exit,
 * which is exactly what a hermetic test run wants.
 */
#ifndef CRYPTICK_NATIVE_PREFERENCES_H
#define CRYPTICK_NATIVE_PREFERENCES_H

#include <cstdint>
#include <map>
#include <string>

class Preferences {
public:
    bool begin(const char * /*name*/, bool /*readOnly*/ = false) { return true; }
    void end() {}

    bool isKey(const char *key) { return store().count(key) != 0; }

    uint16_t getUShort(const char *key, uint16_t defaultValue = 0)
    {
        auto it = store().find(key);
        return it == store().end() ? defaultValue : (uint16_t)it->second;
    }

    size_t putUShort(const char *key, uint16_t value)
    {
        store()[key] = value;
        return sizeof(value);
    }

    uint8_t getUChar(const char *key, uint8_t defaultValue = 0)
    {
        auto it = store().find(key);
        return it == store().end() ? defaultValue : (uint8_t)it->second;
    }

    size_t putUChar(const char *key, uint8_t value)
    {
        store()[key] = value;
        return sizeof(value);
    }

private:
    static std::map<std::string, uint32_t> &store()
    {
        static std::map<std::string, uint32_t> s;
        return s;
    }
};

#endif /* CRYPTICK_NATIVE_PREFERENCES_H */
