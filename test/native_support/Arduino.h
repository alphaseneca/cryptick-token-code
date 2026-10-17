/*
 * Minimal host-side stand-in for the ESP32 Arduino core, used only by the
 * `test_nav_native` PlatformIO environment (platform = native).
 *
 * `test_nav` on real hardware (`[env:test_nav]`) links the real Arduino core
 * and runs on an attached ESP32-S3. That is the only way to exercise actual
 * GPIO/UART/USB timing, but it means the suite can only ever *compile* in CI
 * (`--without-uploading --without-testing`) — nothing executes a single
 * `TEST_ASSERT_*` unless a board happens to be plugged into the runner.
 *
 * This header (plus Preferences.h and cryptick_log_native.cpp alongside it)
 * lets `src/systems/nav_system.cpp`, `event_bus.cpp` and `auth_system.cpp`
 * compile and link as an ordinary host executable so Unity can actually run
 * the assertions. It intentionally covers only the handful of Arduino-core
 * symbols those three files reach for — it is not a general Arduino shim.
 */
#ifndef CRYPTICK_NATIVE_ARDUINO_H
#define CRYPTICK_NATIVE_ARDUINO_H

#include <chrono>
#include <cstdint>

inline unsigned long millis(void)
{
    static const auto start = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::steady_clock::now() - start;
    return (unsigned long)
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
}

inline void delay(unsigned long) { /* no-op on host */ }

/*
 * event_bus.cpp guards its ring buffer with an ESP-IDF critical section
 * (`portMUX_TYPE` / `portENTER_CRITICAL` / `portEXIT_CRITICAL`) because it is
 * written from both the Arduino loop and the FIDO task. The native test
 * binary is single-threaded, so these collapse to no-ops rather than a real
 * lock — correct for this harness, not a general-purpose substitute.
 */
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
inline void portENTER_CRITICAL(portMUX_TYPE *) {}
inline void portEXIT_CRITICAL(portMUX_TYPE *) {}

#endif /* CRYPTICK_NATIVE_ARDUINO_H */
