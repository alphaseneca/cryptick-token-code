/*
 * Host process entry point for the `test_nav_native` PlatformIO environment.
 *
 * [env:test_nav] (hardware) gets its `main()` for free from the Arduino
 * core, which calls `setup()` once and then `loop()` forever. `platform =
 * native` has no Arduino core to provide that, so this file supplies the
 * missing `main()` instead of touching test/test_nav/test_main.cpp — that
 * file stays byte-for-byte shared between the hardware and host envs.
 *
 * `setup()` already does the whole run (`UNITY_BEGIN()` / `RUN_TEST(...)` /
 * `UNITY_END()`); there is no device `loop()` to keep spinning on a host
 * process, so this returns right after it.
 */
extern void setup();

int main()
{
    setup();
    return 0;
}
