#include <Arduino.h>
#include <unity.h>
#include "event_bus.h"

void test_bus_empty_pop(void)
{
    bus_init();
    BusEvent e{};
    TEST_ASSERT_FALSE(bus_pop(e));
}

void test_bus_publish_pop_fifo(void)
{
    bus_init();
    BusEvent a{};
    a.type = EVT_INPUT;
    a.kind = KEY_UP;
    a.a = 1;
    BusEvent b{};
    b.type = EVT_CMD;
    b.kind = CMD_FP_ENROLL_START;
    b.a = 7;
    TEST_ASSERT_TRUE(bus_publish(a));
    TEST_ASSERT_TRUE(bus_publish(b));

    BusEvent out{};
    TEST_ASSERT_TRUE(bus_pop(out));
    TEST_ASSERT_EQUAL((int)EVT_INPUT, (int)out.type);
    TEST_ASSERT_EQUAL((int)KEY_UP, (int)out.kind);

    TEST_ASSERT_TRUE(bus_pop(out));
    TEST_ASSERT_EQUAL((int)EVT_CMD, (int)out.type);
    TEST_ASSERT_EQUAL(7, out.a);

    TEST_ASSERT_FALSE(bus_pop(out));
}

void test_bus_clear(void)
{
    bus_init();
    BusEvent e{};
    e.type = EVT_FP;
    e.kind = FP_MATCHED;
    bus_publish(e);
    bus_clear();
    TEST_ASSERT_FALSE(bus_pop(e));
}

void test_bus_capacity(void)
{
    bus_init();
    BusEvent e{};
    e.type = EVT_BATTERY;
    e.kind = 0;
    int ok = 0;
    for (int i = 0; i < 64; i++) {
        e.a = (uint16_t)i;
        if (bus_publish(e))
            ok++;
    }
    TEST_ASSERT_EQUAL(48, ok); /* BUS_CAP */
    TEST_ASSERT_FALSE(bus_publish(e));

    BusEvent out{};
    TEST_ASSERT_TRUE(bus_pop(out));
    TEST_ASSERT_EQUAL(0, out.a);
}

void setup()
{
    delay(1500);
    UNITY_BEGIN();
    RUN_TEST(test_bus_empty_pop);
    RUN_TEST(test_bus_publish_pop_fifo);
    RUN_TEST(test_bus_clear);
    RUN_TEST(test_bus_capacity);
    UNITY_END();
}

void loop() {}
