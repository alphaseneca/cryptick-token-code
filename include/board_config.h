#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

/**
 * Cryptick Token PCB v0.1.0 — ESP32-S3-WROOM-1 N16R8
 *
 * Pin numbers are ESP32 GPIO numbers. 5-way is active-low
 * (internal pull-up; press → GND). Verified by bring-up serial logs:
 * press physical key and match “[IN] NAME (GPIOx)” to the table below.
 */

#define OLED_RESET -1
#define OLED_ADDRESS 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define OLED_SDA 8
#define OLED_SCL 9

/*
 * R557 UART — ESP_RX = ESP receives (sensor TX), ESP_TX = ESP drives.
 * Boot code auto-tries both cable orientations if first fails.
 */
#define FINGERPRINT_RX 17
#define FINGERPRINT_TX 18
#define FINGERPRINT_IRQ_PIN 16

/*
 * 5-way PCB nets (physical direction → GPIO). Bring-up: pairs were
 * swapped vs first silk guess — UP↔LEFT and RIGHT↔DOWN corrected here.
 *   RIGHT=5  DOWN=4  UP=7  LEFT=6  CENTER=15
 * Verify after flash: physical UP must log [IN] UP (GPIO7), etc.
 */
#define RIGHT_BUTTON_PIN 5
#define DOWN_BUTTON_PIN 4
#define UP_BUTTON_PIN 7
#define LEFT_BUTTON_PIN 6
#define BUTTON_PIN 15 /* CENTER */

#define ENCODER_CW_PIN -1
#define ENCODER_CCW_PIN -1

#define STAT1_PIN 38
#define STAT2_PIN 39

#define ENABLE_FINGERPRINT
#define FINGERPRINT_BAUD 57600
#define FINGERPRINT_CAPACITY 120
#define FINGERPRINT_UART_TIMEOUT_MS 400
#define FINGERPRINT_POLL_INTERVAL_MS 80
#define FINGERPRINT_ENROLL_POLL_MS 30
#define FINGERPRINT_ENROLL_TIMEOUT_MS 90000
/* R557 manual: lift confirmed by consecutive GenImg=NO_FINGER answers */
#define FINGERPRINT_ENROLL_REMOVE_STREAK 2
#define FINGERPRINT_ENROLL_GOOD_IMG 1

#define FINGERPRINT_LED_READY 2
#define FINGERPRINT_LED_ERROR 1
#define FINGERPRINT_LED_ENROLL 3
#define FINGERPRINT_LED_MATCH 2

#define TOTP_PERIOD 30
#define DISPLAY_UPDATE_INTERVAL 1000
#define BUTTON_DEBOUNCE_MS 25
#define ENCODER_DEBOUNCE_MS 8
#define CONFIG_FILE "/totp_config.json"
#define INACTIVITY_TIMEOUT_SEC 60
#define AUTH_ERROR_DISPLAY_MS 2000
#define BATTERY_POLL_INTERVAL_MS 400

#endif /* BOARD_CONFIG_H */
