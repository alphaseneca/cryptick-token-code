#ifndef APP_CONFIG_H
#define APP_CONFIG_H
// Hardware Pin Configuration - ESP32-S3
#define OLED_SDA 8 // ESP32-S3 default I2C SDA (GPIO8)
#define OLED_SCL 9 // ESP32-S3 default I2C SCL (GPIO9)
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C

#define RIGHT_BUTTON_PIN 5 // Optional second button for navigation (e.g. back)
#define BUTTON_PIN 6       // You may want to change this depending on your board wiring
#define LEFT_BUTTON_PIN 7  // Optional third button for navigation (e.g. forward)
// Fingerprint UART
#define FINGERPRINT_RX 16
#define FINGERPRINT_TX 17

// Display Configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

// R558-S Fingerprint: define ENABLE_FINGERPRINT to enable. If enabled, fingerprint verification is required to access any page other than the clock, and the fingerprint sensor LED will be used to indicate status (see FINGERPRINT_LED_*). If disabled, no fingerprint driver is included, and all pages are accessible without verification.
// Comment out the line below to disable: no fingerprint driver, all pages accessible without verification.
// Pins D7/D8 (GPIO13/15) - does not use D5/D6 (OLED I2C on HW364A)
#define ENABLE_FINGERPRINT
#define FINGERPRINT_BAUD 57600

// R558-S LED (cmd 0x3C): 0=off, 1=red(0x04), 2=green(0x02), 3=blue(0x01). 0 = skip.
#define FINGERPRINT_LED_READY 2  // at startup when sensor ready
#define FINGERPRINT_LED_ERROR 1  // on enroll/command error
#define FINGERPRINT_LED_ENROLL 3 // during FINGER_ENROLL
#define FINGERPRINT_LED_MATCH 2  // on successful finger match

// Application Configuration
#define TOTP_PERIOD 30
#define DISPLAY_UPDATE_INTERVAL 1000
#define BUTTON_DEBOUNCE_MS 200
#define CONFIG_FILE "/totp_config.json"
// If no button press for this many seconds when not on clock: go to clock and clear auth
#define INACTIVITY_TIMEOUT_SEC 30
// How long to show fingerprint error screen before returning to clock (ms)
#define AUTH_ERROR_DISPLAY_MS 2000
// Fingerprint poll interval (ms) - higher = smoother UI/button, slower finger detection
#define FINGERPRINT_POLL_INTERVAL_MS 280

#endif // CONFIG_H