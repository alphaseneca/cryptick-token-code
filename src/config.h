#ifndef CONFIG_H
#define CONFIG_H

// Hardware Pin Configuration - HW364A NodeMCU-style with built-in OLED
#define OLED_SDA 14 // GPIO14 (D5) - built-in OLED SDA
#define OLED_SCL 12 // GPIO12 (D6) - built-in OLED SCL
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C
#define BUTTON_PIN 0 // GPIO0 (Flash button). If boot is intermittent: try better USB/cable, 100–470µF on 3.3V; don’t hold button at power-on.

// Display Configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

// WiFi Access Point Configuration
#define AP_SSID "TOTP-Device"
#define AP_PASSWORD "12345678"

// R558-S Fingerprint (comment out ENABLE_FINGERPRINT to disable at compile time)
// Pins D7/D8 (GPIO13/15) - does not use D5/D6 (OLED I2C on HW364A)
#define ENABLE_FINGERPRINT
#define FINGERPRINT_RX 13 // GPIO13 (D7) - ESP RX <- sensor TX
#define FINGERPRINT_TX 15 // GPIO15 (D8) - ESP TX -> sensor RX
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
// Fingerprint poll interval (ms) - higher = smoother UI/button, slower finger detection
#define FINGERPRINT_POLL_INTERVAL_MS 280

#endif