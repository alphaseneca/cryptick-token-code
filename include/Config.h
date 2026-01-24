#ifndef CONFIG_H
#define CONFIG_H

// OLED Configuration - modify these for your display
#define OLED_WIDTH 128
#define OLED_HEIGHT 64
#define OLED_SDA 14  // D6
#define OLED_SCL 12  // D5
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C

// Button Configuration
#define BUTTON_PIN 0
#define BUTTON_DEBOUNCE_MS 200

// TOTP Configuration
#define CONFIG_FILE "/totp_config.json"
#define TOTP_PERIOD 30
#define DISPLAY_UPDATE_INTERVAL 1000

// WiFi Configuration
#define AP_SSID "TOTP-Device"
#define AP_PASSWORD "12345678"

#endif

