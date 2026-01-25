#ifndef CONFIG_H
#define CONFIG_H

// Hardware Pin Configuration
#define OLED_SDA 14 // GPIO14 (D5)
#define OLED_SCL 12 // GPIO12 (D6)
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C
#define BUTTON_PIN 0 // GPIO0 (Flash button)

// Display Configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

// WiFi Access Point Configuration
#define AP_SSID "TOTP-Device"
#define AP_PASSWORD "12345678"

// Application Configuration
#define TOTP_PERIOD 30
#define DISPLAY_UPDATE_INTERVAL 1000
#define BUTTON_DEBOUNCE_MS 200
#define CONFIG_FILE "/totp_config.json"

#endif