# TOTP Hardware Device

A hardware-based Time-based One-Time Password (TOTP) authenticator built with ESP8266 and OLED display. This device generates secure TOTP codes for two-factor authentication, providing a standalone alternative to smartphone authenticator apps.

## Features

- **Hardware TOTP Generator**: Generates RFC 6238 compliant TOTP codes
- **OLED Display Interface**: 128x64 pixel display with dual-page UI (Clock + TOTP)
- **Web Configuration**: Easy setup and management via browser
- **Multiple Accounts**: Store and cycle through multiple TOTP accounts
- **RTC Time Sync**: DS3231 real-time clock for accurate timekeeping
- **Persistent Storage**: Account secrets stored securely in LittleFS
- **Button Navigation**: Physical button to cycle through pages and accounts
- **WiFi Access Point**: Built-in AP for configuration (no router needed)

## Hardware Requirements

### Components

- **ESP8266** development board (ESP-12E/NodeMCU)
- **SSD1306 OLED Display** (128x64, I2C)
- **DS3231 RTC Module** (I2C)
- **Button** (optional, uses built-in FLASH button on most boards)

### Pin Connections

```
OLED Display (SSD1306):
├── VCC → 3.3V
├── GND → GND
├── SDA → GPIO14 (D5)
└── SCL → GPIO12 (D6)

RTC Module (DS3231):
├── VCC → 3.3V
├── GND → GND
├── SDA → GPIO14 (D5)
└── SCL → GPIO12 (D6)

Button:
└── GPIO0 (FLASH button on most ESP8266 boards)
```

**Note**: OLED and RTC share the same I2C bus (SDA/SCL pins).

## Installation

### Using PlatformIO (Recommended)

1. **Install PlatformIO**

   ```bash
   pip install platformio
   ```

2. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd totp-device
   ```

3. **Build and upload**

   ```bash
   # Production build
   pio run -e hw364a -t upload

   # Debug build (with verbose output)
   pio run -e debug -t upload
   ```

4. **Monitor serial output**
   ```bash
   pio device monitor
   ```

### Arduino IDE

1. Install required libraries via Library Manager:
   - Adafruit SSD1306
   - Adafruit GFX Library
   - RTClib
   - ArduinoJson
   - TOTP library (lucadentella)

2. Open `src/main.cpp` in Arduino IDE
3. Select board: "NodeMCU 1.0 (ESP-12E Module)"
4. Upload to board

## Quick Start Guide

### First Boot

1. **Power on the device**
   - Device creates WiFi AP: `TOTP-Device`
   - Default password: `12345678`

2. **Initial display sequence**

   ```
   TOTP Device
   Initializing...
   → Checking RTC...
   → RTC OK!
   → WiFi AP Ready
   ```

3. **Connect to the device**
   - Connect phone/computer to "TOTP-Device" WiFi
   - Open browser and go to: `http://192.168.4.1`

### Adding Your First Account

1. **Sync time** (Important!)
   - Click "Sync Time" button on web interface
   - This sets the RTC to your browser's time

2. **Add account**
   - Account Name: e.g., "Gmail"
   - Issuer: e.g., "Google"
   - Secret Key: Your Base32 secret (from authenticator setup QR code)
   - Digits: Usually 6
   - Click "Add"

3. **View on device**
   - Press the button to switch to TOTP page
   - Your code will be displayed with countdown timer

## Usage

### Display Navigation

The device has two display pages:

**Clock Page** (Default)

```
[WiFi]              [Date]

       HH:MM:SS

[User]          [Battery]
```

**TOTP Page** (Press button)

```
[Account]        [Time]

      123456

[Issuer]          [30s]
```

### Button Controls

- **Single Press**:
  - Clock → First TOTP account
  - TOTP → Next account
  - Last account → Clock

### Web Interface

Access at `http://192.168.4.1` when connected to device WiFi.

**Features:**

- Time synchronization
- Add/delete accounts
- View account list
- Get current TOTP codes via API

## API Reference

### REST Endpoints

#### Get Current TOTP Code

```bash
GET /totp?account=<name>
```

**Response:**

```json
{
	"account": "Gmail",
	"issuer": "Google",
	"code": "123456",
	"timeRemaining": 25
}
```

#### List All Accounts

```bash
GET /list
```

**Response:**

```json
{
	"accounts": [
		{
			"name": "Gmail",
			"issuer": "Google",
			"digits": 6,
			"algorithm": "SHA1"
		}
	]
}
```

#### Add Account

```bash
POST /add
Content-Type: application/json

{
  "name": "GitHub",
  "issuer": "GitHub",
  "secret": "JBSWY3DPEHPK3PXP",
  "digits": 6
}
```

#### Delete Account

```bash
POST /delete
Content-Type: application/json

{
  "index": 0
}
```

#### Set RTC Time

```bash
POST /settime
Content-Type: application/x-www-form-urlencoded

timestamp=1234567890
```

## Project Structure

```
totp-device/
├── src/
│   ├── main.cpp           # Main application entry point
│   ├── config.h           # Hardware pin definitions & constants
│   ├── types.h            # Data structures (TOTPAccount, DeviceStatus)
│   ├── totp_core.h/cpp    # TOTP generation & Base32 decoding
│   ├── storage.h/cpp      # LittleFS configuration management
│   ├── display.h/cpp      # OLED rendering functions
│   ├── navigation.h/cpp   # Button handling & page navigation
│   └── web_server.h/cpp   # HTTP server & API handlers
├── platformio.ini         # Build configuration
└── README.md
```

### Code Architecture

The firmware is organized into functional modules:

**Core Modules:**

- `main.cpp`: Hardware initialization, main loop
- `config.h`: Centralized configuration (pins, WiFi, timing)
- `types.h`: Shared data structures

**Feature Modules:**

- `totp_core`: TOTP algorithm, Base32 decoding
- `storage`: JSON-based account persistence
- `display`: OLED UI rendering (clock & TOTP pages)
- `navigation`: Button debouncing & page switching
- `web_server`: HTTP endpoints & web UI

**Design Principles:**

- No unnecessary wrapper classes
- Direct use of proven libraries
- Clear separation of concerns
- Minimal global state
- Easy to test and debug

## Configuration

### Customizing Settings

Edit `src/config.h`:

```cpp
// Pin Configuration
#define OLED_SDA 14              // Change I2C pins
#define OLED_SCL 12
#define BUTTON_PIN 0             // Navigation button

// WiFi AP Settings
#define AP_SSID "TOTP-Device"    // Change AP name
#define AP_PASSWORD "12345678"   // Change AP password

// Display Settings
#define DISPLAY_UPDATE_INTERVAL 1000  // Refresh rate (ms)
#define TOTP_PERIOD 30                // TOTP refresh period
```

## Troubleshooting

### Display Issues

**OLED not working:**

```
✓ Check I2C connections (SDA/SCL)
✓ Verify 3.3V power supply
✓ Confirm I2C address: 0x3C
✓ Test with I2C scanner sketch
```

**Display shows "RTC Error!":**

```
✓ Check RTC module connections
✓ Verify RTC has backup battery
✓ Ensure both devices on same I2C bus
✓ Check serial output for details
```

### TOTP Code Issues

**Codes don't match authenticator app:**

```
1. Sync time via web interface
2. Verify secret key is correct Base32
3. Check algorithm matches (usually SHA1)
4. Ensure RTC hasn't lost power
```

**"Invalid Secret" displayed:**

```
✓ Secret must be Base32 encoded
✓ Remove spaces from secret key
✓ Use uppercase letters A-Z, digits 2-7
```

### WiFi Issues

**Can't connect to device:**

```
✓ Look for "TOTP-Device" WiFi network
✓ Password: 12345678
✓ Device creates AP automatically
✓ Check OLED for confirmation
```

**Web interface not loading:**

```
✓ Ensure connected to device WiFi
✓ Try: http://192.168.4.1
✓ Clear browser cache
✓ Check serial monitor for errors
```

### Serial Debug Commands

Connect serial monitor (57600 baud) and use:

```bash
TIME              # Show current RTC time
SETTIME <unix>    # Set RTC time manually
ACCOUNTS          # List all configured accounts
COMPARE           # Compare device code with app
```

## Advanced Usage

### Manual Time Setting

If web time sync doesn't work:

```bash
# On Linux/Mac
date +%s

# Send via serial
SETTIME 1704067200
```

### Multiple Accounts Navigation

1. Press button once → Shows first TOTP account
2. Press again → Shows second account
3. Continue pressing → Cycles through all accounts
4. After last account → Returns to clock page

### Storage Location

Account data stored in: `/totp_config.json` (LittleFS)

**Format:**

```json
{
	"accounts": [
		{
			"name": "Gmail",
			"secret": "JBSWY3DPEHPK3PXP",
			"issuer": "Google",
			"digits": 6,
			"period": 30,
			"algorithm": "SHA1"
		}
	]
}
```

## Security Considerations

- ✓ Secrets stored in flash memory (not encrypted)
- ✓ WiFi AP uses WPA2 encryption
- ✓ No cloud connectivity (fully offline)
- ✓ Standard RFC 6238 TOTP implementation
- ✓ Base32 encoding per RFC 4648
- ⚠ Physical access = full access to secrets
- ⚠ Keep device physically secure

## Libraries & Dependencies

```ini
Adafruit SSD1306      # OLED display driver
Adafruit GFX Library  # Graphics primitives
RTClib                # DS3231 RTC interface
ArduinoJson           # JSON parsing/generation
TOTP library          # RFC 6238 implementation (SHA1)
ESP8266WiFi           # Built-in WiFi
ESP8266WebServer      # Built-in HTTP server
LittleFS              # Built-in filesystem
```

## Building from Source

### Build Environments

**Production** (`hw364a`):

- Optimized for size and speed
- Minimal debug output
- Default environment

**Debug** (`debug`):

- Verbose serial output
- Exception decoder enabled
- For development only

```bash
# Build specific environment
pio run -e hw364a
pio run -e debug

# Upload to device
pio run -e hw364a -t upload

# Clean build
pio run -t clean
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NewFeature`)
3. Follow existing code style
4. Test thoroughly on hardware
5. Update documentation
6. Submit pull request

## Future Enhancements

- [ ] Battery level monitoring
- [ ] Multiple user profiles
- [ ] QR code scanning (with camera module)
- [ ] SHA256/SHA512 support
- [ ] Encrypted storage
- [ ] NTP time sync option
- [ ] Deep sleep for battery operation

## License

MIT License - See LICENSE file for details

## Credits

- **RFC 6238**: TOTP Standard
- **RFC 4648**: Base32 Encoding
- **Adafruit**: Display libraries
- **Luca Dentella**: TOTP library
- **ESP8266 Community**: Core firmware

## Support

**Issues?** Open an issue on GitHub with:

- Hardware details (board type, components)
- Serial monitor output
- Steps to reproduce
- Expected vs actual behavior

**Questions?** Check:

1. This README
2. Serial debug output
3. ESP8266 documentation
4. PlatformIO forums

---

**Built with ❤️ for hardware 2FA enthusiasts**
