# TOTP Hardware Device

A hardware-based Time-based One-Time Password (TOTP) device built with ESP8266/ESP32 and OLED display. This device generates TOTP codes for two-factor authentication using standard algorithms (SHA1/SHA256) and stores account information securely in JSON format.

## Features

- **Hardware TOTP Generator**: Generates TOTP codes using standard RFC 6238 algorithm
- **OLED Display**: 128x64 pixel OLED display showing current TOTP codes
- **Web Configuration Interface**: Easy setup via web browser
- **Multiple Accounts**: Support for multiple TOTP accounts
- **Secure Storage**: Account secrets stored in SPIFFS filesystem
- **Standard Algorithms**: Support for SHA1 and SHA256 HMAC
- **WiFi Manager**: Easy WiFi configuration with captive portal

## Hardware Requirements

- ESP8266 or ESP32 development board
- 128x64 OLED display (SSD1306)
- Optional: Physical buttons for navigation

## Pin Connections

### ESP8266/ESP32 to OLED Display
- VCC → 3.3V
- GND → GND
- SCL → GPIO 5 (D1 on NodeMCU)
- SDA → GPIO 4 (D2 on NodeMCU)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cryptick-token
   ```

2. **Install PlatformIO** (if not already installed)
   ```bash
   pip install platformio
   ```

3. **Build and upload**
   ```bash
   pio run --target upload
   ```

4. **Monitor serial output**
   ```bash
   pio device monitor
   ```

## Configuration

### Initial Setup

1. **Power on the device**
   - The device will create a WiFi access point named "TOTP-Device"
   - Default password: "12345678"

2. **Connect to the device**
   - Connect your computer/phone to the "TOTP-Device" WiFi network
   - Open a web browser and navigate to `http://192.168.4.1`

3. **Configure WiFi**
   - Enter your WiFi credentials
   - The device will connect to your network

### Adding TOTP Accounts

1. **Access the web interface**
   - Connect to the same WiFi network as the device
   - Find the device's IP address from the OLED display
   - Navigate to `http://<device-ip>`

2. **Add a new account**
   - Enter the account name (e.g., "Gmail")
   - Enter the issuer (e.g., "Google")
   - Enter the secret key (Base32 encoded)
   - Select number of digits (6 or 8)
   - Select algorithm (SHA1 or SHA256)
   - Click "Add Account"

### Getting TOTP Codes

- **From OLED Display**: The device automatically displays the current TOTP code
- **From Web Interface**: Navigate to `http://<device-ip>/totp?account=<account-name>`
- **API Endpoint**: `GET /totp?account=<account-name>` returns JSON with current code

## API Endpoints

### Web Interface
- `GET /` - Main configuration page
- `GET /list` - List all configured accounts
- `POST /add` - Add a new account
- `POST /delete` - Delete an account
- `GET /totp` - Get current TOTP code

### JSON API Examples

**Add Account:**
```bash
curl -X POST http://<device-ip>/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Gmail",
    "issuer": "Google",
    "secret": "JBSWY3DPEHPK3PXP",
    "digits": 6,
    "algorithm": "SHA1"
  }'
```

**Get TOTP Code:**
```bash
curl http://<device-ip>/totp?account=Gmail
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

## Security Features

- **Secure Storage**: Account secrets stored in SPIFFS filesystem
- **Base32 Encoding**: Standard encoding for secret keys
- **HMAC-SHA1/SHA256**: Industry-standard cryptographic algorithms
- **Time Synchronization**: Automatic NTP time sync
- **WiFi Security**: WPA2 encryption for configuration

## Libraries Used

- **Adafruit SSD1306**: OLED display driver
- **Adafruit GFX**: Graphics library
- **ArduinoJson**: JSON parsing and generation
- **WiFiManager**: WiFi configuration
- **Custom Crypto Library**: SHA1/SHA256/HMAC implementation
- **Custom TOTP Library**: TOTP algorithm implementation

## File Structure

```
cryptick-token/
├── src/
│   └── main.cpp              # Main application code
├── lib/
│   ├── Crypto/
│   │   ├── Crypto.h          # Crypto library header
│   │   └── Crypto.cpp        # Crypto library implementation
│   └── TOTP/
│       ├── TOTP.h            # TOTP library header
│       └── TOTP.cpp          # TOTP library implementation
├── platformio.ini            # PlatformIO configuration
└── README.md                 # This file
```

## Troubleshooting

### Common Issues

1. **OLED Display Not Working**
   - Check I2C connections
   - Verify correct I2C address (default: 0x3C)
   - Check power supply (3.3V)

2. **WiFi Connection Issues**
   - Ensure WiFi credentials are correct
   - Check if device is in range
   - Try resetting the device

3. **TOTP Codes Not Matching**
   - Verify time synchronization
   - Check secret key format (Base32)
   - Ensure correct algorithm selection

4. **Configuration Not Saving**
   - Check SPIFFS initialization
   - Verify sufficient flash memory
   - Check for file system errors

### Debug Information

Enable serial monitoring to see debug information:
```bash
pio device monitor --baud 115200
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- RFC 6238 (TOTP standard)
- RFC 4648 (Base32 encoding)
- Adafruit for OLED libraries
- ESP8266/ESP32 community

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the serial debug output
3. Open an issue on GitHub
4. Check ESP8266/ESP32 documentation 