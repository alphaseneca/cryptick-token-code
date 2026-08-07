/**
 * USB CDC: product path is logs-only.
 *
 * Product credential / time management is HID (OATH + ENTERBOOT). Optional
 * debug CLI is compiled only when CRYPTICK_SERIAL_DEBUG_CMDS is defined.
 */
#include "serial_comm.h"
#include <board_config.h>
#include "usb_device.h"
#include "tusb.h"

#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
#include "totp_storage.h"
#include "device.h"
#include "event_bus.h"
#include <RTClib.h>
#include "totp.h"
#ifdef ENABLE_FINGERPRINT
#include "fingerprint_r558s.h"
#endif
#endif

static String trimStr(const String &s)
{
    String t = s;
    t.trim();
    return t;
}

#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
static void print_date_time(Stream &serial)
{
    uint32_t t = device_get_time_utc();
    serial.printf("unix: %lu\n", (unsigned long)t);
}
#endif

void processSerialCommands(Stream &serial, std::vector<TOTPCredential> &credentials,
    void *finger, bool fingerprintReady)
{
#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
#ifdef ENABLE_FINGERPRINT
    R558SFingerprint *fp = (R558SFingerprint *)finger;
#else
    (void)finger;
    (void)fingerprintReady;
#endif
#else
    (void)credentials;
    (void)finger;
    (void)fingerprintReady;
#endif

    static String line = "";

    while (tud_cdc_available())
    {
        char c = (char)tud_cdc_read_char();
        yield();

        if (c != '\n' && c != '\r' && c >= 32 && c <= 126) {
            serial.print(c);
            serial.flush();
        }

        if (c == '\b' || c == 0x7F)
        {
            if (line.length() > 0) {
                line.remove(line.length() - 1);
                serial.print("\b \b");
            }
            continue;
        }

        if (c == '\r' || c == '\n')
        {
            String cmd = trimStr(line);
            line = "";
            serial.println();

            if (cmd.length() == 0) {
                serial.print("cryptick> ");
                continue;
            }

            int firstSpace = cmd.indexOf(' ');
            String name = (firstSpace == -1) ? cmd : cmd.substring(0, firstSpace);
            String args = (firstSpace == -1) ? String("") : cmd.substring(firstSpace + 1);
            args.trim();
            name.toUpperCase();

            /* Always available: reflash recover + help (no secrets). */
            if (name == "BOOTLOADER" || name == "DFU" || name == "DOWNLOAD")
            {
                serial.println("OK. Entering ROM download mode...");
                serial.flush();
                delay(50);
                usb_device_enter_bootloader();
            }
            else if (name == "HELP" || name == "?")
            {
                serial.println("CDC is logs. Manage TOTP/time over HID (docs/HID_HOST.md).");
                serial.println("Commands: BOOTLOADER | HELP");
#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
                serial.println("DEBUG: DATE SETTIME TOTP_* FINGER_* FIDO_RESET");
#endif
            }
#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
            else if (name == "DATE" || name == "SETTIME")
            {
                if (args.length() == 0)
                    print_date_time(serial);
                else {
                    unsigned long ts = (unsigned long)args.toInt();
                    if (ts == 0)
                        serial.println("Invalid timestamp");
                    else {
                        DateTime dt((uint32_t)ts);
                        extern RTC_DS3231 rtc;
                        rtc.adjust(dt);
                        print_date_time(serial);
                    }
                }
            }
            else if (name == "TOTP_LIST")
            {
                serial.printf("TOTP_LIST %u\n", (unsigned)credentials.size());
                for (size_t i = 0; i < credentials.size(); ++i)
                {
                    const TOTPCredential &cr = credentials[i];
                    serial.printf("[%u] %s | %s\n", (unsigned)i, cr.label.c_str(), cr.issuer.c_str());
                }
            }
            else if (name == "TOTP_ADD" && args.length())
            {
                serial.println("Use HID PUT_OTPAUTH in product mode; debug CLI incomplete.");
            }
            else if (name == "FIDO_RESET")
            {
                extern void ctap_reset();
                ctap_reset();
                serial.println("OK. FIDO2 state wiped.");
            }
#ifdef ENABLE_FINGERPRINT
            else if (fingerprintReady && fp && name == "FINGER_ENROLL")
            {
                BusEvent e{};
                e.type = EVT_CMD;
                e.kind = CMD_FP_ENROLL_START;
                e.a = 0xFFFF;
                bus_publish(e);
                serial.println("Enroll started");
            }
            else if (fingerprintReady && (name == "FINGER_ABORT"))
            {
                BusEvent e{};
                e.type = EVT_CMD;
                e.kind = CMD_FP_ENROLL_ABORT;
                bus_publish(e);
            }
#endif
#endif /* CRYPTICK_SERIAL_DEBUG_CMDS */
            else
            {
                serial.print("Unknown: ");
                serial.println(cmd);
                serial.println("HELP for commands");
            }
            serial.print("cryptick> ");
        }
        else
        {
            line += c;
            if (line.length() > 512)
                line = line.substring(line.length() - 512);
        }
    }
}
