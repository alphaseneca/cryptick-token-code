#include "serial_comm.h"
#include "app_config.h"
#include "totp_storage.h"
#include "../core/fido2/device.h"
#include <RTClib.h>
#ifdef ENABLE_FINGERPRINT
#include "../drivers/fingerprint_r558s.h"
#endif
#include "tusb.h" // Low-level TinyUSB for direct CDC access


static String trimStr(const String &s)
{
    String t = s;
    t.trim();
    return t;
}

/** Decode %XX and + in a URI component. */
static String url_decode(const String &s)
{
    String out;
    for (int i = 0; i < (int)s.length(); i++)
    {
        char c = s[i];
        if (c == '+')
            out += ' ';
        else if (c == '%' && i + 2 < (int)s.length())
        {
            int hi = s[i + 1], lo = s[i + 2];
            hi = (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= '0' && hi <= '9') ? hi - '0' : 0;
            lo = (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= '0' && lo <= '9') ? lo - '0' : 0;
            out += (char)((hi << 4) | lo);
            i += 2;
        }
        else
            out += c;
    }
    return out;
}

/** Parse otpauth://totp/LABEL?secret=BASE32&issuer=X&digits=6&period=30 (or otp:// as alias). */
static bool parse_otpauth_uri(const String &uri, TOTPCredential &out)
{
    String u = uri;
    u.trim();
    if (u.startsWith("otp://"))
        u = "otpauth://" + u.substring(6);
    if (!u.startsWith("otpauth://totp/"))
        return false;
    int pathStart = 14; // after "otpauth://totp/"
    int q = u.indexOf('?');
    String path = (q >= 0) ? u.substring(pathStart, q) : u.substring(pathStart);
    String query = (q >= 0) ? u.substring(q + 1) : "";
    path = url_decode(path);
    int colon = path.indexOf(':');
    if (colon >= 0)
    {
        out.issuer = path.substring(0, colon);
        out.label = path.substring(colon + 1);
    }
    else
    {
        out.issuer = "";
        out.label = path;
    }
    out.secret = "";
    out.digits = 6;
    out.period = 30;
    out.algorithm = "SHA1";
    for (int i = 0; i < (int)query.length(); )
    {
        int amp = query.indexOf('&', i);
        String pair = (amp >= 0) ? query.substring(i, amp) : query.substring(i);
        i = (amp >= 0) ? amp + 1 : query.length();
        int eq = pair.indexOf('=');
        if (eq < 0)
            continue;
        String key = pair.substring(0, eq);
        String val = url_decode(pair.substring(eq + 1));
        if (key == "secret")
            out.secret = val;
        else if (key == "issuer" && val.length())
            out.issuer = val;
        else if (key == "digits")
            out.digits = val.toInt() ? val.toInt() : 6;
        else if (key == "period")
            out.period = val.toInt() ? val.toInt() : 30;
        else if (key == "algorithm" && val.length())
            out.algorithm = val;
    }
    return (out.secret.length() > 0);
}

static void print_date_time(Stream &serial)
{
    uint32_t t = device_get_time_utc();
    unsigned long sec = (unsigned long)t;
    unsigned long min = sec / 60; sec %= 60;
    unsigned long hour = min / 60; min %= 60;
    unsigned long days = hour / 24; hour %= 24;
    int year = 1970;
    int month_days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    while (days >= 365)
    {
        int dpy = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        if (days < (unsigned long)dpy) break;
        days -= dpy;
        year++;
    }
    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) month_days[1] = 29;
    int month = 0;
    while (month < 12 && days >= (unsigned long)month_days[month]) { days -= month_days[month]; month++; }
    int day = (int)days + 1;
    month++;
    serial.printf("%04d-%02d-%02d %02lu:%02lu:%02lu (unix: %lu)\n",
        year, month, day, hour, min, sec, (unsigned long)t);
}

void processSerialCommands(Stream &serial, std::vector<TOTPCredential> &credentials,
    void *finger, bool fingerprintReady)
{
#ifdef ENABLE_FINGERPRINT
    R558SFingerprint *fp = (R558SFingerprint *)finger;
#else
    (void)finger;
    (void)fingerprintReady;
#endif
    static String line = "";
    
    // Use low-level TinyUSB CDC available check
    while (tud_cdc_available())
    {
        char c = (char)tud_cdc_read_char();
        yield();


        
        // Echo back characters for interactivity (except newline which we handle below)
        if (c != '\n' && c != '\r' && c >= 32 && c <= 126) {
            serial.print(c);
            serial.flush();
        }


        if (c == '\b' || c == 0x7F) // Backspace or DEL
        {
            if (line.length() > 0) {
                line.remove(line.length() - 1);
                serial.print("\b \b"); // Erasure on terminal
            }
            continue;
        }

        if (c == '\r' || c == '\n')
        {
            String cmd = trimStr(line);
            line = "";
            serial.println(); // New line after command entered
            
            if (cmd.length() == 0) {
                serial.print("cryptick> ");
                continue;
            }

            int firstSpace = cmd.indexOf(' ');

            String name = (firstSpace == -1) ? cmd : cmd.substring(0, firstSpace);
            String args = (firstSpace == -1) ? String("") : cmd.substring(firstSpace + 1);
            args.trim();
            name.toUpperCase();

            if (name == "DATE")
            {
                if (args.length() == 0)
                {
                    serial.print("DATE ");
                    print_date_time(serial);
                }
                else
                {
                    unsigned long ts = (unsigned long)args.toInt();
                    if (ts == 0)
                        serial.println("Invalid timestamp");
                    else
                    {
                        DateTime dt((uint32_t)ts);
                        extern RTC_DS3231 rtc;
                        rtc.adjust(dt);
                        serial.print("DATE ");
                        print_date_time(serial);
                    }
                }
            }
            else if (name == "SETTIME")
            {
                if (args.length() == 0)
                    serial.println("Usage: SETTIME <unix_timestamp>");
                else
                {
                    unsigned long ts = (unsigned long)args.toInt();
                    if (ts == 0)
                        serial.println("Invalid timestamp");
                    else
                    {
                        DateTime dt((uint32_t)ts);
                        extern RTC_DS3231 rtc;
                        rtc.adjust(dt);
                        serial.print("DATE ");
                        print_date_time(serial);
                    }
                }
            }
            else if (name == "TOTP_LIST")
            {
                serial.printf("TOTP_LIST %u\n", (unsigned)credentials.size());
                for (size_t i = 0; i < credentials.size(); ++i)
                {
                    const TOTPCredential &c = credentials[i];
                    serial.printf("[%u] %s | %s | %dd | period=%d\n", (unsigned)i, c.label.c_str(), c.issuer.c_str(), c.digits, c.period);
                }
            }
            else if (name == "TOTP")
            {
                if (args.length() == 0)
                    serial.println("Usage: TOTP <index>");
                else
                {
                    int idx = args.toInt();
                    if (idx < 0 || (size_t)idx >= credentials.size())
                        serial.println("Invalid index");
                    else
                    {
                        uint32_t ts = device_get_time_utc();
                        String gen = totp_generate(credentials[idx], ts);
                        unsigned long rem = credentials[idx].period - (ts % (unsigned long)credentials[idx].period);
                        serial.printf("TOTP [%d] %s -> %s (remaining %lu)\n", idx, credentials[idx].label.c_str(), gen.c_str(), rem);
                    }
                }
            }
            else if (name == "TOTP_ADD")
            {
                if (args.length() == 0)
                {
                    serial.println("Usage: TOTP_ADD <otpauth_uri>");
                    serial.println("Example: TOTP_ADD otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example");
                }
                else
                {
                    TOTPCredential cred;
                    if (!parse_otpauth_uri(args, cred))
                    {
                        serial.println("Invalid otpauth URI (use otpauth://totp/... or otp://totp/...)");
                        continue;
                    }
                    int maxLen = cred.secret.length() * 5 / 8 + 8;
                    uint8_t *buf = (uint8_t *)malloc((size_t)maxLen);
                    if (!buf)
                    {
                        serial.println("Memory error");
                        continue;
                    }
                    int ret = totp_base32_decode(cred.secret.c_str(), buf, maxLen);
                    free(buf);
                    if (ret <= 0)
                    {
                        serial.println("Invalid Base32 secret");
                        continue;
                    }
                    credentials.push_back(cred);
                    saveConfiguration(credentials);
                    serial.printf("TOTP_ADD [%u] %s\n", (unsigned)credentials.size() - 1, cred.label.c_str());
                }
            }
            else if (name == "TOTP_DELETE")
            {
                if (args.length() == 0)
                    serial.println("Usage: TOTP_DELETE <index>");
                else
                {
                    int idx = args.toInt();
                    if (idx < 0 || (size_t)idx >= credentials.size())
                        serial.println("Invalid index");
                    else
                    {
                        serial.printf("TOTP_DELETE [%d] %s\n", idx, credentials[idx].label.c_str());
                        credentials.erase(credentials.begin() + idx);
                        saveConfiguration(credentials);
                        serial.println("OK");
                    }
                }
            }
#ifdef ENABLE_FINGERPRINT
            else if (fingerprintReady && fp && (name == "FINGER_ENROLL" || name == "FINGER_ADD"))
            {
                uint16_t id = 0xFFFF;
                if (args.length())
                    id = (uint16_t)args.toInt();
#if FINGERPRINT_LED_ENROLL
                fp->setLed(FINGERPRINT_LED_ENROLL);
#endif
                serial.println("FINGER_ENROLL: Follow the step-by-step prompts below.");
                int r = fp->enrollFingerprint(id, &serial);
                serial.print("Enroll result: ");
                serial.println(R558SFingerprint::getErrorMessage(r));
                if (r == 0)
                {
                    uint16_t n;
                    fp->getTemplateCount(&n);
                    serial.printf("Stored. Total templates: %u\n", (unsigned)n);
#if FINGERPRINT_LED_READY
                    fp->setLed(FINGERPRINT_LED_READY);
#endif
                }
                else
                {
#if FINGERPRINT_LED_ERROR
                    fp->setLed(FINGERPRINT_LED_ERROR);
#endif
                }
            }
            else if (fingerprintReady && fp && (name == "FINGER_DELETE" || name == "FINGER_DEL"))
            {
                if (args.length() == 0)
                    serial.println("Usage: FINGER_DELETE <id>");
                else
                {
                    uint16_t id = (uint16_t)args.toInt();
                    int r = fp->deleteModel(id);
                    serial.print("Delete: ");
                    serial.println(R558SFingerprint::getErrorMessage(r));
                }
            }
            else if (fingerprintReady && fp && name == "FINGER_COUNT")
            {
                uint16_t n;
                int r = fp->getTemplateCount(&n);
                if (r == 0)
                    serial.printf("Templates: %u\n", (unsigned)n);
                else
                    serial.printf("Failed: %s\n", R558SFingerprint::getErrorMessage(r));
            }
            else if (fingerprintReady && fp && (name == "FINGER_CLEAR" || name == "FINGER_EMPTY"))
            {
                int r = fp->emptyDatabase();
                serial.print("Clear all: ");
                serial.println(R558SFingerprint::getErrorMessage(r));
            }
#endif
            else if (name == "HELP" || name == "?")
            {
                serial.println("Commands: DATE [unix_ts] | SETTIME <unix> | TOTP_ADD <otpauth_uri> | TOTP_LIST | TOTP <index> | TOTP_DELETE <index>");
#ifdef ENABLE_FINGERPRINT
                if (fingerprintReady)
                    serial.println("FINGER_ENROLL [id] | FINGER_DELETE <id> | FINGER_COUNT | FINGER_CLEAR");
#endif
            }
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
