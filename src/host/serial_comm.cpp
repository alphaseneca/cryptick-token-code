/**
 * Console: logs + product recovery + OATH/TOTP CLI (same store as HID OATH).
 * With CRYPTICK_CONSOLE_UART: Stream is Serial0 (CH340).
 * With CRYPTICK_USB_STACK: TinyUSB CDC when MODE=0.
 */
#include "serial_comm.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include "usb_device.h"
#include "credential_store.h"
#include "oath_ops.h"
#include "totp_storage.h"
#include "nav_system.h"
#include <Preferences.h>

extern "C" {
#include "device.h"
#if CRYPTICK_BLE_FIDO
#include "ble_fido.h"
#endif
}

#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
#include "event_bus.h"
#ifdef ENABLE_FINGERPRINT
#include "fingerprint_r558s.h"
#endif
#endif

#include <stdlib.h>

static String trimStr(const String &s)
{
    String t = s;
    t.trim();
    return t;
}

static void print_date_time(Stream &serial)
{
    uint32_t t = device_get_time_utc();
    serial.printf("OK TIME %lu\n", (unsigned long)t);
}

static int console_available(Stream &serial)
{
#if defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK
    (void)serial;
#endif
    return serial.available();
}

static int console_read(Stream &serial)
{
    return serial.read();
}

/** LIST accounts — always prints a trailer (empty OK). */
static void cmd_totp_list(Stream &serial, const std::vector<TOTPCredential> &credentials)
{
    CredentialLock guard; /* HID OATH on core 0 may be inserting right now */
    serial.printf("OK TOTP_LIST count=%u\n", (unsigned)credentials.size());
    for (size_t i = 0; i < credentials.size(); ++i) {
        const TOTPCredential &cr = credentials[i];
        String display = oath_display_name(cr);
        serial.printf("[%u] %s\n", (unsigned)i, display.c_str());
    }
}

/**
 * Store credential (otpauth or name base32). UV when templates exist.
 * Prints OK/ERR always.
 */
static void cmd_totp_put(Stream &serial, std::vector<TOTPCredential> &credentials,
                         const String &args, const char *verb)
{
    if (args.length() == 0) {
        serial.printf("ERR %s usage: otpauth://… | name base32secret\n", verb);
        return;
    }
    TOTPCredential cred;
    const char *err = nullptr;
    if (!oath_parse_put_args(args, cred, &err)) {
        serial.printf("ERR %s %s\n", verb, err ? err : "bad args");
        return;
    }
    serial.printf("… %s confirm with finger if enrolled (or skip if no templates)\n", verb);
    serial.flush();
    if (!oath_ensure_uv("Manage")) {
        serial.printf("ERR %s UV required (place finger) or timeout\n", verb);
        return;
    }
    bool replaced = false;
    size_t count;
    {
        CredentialLock guard; /* taken after UV so the finger wait stays lock-free */
        if (!oath_put_credential(credentials, cred, &replaced)) {
            serial.printf("ERR %s storage full (max %d)\n", verb, OATH_MAX_CREDS);
            return;
        }
        count = credentials.size();
    }
    String display = oath_display_name(cred);
    serial.printf("OK %s name=%s issuer=%s label=%s %s count=%u\n",
                  verb, display.c_str(),
                  cred.issuer.c_str(), cred.label.c_str(),
                  replaced ? "replaced" : "added",
                  (unsigned)count);
}

static void cmd_totp_delete(Stream &serial, std::vector<TOTPCredential> &credentials,
                            const String &args)
{
    if (args.length() == 0) {
        serial.println("ERR TOTP_DEL usage: TOTP_DEL name | issuer:label");
        return;
    }
    serial.println("… TOTP_DEL confirm with finger if enrolled (or skip if no templates)");
    serial.flush();
    if (!oath_ensure_uv("Manage")) {
        serial.println("ERR TOTP_DEL UV required (place finger) or timeout");
        return;
    }
    size_t count;
    {
        CredentialLock guard;
        if (!oath_delete_credential(credentials, args.c_str())) {
            serial.printf("ERR TOTP_DEL not found: %s\n", args.c_str());
            return;
        }
        count = credentials.size();
    }
    serial.printf("OK TOTP_DEL name=%s count=%u\n", args.c_str(), (unsigned)count);
}

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
    (void)finger;
    (void)fingerprintReady;
#endif

    static String line = "";

    while (console_available(serial) > 0)
    {
        int ri = console_read(serial);
        if (ri < 0)
            break;
        char c = (char)ri;
        yield();

        if (c != '\n' && c != '\r' && c >= 32 && c <= 126) {
            serial.print(c);
            /* no serial.flush() per char — blocks USB CDC for ms each key */
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

            if (name == "BOOTLOADER" || name == "DFU" || name == "DOWNLOAD")
            {
                serial.println("OK. Bootloader path...");
                serial.flush();
                delay(50);
                usb_device_enter_bootloader();
            }
            else if (name == "REBOOT" || name == "RST")
            {
                serial.println("OK. Soft reboot...");
                serial.flush();
                delay(50);
#ifdef ESP32
                ESP.restart();
#endif
            }
            else if (name == "HELP" || name == "?")
            {
#if defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK
                serial.println("CDC console @ 115200 (product USB 1209:BEEE).");
#else
                serial.println("UART console (CH340). Flash: pio run -t upload --upload-port <port>");
                serial.println("Stuck ROM: esptool.py --port <PORT> run --after hard_reset");
#endif
                serial.println("Recovery: BOOTLOADER | REBOOT | HELP | LOGLEVEL [0-5] | ATTEST");
                serial.println("Display: SLEEP [sec|NOW|OFF] | WAKE   (screen only; USB stays up)");
                serial.println("TOTP (LittleFS, same as HID OATH):");
                serial.println("  TOTP_LIST | OATH LIST");
                serial.println("  TOTP_ADD otpauth://… | OATH PUT otpauth://…");
                serial.println("  TOTP_ADD name base32 | OATH PUT name base32");
                serial.println("  TOTP_DEL name | OATH DELETE name");
                serial.println("  DATE | SETTIME <unix> | OATH SET_TIME <unix>");
                serial.println("UV: finger if templates enrolled; bootstrap if none. HID path: docs/HID_HOST.md");
                serial.printf("Reset reason: %d\n", (int)esp_reset_reason());
                serial.printf("Log level now: %d (%s)  0=NONE … 5=TRACE\n",
                              (int)cryptick_log_get_level(),
                              cryptick_log_level_name(cryptick_log_get_level()));
                serial.println("Ship: pio run -e esp32-s3-n16r8-ship  |  LOGLEVEL 0 to silence runtime");
                serial.println("Logs: docs/LOGGING.md  Attest: docs/ATTESTATION.md  WebAuthn: docs/WEBAUTHN_L3.md");
#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
                serial.println("DEBUG: FINGER_ENROLL FINGER_ABORT FIDO_RESET");
#endif
            }
            else if (name == "LOGLEVEL" || name == "LOG" || name == "LEVEL")
            {
                if (args.length() == 0) {
                    serial.printf("OK LOGLEVEL %d (%s)\n",
                                  (int)cryptick_log_get_level(),
                                  cryptick_log_level_name(cryptick_log_get_level()));
                    serial.println("Set: LOGLEVEL 0..5  (NONE ERROR WARN INFO DEBUG TRACE)");
                    serial.println("Persists in NVS across reboot.");
                } else {
                    int v = args.toInt();
                    if (v < 0 || v > 5) {
                        serial.println("ERR LOGLEVEL use 0..5");
                    } else {
                        cryptick_log_set_level((cryptick_log_level_t)v);
                        serial.printf("OK LOGLEVEL %d (%s) (saved)\n",
                                      (int)cryptick_log_get_level(),
                                      cryptick_log_level_name(cryptick_log_get_level()));
                    }
                }
            }
            else if (name == "SLEEP")
            {
                String sub = args;
                sub.toUpperCase();
                if (args.length() == 0) {
                    uint16_t s = nav_system_sleep_timeout_sec();
                    serial.printf("OK SLEEP %u%s asleep=%d\n", (unsigned)s,
                                  s ? "s" : " (never)",
                                  nav_system_is_asleep() ? 1 : 0);
                    serial.printf("Set: SLEEP <sec 0..%d> | SLEEP NOW | SLEEP OFF\n",
                                  UI_SLEEP_MAX_SEC);
                    serial.println("Screen + fingerprint only — USB/FIDO stay up. Persists in NVS.");
                } else if (sub == "NOW") {
                    nav_system_sleep_now();
                    serial.println("OK SLEEP now");
                } else if (sub == "OFF" || sub == "NEVER") {
                    nav_system_set_sleep_timeout_sec(0, true);
                    serial.println("OK SLEEP never (saved)");
                } else {
                    char *end = nullptr;
                    unsigned long v = strtoul(args.c_str(), &end, 10);
                    if (end == args.c_str() || v > (unsigned long)UI_SLEEP_MAX_SEC) {
                        serial.printf("ERR SLEEP use 0..%d seconds, NOW, or OFF\n",
                                      UI_SLEEP_MAX_SEC);
                    } else {
                        nav_system_set_sleep_timeout_sec((uint16_t)v, true);
                        serial.printf("OK SLEEP %lus%s (saved)\n", v,
                                      v ? "" : " (never)");
                    }
                }
            }
            else if (name == "WAKE")
            {
                nav_system_wake();
                serial.println("OK WAKE");
            }
            else if (name == "UNPAIR" || name == "BLE_CLEAR_BONDS" || name == "CLEAR_BONDS")
            {
#if CRYPTICK_BLE_FIDO
                /*
                 * Security gap found during the on-device nav_system sweep
                 * (same action, same risk, a different front door): this
                 * CDC command wiped every BLE bond with no gate at all,
                 * unlike OATH PUT/TOTP_DEL above which already require UV
                 * via oath_ensure_uv(). Same fix, same established
                 * mechanism — a USB-connected caller now needs a finger on
                 * the sensor (or a bootstrap unit with nothing enrolled)
                 * exactly like managing TOTP credentials already does.
                 *
                 * if/else rather than early return: this branch is inline
                 * in processSerialCommands (unlike cmd_totp_put/_delete,
                 * which are their own functions), so a bare `return` here
                 * would skip the "cryptick> " reprompt every other command
                 * path falls through to below.
                 */
                serial.println("… UNPAIR confirm with finger if enrolled (or skip if no templates)");
                serial.flush();
                if (!oath_ensure_uv("Unpair")) {
                    serial.println("ERR UNPAIR UV required (place finger) or timeout");
                } else {
                    ble_fido_clear_all_bonds();
                    serial.println("OK BLE_CLEAR_BONDS all BLE bonding records deleted from token");
                }
#else
                serial.println("ERR BLE not supported in this build");
#endif
            }
            else if (name == "ATTEST" || name == "AAGUID" || name == "ATTESTATION")
            {
                uint8_t a[16];
                device_read_aaguid(a);
                serial.printf(
                    "OK AAGUID %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                    a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
                serial.printf("attest_cert_der_bytes=%d (self-signed Cryptick Token batch)\n",
                              device_attestation_cert_der_get_size());
                serial.println("docs/ATTESTATION.md — not FIDO MDS / public CA");
            }
            else if (name == "DATE" || name == "SETTIME")
            {
                if (args.length() == 0)
                    print_date_time(serial);
                else {
                    char *end = nullptr;
                    unsigned long ts = strtoul(args.c_str(), &end, 10);
                    if (ts == 0 || end == args.c_str())
                        serial.println("ERR SETTIME invalid timestamp");
                    else {
                        device_set_time_utc((uint32_t)ts);
                        print_date_time(serial);
                    }
                }
            }
            else if (name == "TOTP_LIST")
            {
                cmd_totp_list(serial, credentials);
            }
            else if (name == "TOTP_ADD")
            {
                cmd_totp_put(serial, credentials, args, "TOTP_ADD");
            }
            else if (name == "TOTP_DEL" || name == "TOTP_DELETE" || name == "TOTP_RM")
            {
                cmd_totp_delete(serial, credentials, args);
            }
            else if (name == "OATH")
            {
                /* OATH LIST | PUT … | DELETE name | SET_TIME <unix> */
                int sp = args.indexOf(' ');
                String sub = (sp < 0) ? args : args.substring(0, sp);
                String rest = (sp < 0) ? String("") : args.substring(sp + 1);
                rest.trim();
                sub.toUpperCase();
                if (sub == "LIST" || sub.length() == 0) {
                    cmd_totp_list(serial, credentials);
                } else if (sub == "PUT" || sub == "ADD") {
                    cmd_totp_put(serial, credentials, rest, "OATH PUT");
                } else if (sub == "DELETE" || sub == "DEL" || sub == "RM") {
                    cmd_totp_delete(serial, credentials, rest);
                } else if (sub == "SET_TIME" || sub == "SETTIME") {
                    if (rest.length() == 0)
                        print_date_time(serial);
                    else {
                        char *end = nullptr;
                        unsigned long ts = strtoul(rest.c_str(), &end, 10);
                        if (ts == 0 || end == rest.c_str())
                            serial.println("ERR OATH SET_TIME invalid timestamp");
                        else {
                            device_set_time_utc((uint32_t)ts);
                            print_date_time(serial);
                        }
                    }
                } else {
                    serial.println("ERR OATH unknown subcmd (LIST|PUT|DELETE|SET_TIME)");
                }
            }
#ifdef CRYPTICK_SERIAL_DEBUG_CMDS
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
                serial.println("OK Enroll started");
            }
            else if (fingerprintReady && (name == "FINGER_ABORT"))
            {
                BusEvent e{};
                e.type = EVT_CMD;
                e.kind = CMD_FP_ENROLL_ABORT;
                bus_publish(e);
                serial.println("OK Enroll abort");
            }
#endif
#endif /* CRYPTICK_SERIAL_DEBUG_CMDS */
            else
            {
                serial.print("ERR unknown: ");
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
