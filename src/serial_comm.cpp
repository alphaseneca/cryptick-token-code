#include "serial_comm.h"
#include "totp_core.h"
#include "storage.h"
#include <Arduino.h>

static String trimStr(const String &s)
{
    String t = s;
    t.trim();
    return t;
}

static void printDateTime(Stream &serial, const DateTime &dt)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d (unix: %lu)",
             dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second(), (unsigned long)dt.unixtime());
    serial.println(buf);
}

void processSerialCommands(Stream &serial, RTC_DS3231 &rtc, std::vector<TOTPAccount> &accounts)
{
    static String line = "";
    while (serial.available())
    {
        char c = (char)serial.read();
        if (c == '\r')
            continue;
        if (c == '\n')
        {
            String cmd = trimStr(line);
            line = "";
            if (cmd.length() == 0)
                return;

            // Tokenize
            int firstSpace = cmd.indexOf(' ');
            String name = (firstSpace == -1) ? cmd : cmd.substring(0, firstSpace);
            String args = (firstSpace == -1) ? String("") : cmd.substring(firstSpace + 1);
            name.toUpperCase();

            if (name == "TIME")
            {
                DateTime now = rtc.now();
                serial.print("RTC: ");
                printDateTime(serial, now);
            }
            else if (name == "SETTIME")
            {
                args.trim();
                if (args.length() == 0)
                {
                    serial.println("Usage: SETTIME <unix_timestamp>");
                }
                else
                {
                    unsigned long ts = args.toInt();
                    if (ts == 0)
                    {
                        serial.println("Invalid timestamp");
                    }
                    else
                    {
                        rtc.adjust(DateTime((uint32_t)ts));
                        serial.print("RTC updated: ");
                        printDateTime(serial, rtc.now());
                    }
                }
            }
            else if (name == "ACCOUNTS" || name == "LIST")
            {
                serial.printf("Accounts: %u\n", (unsigned)accounts.size());
                for (size_t i = 0; i < accounts.size(); ++i)
                {
                    const TOTPAccount &a = accounts[i];
                    serial.printf("[%u] %s | %s | %dd | period=%d\n", (unsigned)i, a.name.c_str(), a.issuer.c_str(), a.digits, a.period);
                }
            }
            else if (name == "TOTP" || name == "GET")
            {
                args.trim();
                if (args.length() == 0)
                {
                    serial.println("Usage: TOTP <index>");
                }
                else
                {
                    int idx = args.toInt();
                    if (idx < 0 || idx >= (int)accounts.size())
                    {
                        serial.println("Invalid account index");
                    }
                    else
                    {
                        time_t ts = rtc.now().unixtime();
                        String gen = generateTOTP(accounts[idx], ts);
                        serial.printf("Account [%d] %s -> %s (remaining %ld)\n", idx, accounts[idx].name.c_str(), gen.c_str(), (long)(accounts[idx].period - (ts % accounts[idx].period)));
                    }
                }
            }
            else if (name == "ADD")
            {
                // Usage: ADD Name|Issuer|Secret|digits|period|algorithm
                args.trim();
                if (args.length() == 0)
                {
                    serial.println("Usage: ADD Name|Issuer|Secret|digits|period|algorithm");
                }
                else
                {
                    // split by '|'
                    std::vector<String> parts;
                    int start = 0;
                    int len = args.length();
                    for (int i = 0; i <= len; ++i)
                    {
                        if (i == len || args.charAt(i) == '|')
                        {
                            parts.push_back(args.substring(start, i));
                            start = i + 1;
                        }
                    }
                    for (auto &p : parts)
                        p.trim();
                    if (parts.size() < 3)
                    {
                        serial.println("Not enough fields. Need at least Name|Issuer|Secret");
                    }
                    else
                    {
                        TOTPAccount a;
                        a.name = parts[0];
                        a.issuer = parts[1];
                        a.secret = parts[2];
                        a.digits = (parts.size() > 3 && parts[3].length()) ? parts[3].toInt() : 6;
                        a.period = (parts.size() > 4 && parts[4].length()) ? parts[4].toInt() : 30;
                        a.algorithm = (parts.size() > 5 && parts[5].length()) ? parts[5] : String("SHA1");

                        // Validate secret by attempting Base32 decode
                        int maxLen = a.secret.length() * 5 / 8 + 8;
                        uint8_t *buf = (uint8_t *)malloc(maxLen);
                        if (!buf)
                        {
                            serial.println("Memory error");
                        }
                        else
                        {
                            int ret = base32_decode(a.secret.c_str(), buf, maxLen);
                            free(buf);
                            if (ret <= 0)
                            {
                                serial.println("Invalid Base32 secret");
                            }
                            else
                            {
                                accounts.push_back(a);
                                saveConfiguration(accounts);
                                serial.printf("Added account [%u] %s\n", (unsigned)accounts.size() - 1, a.name.c_str());
                            }
                        }
                    }
                }
            }
            else if (name == "DELETE" || name == "DEL")
            {
                args.trim();
                if (args.length() == 0)
                {
                    serial.println("Usage: DELETE <index>");
                }
                else
                {
                    int idx = args.toInt();
                    if (idx < 0 || idx >= (int)accounts.size())
                    {
                        serial.println("Invalid account index");
                    }
                    else
                    {
                        serial.printf("Deleting account [%d] %s\n", idx, accounts[idx].name.c_str());
                        accounts.erase(accounts.begin() + idx);
                        saveConfiguration(accounts);
                        serial.println("Deleted and saved configuration");
                    }
                }
            }
            else if (name == "HELP" || name == "?")
            {
                serial.println("Available commands:");
                serial.println("TIME                - show RTC time");
                serial.println("SETTIME <unix>      - set RTC time");
                serial.println("ACCOUNTS | LIST     - list stored accounts");
                serial.println("TOTP <index>        - show generated TOTP for account index");
                serial.println("ADD Name|Issuer|Secret|digits|period|algorithm - add account");
                serial.println("DELETE <index>      - delete account and save");
            }
            else
            {
                serial.print("Unknown command: ");
                serial.println(cmd);
                serial.println("Type HELP for commands");
            }
        }
        else
        {
            line += c;
            // prevent runaway length
            if (line.length() > 256)
                line = line.substring(line.length() - 256);
        }
    }
}
