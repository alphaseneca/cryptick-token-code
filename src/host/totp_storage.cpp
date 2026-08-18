#include "totp_storage.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <new>
#include "oath_ops.h"
#include "secret_crypto.h"
#include "totp.h"

#define CONFIG_SCHEMA_V2 2

static bool wrap_cred_secret(const TOTPCredential &cred, char *b64, size_t cap)
{
    uint8_t raw[OATH_MAX_SECRET];
    int n = totp_base32_decode(cred.secret.c_str(), raw, (int)sizeof(raw));
    if (n <= 0)
        return false;
    return secret_crypto_wrap(raw, (size_t)n, b64, cap);
}

static bool unwrap_to_cred_secret(const char *b64, TOTPCredential &cred)
{
    uint8_t raw[OATH_MAX_SECRET];
    size_t n = 0;
    if (!secret_crypto_unwrap(b64, raw, sizeof(raw), &n) || n == 0)
        return false;
    cred.secret = oath_secret_to_base32(raw, (uint8_t)n);
    return true;
}

void storage_load_config(TOTPCredential *credentials, size_t max_count, size_t *count)
{
    *count = 0;
    if (!credentials || max_count == 0)
        return;
    if (!secret_crypto_init()) {
        CLOG_E("STOR", "wrap-key init failed");
        return;
    }
    if (!LittleFS.exists(CONFIG_FILE))
        return;

    File file = LittleFS.open(CONFIG_FILE, "r");
    if (!file)
        return;

    DynamicJsonDocument *doc = new (std::nothrow) DynamicJsonDocument(4096);
    if (!doc) {
        file.close();
        return;
    }
    if (deserializeJson(*doc, file) != DeserializationError::Ok) {
        file.close();
        delete doc;
        return;
    }
    file.close();

    bool need_rewrite = false;
    JsonArray arr = (*doc)["accounts"];
    for (JsonObject obj : arr) {
        if (*count >= max_count)
            break;
        TOTPCredential &cred = credentials[*count];
        cred.label = obj["label"].as<String>();
        cred.issuer = obj["issuer"].as<String>();
        cred.digits = obj["digits"] | 6;
        cred.period = obj["period"] | 30;
        cred.algorithm = "SHA1";
        cred.secret = "";

        const char *sec_enc = obj["sec"] | (const char *)nullptr;
        const char *plain = obj["secret"] | (const char *)nullptr;

        if (sec_enc && sec_enc[0]) {
            if (!unwrap_to_cred_secret(sec_enc, cred)) {
                CLOG_E("STOR", "unwrap fail label=%s — skip",
                                   cred.label.c_str());
                continue;
            }
        } else if (plain && plain[0]) {
            /* v1 migration: plaintext secret in JSON */
            cred.secret = plain;
            need_rewrite = true;
        } else {
            continue;
        }

        if (cred.label.length() == 0 && cred.issuer.length() == 0)
            continue;
        (*count)++;
    }
    delete doc;

    if (need_rewrite && *count > 0) {
        CLOG_D("STOR", "migrating plaintext secrets → AES-GCM");
        storage_save_config(credentials, *count);
    }
}

void storage_save_config(const TOTPCredential *credentials, size_t count)
{
    if (!secret_crypto_init()) {
        CLOG_E("STOR", "save aborted — no wrap key");
        return;
    }

    DynamicJsonDocument *doc = new (std::nothrow) DynamicJsonDocument(4096);
    if (!doc)
        return;
    (*doc)["v"] = CONFIG_SCHEMA_V2;
    JsonArray arr = doc->createNestedArray("accounts");
    if (!credentials)
        count = 0;
    for (size_t i = 0; i < count; i++) {
        char b64[SECRET_CRYPTO_B64_MAX];
        if (!wrap_cred_secret(credentials[i], b64, sizeof(b64))) {
            CLOG_E("STOR", "wrap fail idx=%u — skip entry", (unsigned)i);
            continue;
        }
        JsonObject obj = arr.createNestedObject();
        obj["label"] = credentials[i].label;
        obj["issuer"] = credentials[i].issuer;
        obj["digits"] = credentials[i].digits;
        obj["period"] = credentials[i].period;
        obj["algorithm"] = "SHA1";
        obj["sec"] = b64;
        /* intentional: no plaintext "secret" field */
    }
    File file = LittleFS.open(CONFIG_FILE, "w");
    if (!file) {
        delete doc;
        return;
    }
    serializeJson(*doc, file);
    file.close();
    delete doc;
}

void loadConfiguration(std::vector<TOTPCredential> &credentials)
{
    static TOTPCredential buf[OATH_MAX_CREDS];
    size_t count = 0;
    storage_load_config(buf, OATH_MAX_CREDS, &count);
    credentials.clear();
    for (size_t i = 0; i < count; i++)
        credentials.push_back(buf[i]);
    if (count > 0)
        CLOG_I("STOR", "loaded %u credentials (encrypted at rest)", (unsigned)count);
}

void saveConfiguration(const std::vector<TOTPCredential> &credentials)
{
    storage_save_config(credentials.empty() ? nullptr : credentials.data(), credentials.size());
    CLOG_I("STOR", "config saved n=%u", (unsigned)credentials.size());
}
