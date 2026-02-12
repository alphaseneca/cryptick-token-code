#include "storage.h"
#include "config.h"
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <new>

#define MAX_CREDENTIALS 64

void storage_load_config(TOTPCredential *credentials, size_t max_count, size_t *count)
{
    *count = 0;
    if (!credentials || max_count == 0)
        return;
    if (!LittleFS.exists(CONFIG_FILE))
        return;

    File file = LittleFS.open(CONFIG_FILE, "r");
    if (!file)
        return;

    DynamicJsonDocument *doc = new (std::nothrow) DynamicJsonDocument(2048);
    if (!doc)
    {
        file.close();
        return;
    }
    if (deserializeJson(*doc, file) != DeserializationError::Ok)
    {
        file.close();
        delete doc;
        return;
    }
    file.close();

    JsonArray arr = (*doc)["accounts"];
    for (JsonObject obj : arr)
    {
        if (*count >= max_count)
            break;
        TOTPCredential &cred = credentials[*count];
        cred.label = obj["label"].as<String>();
        cred.secret = obj["secret"].as<String>();
        cred.issuer = obj["issuer"].as<String>();
        cred.digits = obj["digits"] | 6;
        cred.period = obj["period"] | 30;
        cred.algorithm = "SHA1";
        (*count)++;
    }
    delete doc;
}

void storage_save_config(const TOTPCredential *credentials, size_t count)
{
    DynamicJsonDocument *doc = new (std::nothrow) DynamicJsonDocument(2048);
    if (!doc)
        return;
    JsonArray arr = doc->createNestedArray("accounts");
    if (!credentials)
        count = 0;
    for (size_t i = 0; i < count; i++)
    {
        JsonObject obj = arr.createNestedObject();
        obj["label"] = credentials[i].label;
        obj["secret"] = credentials[i].secret;
        obj["issuer"] = credentials[i].issuer;
        obj["digits"] = credentials[i].digits;
        obj["period"] = credentials[i].period;
        obj["algorithm"] = "SHA1";
    }
    File file = LittleFS.open(CONFIG_FILE, "w");
    if (!file)
    {
        delete doc;
        return;
    }
    serializeJson(*doc, file);
    file.close();
    delete doc;
}

void loadConfiguration(std::vector<TOTPCredential> &credentials)
{
    static TOTPCredential buf[MAX_CREDENTIALS];
    size_t count = 0;
    storage_load_config(buf, MAX_CREDENTIALS, &count);
    credentials.clear();
    for (size_t i = 0; i < count; i++)
        credentials.push_back(buf[i]);
    if (count > 0)
        Serial.printf("Loaded %u credentials\n", (unsigned)count);
}

void saveConfiguration(const std::vector<TOTPCredential> &credentials)
{
    storage_save_config(credentials.empty() ? nullptr : credentials.data(), credentials.size());
    Serial.println("Config saved");
}
