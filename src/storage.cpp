#include "storage.h"
#include <ArduinoJson.h>
#include <LittleFS.h>
#include "config.h"

void loadConfiguration(std::vector<TOTPAccount> &accounts)
{
    if (!LittleFS.exists(CONFIG_FILE))
    {
        Serial.println("No config file, creating default");
        saveConfiguration(accounts);
        return;
    }

    File file = LittleFS.open(CONFIG_FILE, "r");
    if (!file)
    {
        Serial.println("Failed to open config file");
        return;
    }

    DynamicJsonDocument doc(2048);
    DeserializationError error = deserializeJson(doc, file);
    file.close();

    if (error)
    {
        Serial.println("Failed to parse config");
        return;
    }

    accounts.clear();
    JsonArray arr = doc["accounts"];
    for (JsonObject obj : arr)
    {
        TOTPAccount account;
        account.name = obj["name"].as<String>();
        account.secret = obj["secret"].as<String>();
        account.issuer = obj["issuer"].as<String>();
        account.digits = obj["digits"] | 6;
        account.period = obj["period"] | 30;
        account.algorithm = "SHA1";
        accounts.push_back(account);
    }

    Serial.printf("Loaded %d accounts\n", accounts.size());
}

void saveConfiguration(const std::vector<TOTPAccount> &accounts)
{
    DynamicJsonDocument doc(2048);
    JsonArray arr = doc.createNestedArray("accounts");

    for (const auto &account : accounts)
    {
        JsonObject obj = arr.createNestedObject();
        obj["name"] = account.name;
        obj["secret"] = account.secret;
        obj["issuer"] = account.issuer;
        obj["digits"] = account.digits;
        obj["period"] = account.period;
        obj["algorithm"] = "SHA1";
    }

    File file = LittleFS.open(CONFIG_FILE, "w");
    if (!file)
    {
        Serial.println("Failed to open config for writing");
        return;
    }

    serializeJson(doc, file);
    file.close();
    Serial.println("Config saved");
}