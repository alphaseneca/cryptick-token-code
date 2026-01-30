// Web server implementation is optional; only compile when ENABLE_WEBSERVER is defined
#ifdef ENABLE_WEBSERVER
#include "web_server.h"
#include <ArduinoJson.h>
#include "storage.h"
#include "totp_core.h"
#include "config.h"

// Global pointers for server callbacks
static std::vector<TOTPAccount> *g_accounts = nullptr;
static RTC_DS3231 *g_rtc = nullptr;
static ESP8266WebServer *g_server = nullptr;

static void handleRoot();
static void handleAddAccount();
static void handleDeleteAccount();
static void handleListAccounts();
static void handleGetTOTP();
static void handleSetTime();

void setupWebServer(ESP8266WebServer &server, std::vector<TOTPAccount> &accounts,
                    RTC_DS3231 &rtc)
{
    g_server = &server;
    g_accounts = &accounts;
    g_rtc = &rtc;

    server.on("/", HTTP_GET, handleRoot);
    server.on("/add", HTTP_POST, handleAddAccount);
    server.on("/delete", HTTP_POST, handleDeleteAccount);
    server.on("/list", HTTP_GET, handleListAccounts);
    server.on("/totp", HTTP_GET, handleGetTOTP);
    server.on("/settime", HTTP_POST, handleSetTime);

    server.begin();
    Serial.println("Web server started");
}

static void handleRoot()
{
    g_server->setContentLength(CONTENT_LENGTH_UNKNOWN);
    g_server->send(200, "text/html", "");

    g_server->sendContent("<!DOCTYPE html><html><head>");
    g_server->sendContent("<title>TOTP Device</title>");
    g_server->sendContent("<meta name='viewport' content='width=device-width,initial-scale=1'>");
    g_server->sendContent("<style>");
    g_server->sendContent("body{font-family:Arial;margin:20px}");
    g_server->sendContent(".container{max-width:600px;margin:0 auto}");
    g_server->sendContent(".form-group{margin-bottom:15px}");
    g_server->sendContent("label{display:block;margin-bottom:5px}");
    g_server->sendContent("input,select{width:100%;padding:8px;box-sizing:border-box}");
    g_server->sendContent("button{background:#007cba;color:white;padding:10px 20px;border:none;cursor:pointer;margin:5px}");
    g_server->sendContent(".account{border:1px solid #ddd;padding:10px;margin:10px 0}");
    g_server->sendContent(".time-sync{background:#f0f0f0;padding:15px;border-radius:5px;margin-bottom:20px}");
    g_server->sendContent(".status{padding:10px;margin:10px 0;border-radius:5px}");
    g_server->sendContent(".success{background:#d4edda;color:#155724;border:1px solid #c3e6cb}");
    g_server->sendContent(".error{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}");
    g_server->sendContent("</style></head><body>");
    g_server->sendContent("<div class='container'>");
    g_server->sendContent("<h1>TOTP Device</h1>");

    g_server->sendContent("<div class='time-sync'><h3>Time Sync</h3>");
    g_server->sendContent("<p>Browser time: <span id='browserTime'>Loading...</span></p>");
    g_server->sendContent("<button onclick='syncTime()'>Sync Time</button>");
    g_server->sendContent("<div id='timeStatus'></div></div>");

    g_server->sendContent("<h2>Add Account</h2><form id='addForm'>");
    g_server->sendContent("<div class='form-group'><label>Name:</label><input type='text' id='name' required></div>");
    g_server->sendContent("<div class='form-group'><label>Issuer:</label><input type='text' id='issuer' required></div>");
    g_server->sendContent("<div class='form-group'><label>Secret (Base32):</label><input type='text' id='secret' required></div>");
    g_server->sendContent("<div class='form-group'><label>Digits:</label><select id='digits'><option value='6'>6</option><option value='8'>8</option></select></div>");
    g_server->sendContent("<button type='submit'>Add</button></form>");

    g_server->sendContent("<h2>Accounts</h2><div id='accounts'></div></div>");

    g_server->sendContent("<script>");
    g_server->sendContent("function updateBrowserTime(){document.getElementById('browserTime').textContent=new Date().toLocaleString()}");
    g_server->sendContent("function syncTime(){const t=Math.floor(Date.now()/1000);");
    g_server->sendContent("fetch('/settime',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'timestamp='+t})");
    g_server->sendContent(".then(r=>r.text()).then(()=>{document.getElementById('timeStatus').innerHTML='<div class=\"status success\">Synced!</div>';");
    g_server->sendContent("setTimeout(()=>document.getElementById('timeStatus').innerHTML='',3000)})");
    g_server->sendContent(".catch(e=>document.getElementById('timeStatus').innerHTML='<div class=\"status error\">Failed: '+e+'</div>')}");

    g_server->sendContent("function loadAccounts(){fetch('/list').then(r=>r.json()).then(d=>{");
    g_server->sendContent("const div=document.getElementById('accounts');div.innerHTML='';");
    g_server->sendContent("if(d.accounts&&d.accounts.length){d.accounts.forEach((a,i)=>{");
    g_server->sendContent("const ad=document.createElement('div');ad.className='account';");
    g_server->sendContent("ad.innerHTML=`<strong>${a.name}</strong> (${a.issuer})<br>Digits: ${a.digits}<br>");
    g_server->sendContent("<button onclick='deleteAccount(${i})'>Delete</button>`;div.appendChild(ad)})}");
    g_server->sendContent("else{div.innerHTML='<p>No accounts</p>'}})}");

    g_server->sendContent("function deleteAccount(i){fetch('/delete',{method:'POST',headers:{'Content-Type':'application/json'},");
    g_server->sendContent("body:JSON.stringify({index:i})}).then(r=>r.json()).then(d=>{if(d.status==='success')loadAccounts()})}");

    g_server->sendContent("document.getElementById('addForm').addEventListener('submit',e=>{e.preventDefault();");
    g_server->sendContent("const data={name:document.getElementById('name').value,issuer:document.getElementById('issuer').value,");
    g_server->sendContent("secret:document.getElementById('secret').value,digits:parseInt(document.getElementById('digits').value),algorithm:'SHA1'};");
    g_server->sendContent("fetch('/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})");
    g_server->sendContent(".then(r=>r.json()).then(d=>{if(d.status==='success'){document.getElementById('addForm').reset();loadAccounts()}})});");

    g_server->sendContent("window.addEventListener('load',()=>{updateBrowserTime();setInterval(updateBrowserTime,1000);");
    g_server->sendContent("loadAccounts();setTimeout(syncTime,2000)});");
    g_server->sendContent("</script></body></html>");
}

static void handleAddAccount()
{
    if (!g_server->hasArg("plain"))
    {
        g_server->send(400, "application/json", "{\"status\":\"error\"}");
        return;
    }

    DynamicJsonDocument doc(512);
    if (deserializeJson(doc, g_server->arg("plain")))
    {
        g_server->send(400, "application/json", "{\"status\":\"error\"}");
        return;
    }

    TOTPAccount account;
    account.name = doc["name"].as<String>();
    account.issuer = doc["issuer"].as<String>();
    account.secret = doc["secret"].as<String>();
    account.digits = doc["digits"] | 6;
    account.algorithm = "SHA1";
    account.period = 30;

    g_accounts->push_back(account);
    saveConfiguration(*g_accounts);

    g_server->send(200, "application/json", "{\"status\":\"success\"}");
}

static void handleDeleteAccount()
{
    if (!g_server->hasArg("plain"))
    {
        g_server->send(400, "application/json", "{\"status\":\"error\"}");
        return;
    }

    DynamicJsonDocument doc(256);
    if (deserializeJson(doc, g_server->arg("plain")))
    {
        g_server->send(400, "application/json", "{\"status\":\"error\"}");
        return;
    }

    unsigned int index = doc["index"];
    if (index < g_accounts->size())
    {
        g_accounts->erase(g_accounts->begin() + index);
        saveConfiguration(*g_accounts);
        g_server->send(200, "application/json", "{\"status\":\"success\"}");
    }
    else
    {
        g_server->send(400, "application/json", "{\"status\":\"error\"}");
    }
}

static void handleListAccounts()
{
    DynamicJsonDocument doc(2048);
    JsonArray arr = doc.createNestedArray("accounts");

    for (const auto &account : *g_accounts)
    {
        JsonObject obj = arr.createNestedObject();
        obj["name"] = account.name;
        obj["issuer"] = account.issuer;
        obj["digits"] = account.digits;
        obj["algorithm"] = account.algorithm;
    }

    String response;
    serializeJson(doc, response);
    g_server->send(200, "application/json", response);
}

static void handleGetTOTP()
{
    if (g_accounts->empty())
    {
        g_server->send(404, "application/json", "{\"error\":\"No accounts\"}");
        return;
    }

    const TOTPAccount &account = (*g_accounts)[0];
    time_t timestamp = g_rtc->now().unixtime();
    String code = generateTOTP(account, timestamp);

    DynamicJsonDocument doc(256);
    doc["account"] = account.name;
    doc["issuer"] = account.issuer;
    doc["code"] = code;
    doc["timeRemaining"] = TOTP_PERIOD - (timestamp % TOTP_PERIOD);

    String response;
    serializeJson(doc, response);
    g_server->send(200, "application/json", response);
}

static void handleSetTime()
{
    if (g_server->hasArg("timestamp"))
    {
        time_t timestamp = g_server->arg("timestamp").toInt();
        g_rtc->adjust(DateTime(timestamp));
        g_server->send(200, "text/plain", "Time set");
        Serial.printf("RTC set to: %lu\n", timestamp);
    }
    else
    {
        g_server->send(400, "text/plain", "Missing timestamp");
    }
}
#endif