/*
 * NimBLE glue for the FIDO BLE transport.
 *
 * Layering (docs/ARCHITECTURE.md#threading-model):
 *
 *   USB HID report ──► ctaphid_handle_packet() ──┐
 *                                                ├──► ctap_request()
 *   BLE fragment ────► ble_fido_rx_fragment() ───┘
 *
 * That is a layering diagram, not a threading one. Everything in this file
 * runs on the NimBLE host task: fragment reassembly is pure byte work and is
 * safe here, but the finished message is *posted* to the FIDO task. Nothing
 * here may call ctap_request().
 */
#include <board_config.h>

#if CRYPTICK_BLE_FIDO

#include "ble_fido.h"
#include "device.h"
#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV
#include "ble_piv.h"
#endif
#include "ble_daemon.h"
#include <NimBLEDevice.h>
#if __has_include("nimble/nimble/host/include/host/ble_att.h")
#include "nimble/nimble/host/include/host/ble_att.h"
#else
#include "host/ble_att.h"
#endif
#include <cryptick_log.h>
#include <esp_random.h>
#include <esp_mac.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

extern "C" void ctaphid_cancel_request(void);

/*
 * NimBLE keeps one global permission mask for every CCCD it auto-creates, and
 * it defaults to BLE_ATT_F_READ | BLE_ATT_F_WRITE -- no encryption, no
 * authentication. The NIMBLE_PROPERTY flags on a characteristic do not reach
 * it: they guard the characteristic *value*, and fidoStatus is notify-only, so
 * it has no value access to guard. Subscribing is a CCCD write, which is why
 * READ_ENC | READ_AUTHEN on fidoStatus does not stop an unbonded peer from
 * subscribing to it.
 *
 * Declared here because ble_gatt_priv.h is internal to NimBLE, while the
 * symbol itself is exported and has no public equivalent. The alternative is
 * leaving every CCCD on this device world-writable.
 */
extern "C" void ble_gatts_set_clt_cfg_perm_flags(uint8_t flags);

namespace {

NimBLEServer         *g_server = nullptr;
NimBLECharacteristic *g_control_point = nullptr;
NimBLECharacteristic *g_status = nullptr;
NimBLECharacteristic *g_control_point_len = nullptr;
NimBLECharacteristic *g_revision = nullptr;
static volatile bool g_connected = false;
static char g_device_name[32] = CRYPTICK_BLE_DEVICE_NAME;

/*
 * Advertising interval tiers.
 *
 * Units are 0.625 ms per tick (the BLE advertising-interval field). The
 * split follows the Bluetooth Core Specification Supplement, Part A
 * §3.1.1 "recommended advertising intervals" — the same fast/slow pattern
 * most battery-powered accessories use:
 *
 *   - Fast (30-60 ms): run for a bounded 60s window right after boot,
 *     right after a disconnect, and on an explicit "Restart Adv" — the
 *     moments a central is actually likely to be looking (the daemon
 *     reconnecting, a fresh pairing attempt).
 *   - Slow / reduced-power (1000-2500 ms): what the radio drops to once a
 *     fast window elapses with nobody connecting. That is roughly 1/40th
 *     the duty cycle of the old fixed 20-40 ms interval this replaces —
 *     a device sitting unpaired on a desk for hours was keying the radio
 *     25-50 times a second indefinitely for no reason. 0xFFFD still goes
 *     out on every advertising event in both tiers; only the cadence
 *     changes, so FIDO discoverability is unaffected, just less frequent
 *     when nothing has shown interest in a while.
 */
constexpr uint16_t ADV_FAST_MIN_UNITS = 48;        // 30.00 ms
constexpr uint16_t ADV_FAST_MAX_UNITS = 96;        // 60.00 ms
constexpr uint32_t ADV_FAST_DURATION_MS = 60000;   // 60 s fast window
constexpr uint16_t ADV_SLOW_MIN_UNITS = 1600;      // 1000.00 ms
constexpr uint16_t ADV_SLOW_MAX_UNITS = 4000;      // 2500.00 ms

/*
 * Connection parameters requested once a central bonds. Units: 1.25 ms per
 * interval tick, 10 ms per supervision-timeout tick (BLE connection params).
 *
 *   - 15-30 ms interval: snappy enough that a FIDO sign, a PIV APDU, or an
 *     OATH calculate does not feel laggy over BLE compared to USB — well
 *     inside the CRYPTICK_FIDO_KEEPALIVE_MS=100ms budget this firmware
 *     already promises the host (board_config.h).
 *   - Slave latency 4: lets the radio skip up to 4 connection events (up to
 *     ~150 ms) when the link is idle and we have nothing queued. This does
 *     not delay anything *we* initiate — a KEEPALIVE or a response is
 *     always sent at the next scheduled event regardless of the latency
 *     budget — it only lets the radio sleep between events that would
 *     otherwise be wasted. This is the "stays alive without needlessly
 *     aggressive duty cycling" half of the request, for the connected case.
 *   - Supervision timeout 4000 ms: comfortably satisfies the mandatory
 *     constraint timeout > (1 + latency) * interval_max * 2 (= 300 ms
 *     here) with headroom for a brief radio interference event, without
 *     leaving a truly dead link undetected for long.
 *
 * Central platforms are free to renegotiate this (iOS in particular tends
 * to substitute its own preferred range); onConnParamsUpdate logs whatever
 * was actually accepted so the real value is visible over the console.
 */
constexpr uint16_t CONN_MIN_INTERVAL_UNITS = 12;         // 15.00 ms
constexpr uint16_t CONN_MAX_INTERVAL_UNITS = 24;         // 30.00 ms
constexpr uint16_t CONN_LATENCY_EVENTS = 4;              // may skip up to 4 idle events
constexpr uint16_t CONN_SUPERVISION_TIMEOUT_UNITS = 400; // 4000 ms

/** GAP advertising interval only: name/UUID/appearance are set once, at
 *  init, since NimBLEAdvertising::addServiceUUID() appends rather than
 *  replacing — calling it again on every tier switch would grow the
 *  advertisement payload without bound and eventually overflow it. */
void configure_adv_interval(NimBLEAdvertising *adv, bool fast)
{
    adv->setMinInterval(fast ? ADV_FAST_MIN_UNITS : ADV_SLOW_MIN_UNITS);
    adv->setMaxInterval(fast ? ADV_FAST_MAX_UNITS : ADV_SLOW_MAX_UNITS);
}

/** (Re)start advertising in the given tier. Safe to call while already
 *  advertising (stops first) so tier transitions never race a start. */
void begin_advertising(bool fast)
{
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    if (!adv)
        return;
    if (adv->isAdvertising())
        NimBLEDevice::stopAdvertising();
    configure_adv_interval(adv, fast);
    NimBLEDevice::startAdvertising(fast ? ADV_FAST_DURATION_MS : 0);
    CLOG_I("BLE", "advertising %s (%u-%ums) as \"%s\"",
           fast ? "fast" : "slow",
           (unsigned)((fast ? ADV_FAST_MIN_UNITS : ADV_SLOW_MIN_UNITS) * 5 / 8),
           (unsigned)((fast ? ADV_FAST_MAX_UNITS : ADV_SLOW_MAX_UNITS) * 5 / 8),
           g_device_name);
}

/*
 * Fires only when a *bounded*-duration advertising window elapses with
 * nobody connecting — begin_advertising() only ever bounds the fast tier,
 * so reaching here always means the 60s fast window ran out unanswered.
 * Dropping to the slow cadence here, rather than re-arming fast forever, is
 * the actual fix for "battery consumption is like hell".
 */
void on_adv_complete(NimBLEAdvertising *adv)
{
    (void)adv;
    if (g_connected)
        return; /* a connection landed right as the timer fired; nothing to do */
    CLOG_I("BLE", "fast advertising window elapsed, unanswered -> slow cadence");
    begin_advertising(false);
}

/** fidoControlPointLength is read as 2 bytes, big-endian. */
void publish_control_point_length()
{
    if (!g_control_point_len)
        return;
    uint16_t len = ble_fido_control_point_length();
    uint8_t be[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    g_control_point_len->setValue(be, sizeof(be));
}

/** Notify one fragment on fidoStatus. Called by the framing layer. */
int notify_fragment(const uint8_t *frag, uint16_t len)
{
    if (!g_status || !g_connected)
        return 0;
    for (int retry = 0; retry < 5; retry++) {
        if (g_status->notify(frag, len)) {
            return 1;
        }
        if (!g_connected)
            return 0;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return 0;
}

/** Hand a reassembled request to the FIDO task; never process it here. */
void deliver_request(uint8_t cmd, const uint8_t *msg, uint16_t len)
{
    if (!fido_ble_submit_request(cmd, msg, len))
        ble_fido_send_error(BLE_FIDO_ERR_BUSY);
}

class ControlPointCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic *chr, NimBLEConnInfo &info) override
    {
        if (!info.isEncrypted() || !info.isAuthenticated()) {
            CLOG_W("BLE", "control point write on unauthenticated link");
            ble_fido_send_error(BLE_FIDO_ERR_OTHER);
            return;
        }
        NimBLEAttValue val = chr->getValue();
        if (val.size() == 0 || val.size() > 0xFFFF)
            return;
        ble_fido_rx_fragment(val.data(), (uint16_t)val.size());
    }
};

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override
    {
        (void)server;
        g_connected = true;
        ble_fido_reset();
        /* Start from the mandatory minimum until the MTU is negotiated. */
        ble_fido_set_mtu(BLE_ATT_MTU_DFLT);
        publish_control_point_length();
#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV
        ble_piv_set_mtu(BLE_ATT_MTU_DFLT);
#endif
        ble_daemon_set_mtu(BLE_ATT_MTU_DFLT);
        CLOG_I("BLE", "connected handle=%u", (unsigned)info.getConnHandle());

        /* See CONN_MIN_INTERVAL_UNITS above for the numbers and why. */
        server->updateConnParams(info.getConnHandle(), CONN_MIN_INTERVAL_UNITS,
                                  CONN_MAX_INTERVAL_UNITS, CONN_LATENCY_EVENTS,
                                  CONN_SUPERVISION_TIMEOUT_UNITS);
    }

    void onConnParamsUpdate(NimBLEConnInfo &info) override
    {
        CLOG_I("BLE", "conn params: interval=%ums latency=%u timeout=%ums",
               (unsigned)(info.getConnInterval() * 125 / 100),
               (unsigned)info.getConnLatency(),
               (unsigned)info.getConnTimeout() * 10);
    }

    void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override
    {
        (void)server;
        (void)info;
        g_connected = false;
        fido_ble_on_disconnect();
        ble_fido_reset();
#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV
        ble_piv_reset();
#endif
        ble_daemon_reset();
        device_clear_pairing_passkey();
        CLOG_I("BLE", "disconnected reason=%d, advertising again (fast)", reason);
        /* A disconnect is the strongest signal reconnection is imminent (the
         * daemon retrying, or the same host coming back) — re-arm the fast
         * tier rather than whatever cadence was active before. */
        begin_advertising(true);
    }

    void onMTUChange(uint16_t mtu, NimBLEConnInfo &info) override
    {
        (void)info;
        ble_fido_set_mtu(mtu);
        publish_control_point_length();
#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV
        ble_piv_set_mtu(mtu);
#endif
        ble_daemon_set_mtu(mtu);
        CLOG_I("BLE", "ATT MTU=%u → fidoControlPointLength=%u",
               (unsigned)mtu, (unsigned)ble_fido_control_point_length());
    }

    uint32_t onPassKeyDisplay() override
    {
        uint32_t passkey = 100000u + (esp_random() % 900000u);
        char label[32];
        snprintf(label, sizeof(label), "%06u", (unsigned)passkey);
        device_show_pairing_passkey(label);
        CLOG_I("BLE", "pairing passkey on OLED (6 digits, typed on the host)");
        return passkey;
    }

    void onConfirmPassKey(NimBLEConnInfo &info, uint32_t pin) override
    {
        char label[32];
        snprintf(label, sizeof(label), "%06u", (unsigned)pin);
        device_show_pairing_passkey(label);
        CLOG_I("BLE", "numeric comparison passkey on OLED: %s", label);
        NimBLEDevice::injectConfirmPasskey(info, true);
    }

    void onAuthenticationComplete(NimBLEConnInfo &info) override
    {
        device_clear_pairing_passkey();
        if (!info.isEncrypted() || !info.isAuthenticated()) {
            CLOG_W("BLE", "auth event: enc=%d auth=%d bonded=%d",
                   (int)info.isEncrypted(), (int)info.isAuthenticated(), (int)info.isBonded());
            return;
        }
        CLOG_I("BLE", "bonded: encrypted + authenticated (LESC)");
    }
};

ControlPointCallbacks g_cp_callbacks;
ServerCallbacks       g_server_callbacks;

} // namespace

extern "C" int ble_fido_is_connected(void)
{
    return g_connected ? 1 : 0;
}

#include <Preferences.h>

static uint8_t get_ble_epoch(void)
{
    Preferences p;
    p.begin("ble_cfg", true);
    uint8_t ep = p.getUChar("epoch", 1);
    p.end();
    return ep;
}

static void inc_ble_epoch(void)
{
    Preferences p;
    p.begin("ble_cfg", false);
    uint8_t ep = p.getUChar("epoch", 1) + 1;
    if (ep == 0) ep = 1;
    p.putUChar("epoch", ep);
    p.end();
}

extern "C" const char *ble_fido_get_device_name(void)
{
    return g_device_name;
}

void ble_fido_gatt_init(void)
{
    if (g_server)
        return;

    uint8_t mac[6] = {0};
    if (esp_read_mac(mac, ESP_MAC_BT) == ESP_OK) {
        uint8_t ep = get_ble_epoch();
        mac[5] |= 0xC0;
        mac[0] ^= ep;
        mac[1] ^= (ep << 2);
        snprintf(g_device_name, sizeof(g_device_name), "Cryptick-Token-%02X%02X", mac[1], mac[0]);
    } else {
        snprintf(g_device_name, sizeof(g_device_name), "%s", CRYPTICK_BLE_DEVICE_NAME);
    }

    NimBLEDevice::init(g_device_name);
    NimBLEDevice::setOwnAddr(mac);
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    /* LE Secure Connections + MITM + bonding; passkey shown on the OLED. */
    NimBLEDevice::setSecurityAuth(true /* bonding */, true /* MITM */, true /* SC */);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);

    /*
     * Must precede createService(): the mask is read when each CCCD is
     * registered, not when it is accessed.
     *
     * Bluetooth Core Spec Vol 3 Part G Section 3.3.3.3 strictly requires:
     * "The Client Characteristic Configuration descriptor shall not require
     * authentication or authorization to read. The read operation shall not
     * return an Insufficient Authentication error or Insufficient Authorization
     * error."
     *
     * Gating CCCD read behind authentication breaks GATT discovery on macOS,
     * Windows, and Linux, wedging the connection into an endless retry loop.
     *
     * CCCD *write* (i.e. subscribing: enabling notify) is a different
     * operation and the spec clause above does not cover it. This mask used
     * to be plain READ|WRITE — which left every status/report CCCD on this
     * device (fidoStatus, the daemon bridge status, pivStatus, and the BLE
     * HID keyboard's input-report CCCD) subscribable by *any* connected
     * peer, bonded or not: ble_gatts_clt_cfg_access() in NimBLE enforces
     * exactly the bits passed here, at the ATT layer, before the write ever
     * reaches a characteristic callback, so no per-characteristic onWrite
     * check downstream could compensate for the missing bits. Concretely,
     * an unbonded attacker's phone sitting nearby could subscribe to the HID
     * input report and silently receive every OTP/PIV keystroke this device
     * ever sends to the real host via the quick-action feature.
     * WRITE_ENC | WRITE_AUTHEN closes that: subscribing now requires the
     * same encrypted + MITM-authenticated link as the control point writes
     * already require (NimBLEDevice::setSecurityAuth(true, true, true)
     * above), while CCCD read stays open as the spec mandates.
     */
    ble_gatts_set_clt_cfg_perm_flags(BLE_ATT_F_READ | BLE_ATT_F_WRITE |
                                      BLE_ATT_F_WRITE_ENC | BLE_ATT_F_WRITE_AUTHEN);

    g_server = NimBLEDevice::createServer();
    g_server->setCallbacks(&g_server_callbacks);

    NimBLEService *svc =
        g_server->createService(NimBLEUUID((uint16_t)BLE_FIDO_SERVICE_UUID16));

    /*
     * Write *with response* only: the peer must learn that a fragment was
     * rejected. Encryption and authentication are required at the ATT layer,
     * so an unbonded peer cannot reach these characteristics at all.
     */
    g_control_point = svc->createCharacteristic(
        BLE_FIDO_UUID_CONTROL_POINT,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC |
            NIMBLE_PROPERTY::WRITE_AUTHEN);
    g_control_point->setCallbacks(&g_cp_callbacks);

    g_status = svc->createCharacteristic(
        BLE_FIDO_UUID_STATUS, NIMBLE_PROPERTY::NOTIFY);

    /*
     * The two descriptive characteristics are readable without a bond, which
     * is what CTAP's table describes and what lets a host discover the service
     * before it pairs. Gating them buys nothing -- the length is derived from
     * the negotiated ATT MTU and the revision says "FIDO2", both of which the
     * advertised service UUID already implies -- while costing a discovery
     * path on any stack that reads them before initiating security.
     *
     * Writing the revision bitfield is a different matter: it selects the
     * protocol version this authenticator will speak, and an unbonded peer has
     * no business changing that. WRITE therefore carries the same gate as the
     * control point.
     */
    g_control_point_len = svc->createCharacteristic(
        BLE_FIDO_UUID_CONTROL_POINT_LEN, NIMBLE_PROPERTY::READ);

    g_revision = svc->createCharacteristic(
        BLE_FIDO_UUID_SERVICE_REVISION,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE |
            NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);
    /* FIDO2 only: this authenticator does not offer the U2F 1.1/1.2 profiles. */
    uint8_t revision = BLE_FIDO_REVISION_FIDO2;
    g_revision->setValue(&revision, 1);

    ble_fido_set_notify(notify_fragment);
    ble_fido_set_deliver(deliver_request);
    ble_fido_set_mtu(BLE_ATT_MTU_DFLT);
    publish_control_point_length();

    svc->start();

    /*
     * Static advertisement payload: set once, never repeated. (See
     * configure_adv_interval() above for why addServiceUUID() in particular
     * must not be called again on every tier switch.) The completion
     * callback is what lets a bounded fast-tier window hand off to the
     * slow tier on its own, with no main-loop polling needed to notice it.
     */
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    if (adv) {
        adv->setAppearance(0x03C1); // HID_KEYBOARD
        adv->addServiceUUID(NimBLEUUID((uint16_t)BLE_FIDO_SERVICE_UUID16));
        adv->setName(g_device_name);
        adv->enableScanResponse(true);
        adv->setAdvertisingCompleteCallback(on_adv_complete);
    }

    CLOG_I("BLE", "FIDO service 0xFFFD up (advertising deferred until all services ready)");
}

void ble_fido_start_advertising(void)
{
    if (g_server) {
        g_server->start();
    }
    begin_advertising(true);
    CLOG_I("BLE", "All services started, advertising as \"%s\"", g_device_name);
}

int ble_fido_is_advertising(void)
{
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    return (adv && adv->isAdvertising()) ? 1 : 0;
}

void ble_fido_restart_advertising(void)
{
    /* Explicit user/console request: treat it the same as "just
     * disconnected" and re-arm the fast, easy-to-find tier. */
    begin_advertising(true);
    CLOG_I("BLE", "Advertising restarted (fast) as \"%s\"", g_device_name);
}

size_t ble_fido_bond_count(void)
{
    return NimBLEDevice::getNumBonds();
}

void ble_fido_clear_all_bonds(void)
{
    CLOG_I("BLE", "Disconnecting peer and clearing all BLE bonding records from NVS...");
    if (g_server && g_connected) {
        for (const auto &conn_id : g_server->getPeerDevices()) {
            g_server->disconnect(conn_id, BLE_ERR_REM_USER_CONN_TERM);
        }
    }
    NimBLEDevice::deleteAllBonds();
    inc_ble_epoch();
    CLOG_I("BLE", "All BLE bonds cleared. Restarting device for fresh identity...");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

void ble_fido_cancel_pairing(void)
{
    /*
     * Pairing is still in flight (not yet bonded), so there is no bond
     * record to lose: just drop the connection. onDisconnect() already
     * clears the OLED passkey and calls NimBLEDevice::startAdvertising(),
     * so the only thing left to do here is disconnect.
     */
    if (g_server && g_connected) {
        CLOG_I("BLE", "Pairing declined from the device — disconnecting peer");
        for (const auto &conn_id : g_server->getPeerDevices()) {
            g_server->disconnect(conn_id, BLE_ERR_REM_USER_CONN_TERM);
        }
    } else {
        /* Not connected (e.g. passkey left over from a dropped link): just
         * make sure advertising is running so the host can retry. */
        ble_fido_restart_advertising();
    }
}

#endif /* CRYPTICK_BLE_FIDO */
