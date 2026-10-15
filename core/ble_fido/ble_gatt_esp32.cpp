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
        CLOG_I("BLE", "disconnected reason=%d, advertising again", reason);
        NimBLEDevice::startAdvertising();
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

static char g_device_name[32] = CRYPTICK_BLE_DEVICE_NAME;

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
     * CCCD write remains protected, and control point write enforces bonding.
     */
    ble_gatts_set_clt_cfg_perm_flags(BLE_ATT_F_READ | BLE_ATT_F_WRITE);

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
    CLOG_I("BLE", "FIDO service 0xFFFD up (advertising deferred until all services ready)");
}

void ble_fido_start_advertising(void)
{
    if (g_server) {
        g_server->start();
    }
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    if (adv && !adv->isAdvertising()) {
        adv->setMinInterval(32);
        adv->setMaxInterval(64);
        adv->setAppearance(0x03C1); // HID_KEYBOARD
        adv->addServiceUUID(NimBLEUUID((uint16_t)BLE_FIDO_SERVICE_UUID16));
        adv->setName(g_device_name);
        adv->enableScanResponse(true);
        NimBLEDevice::startAdvertising();
        CLOG_I("BLE", "All services started, advertising as \"%s\"", g_device_name);
    }
}

int ble_fido_is_advertising(void)
{
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    return (adv && adv->isAdvertising()) ? 1 : 0;
}

void ble_fido_restart_advertising(void)
{
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    if (adv) {
        if (adv->isAdvertising()) {
            NimBLEDevice::stopAdvertising();
        }
        adv->setMinInterval(32);
        adv->setMaxInterval(64);
        adv->setAppearance(0x03C1); // HID_KEYBOARD
        adv->addServiceUUID(NimBLEUUID((uint16_t)BLE_FIDO_SERVICE_UUID16));
        adv->setName(g_device_name);
        adv->enableScanResponse(true);
        NimBLEDevice::startAdvertising();
        CLOG_I("BLE", "Advertising restarted as \"%s\"", g_device_name);
    }
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

#endif /* CRYPTICK_BLE_FIDO */
