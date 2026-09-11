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
#include <NimBLEDevice.h>
#if __has_include("nimble/nimble/host/include/host/ble_att.h")
#include "nimble/nimble/host/include/host/ble_att.h"
#else
#include "host/ble_att.h"
#endif
#include <cryptick_log.h>
#include <esp_random.h>
#include <string.h>

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
bool                  g_connected = false;

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
    g_status->setValue(frag, len);
    return g_status->notify() ? 1 : 0;
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
        /*
         * The characteristic requires encryption *and* authentication, so an
         * unbonded peer cannot reach this at all. Belt and braces: refuse
         * anything that is not both encrypted and authenticated, since a
         * downgraded link is exactly what an attacker would want here.
         */
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
        CLOG_I("BLE", "connected handle=%u", (unsigned)info.getConnHandle());
    }

    void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override
    {
        (void)server;
        (void)info;
        g_connected = false;
        /* Drop any half-received request; the next peer starts clean. */
        ble_fido_reset();
        /* A peer that disconnects mid-pairing must not leave a stale passkey
         * on the OLED — it would be meaningless and looks like a live prompt. */
        device_clear_pairing_passkey();
        CLOG_I("BLE", "disconnected reason=%d, advertising again", reason);
        NimBLEDevice::startAdvertising();
    }

    void onMTUChange(uint16_t mtu, NimBLEConnInfo &info) override
    {
        (void)info;
        ble_fido_set_mtu(mtu);
        publish_control_point_length();
        CLOG_I("BLE", "ATT MTU=%u → fidoControlPointLength=%u",
               (unsigned)mtu, (unsigned)ble_fido_control_point_length());
    }

    /*
     * CTAP requires LE Secure Connections bonding with MITM protection. Just
     * Works pairing does not provide it, and without a display there is no way
     * to do better. The OLED is what earns the device Passkey Entry: we show a
     * fresh 6-digit passkey and the peer types it.
     */
    uint32_t onPassKeyDisplay() override
    {
        uint32_t passkey = 100000u + (esp_random() % 900000u);
        char label[32];
        snprintf(label, sizeof(label), "%06u", (unsigned)passkey);
        /*
         * Raises UI_BLE_PAIRING, which also wakes the panel. Parking only the
         * caption is not enough: the caption is drawn by whichever screen is
         * open, and if none of the FIDO screens is open — which is the normal
         * case during pairing — the passkey is stored and never rendered, on a
         * panel that is probably asleep anyway.
         */
        device_show_pairing_passkey(label);
        CLOG_I("BLE", "pairing passkey on OLED (6 digits, typed on the host)");
        return passkey;
    }

    void onAuthenticationComplete(NimBLEConnInfo &info) override
    {
        device_clear_pairing_passkey();
        if (!info.isEncrypted() || !info.isAuthenticated()) {
            CLOG_W("BLE", "pairing did not reach authenticated LESC — dropping");
            NimBLEDevice::getServer()->disconnect(info.getConnHandle());
            return;
        }
        CLOG_I("BLE", "bonded: encrypted + authenticated (LESC)");
    }
};

ControlPointCallbacks g_cp_callbacks;
ServerCallbacks       g_server_callbacks;

} // namespace

void ble_fido_gatt_init(void)
{
    if (g_server)
        return;

    NimBLEDevice::init(CRYPTICK_BLE_DEVICE_NAME);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    /* LE Secure Connections + MITM + bonding; passkey shown on the OLED. */
    NimBLEDevice::setSecurityAuth(true /* bonding */, true /* MITM */, true /* SC */);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);

    /*
     * Must precede createService(): the mask is read when each CCCD is
     * registered, not when it is accessed. See the declaration above for why
     * the characteristic flags do not cover this.
     */
    ble_gatts_set_clt_cfg_perm_flags(BLE_ATT_F_READ | BLE_ATT_F_READ_ENC |
                                     BLE_ATT_F_READ_AUTHEN | BLE_ATT_F_WRITE |
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
        BLE_FIDO_UUID_STATUS,
        NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ_ENC |
            NIMBLE_PROPERTY::READ_AUTHEN);

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

    /* The 16-bit FIDO Service UUID must appear in the advertisement. */
    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(NimBLEUUID((uint16_t)BLE_FIDO_SERVICE_UUID16));
    adv->setName(CRYPTICK_BLE_DEVICE_NAME);
    adv->enableScanResponse(true);
    NimBLEDevice::startAdvertising();

    CLOG_I("BLE", "FIDO service 0xFFFD up, advertising as \"%s\"",
           CRYPTICK_BLE_DEVICE_NAME);
}

#endif /* CRYPTICK_BLE_FIDO */
