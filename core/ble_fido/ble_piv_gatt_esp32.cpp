/*
 * NimBLE glue for the PIV-over-BLE service (daemon docs/device-protocol.md).
 *
 * Deliberately thin. The framing is ble_fido.c's, reached through a second
 * context, so what is left here is a GATT service definition, one write
 * callback and the hand-off to the task that owns the applet.
 *
 * This service is discoverable but not advertised. The CTAP BLE spec requires
 * 0xFFFD in the advertisement, so the device already announces itself as a
 * FIDO token to any passing scanner and that cannot be helped. Adding this one
 * would additionally tell that scanner the hardware is a smart card — strictly
 * more information for no gain, since the daemon discovers it after bonding.
 */
#include "ble_piv.h"

#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV

#include "ble_fido.h"
#include "ccid_proto.h"
/* The applet's fingerprint wait is the CTAP one, so cancelling it is the CTAP
 * call. Declared here rather than pulling the whole CTAP HID header into a
 * file that must never reach ctap_request(). */
extern "C" void ctaphid_cancel_request(void);
#include <NimBLEDevice.h>
#include <cryptick_log.h>
#include <string.h>

namespace {

NimBLECharacteristic *g_cp = nullptr;
NimBLECharacteristic *g_status = nullptr;
NimBLECharacteristic *g_cp_len = nullptr;
NimBLECharacteristic *g_atr = nullptr;

uint8_t        g_msg[BLE_PIV_MAX_MSG];
ble_fido_ctx_t g_ctx;
bool           g_up = false;

int notify_fragment(const uint8_t *frag, uint16_t len)
{
    if (!g_status || !g_up)
        return 0;
    g_status->setValue(frag, len);
    return g_status->notify() ? 1 : 0;
}

void publish_control_point_length()
{
    if (!g_cp_len)
        return;
    uint16_t len = ble_fido_ctx_control_point_length(&g_ctx);
    uint8_t be[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    g_cp_len->setValue(be, sizeof(be));
}

/**
 * A reassembled message from the peer.
 *
 * CANCEL arrives here with a null body and is never answered — the framing
 * layer has already dropped the in-flight message. Aborting the applet's
 * fingerprint wait is the only thing left to do, and it shares the flag the
 * CTAP path uses because it is the same wait.
 */
void deliver(uint8_t cmd, const uint8_t *msg, uint16_t len)
{
    if (cmd == BLE_FIDO_CMD_CANCEL) {
        ctaphid_cancel_request();
        return;
    }
    if (cmd != BLE_PIV_CMD_APDU) {
        ble_fido_ctx_send_error(&g_ctx, BLE_FIDO_ERR_INVALID_CMD);
        return;
    }
    if (!piv_ble_submit_apdu(msg, len))
        ble_fido_ctx_send_error(&g_ctx, BLE_FIDO_ERR_BUSY);
}

class ControlPointCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic *chr, NimBLEConnInfo &info) override
    {
        /*
         * ATT already refused an unbonded or Just-Works-bonded peer, since the
         * characteristic requires encryption and authentication. Re-checking
         * here costs nothing and means a future property change cannot quietly
         * open a path to signing keys.
         */
        if (!info.isEncrypted() || !info.isAuthenticated()) {
            CLOG_W("PIV-BLE", "write from an unauthenticated peer, dropped");
            return;
        }
        NimBLEAttValue v = chr->getValue();
        if (v.size() == 0)
            return;
        ble_fido_ctx_rx_fragment(&g_ctx, v.data(), (uint16_t)v.size());
    }
};

ControlPointCallbacks g_cp_callbacks;

} // namespace

void ble_piv_reset(void)
{
    ble_fido_ctx_reset(&g_ctx);
}

void ble_piv_set_mtu(uint16_t att_mtu)
{
    ble_fido_ctx_set_mtu(&g_ctx, att_mtu);
    publish_control_point_length();
}

int ble_piv_send_response(const uint8_t *apdu, uint16_t len)
{
    return ble_fido_ctx_send_response(&g_ctx, BLE_PIV_CMD_APDU, apdu, len);
}

int ble_piv_send_error(uint8_t err)
{
    return ble_fido_ctx_send_error(&g_ctx, err);
}

int ble_piv_send_keepalive(uint8_t status)
{
    return ble_fido_ctx_send_keepalive(&g_ctx, status);
}

int ble_piv_ready(void) { return g_up ? 1 : 0; }

void ble_piv_gatt_init(void)
{
    if (g_cp)
        return;

    NimBLEServer *server = NimBLEDevice::getServer();
    if (!server) {
        /* ble_fido_gatt_init() owns NimBLEDevice::init() and the server. */
        CLOG_E("PIV-BLE", "no GATT server; call ble_fido_gatt_init() first");
        return;
    }

    ble_fido_ctx_init(&g_ctx, g_msg, (uint16_t)sizeof(g_msg),
                      BLE_FIDO_CTX_NO_PING);
    ble_fido_ctx_set_notify(&g_ctx, notify_fragment);
    ble_fido_ctx_set_deliver(&g_ctx, deliver);
    ble_fido_ctx_set_mtu(&g_ctx, BLE_ATT_MTU_DFLT);

    NimBLEService *svc = server->createService(NimBLEUUID(BLE_PIV_UUID_SERVICE));

    /*
     * This service reaches signing keys, so there is no weaker tier available:
     * both the control point and the status channel require LE Secure
     * Connections with MITM protection. The CCCD behind fidoStatus and
     * pivStatus is covered by the global mask set in ble_gatt_esp32.cpp —
     * NimBLE does not derive it from these flags.
     */
    g_cp = svc->createCharacteristic(
        BLE_PIV_UUID_CONTROL_POINT,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC |
            NIMBLE_PROPERTY::WRITE_AUTHEN);
    g_cp->setCallbacks(&g_cp_callbacks);

    g_status = svc->createCharacteristic(
        BLE_PIV_UUID_STATUS,
        NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ_ENC |
            NIMBLE_PROPERTY::READ_AUTHEN);

    /* Descriptive, and read before the first transaction. Same reasoning as
     * fidoControlPointLength: gating them costs a discovery path and protects
     * nothing the advertisement does not already give away. */
    g_cp_len = svc->createCharacteristic(BLE_PIV_UUID_CONTROL_POINT_LEN,
                                         NIMBLE_PROPERTY::READ);

    g_atr = svc->createCharacteristic(BLE_PIV_UUID_ATR, NIMBLE_PROPERTY::READ);
    const uint8_t *atr = nullptr;
    size_t atr_len = ccid_get_atr(&atr);
    if (atr && atr_len)
        g_atr->setValue(atr, atr_len);

    publish_control_point_length();
    svc->start();
    g_up = true;

    CLOG_I("PIV-BLE", "service up (not advertised), cap=%u ATR=%u bytes",
           (unsigned)BLE_PIV_MAX_MSG, (unsigned)atr_len);
}

#endif /* CRYPTICK_BLE_PIV */
