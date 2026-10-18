/*
 * NimBLE glue for the Daemon Bridge over BLE service.
 *
 * Runs on service FBF6EB80-7F39-41B1-A191-9527CC42F8BE to isolate
 * the host daemon from standard FIDO GATT 0xFFFD and PIV FBF6EB90.
 */
#include "ble_daemon.h"

#if defined(CRYPTICK_BLE_FIDO) && CRYPTICK_BLE_FIDO

#include "ble_fido.h"
#include "device.h"
extern "C" void ctaphid_cancel_request(void);
#include <NimBLEDevice.h>
#include <cryptick_log.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
/* Same factory-unique identity string the USB build programs into
 * iSerialNumber (drivers/usb_device.h) — see BLE_DAEMON_UUID_SERIAL_NUMBER's
 * doc comment in ble_daemon.h for why it is reused verbatim here rather
 * than inventing a second BLE-specific identity. */
#include "usb_device.h"

namespace {

NimBLECharacteristic *g_cp = nullptr;
NimBLECharacteristic *g_status = nullptr;
NimBLECharacteristic *g_cp_len = nullptr;
NimBLECharacteristic *g_ver = nullptr;
NimBLECharacteristic *g_serial = nullptr;

uint8_t        g_msg[BLE_DAEMON_MAX_MSG];
ble_fido_ctx_t g_ctx;
static volatile bool g_up = false;

int notify_fragment(const uint8_t *frag, uint16_t len)
{
    if (!g_status || !g_up || !ble_fido_is_connected())
        return 0;
    g_status->setValue(frag, len);
    for (int retry = 0; retry < 5; retry++) {
        if (g_status->notify()) {
            vTaskDelay(pdMS_TO_TICKS(2));
            return 1;
        }
        if (!ble_fido_is_connected())
            return 0;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return 0;
}

void publish_control_point_length()
{
    if (!g_cp_len)
        return;
    uint16_t len = ble_fido_ctx_control_point_length(&g_ctx);
    uint8_t be[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    g_cp_len->setValue(be, sizeof(be));
}

void deliver(uint8_t cmd, const uint8_t *msg, uint16_t len)
{
    if (cmd == BLE_FIDO_CMD_CANCEL) {
        ctaphid_cancel_request();
        return;
    }
    if (!daemon_ble_submit_request(cmd, msg, len))
        ble_fido_ctx_send_error(&g_ctx, BLE_FIDO_ERR_BUSY);
}

class ControlPointCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic *chr, NimBLEConnInfo &info) override
    {
        if (!info.isEncrypted() || !info.isAuthenticated()) {
            CLOG_W("DAEMON-BLE", "write from unauthenticated peer, dropped");
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

void ble_daemon_reset(void)
{
    ble_fido_ctx_reset(&g_ctx);
}

void ble_daemon_set_mtu(uint16_t att_mtu)
{
    ble_fido_ctx_set_mtu(&g_ctx, att_mtu);
    publish_control_point_length();
}

int ble_daemon_send_response(uint8_t cmd, const uint8_t *resp, uint16_t len)
{
    return ble_fido_ctx_send_response(&g_ctx, cmd, resp, len);
}

int ble_daemon_send_error(uint8_t err)
{
    return ble_fido_ctx_send_error(&g_ctx, err);
}

int ble_daemon_send_keepalive(uint8_t status)
{
    return ble_fido_ctx_send_keepalive(&g_ctx, status);
}

int ble_daemon_ready(void) { return g_up ? 1 : 0; }

void ble_daemon_gatt_init(void)
{
    if (g_cp)
        return;

    NimBLEServer *server = NimBLEDevice::getServer();
    if (!server) {
        CLOG_E("DAEMON-BLE", "no GATT server; call ble_fido_gatt_init() first");
        return;
    }

    ble_fido_ctx_init(&g_ctx, g_msg, (uint16_t)sizeof(g_msg), 0);
    ble_fido_ctx_set_notify(&g_ctx, notify_fragment);
    ble_fido_ctx_set_deliver(&g_ctx, deliver);
    ble_fido_ctx_set_mtu(&g_ctx, BLE_ATT_MTU_DFLT);

    NimBLEService *svc = server->createService(NimBLEUUID(BLE_DAEMON_UUID_SERVICE));

    g_cp = svc->createCharacteristic(
        BLE_DAEMON_UUID_CONTROL_POINT,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC |
            NIMBLE_PROPERTY::WRITE_AUTHEN);
    g_cp->setCallbacks(&g_cp_callbacks);

    g_status = svc->createCharacteristic(
        BLE_DAEMON_UUID_STATUS,
        NIMBLE_PROPERTY::NOTIFY);

    g_cp_len = svc->createCharacteristic(BLE_DAEMON_UUID_CONTROL_POINT_LEN,
                                         NIMBLE_PROPERTY::READ);

    g_ver = svc->createCharacteristic(BLE_DAEMON_UUID_VERSION, NIMBLE_PROPERTY::READ);
    uint8_t ver = 0x01;
    g_ver->setValue(&ver, 1);

    /*
     * --- Device identity (additive) -----------------------------------
     *
     * Factory-unique serial, gated the same as daemonControlPoint
     * (encrypted + authenticated) rather than left world-readable like
     * daemonControlPointLength/daemonVersion above: those two carry no
     * information that survives a reboot or means anything off this one
     * connection, but a serial number is a permanent per-unit identifier,
     * and this device already randomizes its BLE address specifically to
     * resist being tracked by an address that doesn't change — a bond-free
     * read of a permanent serial would reopen exactly that. A daemon that
     * already has to bond to exchange CTAP over this same service pays
     * nothing extra to read it once connected. See
     * BLE_DAEMON_UUID_SERIAL_NUMBER's doc comment (ble_daemon.h) and
     * NOTES.md, "BLE device identity".
     */
    g_serial = svc->createCharacteristic(
        BLE_DAEMON_UUID_SERIAL_NUMBER,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC |
            NIMBLE_PROPERTY::READ_AUTHEN);
    {
        const char *serial = usb_device_serial_number();
        g_serial->setValue((const uint8_t *)serial, (uint16_t)strlen(serial));
    }

    publish_control_point_length();
    svc->start();
    g_up = true;

    CLOG_I("DAEMON-BLE", "service up (FBF6EB80-...), cap=%u bytes",
           (unsigned)BLE_DAEMON_MAX_MSG);
}

#endif /* CRYPTICK_BLE_FIDO */
