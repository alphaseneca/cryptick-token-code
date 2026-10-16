/*
 * USB CCID transport for the PIV applet.
 *
 * The protocol itself lives in ccid_proto.c, which is freestanding and fully
 * host-tested (tests/host/test_ccid_proto.py). What is here is the part that
 * cannot be tested off-device: the descriptors, a TinyUSB class driver, the
 * two bulk endpoints, and the hand-off to the task that owns user presence.
 *
 * That split is deliberate. Every defect found in this project so far has been
 * in platform glue rather than in protocol logic, so the glue is kept as small
 * as it can be — and the one part of it that *is* checkable off-device, the
 * descriptor bytes, is laid out as a parseable template so the host suite can
 * assert on it (tests/host/test_ccid_descriptors.py).
 *
 * Two hazards shape the code below.
 *
 * Blocking. A PIV signature waits on a fingerprint for up to 29 s. Doing that
 * on the TinyUSB task would stall CDC and HID with it, which is
 * indistinguishable from the device having hung. Reassembly therefore happens
 * on the USB task (pure byte work) and the finished message is posted to the
 * FIDO task, which is already the single owner of the presence gate.
 *
 * Bricking. This device has no BOOT pads: the only reflash paths run over a
 * composite that enumerates. Adding an interface to a working composite is
 * exactly how that stops being true, so the interface is behind a latch that
 * disables it after two boots that never reached the configured state, and
 * arms itself again when the firmware image changes. A descriptor bug then
 * costs two reboots instead of the device.
 */
#include "usb_ccid.h"
#include "ccid_proto.h"
#include "ccid_descriptors.h"
#include "piv.h"

#include <string.h>

#if defined(CRYPTICK_USB_CCID) && CRYPTICK_USB_CCID && \
    defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK && \
    defined(ARDUINO_USB_MODE) && (ARDUINO_USB_MODE == 0)
#define CCID_GLUE_ACTIVE 1
#else
#define CCID_GLUE_ACTIVE 0
#endif

/* One message in flight; CCID is strictly request/response per slot. */
static uint8_t _reply[CCID_MAX_MESSAGE];
static size_t  _reply_len;

size_t usb_ccid_on_message(const uint8_t *msg, size_t len)
{
    _reply_len = ccid_handle_message(msg, len, _reply, sizeof(_reply));
    return _reply_len;
}

const uint8_t *usb_ccid_take_reply(size_t *len)
{
    if (len)
        *len = _reply_len;
    return _reply_len ? _reply : NULL;
}

#if !CCID_GLUE_ACTIVE

/*
 * Kept compiling when the transport is off so signature drift against
 * ccid_proto.h shows up in the build rather than in a future bring-up.
 */
void usb_ccid_init(void) { ccid_reset(); _reply_len = 0; }
void usb_ccid_poll(void) {}
bool usb_ccid_register(void) { return false; }
void usb_ccid_mount_ok(void) {}
bool usb_ccid_enabled(void) { return false; }
bool usb_ccid_pump(void) { return false; }

#else /* CCID_GLUE_ACTIVE */

#include <Arduino.h>
#include <cryptick_log.h>
#include "esp32-hal-tinyusb.h"
#include "tusb.h"
#include "device/usbd_pvt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "nvs.h"
#include "esp_ota_ops.h"

#define CCID_EP_SIZE 64
#define CCID_RHPORT  0

/* ------------------------------------------------------------------ */
/* Descriptors                                                        */
/* ------------------------------------------------------------------ */

/*
 * The bytes come from ccid_descriptors.h, which is freestanding so the host
 * suite can compile and assert on them. These four assertions are what keep
 * that copy honest: the header spells the USB constants out itself, and a
 * TinyUSB that disagreed would make the host suite check a descriptor the
 * firmware does not emit.
 */
static_assert(CCID_DESC_TYPE_INTERFACE == TUSB_DESC_INTERFACE, "interface descriptor type drifted from TinyUSB");
static_assert(CCID_DESC_TYPE_ENDPOINT == TUSB_DESC_ENDPOINT, "endpoint descriptor type drifted from TinyUSB");
static_assert(CCID_XFER_BULK == TUSB_XFER_BULK, "bulk transfer type drifted from TinyUSB");
static_assert(CCID_INTERFACE_CLASS == TUSB_CLASS_SMART_CARD, "smartcard class drifted from TinyUSB");

/* Mutable copy: the interface number, string index and endpoint addresses are
 * not known until registration. */
static uint8_t _desc[CCID_DESC_TOTAL_LEN] = CCID_DESCRIPTOR_TEMPLATE;

/* The applet must never be handed more than it can answer. */
static_assert(CCID_MAX_MESSAGE <= 0xFFFF, "dwMaxCCIDMessageLength is 32-bit but the reassembler is not");

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

static uint8_t  _ep_in;              /* full address, 0x8N */
static uint8_t  _ep_out;
static uint8_t  _itf_num = 0xFF;
static bool     _registered;
static bool     _opened;

/* Reassembly, TinyUSB task only. */
static uint8_t  _rx[CCID_MAX_MESSAGE];
static uint32_t _rx_len;

/* Hand-off to the FIDO task. Two slots so the next message can land while the
 * previous one is still being processed, exactly as the BLE side does. */
typedef struct {
    uint32_t len;
    uint8_t  data[CCID_MAX_MESSAGE];
} ccid_msg_t;
static ccid_msg_t     _pool[2];
static uint8_t        _pool_next;
static QueueHandle_t volatile _queue;
static volatile bool  _busy;

/* Bulk-IN staging. Owned by whichever side claimed the endpoint. */
static uint8_t  _tx[CCID_MAX_MESSAGE];
static uint16_t _tx_len;
static volatile bool _tx_zlp;

/* ------------------------------------------------------------------ */
/* Enumeration-failure latch                                          */
/* ------------------------------------------------------------------ */

#define CCID_NVS_NS    "cryptick"
#define CCID_NVS_FAIL  "ccid_fail"
#define CCID_NVS_IMG   "ccid_img"
#define CCID_FAIL_LIMIT 10

/**
 * Decide whether to put CCID on the composite this boot, and count the try.
 *
 * Counts boots that enabled CCID and never reached the configured state;
 * usb_ccid_mount_ok() zeroes the count. Two such boots latch the interface
 * off, which restores the CDC+HID composite the reflash paths depend on.
 *
 * The count is tied to the image that produced it: a different firmware gets
 * a clean slate, because the latch exists to survive a bad build and a new
 * build is exactly the thing that fixes one. Without that, a device latched
 * off would stay off across the very reflash meant to recover it.
 *
 * Fails open. If NVS cannot be opened there is no latch to consult, and
 * refusing to enumerate CCID on that basis would trade a real feature for a
 * hazard that is not in evidence.
 */
static bool ccid_latch_allows(void)
{
    nvs_handle_t h;
    if (nvs_open(CCID_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return true;

    const esp_app_desc_t *app = esp_ota_get_app_description();
    uint8_t cur[8];
    memcpy(cur, app->app_elf_sha256, sizeof(cur));

    uint8_t prev[8];
    size_t  prev_len = sizeof(prev);
    uint8_t fails = 0;

    if (nvs_get_blob(h, CCID_NVS_IMG, prev, &prev_len) != ESP_OK ||
        prev_len != sizeof(cur) || memcmp(prev, cur, sizeof(cur)) != 0) {
        nvs_set_blob(h, CCID_NVS_IMG, cur, sizeof(cur));
        fails = 0;
    } else if (nvs_get_u8(h, CCID_NVS_FAIL, &fails) != ESP_OK) {
        fails = 0;
    }

    bool allow = fails < CCID_FAIL_LIMIT;
    if (allow)
        nvs_set_u8(h, CCID_NVS_FAIL, (uint8_t)(fails + 1));

    nvs_commit(h);
    nvs_close(h);

    if (!allow)
        CLOG_W("CCID", "latched off after %u boots without enumeration", fails);
    return allow;
}

void usb_ccid_mount_ok(void)
{
    if (!_registered)
        return;
    nvs_handle_t h;
    if (nvs_open(CCID_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    uint8_t fails = 0;
    if (nvs_get_u8(h, CCID_NVS_FAIL, &fails) == ESP_OK && fails != 0) {
        nvs_set_u8(h, CCID_NVS_FAIL, 0);
        nvs_commit(h);
    }
    nvs_close(h);
}

/* ------------------------------------------------------------------ */
/* Registration                                                       */
/* ------------------------------------------------------------------ */

static uint16_t ccid_load_descriptor(uint8_t *dst, uint8_t *itf)
{
    _desc[CCID_OFF_ITF_NUM] = *itf;
    memcpy(dst, _desc, sizeof(_desc));
    *itf += 1;
    return sizeof(_desc);
}

bool usb_ccid_register(void)
{
    if (_registered)
        return true;
    if (!ccid_latch_allows())
        return false;

    /*
     * Endpoints are reserved here rather than inside the descriptor callback
     * because a callback that returns 0 aborts the whole descriptor load and
     * takes CDC and HID down with it. Reserving early turns "no endpoints
     * left" into a CCID that is simply absent.
     *
     * This does move HID off the endpoint it would otherwise get. Endpoint
     * addresses are read from the descriptors by every host driver, so the
     * renumbering is invisible; the FIFO budget is what actually matters, and
     * the allocator refuses rather than oversubscribing it.
     */
    uint8_t in  = tinyusb_get_free_in_endpoint();
    uint8_t out = tinyusb_get_free_out_endpoint();
    if (!in || !out) {
        CLOG_W("CCID", "no endpoint budget left; interface not added");
        return false;
    }
    _desc[CCID_OFF_EP_OUT] = out;
    _desc[CCID_OFF_EP_IN]  = (uint8_t)(0x80 | in);
    _desc[CCID_OFF_ITF_STR] = tinyusb_add_string_descriptor("Cryptick PIV");

    if (tinyusb_enable_interface(USB_INTERFACE_CUSTOM, sizeof(_desc),
                                 ccid_load_descriptor) != ESP_OK) {
        CLOG_W("CCID", "interface registration refused");
        return false;
    }

    _registered = true;
    CLOG_I("CCID", "interface registered  in=0x%02X out=0x%02X",
           _desc[CCID_OFF_EP_IN], _desc[CCID_OFF_EP_OUT]);
    return true;
}

bool usb_ccid_enabled(void) { return _registered; }

/* ------------------------------------------------------------------ */
/* Class driver                                                       */
/* ------------------------------------------------------------------ */

static void ccid_arm_out(void)
{
    if (!_opened)
        return;
    if (_rx_len + CCID_EP_SIZE > sizeof(_rx))
        _rx_len = 0;
    usbd_edpt_xfer(CCID_RHPORT, _ep_out, _rx + _rx_len, CCID_EP_SIZE);
}

/** CCID_ERR_CMD_SLOT_BUSY — the reader is still answering an earlier bSeq. */
#define CCID_ERR_SLOT_BUSY 0xE0

/**
 * Answer a message the USB task cannot pass on, from the USB task.
 *
 * Must not block and must not queue. CCID has defined errors for both cases
 * this is used for, and silence has none: a reader that stops answering
 * wedges the host on a bSeq that never arrives.
 *
 * Claiming the IN endpoint is also what keeps _tx safe. A reply the FIDO task
 * has in flight still holds the claim, so this returns empty-handed rather
 * than overwriting it, and the host falls back on its own timeout.
 */
static void ccid_reply_error(const uint8_t *hdr, uint8_t b_error)
{
    if (!usbd_edpt_claim(CCID_RHPORT, _ep_in))
        return;
    uint8_t *r = _tx;
    memset(r, 0, CCID_HEADER_LEN);
    r[0] = CCID_RDR_TO_PC_SLOT_STATUS;
    r[5] = hdr[5];                  /* bSlot */
    r[6] = hdr[6];                  /* bSeq  */
    r[7] = CCID_ICC_PRESENT_ACTIVE | CCID_CMD_FAILED;
    r[8] = b_error;
    _tx_len = CCID_HEADER_LEN;
    _tx_zlp = false;
    if (!usbd_edpt_xfer(CCID_RHPORT, _ep_in, _tx, _tx_len))
        usbd_edpt_release(CCID_RHPORT, _ep_in);
}

static void ccid_drv_init(void)
{
    if (_queue == NULL)
        _queue = xQueueCreate(1, sizeof(ccid_msg_t *));
}

static void ccid_drv_reset(uint8_t rhport)
{
    (void)rhport;
    _itf_num = 0xFF;
    _opened  = false;
    _rx_len  = 0;
    _tx_zlp  = false;
    ccid_reset();
}

static uint16_t ccid_drv_open(uint8_t rhport, tusb_desc_interface_t const *itf,
                              uint16_t max_len)
{
    if (itf->bInterfaceClass != TUSB_CLASS_SMART_CARD ||
        itf->bInterfaceSubClass != 0 || itf->bInterfaceProtocol != 0)
        return 0;

    const uint16_t drv_len = CCID_DESC_TOTAL_LEN;
    TU_VERIFY(max_len >= drv_len, 0);

    /* Step past the interface descriptor and our functional descriptor to
     * reach the endpoint pair. */
    uint8_t const *p = tu_desc_next(itf);
    TU_VERIFY(tu_desc_type(p) == 0x21, 0);
    p = tu_desc_next(p);

    TU_ASSERT(usbd_open_edpt_pair(rhport, p, 2, TUSB_XFER_BULK, &_ep_out, &_ep_in), 0);

    _itf_num = itf->bInterfaceNumber;
    _opened  = true;
    _rx_len  = 0;
    ccid_arm_out();
    return drv_len;
}

static bool ccid_drv_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                     tusb_control_request_t const *req)
{
    if (req->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS)
        return false;
    if (req->wIndex != _itf_num)
        return false;
    if (stage != CONTROL_STAGE_SETUP)
        return true;

    switch (req->bRequest) {
    case 0x01: /* ABORT */
        /*
         * Drop whatever is half-received. The message already handed to the
         * FIDO task is deliberately left alone: it may be inside a
         * fingerprint wait, and abandoning it there would leave the applet
         * mid-command with no way to say so.
         */
        _rx_len = 0;
        return tud_control_status(rhport, req);
    default:
        /* GET_CLOCK_FREQUENCIES / GET_DATA_RATES: the descriptor reports none
         * supported beyond the defaults, so a host asking is out of contract
         * and gets a stall rather than an invented answer. */
        return false;
    }
}

static bool ccid_drv_xfer_cb(uint8_t rhport, uint8_t ep_addr,
                             xfer_result_t result, uint32_t xferred)
{
    (void)rhport;

    if (ep_addr == _ep_in) {
        if (_tx_zlp) {
            _tx_zlp = false;
            if (usbd_edpt_claim(CCID_RHPORT, _ep_in) &&
                !usbd_edpt_xfer(CCID_RHPORT, _ep_in, NULL, 0))
                usbd_edpt_release(CCID_RHPORT, _ep_in);
        }
        return true;
    }

    if (ep_addr != _ep_out)
        return true;

    if (result != XFER_RESULT_SUCCESS) {
        _rx_len = 0;
        ccid_arm_out();
        return true;
    }

    _rx_len += xferred;

    if (_rx_len >= CCID_HEADER_LEN) {
        uint32_t body = (uint32_t)_rx[1] | ((uint32_t)_rx[2] << 8) |
                        ((uint32_t)_rx[3] << 16) | ((uint32_t)_rx[4] << 24);
        if (body > CCID_MAX_APDU) {
            /*
             * Longer than dwMaxCCIDMessageLength said we would accept, so the
             * body can never arrive in full and waiting for it would strand
             * the reassembler. bError carries the offset of the offending
             * field, and dwLength is at offset 1.
             */
            uint8_t hdr[CCID_HEADER_LEN];
            memcpy(hdr, _rx, CCID_HEADER_LEN);
            _rx_len = 0;
            ccid_reply_error(hdr, CCID_ERR_BAD_LENGTH);
            ccid_arm_out();
            return true;
        }
        if (_rx_len >= CCID_HEADER_LEN + body) {
            uint32_t msg_total_len = CCID_HEADER_LEN + body;
            /*
             * Is this a blocking message?
             *
             * Two instructions can call into _hal->user_presence(): INS 0x87
             * (GENERAL_AUTHENTICATE, to sign or do ECDH) and INS 0x47
             * (GENERATE_KEYPAIR, to roll a slot's key). Both take the slot in
             * the P2 byte. piv_user_presence() in piv_hal_esp32.cpp returns
             * immediately for 9A/9D/9E (9A is verified by PIN, not touch; 9D
             * and 9E have no touch requirement) and only blocks — on
             * ctap_user_presence_test(), up to CRYPTICK_FIDO_UP_TIMEOUT_MS —
             * for slot 9C (PIV_SLOT_SIGNATURE).
             *
             * This used to check only INS==0x87, which had two failure
             * modes:
             *   1. Every GENERAL_AUTHENTICATE, including the 9A login slot —
             *      the single most common PIV operation, since 9A is what
             *      macOS/Linux use for every unlock — was routed through the
             *      FIDO-task queue for no reason: queue latency, and a
             *      spurious CCID_ERR_SLOT_BUSY if the FIDO task happened to
             *      be mid-ceremony on an unrelated USB/BLE FIDO request,
             *      despite 9A never touching that gate.
             *   2. GENERATE_KEYPAIR on slot 9C was not flagged at all, so it
             *      took the "answer immediately on this task" path below and
             *      called straight into ctap_user_presence_test() — up to a
             *      29-second block of the TinyUSB task itself, stalling CDC
             *      and HID along with it (see the file banner's "Blocking"
             *      hazard). Rolling the signature key over USB looked like
             *      the device had hung.
             *
             * Gating on slot as well as instruction fixes both: only a
             * request that can actually wait on a fingerprint is deferred to
             * the FIDO task, and every one that can is.
             */
            bool is_presence_gated_ins =
                (_rx[CCID_HEADER_LEN + 1] == PIV_INS_GENERAL_AUTHENTICATE ||
                 _rx[CCID_HEADER_LEN + 1] == PIV_INS_GENERATE_KEYPAIR);
            bool is_blocking = (_rx[0] == CCID_PC_TO_RDR_XFR_BLOCK && body >= 4 &&
                                is_presence_gated_ins &&
                                _rx[CCID_HEADER_LEN + 3] == PIV_SLOT_SIGNATURE);

            if (!is_blocking) {
                if (_busy) {
                    uint8_t hdr[CCID_HEADER_LEN];
                    memcpy(hdr, _rx, CCID_HEADER_LEN);
                    _rx_len = 0;
                    ccid_reply_error(hdr, CCID_ERR_SLOT_BUSY);
                    ccid_arm_out();
                    return true;
                }
                if (usbd_edpt_claim(CCID_RHPORT, _ep_in)) {
                    size_t rlen = ccid_handle_message(_rx, msg_total_len, _reply, sizeof(_reply));
                    _rx_len = 0;
                    if (rlen > 0 && rlen <= sizeof(_tx)) {
                        memcpy(_tx, _reply, rlen);
                        _tx_len = (uint16_t)rlen;
                        _tx_zlp = (rlen % CCID_EP_SIZE) == 0;
                        if (!usbd_edpt_xfer(CCID_RHPORT, _ep_in, _tx, _tx_len)) {
                            _tx_zlp = false;
                            usbd_edpt_release(CCID_RHPORT, _ep_in);
                        }
                    } else {
                        usbd_edpt_release(CCID_RHPORT, _ep_in);
                    }
                }
                ccid_arm_out();
                return true;
            }

            /* Blocking message: route to FIDO task queue for user presence / touch */
            if (_busy || !_queue || uxQueueSpacesAvailable(_queue) == 0) {
                uint8_t hdr[CCID_HEADER_LEN];
                memcpy(hdr, _rx, CCID_HEADER_LEN);
                _rx_len = 0;
                ccid_reply_error(hdr, CCID_ERR_SLOT_BUSY);
                ccid_arm_out();
                return true;
            }
            ccid_msg_t *slot = &_pool[_pool_next & 1u];
            _pool_next++;
            slot->len = msg_total_len;
            memcpy(slot->data, _rx, slot->len);
            _rx_len = 0;
            if (xQueueSend(_queue, &slot, 0) != pdTRUE)
                ccid_reply_error(slot->data, CCID_ERR_SLOT_BUSY);
        }
    }

    ccid_arm_out();
    return true;
}

static usbd_class_driver_t const _ccid_driver = {
#if CFG_TUSB_DEBUG >= CFG_TUD_LOG_LEVEL
    .name = "CCID",
#endif
    .init            = ccid_drv_init,
    .reset           = ccid_drv_reset,
    .open            = ccid_drv_open,
    .control_xfer_cb = ccid_drv_control_xfer_cb,
    .xfer_cb         = ccid_drv_xfer_cb,
    .sof             = NULL,
};

extern "C" usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{
    *driver_count = 1;
    return &_ccid_driver;
}

/* ------------------------------------------------------------------ */
/* FIDO-task end                                                      */
/* ------------------------------------------------------------------ */

bool usb_ccid_pump(void)
{
    if (!_queue)
        return false;
    ccid_msg_t *msg = NULL;
    if (xQueueReceive(_queue, &msg, 0) != pdTRUE || !msg)
        return false;

    _busy = true;
    size_t len = usb_ccid_on_message(msg->data, msg->len);
    _busy = false;

    if (!len || !_opened)
        return true;

    if (len > sizeof(_tx))
        return true;

    if (!usbd_edpt_claim(CCID_RHPORT, _ep_in))
        return true;
    memcpy(_tx, _reply, len);
    _tx_len = (uint16_t)len;
    /*
     * A reply that is an exact multiple of the packet size needs a zero-length
     * packet to end the transfer: the host reads up to dwMaxCCIDMessageLength
     * and only a short packet tells it to stop.
     */
    _tx_zlp = (len % CCID_EP_SIZE) == 0;
    if (!usbd_edpt_xfer(CCID_RHPORT, _ep_in, _tx, _tx_len)) {
        _tx_zlp = false;
        usbd_edpt_release(CCID_RHPORT, _ep_in);
    }
    return true;
}

void usb_ccid_init(void)
{
    ccid_reset();
    _reply_len = 0;
    if (_queue == NULL)
        _queue = xQueueCreate(1, sizeof(ccid_msg_t *));
}

void usb_ccid_poll(void) {}

#endif /* CCID_GLUE_ACTIVE */
