#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

/**
 * Cryptick Token PCB v0.1.0 — ESP32-S3-WROOM-1 N16R8
 *
 * Pin numbers are ESP32 GPIO numbers. 5-way is active-low
 * (internal pull-up; press → GND). Verified by bring-up serial logs:
 * press physical key and match “[IN] NAME (GPIOx)” to the table below.
 */

#define OLED_RESET -1
#define OLED_ADDRESS 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define OLED_SDA 8
#define OLED_SCL 9

/*
 * R557 UART — ESP_RX = ESP receives (sensor TX), ESP_TX = ESP drives.
 * Boot code auto-tries both cable orientations if first fails.
 * R558-S TOUCH_OUT (manual): no finger = high; finger = low.
 * ESP internal pull-up on GPIO (no board pull required). CHANGE ISR.
 * Idle-low at boot is a float/wiring issue — do not invert polarity in firmware.
 */
#define FINGERPRINT_RX 17
#define FINGERPRINT_TX 18
#define FINGERPRINT_IRQ_PIN 16

/*
 * 5-way PCB nets (physical direction → GPIO). Bring-up: pairs were
 * swapped vs first silk guess — UP↔LEFT and RIGHT↔DOWN corrected here.
 *   RIGHT=5  DOWN=4  UP=7  LEFT=6  CENTER=15
 * Verify after flash: physical UP must log [IN] UP (GPIO7), etc.
 */
#define RIGHT_BUTTON_PIN 5
#define DOWN_BUTTON_PIN 4
#define UP_BUTTON_PIN 7
#define LEFT_BUTTON_PIN 6
#define BUTTON_PIN 15 /* CENTER */

/*
 * SW2 (silkscreen), ALPS EC05E1220401 quadrature rotary encoder, sits next to
 * the fingerprint sensor opening near the logo edge. Verified in the KiCad
 * source (not on a flashed board — no hardware was available to this change):
 * cryptick-token-pcb.kicad_pcb footprint "easyeda2kicad:SW-SMD_EC05E1220401"
 * ref SW2 — pad "A" (channel 1) is net `/CW`, pad "B" (channel 2) is net
 * `/CCW`. Both nets carry a real routed F.Cu/B.Cu track + via (not just a
 * schematic label) to ESP32-S3-WROOM-1 module pads 33 (`IO40_33`) and 34
 * (`IO41_34`) respectively — i.e. GPIO40 / GPIO41 — each pulled up to +3V3
 * through its own 0603 resistor. Earlier firmware shipped this as -1/-1;
 * that was stale against this PCB revision, not a hardware absence.
 *
 * The encoder's integral pushbutton (pads 4/5, common C) is wired straight to
 * GND on this revision, not to any GPIO — so there is no separate "encoder
 * click" signal available in firmware. Only rotation is readable. Confirm
 * GPIO40/41 on a flashed unit before relying on this for production;
 * schematic/PCB review is not the same as a bring-up log.
 */
#define ENCODER_CW_PIN 40
#define ENCODER_CCW_PIN 41

#define STAT1_PIN 38
#define STAT2_PIN 39

#define ENABLE_FINGERPRINT
#define FINGERPRINT_BAUD 57600
#define FINGERPRINT_CAPACITY 120
/* R558-S manual timing; AutoEnroll status drain uses short peek timeouts inside driver */
#define FINGERPRINT_UART_TIMEOUT_MS 500
#define FINGERPRINT_CMD_TIMEOUT_MS 1500
#define FINGERPRINT_ENROLL_TIMEOUT_MS 90000
/* GenImg interval only while MATCH_AUTH / MATCH_FIDO is active (not idle) */
#define FINGERPRINT_MATCH_POLL_MS 280
#define FINGERPRINT_POLL_INTERVAL_MS FINGERPRINT_MATCH_POLL_MS
#define FINGERPRINT_ENROLL_POLL_MS 20

#define TOTP_PERIOD 30
#define DISPLAY_UPDATE_INTERVAL 1000
#define BUTTON_DEBOUNCE_MS 18
#define ENCODER_DEBOUNCE_MS 8
#define CONFIG_FILE "/totp_config.json"
#define INACTIVITY_TIMEOUT_SEC 60
#define AUTH_ERROR_DISPLAY_MS 2000
#define BATTERY_POLL_INTERVAL_MS 400

/*
 * Idle → sleep.
 *
 * "Sleep" here means the UI sleeps, not the SoC: the OLED is powered down, the
 * fingerprint sensor stops matching and the unlock session is dropped. The MCU
 * and USB stay up on purpose — this is a security key, and a host must still be
 * able to reach it for FIDO while the screen is dark. A real esp_light_sleep
 * would drop the USB connection mid-session.
 *
 * CENTER wakes it. A host FIDO/OATH request wakes it too, otherwise the
 * "Place finger" prompt would be invisible.
 *
 * 0 disables sleep entirely. Runtime override: console `SLEEP <sec>`, or
 * Settings → Sleep on the device. Both persist in NVS.
 */
#ifndef UI_SLEEP_TIMEOUT_SEC
#define UI_SLEEP_TIMEOUT_SEC 45
#endif
#define UI_SLEEP_MAX_SEC 3600

/**
 * Opening animation budget in milliseconds, spread over ~46 frames.
 * 0 skips it and boots straight to the clock.
 */
#ifndef BOOT_ANIM_MS
#define BOOT_ANIM_MS 900
#endif

/*
 * OATH management UV policy (product):
 *  - When 1: PUT / DELETE / PUT_OTPAUTH / CALCULATE require fingerprint user
 *    presence if any fingerprint is enrolled. Empty template database allows
 *    host bootstrap (first credentials) without UV.
 *  - When 0: lab convenience only — do not use for distribution builds.
 */
#ifndef CRYPTICK_OATH_REQUIRE_FP
#define CRYPTICK_OATH_REQUIRE_FP 1
#endif

/** Max wait for finger on UV-gated OATH ops (matches host HID timeouts). */
#ifndef CRYPTICK_OATH_UV_TIMEOUT_MS
#define CRYPTICK_OATH_UV_TIMEOUT_MS 25000
#endif

/**
 * Prefer WebAuthn "none" attestation for product demos.
 * Packed attestation (~500B cert) multi-frame HID writebacks are fragile on
 * composite CDC+HID; browsers that request attestation:none accept fmt "none"
 * with an empty attStmt and still get a usable credential.
 * Set to 0 for enterprise packed attestation testing.
 */
#ifndef CRYPTICK_ATTEST_FMT_NONE
#define CRYPTICK_ATTEST_FMT_NONE 1
#endif

/**
 * FIDO/U2F user presence timeout (fingerprint). Browsers and some CTAP1
 * paths use short retries; we must hold the "Place finger" UI long enough.
 * CTAP2 path uses CTAP2_UP_DELAY_MS (29s) in ctap.h; U2F MSG uses this.
 */
#ifndef CRYPTICK_FIDO_UP_TIMEOUT_MS
#define CRYPTICK_FIDO_UP_TIMEOUT_MS 29000
#endif

/*
 * Chrome GetTouch (bogus U2F_REGISTER) is immediately followed by CTAP2
 * MakeCredential. Reuse that one fingerprint for MakeCredential only, inside
 * this window. GetAssertion and U2F_AUTHENTICATE always require a new finger.
 */
#ifndef CRYPTICK_FIDO_UV_CACHE_MS
#define CRYPTICK_FIDO_UV_CACHE_MS 10000
#endif

/*
 * FIDO BLE transport (GATT service 0xFFFD). USB works natively on every OS
 * with no host software; BLE is the second product transport. Both are live at
 * once, so the arbitration in docs/ARCHITECTURE.md#threading-model is
 * mandatory, not optional.
 */
#ifndef CRYPTICK_BLE_FIDO
#define CRYPTICK_BLE_FIDO 0
#endif

/* Advertised name. Keep it short: it shares the advertisement with the
 * mandatory 16-bit FIDO Service UUID. */
#ifndef CRYPTICK_BLE_DEVICE_NAME
#define CRYPTICK_BLE_DEVICE_NAME "Cryptick Token"
#endif

/*
 * CTAP keepalive cadence while blocked waiting for the fingerprint. The host
 * must keep hearing from the authenticator or it gives up on the transaction.
 * 100 ms suits every transport: it is the CTAPHID convention on USB, and it is
 * inside what the FIDO BLE transport expects from a KEEPALIVE notification.
 */
#ifndef CRYPTICK_FIDO_KEEPALIVE_MS
#define CRYPTICK_FIDO_KEEPALIVE_MS 100
#endif

/*
 * Hold the OLED awake after FIDO HID/UV so idle sleep cannot blank the token
 * under a still-open WebAuthn prompt (GetTouch → MakeCredential).
 */
#ifndef CRYPTICK_FIDO_CEREMONY_HOLD_MS
#define CRYPTICK_FIDO_CEREMONY_HOLD_MS 30000
#endif

/*
 * CDC log verbosity (see include/cryptick_log.h).
 * Lab default: DEBUG via -DCRYPTICK_LOG_LEVEL_DEFAULT=4
 * Ship: -DCRYPTICK_LOG_LEVEL_DEFAULT=1  and  -DDEBUG_LEVEL=0
 * Runtime: CDC "LOGLEVEL 0..5"
 */
#ifndef CRYPTICK_LOG_LEVEL_DEFAULT
#define CRYPTICK_LOG_LEVEL_DEFAULT 4
#endif

#endif /* BOARD_CONFIG_H */
