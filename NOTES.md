# Agent work notes — branch `feature/uv-token-credential-management`

Three pieces of work, done in priority order: (1) a critical on-device
authentication gap found and fixed across `src/systems/nav_system.cpp` and
`src/host/serial_comm.cpp`, (2) an investigation (no firmware fix needed —
or possible, from this repo) into a reported BLE disconnect during OATH
`CALCULATE`, (3) the originally-assigned task: CTAP2.1
`getPinUvAuthTokenUsingUvWithPermissions`, so credential management can be
gated by the fingerprint sensor instead of a PIN. No physical device was
available — verification is `pio run` across all four firmware
environments (`esp32-s3-n16r8`, `-ship`, `-jtag`, `-install`) plus
`pio test -e test_nav --without-uploading --without-testing`, all
succeeding, and careful manual tracing against the existing code and the
CTAP2.1 spec text. Everything below marked "needs hardware" is unverified
until someone runs it on a unit.

---

## 0. Critical: on-device menu had zero authentication on three destructive actions

Found while sweeping `src/systems/nav_system.cpp`'s state machine (asked for
explicitly, ahead of the UV-token task, once the gap was reported):

- **`start_enroll()`** (Settings → Enroll finger): gated on `fp_system_ready()`
  (sensor present) only — nothing checked *who* was pressing the button.
  Enrolling only ever appends a template, never replaces one, so this was
  the easy way in even on a device that already had an owner's fingerprint
  and an active Clear-FP gate: just add a second one.
- **`start_clear()`** (Settings → Clear FP → confirm → wipes every
  template): gated on `auth_system_needs_auth()`, which is satisfied by an
  *existing session* (`auth_system_is_authenticated()`) — not a fresh
  touch. An owner who viewed a TOTP code a minute ago and walked away left
  the device one CENTER-press-to-prompt, one fingerprint-confirm away from
  a totally open wipe for anyone who picked it up inside the inactivity
  window. The double-press "confirm" screen is a fat-finger safety net, not
  authentication.
- **`BLE_ACT_UNPAIR`** (BLE menu → Unpair/Wipe Bonds): a single CENTER
  press called `ble_fido_clear_all_bonds()` with no gate of any kind —
  the least-protected of the three.

**Fix:** all three now call a new `require_fresh_touch(PendingAction)` in
`nav_system.cpp`, which always starts a brand-new `CMD_FP_MATCH_AUTH`
match window (`fp_system`'s `_lastMatchPoll` reset to 0 — no cached/stale
match can satisfy it) and only proceeds once `FP_MATCHED` arrives, never on
an existing `auth_system` session. `PendingAction` (`PENDING_TOTP` /
`_CLEAR_CONFIRM` / `_ENROLL` / `_BLE_UNPAIR`) replaces the old single
`_pending_clear` bool so the one `UI_AUTH_PROMPT` screen can resume any of
four different actions after the touch. A failed match or a `KEY_LEFT`
abort clears `_pendingAction` so a later, unrelated match can't be
misattributed. **Bootstrap case** (`fp_system_template_count() == 0`) stays
fully open for all three — there is nothing yet to prove ownership of, so
first-time setup still works unattended.

This mirrors `enter_totp()`'s own pre-existing fresh-touch mechanism rather
than reusing `ctap_user_presence_test`/`oath_ensure_uv` directly:
`nav_system_on_event()` runs synchronously on the Arduino main loop and
cannot block on a multi-second finger wait without stalling display/input/
BLE servicing for everyone else, so it uses the same asynchronous "ask,
then resume on the next `FP_MATCHED` event" pattern `enter_totp()` already
established, generalized to four callers instead of one. The underlying
sensor access is still the same single `fp_system` singleton every other
UV path in this firmware shares.

**Bonus, same sweep:** `src/host/serial_comm.cpp`'s CDC `UNPAIR` /
`BLE_CLEAR_BONDS` / `CLEAR_BONDS` command — a *different* front door to the
exact same `ble_fido_clear_all_bonds()` action — had the same zero-gate
problem, and unlike `OATH PUT`/`TOTP_DEL` two commands above it in the same
file, called it directly. Fixed using that file's own established pattern:
`oath_ensure_uv("Unpair")` before clearing, if/else (not an early `return`,
since this branch is inline in `processSerialCommands` rather than its own
helper function — a bare `return` would skip the `"cryptick> "` reprompt
every other command path falls through to).

**Found, not fixed, with reason:**
- No other destructive/trust-changing action exists in `nav_system.cpp`'s
  state machine — grepped the whole file and `src/systems/` for
  factory-reset/wipe/erase patterns; `CMD_FP_CLEAR_ALL` and
  `ble_fido_clear_all_bonds()` (now both gated, the latter in two places)
  are the only two sinks. There is no PIV-reset or FIDO-reset reachable
  from this on-device menu at all (`CTAP_RESET` is a host-driven CTAPHID
  command, already gated by its own `ctap2_user_presence_test(0)`).
- `nav_system`'s `CMD_FP_MATCH_AUTH` ceremony and the HAL's
  `ctap_user_presence_test_ex()`/`device_presence_fp_*` ceremony
  (`core/fido2/hal_esp32.cpp`) are two *different* mechanisms driving the
  same single `fp_system` sensor singleton, and nothing serializes them
  against each other the way `_up_mutex` serializes concurrent
  `ctap_user_presence_test_ex()` callers. In principle a CDC `OATH PUT`
  self-service wait (blocks the main loop, polls the sensor directly) could
  overlap a `UI_AUTH_PROMPT` ceremony the user had just triggered from the
  menu on a *previous* loop iteration, and a touch meant for one could be
  misattributed to the other. This is pre-existing (the exact same
  structure `enter_totp()` already had), not introduced by this change, and
  genuinely serializing two independently-evolved async/UI state machines
  without hardware to test the result felt riskier than leaving a
  already-present, narrow, hard-to-trigger race alone. Flagging it here for
  whoever owns `fp_system`/`nav_system` next.
- While adding regression tests for the fix (`test/test_nav/test_main.cpp`),
  found that the pre-existing `test_menu_to_settings` and
  `test_settings_enroll_flow_via_bus` tests navigate the top menu with the
  wrong number of key presses (one `KEY_DOWN` from `MENU_TOTP` lands on
  `MENU_PIV`, index 1, not `MENU_SETTINGS`, index 3 — confirmed directly
  against the `enum MenuItem` ordering and the `UI_MENU` key-dispatch code).
  They would fail if actually executed. This was never caught because, per
  this file's own prior note, `test_nav` has only ever been compiled, never
  run (no hardware). Not fixed — out of scope for this change, and I did
  not want to touch pre-existing test assertions I wasn't asked to audit.
  My own four new test helpers (`goto_settings()`, `goto_ble_menu()`) use
  the verified-correct navigation.

**Needs hardware to confirm:** a real fresh-touch wait on `UI_AUTH_PROMPT`
feels/behaves the same for these three new callers as it already does for
TOTP unlock; whether the nav/HAL dual-mechanism race above is actually
reachable in practice.

## 0a. Investigation: does the OATH `CALCULATE` UV wait cause a real BLE disconnect?

Looked for a firmware-side cause first. `up_test_locked()`
(`core/fido2/hal_esp32.cpp`) is the function actually running during this
wait when `CTAPHID_CRYPTICK_OATH`'s `CALCULATE` reaches the token over BLE
(dispatched on the core-0 FIDO task, so it takes the *not* self-service
branch): it sends a real `CMD_KEEPALIVE` (`fido_send_keepalive` →
`ble_fido_send_keepalive`/`ble_daemon_send_keepalive`) every
`CRYPTICK_FIDO_KEEPALIVE_MS` (100 ms), `vTaskDelay(10ms)`-yielding every
loop iteration — no blocking call runs in this specific branch. The
product's own BLE connection-parameter tuning (already merged to `main`)
sets the supervision timeout to `CONN_SUPERVISION_TIMEOUT_UNITS = 400`
(4000 ms, `core/ble_fido/ble_gatt_esp32.cpp`). A 100 ms keepalive cadence
against a 4000 ms supervision timeout is a ~40x margin — **the firmware's
own BLE radio tuning does not look, from source, like the cause.**

The actual mechanism, found by reading the sibling `cryptick-token-daemon`
repo (checked out alongside this one at
`/Users/aurelius/Projects/cryptick-token-daemon`, read for context only —
no changes made there, it's a different team's repo):
`crates/daemon/src/session.rs`'s `Session::transact()` enforces an
**absolute deadline from entry that keepalives explicitly do not extend**
(its own doc comment: *"a device that keeps saying 'still working' must not
be able to hold a transaction open indefinitely"*). On expiry it sends
`CANCEL` to the device and returns `DaemonError::Timeout` →
`ErrorCode::Timeout` on the IPC wire (`crates/ipc/src/lib.rs`) — a value
distinct from `ErrorCode::NotConnected`, so the daemon itself does not
conflate "timed out" with "disconnected." For the `ctap.request` IPC
message this whole thing hangs off, `timeout_ms` is a **mandatory,
client-supplied field with no server-side default**
(`crates/daemon/src/server.rs`) — i.e. the browser extension decides it,
and I did not find the extension's own source anywhere in reach to read
what it actually sends. Separately, `crates/token-manager/src/oath.rs`
(a different, APDU/YKOATH-style OATH client in the same daemon, unclear
whether it's the one actually wired to the Authenticator tab) hardcodes its
own `OATH_UV_TIMEOUT = 30s` for the CALCULATE transceive — comfortably
above the firmware's own 25s `CRYPTICK_OATH_UV_TIMEOUT_MS` / 29s
`CRYPTICK_FIDO_UP_TIMEOUT_MS`, so *that* specific pairing looks safe on its
face.

**Conclusion:** most likely a host-side (daemon and/or extension) timeout
racing real-world finger-placement time against a deadline that firmware
keepalives cannot extend by design — not a firmware BLE tuning problem.
Whether the extension's UI then renders a `Timeout` indistinguishable from
a real disconnect is an extension-side question I could not answer: that
repo was not in reach from here. **What would confirm this:** either read
the extension's own source for the actual `timeout_ms` it sends and how it
maps `error{code:"TIMEOUT"}` in its UI, or capture a live repro's IPC
traffic (or a BLE sniffer trace) around the moment the UI shows
"disconnected" — specifically whether it was preceded by
`ctap.keepalive{reason:"up"}` / `error{code:"TIMEOUT"}` (host gave up) or
an actual `device.range{inRange:false}` (real link loss). No firmware
change is proposed here; I did not find one to make.

## 0b. CTAP2.1 `getPinUvAuthTokenUsingUvWithPermissions` — the originally-assigned task

The real problem, confirmed in source before touching anything: FIDO2
sign-in is fingerprint-gated (`core/fido2/ctap.c`, `ctap_get_info()`'s own
comment: *"UV = fingerprint (options.uv=true), not clientPin"*), but
`ctap_cred_mgmt_pinauth()` requires a valid `pinAuth`, checked by
`verify_pin_auth_ex()` against the global `PIN_TOKEN` — and the *only*
thing that ever populated `PIN_TOKEN` was `CP_cmdGetPinToken`, which
requires a PIN hash the product has no PIN-entry UI to set in the first
place. There was no fingerprint path to credential management at all.

### Exact wire format (for the daemon/extension tasks to build against)

**Subcommand:** `CP_cmdGetPinUvAuthTokenUsingUvWithPermissions = 0x06`
(`CP_subCommand`, request key `0x02`). Confirmed against the CTAP2.1 spec
text itself, not assumed from the numbering — verified the subcommand
table (`0x01 getRetries, 0x02 getKeyAgreement, 0x03 setPin, 0x04
changePin, 0x05 getPinToken, 0x06 getPinUvAuthTokenUsingUvWithPermissions,
0x07 getUVRetries, 0x09 getPinUvAuthTokenUsingPinWithPermissions`) against
two independent published sources (the FIDO Alliance CTAP 2.1-ps-20210615
spec and the WebauthnWorks CTAP2.1-Migration-Guide) plus cross-checking
third-party implementations, because the first fetch of the FIDO Alliance
page itself came back internally inconsistent (its own summarizer
duplicated key 0x02/0x03 across two different subcommand names) and was
*not* trusted on its own. `0x06` being this file's natural next integer
and the spec's real assigned value are confirmed independently coincident,
not assumed.

**Request (CBOR map, same `authenticatorClientPIN` command 0x06 as every
other ClientPIN subcommand):**

| Key | Name | Type | Required |
| --- | --- | --- | --- |
| 0x01 | pinUvAuthProtocol | uint | yes, must be `1` (this device implements only PIN/UV Auth Protocol One) |
| 0x02 | subCommand | uint | yes, `0x06` |
| 0x03 | keyAgreement | COSE key | yes — used to derive the shared secret the response is wrapped under |
| 0x09 | permissions | uint (bitmask) | yes, must be non-zero |
| 0x0A | rpId | text string | no — parsed and stored (`struct rpId`, reusing the existing `parse_rp_id()`) but not currently enforced; nothing downstream scopes `PIN_TOKEN` by rpId yet, same as before this change |

Permission bits (CTAP2.1 §6.4, verified against the same two sources, not
a half-remembered layout): `mc=0x01, ga=0x02, cm=0x04, be=0x08, lbw=0x10,
acfg=0x20`. **`cm` (credential management) is bit 2, value `0x04`** — the
one value the task asked me to specifically double-check, and it is not
`0x02` or `0x08` as a slightly-off guess might produce. This device does
not currently enforce *which* bits were granted against what's actually
attempted later (nothing downstream checks permissions at all — see
`ctap_cred_mgmt_pinauth()`/`verify_pin_auth_ex()`, both untouched) — a
request for `cm` alone is what credential management needs and is what
this was built for; requesting other bits is accepted, not rejected, since
there is no enforcement point yet to reject them meaningfully against.

**Response (identical CBOR shape to `CP_cmdGetPinToken`'s, by design, so
nothing downstream needs to special-case which subcommand produced it):**

| Key | Name | Type |
| --- | --- | --- |
| 0x02 | pinUvAuthToken (`RESP_pinToken`) | byte string, `PIN_TOKEN_SIZE` bytes, AES-256-CBC-encrypted under the shared secret from `keyAgreement`, zero IV — identical wrapping to `CP_cmdGetPinToken`'s `ctap_add_pin_if_verified()` |

**Errors:** `CTAP2_ERR_MISSING_PARAMETER` (0x14) if `keyAgreement` or
`permissions` is absent; `CTAP1_ERR_INVALID_PARAMETER` (0x02) if
`permissions == 0`; on a failed/timed-out fingerprint match,
`CTAP2_ERR_ACTION_TIMEOUT` (0x3A) or `CTAP2_ERR_KEEPALIVE_CANCEL` (0x2D) —
this file's own existing `ctap2_user_presence_test()` helper (already used
by `CTAP_RESET`) does this conversion; no new error convention invented.

**GetInfo change:** `pinUvAuthProtocols` (`RESP_pinProtocols`, key `0x6`)
was previously only advertised when a PIN was set — meaning a factory-
fresh device (no PIN) advertised no protocol number at all, so a platform
had nothing telling it which protocol to negotiate `keyAgreement`/encrypt
the response under before it could even attempt this subcommand. Now
advertised whenever a pinUvAuthToken is obtainable *at all* — by PIN or by
UV — matching how `options.uv` is already unconditionally `true` on this
product. Always `[1]` (Protocol One only). `options.credMgmt` was already
unconditionally `true` before this change — it is now actually true
rather than aspirational, since there is finally a way to obtain a usable
token for it.

### The fingerprint gate itself

Reuses `ctap2_user_presence_test(allow_uv_cache)` — a `static` helper
**already in `ctap.c`** (used today by `CTAP_RESET`), which itself wraps
`ctap_user_presence_test_ex()`, the exact mechanism named in the brief
(`oath_ensure_uv → ctap_user_presence_test`, same family). Called as
`ctap2_user_presence_test(0)` — **`allow_uv_cache` is deliberately `0`,
not `1`.** `_uv_cache_until_ms` (armed by `ctap_uv_cache_arm_gettouch()`)
is a one-shot credit that lets a prior Chrome `GetTouch` satisfy exactly
one later `MakeCredential`, and nothing else is supposed to opt into
consuming it (`device.h`'s own doc comment: *"GetAssertion / U2F_AUTHENTICATE
must pass 0"*). Passing `1` here would let a touch meant for an unrelated
`MakeCredential` moments earlier silently authorize listing or deleting
resident credentials — exactly the double-count hazard the brief warned
about. Passing `0` sidesteps it entirely: this subcommand always demands a
finger placed *after* the request arrives, full stop.

On success: `ctap_make_uv_pin_token()` (new, `ctap.c`, declared in `ctap.h`
next to its sibling `ctap_add_pin_if_verified()`) generates a **brand-new**
`PIN_TOKEN` via `ctap_generate_rng()` (same RNG-failure → `device_reboot()`
convention as `ctap_init()`/`ctap_reset()`), then wraps it under the ECDH
shared secret exactly the way `ctap_add_pin_if_verified()`'s tail already
does (same `crypto_ecc256_shared_secret` → SHA-256 → `crypto_aes256_init`
→ reset IV → encrypt sequence, copied, not reinvented). Regenerating
`PIN_TOKEN` per UV grant (rather than re-wrapping whatever the PIN path
last issued, which is what `CP_cmdGetPinToken` itself does today) means a
fresh UV grant invalidates whatever token a PIN-based grant last issued —
correct for this single-session, single-`PIN_TOKEN` authenticator, and
transparent to both consumers since `verify_pin_auth_ex()` and
`ctap_cred_mgmt_pinauth()` only ever check whatever is *currently* in
`PIN_TOKEN` — confirmed **zero changes** needed to either, as required.

Not gated behind `ctap_device_locked()`/`ctap_device_boot_locked()`
(the PIN-retry lockout counters) — deliberately: those track *PIN*-hash
mismatches, a completely different retry budget than the fingerprint
sensor's own. A PIN lockout must not block UV, and this codebase's
existing dispatch switch already only applies that check to
`SetPin`/`ChangePin`/`GetPinToken`, so leaving the new subcommand out of
it is consistent with, not a deviation from, the existing pattern.

### What's verified vs. inferred

Verified directly against spec text (cross-checked, not memory-only): the
subcommand number, the four request parameter keys and their types, the
six permission bit values. Verified directly against this codebase: every
reused helper/pattern cited above actually does what the comment next to
my call site says it does (read, not assumed). Inferred/not spec-checked:
exact platform error-recovery behavior on `CTAP1_ERR_INVALID_PARAMETER`
for `permissions == 0` (plausible per spec intent, not cross-referenced
against a second source the way the subcommand table was).

### Build verification

`pio run` for `esp32-s3-n16r8`, `-ship`, `-jtag`, `-install` — all succeed,
no new warnings. `core/fido2/ctap.c`/`.h`/`ctap_parse.c` are not part of
`test_nav`'s build, and this repo has no native/host-compiled harness for
`ctap_client_pin()`'s CBOR dispatch the way `tests/host/test_piv_apdu.py`
has for `piv.c` (that harness is specific to `piv.c`/`ccid_proto.c`) — a
`pytest tests/host` run was not attempted this session (no `pytest`
installed in this environment), but nothing in `core/piv` or
`drivers/ccid_proto.c` was touched, so no regression risk there.

### Needs real hardware to confirm

Everything above is static review and spec-text cross-referencing, not a
flashed board: a real fingerprint touch actually producing a `PIN_TOKEN`
that a real daemon can decrypt and then successfully HMAC-verify through
`ctap_cred_mgmt_pinauth()` end-to-end has not been exercised. In
particular: that a real platform's ECDH/AES wrapping round-trips
correctly against `ctap_make_uv_pin_token()`'s output, and that the
fingerprint sensor's actual retry/match timing behaves sanely under this
new call path the same way it already does under `CTAP_RESET`'s.

---

Scope: rotary encoder wiring, BLE power/advertising tuning, BLE/PIV transport
encryption, PIV correctness, OLED UI overhaul. No physical device was
available — everything below is static review, logic tracing, the real KiCad
PCB/schematic source, and `pio run` / `pytest tests/host` builds, never a
flashed board. Treat anything marked "needs hardware" as unverified until
someone runs it on a unit.

Build verification performed: `pio run` for `esp32-s3-n16r8`,
`esp32-s3-n16r8-ship`, `esp32-s3-n16r8-jtag`, and `pio test -e test_nav
--without-uploading --without-testing` (compile-only) all succeed. The L0
host suite (`pytest tests/host`, compiles `piv.c`/`ccid_proto.c` as native
shared libraries and drives them for real) passes 306/306, including two new
tests this change adds.

---

## 1. Rotary encoder — hardware gap resolved, not a gap

`board_config.h` shipped `ENCODER_CW_PIN -1` / `ENCODER_CCW_PIN -1`. The task
brief predicted this was probably a real hardware absence. It is not.

Checked directly against `cryptick-token-pcb/cryptick-token-pcb.kicad_pcb`
and `.kicad_sch` (plain S-expression text, grepped): SW2 is a populated ALPS
EC05E1220401 quadrature encoder. Its pad "A" sits on net `/CW`, pad "B" on
net `/CCW`, and both nets carry real routed F.Cu/B.Cu copper + vias (not just
a schematic label) to ESP32-S3-WROOM-1 module pads 33 (`IO40_33`) and 34
(`IO41_34`) — i.e. **GPIO40 and GPIO41**, each pulled up to 3V3 through its
own resistor. The schematic independently confirms net labels "CW"/"CCW" at
the same nets. `-1/-1` was stale firmware against this PCB revision, not a
documented hardware absence.

**Real hardware gap found in its place:** the encoder's integral pushbutton
(pads 4/5, common C) is wired straight to GND on this PCB rev, not to any
GPIO. Rotation is real; a distinct "encoder click" is not — there is no GPIO
to read it from. CENTER (the existing 5-way button) remains the only
confirm/select action.

What shipped:
- `include/board_config.h`: `ENCODER_CW_PIN 40` / `ENCODER_CCW_PIN 41`, with
  the PCB citation above in-line.
- `src/systems/input_system.cpp`: a debounced Gray-code quadrature decoder
  (same 2ms timer that already scans the 5-way), accumulating 4 valid steps
  per detent (matching the EC05E1220401's quadrature-to-detent ratio) before
  emitting one tick. New `KEY_ENCODER_CW`/`KEY_ENCODER_CCW` events, logged by
  name/pin like every other input source.
- `src/systems/nav_system.cpp`: encoder ticks are remapped to `KEY_DOWN` /
  `KEY_UP` at the top of `nav_system_on_event`, so every existing list
  (top menu, BLE menu, Settings, TOTP accounts, Home quick cards) becomes
  encoder-scrollable for free — one change, no per-screen duplication, and
  the 5-way keeps working exactly as before (purely additive).
- The "quick action": the firmware already had a BLE-HID keystroke-send
  feature (Quick PIV PIN / Quick TOTP code, triggered by CENTER on a Home
  card) that was only reachable via the 5-way D-pad. It's now reachable by
  spinning the encoder to the card and pressing CENTER — an encoder-driven
  path to the exact feature the task's example called out, without
  inventing a GPIO that doesn't exist.

**Needs hardware to confirm:** which physical rotation direction the PCB's
own "/CW" net actually corresponds to — I verified the net topology, not
which way the knob spins when the net goes low first. If a flashed unit
scrolls backwards, swap `ENCODER_CW_PIN`/`ENCODER_CCW_PIN` in
`board_config.h`; the decode logic needs no change. Also unverified: the
debounce timing (4 samples @ 2ms per phase) against a real finger-spun
encoder's bounce characteristics.

## 2. BLE power behavior

`core/ble_fido/ble_gatt_esp32.cpp` previously advertised at a fixed 20-40ms
interval (`setMinInterval(32)/setMaxInterval(64)`, 0.625ms units) forever,
restarted identically on every disconnect, with a 2s main-loop safety net.
That is below the Bluetooth Core Specification Supplement Part A §3.1.1
"fast" recommendation (30-60ms) and never backs off — a device sitting
unpaired on a desk for hours was keying the radio 25-50 times/second
indefinitely. That's the actual mechanism behind "battery consumption is
like hell."

Implemented a two-tier advertising cadence:
- **Fast** (30-60ms, CSS "fast advertising interval 1"): a bounded 60s
  window, (re)armed on boot, on disconnect, and on an explicit "Restart Adv"
  request — the moments a central is actually likely to be looking.
- **Slow** (1000-2500ms, CSS "reduced power advertising interval"): what the
  radio drops to automatically via NimBLE's advertising-complete callback
  when the fast window elapses with nobody connecting. ~1/40th the old duty
  cycle. 0xFFFD still goes out on every event in both tiers — cadence
  changes, not FIDO discoverability or spec compliance.

Also added connection-parameter tuning, requested once per connection via
`NimBLEServer::updateConnParams()`: 15-30ms interval (keeps BLE round-trips
well inside the existing `CRYPTICK_FIDO_KEEPALIVE_MS=100ms` budget), slave
latency 4 (lets the radio skip up to ~150ms of idle connection events — this
never delays anything the device itself initiates, like a KEEPALIVE, which
is always sent at the next scheduled event regardless of the latency
budget), supervision timeout 4000ms (clears the mandatory `timeout > (1 +
latency) * interval_max * 2` constraint with headroom). A logged
`onConnParamsUpdate` callback reports what a central actually accepted,
since platforms (iOS especially) can substitute their own preferred range.

Every numeric choice is cited in-line in `ble_gatt_esp32.cpp` against the
CSS section and the spec's own connection-parameter constraint — not
guessed.

**Needs hardware to confirm:** actual battery-life delta, and whether a real
daemon/extension reconnects reliably within the 60s fast window after a
disconnect (if the daemon's own retry backoff is slower than that, the fast
window may need lengthening — easy to tune, one constant).

## 3. BLE/PIV transport encryption — real gap found and fixed

`NimBLEDevice::setSecurityAuth(true, true, true)` (bonding + MITM + LE
Secure Connections) plus `WRITE_ENC | WRITE_AUTHEN` on every control-point
characteristic (FIDO 0xFFFD, daemon FBF6EB80, PIV FBF6EB90) was already
correct — verified against device-protocol.md's "same bar as 0xFFFD, no
weaker tier available" and against the actual NimBLE source once `pio run`
fetched it.

The gap: the global CCCD (notification-subscribe descriptor) permission mask
in `ble_gatt_esp32.cpp` was `BLE_ATT_F_READ | BLE_ATT_F_WRITE` — no
encryption/authentication bits. Traced into NimBLE's own
`ble_gatts_register_clt_cfg_dsc()` (confirmed from the fetched library
source, not from memory): this mask is what the ATT layer enforces on CCCD
*write* (i.e. subscribing to notifications), before any application
callback ever runs. The code's own comment claimed "CCCD write remains
protected," but the flags passed didn't actually protect it. Bluetooth Core
Spec Vol 3 Part G §3.3.3.3 only forbids gating CCCD *read* behind
authentication — write was never covered by that rule, and was simply
missing the escalation bits.

Concretely: any connected peer, bonded or not, could subscribe to
`fidoStatus`, the daemon bridge status, `pivStatus`, **and the BLE HID
keyboard's input-report characteristic** — the channel the Quick PIV/TOTP
"type the code over BLE HID" feature uses. An unbonded attacker's phone
sitting nearby and subscribing to the HID input report would silently
receive every OTP/PIV keystroke the device ever sent to the real host.

Fix (`core/ble_fido/ble_gatt_esp32.cpp`, one call site):
`BLE_ATT_F_READ | BLE_ATT_F_WRITE | BLE_ATT_F_WRITE_ENC | BLE_ATT_F_WRITE_AUTHEN`.
CCCD read stays open (spec-mandated, keeps GATT discovery working on
macOS/Windows/Linux); CCCD write now requires the same encrypted +
MITM-authenticated link the control points already require. One shared
fix covers FIDO, daemon, PIV, and HID — they all register through the same
global mask.

**Needs hardware to confirm:** that a real central still completes pairing
and subscription cleanly with the stricter CCCD write gate (the mechanism —
server returns insufficient-authentication, client-side security manager
upgrades the link — is standard and already relied on for the control-point
writes, but I could not watch an actual pairing dialog happen).

## 4. PIV correctness — three concrete bugs fixed

`core/piv/piv.c` (the ISO 7816 applet) and `drivers/ccid_proto.c` are
freestanding and already extensively host-tested
(`tests/host/test_piv_apdu.py`, `test_ccid_proto.py` — 304 tests, all
passing before I touched anything, which says a lot about how carefully
that logic was written). I cross-checked every framing rule in
device-protocol.md by hand (SEQ wrap at 0x7F, CANCEL-on-first-fragment,
reassembler bounded by `BLE_PIV_MAX_MSG=261` not by `pivControlPointLength`,
case-2/3/4 APDU parsing) and found it already correct, including a verified
self-signed-certificate DER-splicing routine in `piv_hal_esp32.cpp` that
looked fragile on sight — I decoded both embedded certificate templates with
a throwaway ASN.1 walker and confirmed every hand-computed byte offset
(`pub_offset`, `tbs_start`, `tbs_len`, `second_alg`) lands exactly where it
claims to.

Also confirmed: device-protocol.md's own header says the PIV-over-BLE
service is "specification, not yet implemented on either side" as of
authoring. That is no longer true in this repo — `ble_piv_gatt_esp32.cpp`,
`ble_piv.h`, and the `ble_fido_ctx_t`-based refactor of `ble_fido.c` the doc
said had to land first are all implemented and match the spec precisely
(`BLE_PIV_MAX_MSG` is literally `261`).

Three real bugs found and fixed:

**a) Extended-length APDUs were accepted, not rejected with 6700
(`core/piv/piv.c`).** device-protocol.md: "The applet accepts short APDUs
only; extended-length encoding is rejected with 6700." The code instead
parsed ISO 7816 case 2E/3E/4E APDUs as valid input. Not a buffer-safety bug
(bounds-checked the same as the short-form path), but a real contract
violation: a certificate too large for a short Lc must go through GET
RESPONSE chaining so every transport sees the same command shape — BLE PIV's
261-byte ceiling can't carry an extended APDU intact regardless, and a CCID
host that opportunistically tries extended length would get an unclean
CCID-level length failure (`CCID_MAX_APDU=512`) instead of a clean 6700 the
PC/SC middleware knows how to fall back from. Fixed: the escape sequence is
now refused outright. Covered by two new host tests
(`test_extended_length_body_is_rejected`,
`test_extended_length_le_only_is_rejected`).

**b) USB-CCID routed every GENERAL_AUTHENTICATE through the slow queued
path, not just the one slot that can block (`drivers/usb_ccid.cpp`).**
`piv_user_presence()` only actually waits on a fingerprint for slot 9C
(Digital Signature); slots 9A/9D/9E return immediately by design (9A is PIN-
verified, not touch-gated). The USB glue's `is_blocking` check tested only
the instruction byte (0x87), not the slot (P2), so a 9A login APDU — the
single most common PIV operation, since 9A is what macOS/Linux use for
every unlock — paid FIDO-task queue latency for no reason, and could be
bounced with `CCID_ERR_SLOT_BUSY` if the FIDO task happened to be
mid-ceremony on an unrelated USB/BLE FIDO request, despite 9A never
touching that gate. Fixed: gate on slot == 0x9C as well as instruction.

**c) GENERATE_KEYPAIR wasn't flagged as blocking at all
(`drivers/usb_ccid.cpp`) — the more serious one.** `is_blocking` only
checked for `GENERAL_AUTHENTICATE` (0x87); `GENERATE_KEYPAIR` (0x47) also
calls `_hal->user_presence()` and, on slot 9C, can block on
`ctap_user_presence_test()` for up to 29 seconds. Unflagged, it took the
"answer immediately on the TinyUSB task" fast path — meaning rolling the
signature key over USB called a up-to-29-second blocking wait **directly on
the TinyUSB task**, stalling CDC and HID along with it, exactly the hazard
the file's own top-of-file comment warns about. The device would look
hung for half a minute. Fixed: `is_blocking` now also matches
`GENERATE_KEYPAIR` on slot 9C.

All three fixes are in the USB-CCID/APDU-dispatch layer, which the host test
harness can't reach (it needs the real TinyUSB stack); verified by careful
reading and by the fact that the BLE-PIV path (which always queues
unconditionally, correctly, per its own comment about the shared
single-consumer presence gate) was the working reference I checked the USB
path's intent against.

**Needs hardware to confirm:** that a real PC/SC stack (OpenSC,
CryptoTokenKit, a Windows minidriver) actually logs in faster now on 9A and
doesn't hang on a 9C key-roll. I could not exercise USB CCID without a
board.

## 5. Also found, out of scope to fix here: PCB README vs. firmware disagree
on the charger IC, resolved in firmware's favor

The top-level `cryptick-token-pcb/README.md` says "TP4056 / BQ24040";
`battery_system.cpp`'s STAT1/STAT2 truth-table comment says BQ25185. Rather
than guess, I grepped the actual schematic: the populated part is
`BQ25185DLHR` (`cryptick-token-pcb.kicad_sch`, symbol
`easyeda2kicad:BQ25185DLHR`, described in its own datasheet properties as
"1-Cell, 1-A Standalone Linear Battery Charger with PowerPath..."). The
firmware comment is correct; the PCB-repo README is stale (probably left
over from an earlier candidate part). I did not touch the PCB repo — it's a
separate git repo and out of this branch's scope — but this is worth a
one-line fix there.

## 6. OLED UI overhaul

`src/systems/display_system.cpp` (~1000 lines) is organized around a
title/status-bar pattern (`draw_title`, `draw_status_bar`,
`draw_list_row`/`LIST_ROWS`/`draw_scrollbar`) that most screens already
used — the "messy, has its own thing" complaint was real but localized, not
systemic.

**A real, pervasive rendering bug found first:** every font this file uses
(`u8g2_font_5x7_tr`, `_6x12_tr`, `_7x14B_tr`, `_logisoso22_tn`) is built
with exactly 95 glyphs — confirmed by reading the actual compiled U8g2 font
table's own "Glyphs: 95/N" header comment for each — the printable ASCII
range 0x20-0x7E and nothing else. `u8g2.drawStr()` draws via
`u8x8_ascii_next` (one input byte = one glyph lookup; UTF-8 decoding only
exists in the separate `drawUTF8()` call, which this file never uses). So
the ellipsis character ('…', UTF-8 bytes E2 80 A6) used throughout
`draw_str_ellipsis()` — this file's single most-used truncation path,
reached from nearly every screen — three-byte-decomposed into three
out-of-font glyph lookups instead of rendering as "…". Same for the bullet
in "Slot 9A • NIST PIV" and the dash standing in for "no fingerprint."
Fixed by replacing all of it with ASCII (".." for truncation, "-" for the
separator); this alone touches more of the screen output than anything
else in this pass.

Built a small real icon set (`src/systems/display_icons.h`), hand-authored
as XBM bitmaps (visually checked via a throwaway Python+Pillow render before
transcribing, not typed blind), and reused consistently: Bluetooth rune,
fingerprint/scan glyph, padlock, warning triangle, USB trident, and a
battery shell. One shared `draw_icon_state()` helper draws a glyph and
strikes it diagonally for the negative state (disconnected/absent), instead
of doubling the bitmap count. The battery glyph is shell(XBM) + a dynamically
sized fill — deliberately not a fake "level" meter: **this board has no
battery ADC**, only the BQ25185's two-pin digital charge state
(idle/charging/done/fault, see `battery_system.h`), so the fill communicates
state, the one thing the hardware can actually report, not a percentage it
can't measure.

Applied:
- A shared, fixed-width status-icon zone (battery + BLE, right-aligned) used
  by `draw_title`, `draw_status_bar`, `draw_clock`, and `draw_message`,
  replacing each screen's own hand-placed charge icon. This also fixes a
  real overlap bug: the old `draw_title` gave titles a 90px ellipsis budget
  with no awareness that `draw_charge_icon` could also draw a variable-width
  text label (CHG/FULL/FLT) starting as far left as ~86px when charging —
  the two could and would collide on a long title during a charge state.
  Title text now clips at `TITLE_SAFE_W` (86px with BLE built in), computed
  from where the icon zone actually starts, instead of a hand-guessed
  constant.
- `draw_clock`: the literal "FP" / "—" text indicator is now the fingerprint
  icon, struck through when absent.
- `draw_ble_menu`: rebuilt on the same `draw_list_row`/`LIST_ROWS`/
  `draw_scrollbar` grid every other list screen (Settings, top menu) uses,
  instead of its own hand-placed y-coordinates — this is the concrete fix
  for "settings and Bluetooth have their own thing." The connection-status
  line now carries the BLE icon and is wrapped in `draw_str_ellipsis`
  instead of an unbounded `drawStr` (the old "Status: Connected (N bnd)"
  line had no overflow protection at all against bond-count digit width).
- `draw_piv_pin` and the Home "Quick PIV" card: lock + BLE icons, copy
  tightened and ASCII-only, all dynamic-content lines through
  `draw_str_ellipsis`.
- `draw_message()` gained an optional centered icon parameter (default
  none, so existing simple callers are unaffected); wired up for the
  fingerprint prompt and the auth-error warning.
- `draw_device_info`'s four lines (the one genuinely diagnostic, text-dense
  screen — left as text by design) now route through `draw_str_ellipsis`
  defensively, since uptime in particular grows unbounded over a long-running
  device.

I did not rewrite every screen from scratch — `draw_totp`, `draw_enroll`,
`draw_fido_prompt`/`_processing`/`_success` were already internally
consistent and within bounds on inspection, and a blind rewrite with no
hardware to verify pixel placement is how new bugs get introduced. I fixed
what I could point to a concrete overlap, clipping, or rendering defect
for.

**Needs hardware to confirm:** every pixel position above is arithmetic, not
a render — I cannot see the actual OLED. In particular: the new icons'
visual weight/legibility against the real 0.96" SSD1306 glass, and whether
`TITLE_SAFE_W` leaves a comfortable gap or feels tight in practice.

---

## What's left open (not attempted, and why)

- **Device Info / Settings screens' overall visual density** — functional
  and bounded, not restyled, to keep the diff reviewable without hardware
  to check each change against.
- **A true "fast" tier duration tuned to a real daemon's reconnect
  behavior** — 60s is a reasonable default per the cited spec guidance, not
  measured against the actual `cryptick-daemon` retry loop (different repo).
- **PCB README fix** — identified with certainty (§5 above), not applied;
  out of this repo.

## Summary of files touched

- `include/board_config.h` — encoder pins, cited against the PCB source.
- `src/systems/event_bus.h`, `input_system.cpp`, `nav_system.cpp` — encoder
  quadrature decode + scroll-nav integration.
- `core/ble_fido/ble_gatt_esp32.cpp` — advertising tiers, connection
  parameters, CCCD authentication fix.
- `core/piv/piv.c` — extended-length APDU rejection.
- `drivers/usb_ccid.cpp` — blocking-detection slot gate + GENERATE_KEYPAIR
  coverage.
- `src/systems/display_system.cpp`, new `display_icons.h` — icon system,
  ASCII font-glyph fix, BLE menu layout unification, overlap fix.
- `tests/host/test_piv_apdu.py` — two new regression tests for (4a).
