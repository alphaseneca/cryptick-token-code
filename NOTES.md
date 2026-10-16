# Agent work notes — branch `agent/ble-power-piv-ui`

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
