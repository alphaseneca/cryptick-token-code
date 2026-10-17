# FIDO BLE transport

USB works natively on every OS with no host software. BLE is the second product
transport, and both are live at once.

The single most important thing on this page: **FIDO BLE is not CTAPHID over
BLE.** CTAPHID is the USB HID transport and nothing else. Tunnelling it over a
GATT link produces a token that only a bespoke host daemon can drive — Windows'
native BLE FIDO stack, `libfido2`, Chrome/Edge and `webauthn-authenticator-rs`
would all fail to talk to it, which removes the main reason to pick BLE FIDO
over a private protocol.

|  | CTAPHID (USB) | FIDO BLE |
| --- | --- | --- |
| Unit | 64-byte report, fixed | fragment sized by `fidoControlPointLength` (20–512) |
| Init header | CID(4) ‖ CMD(1) ‖ BCNT(2) = 7 bytes | CMD(1, high bit set) ‖ HLEN(2, big-endian) = 3 bytes |
| Cont header | CID(4) ‖ SEQ(1) = 5 bytes | SEQ(1, high bit clear, wraps 0x7f→0x00) = 1 byte |
| Channels | yes — CIDs, `INIT` handshake | **none** |
| Commands | `INIT`/`MSG`/`CBOR`/`PING`/`CANCEL`/`KEEPALIVE`/`ERROR`/`WINK` | `PING 0x81`, `KEEPALIVE 0x82`, `MSG 0x83`, `CANCEL 0xBE`, `ERROR 0xBF` |

There is no CID on the wire and no `CTAPHID_INIT` equivalent, so a 64-byte-report
entry point cannot express a BLE transaction. CTAP2 CBOR rides directly inside
`MSG`, not inside a CTAPHID frame.

## Layering

`ctap_request()` (`core/fido2/ctap.h`) is transport-independent. `ctaphid.c` is
one caller of it; BLE is a **sibling** caller, not a layer that squeezes itself
through `ctaphid.c`. `ctaphid.c` stays USB-only and untouched.

```text
USB HID report ──► ctaphid_handle_packet() ──┐
                                             ├──► ctap_request() ──► CTAP_RESPONSE
BLE fragment ────► ble_fido_rx_fragment() ───┘
```

**That is a layering diagram, not a threading one.** See
[Arbitration](#arbitration-usb-and-ble-share-one-ctap-core) below — getting it
wrong gives you state corruption and a user-presence confusion bug.

## Files

| File | Role |
| --- | --- |
| `core/ble_fido/ble_fido.h` | Wire format, UUIDs, commands, error codes, bounds |
| `core/ble_fido/ble_fido.c` | Reassembly and response fragmentation. Freestanding C — no NimBLE, no FreeRTOS |
| `core/ble_fido/ble_gatt_esp32.cpp` | NimBLE glue: GATT table, pairing, advertising |
| `core/ble_fido/ble_daemon.h` / `ble_daemon_gatt_esp32.cpp` | Daemon Bridge GATT service (`FBF6EB80-…`) — a private tunnel carrying CTAP messages between `cryptick-daemon` and the token. Same framing as this page, a sibling service on the same NimBLE server, and a fourth producer into the one `ctap_request()` consumer (`daemon_ble_submit_request()`, `core/fido2/hal_esp32.cpp`) |
| `core/ble_fido/ble_hid_keyboard.h/.cpp` | A separate BLE HID-keyboard service used to type a PIN (e.g. the PIV PIN) into a paired host. Output-only; does not read `fidoControlPoint` and carries no CTAP traffic |
| `tests/host/test_ble_fido_framing.py` | Unit layer: compiles the framing and drives it through `ctypes` |
| `tests/conformance/ble_fido_v1.json` | Shared corpus, replayed by both this repo and the daemon |
| `tests/host/test_ble_fido_conformance.py` | Replays that corpus against the C |
| `tests/fuzz/ble_fuzz_driver.c` | ASan/UBSan + libFuzzer driver for the reassembler |

The split is deliberate: the framing layer is where the adversarial input
arrives, so it is kept host-compilable and tested directly rather than only on
the bench.

## GATT service

The advertisement must carry the 16-bit FIDO Service UUID `0xFFFD`.

| Characteristic | UUID | Properties |
| --- | --- | --- |
| fidoControlPoint | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB` | Write (request, **not** write-without-response), encrypted + authenticated |
| fidoStatus | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB` | Notify, encrypted + authenticated |
| fidoControlPointLength | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB` | Read, 2 bytes big-endian, 20–512 |
| fidoServiceRevisionBitfield | `F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB` | Read/Write, 1 byte; bit 5 (`0x20`) = FIDO2 |

`fidoControlPointLength` is derived from the negotiated ATT MTU (`ATT_MTU - 3`),
clamped to `[20, 512]`, and republished on every MTU change. **Never send a
fragment larger than the value you published**, and never accept one either.

Write-*with-response* is required: the peer has to learn that a fragment was
rejected.

## Pairing

CTAP requires LE Secure Connections bonding **with MITM protection**. Just Works
pairing does not provide it. The OLED is what earns the device Passkey Entry:

```c
NimBLEDevice::setSecurityAuth(true /* bonding */, true /* MITM */, true /* SC */);
NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
```

A fresh 6-digit passkey is generated per pairing and raised on the OLED with
`device_show_pairing_passkey()`, which opens the dedicated `UI_BLE_PAIRING`
screen and wakes the panel.

That screen exists for a reason. Parking only the caption with
`device_set_ui_label()` is **not** enough: the caption is drawn by whichever
screen is open, and during pairing none of the FIDO screens is — so the passkey
would be stored and never rendered, on a panel that is most likely asleep.
Reusing `UI_FIDO_PROMPT` instead would draw the digits under the subtitle
"Place finger" and start the fingerprint matcher, telling the user to do the
wrong thing. Pairing takes a typed passkey, not a finger.

The screen is cleared on `onAuthenticationComplete` and on disconnect, so a peer
that walks away mid-pairing does not leave a stale prompt on the display. The
idle heartbeat also leaves it alone — it would otherwise clear the passkey after
1.5s, while a human is still typing.

fidoControlPoint and fidoStatus require encryption *and* authentication, so an
unbonded peer cannot reach them at all; `onAuthenticationComplete` drops any
link that somehow settles unauthenticated.

## Bounds

`HLEN` is 16-bit, so a peer can declare up to 65535 bytes. Do not allocate that.
The ceiling is `BLE_FIDO_MAX_MSG` (1200), which tracks `CTAP_MAX_MESSAGE_SIZE`
— `hal_esp32.cpp` static-asserts the two agree. Rejected at the init fragment,
before allocating. Also rejected:

- a continuation with no active transaction → `ERR_INVALID_SEQ`
- a `SEQ` that is not `(prev + 1) & 0x7f` → `ERR_INVALID_SEQ`
- a continuation carrying zero data bytes → `ERR_INVALID_LEN` (otherwise a peer stalls forever)
- total delivered bytes exceeding the declared `HLEN` → `ERR_INVALID_LEN`
- any fragment longer than the published `fidoControlPointLength` → `ERR_INVALID_LEN`

That last rule is the **device's alone**. `fidoControlPointLength` bounds writes
to fidoControlPoint; a host reassembling notifications on fidoStatus sizes them
by the negotiated ATT MTU, which may legitimately exceed it. Enforcing it on the
host side would be an interop bug, so the shared corpus tags that vector
`host_to_device`.

`ERR_BUSY` (`0x06`) is a real BLE error code — only `0x0a` and `0x0b` are
reserved for HID. A request refused because the CTAP core is busy reports
`ERR_BUSY`, not `ERR_OTHER`, which is the only form of it the peer can act on.

Any error aborts the transaction and returns to idle. Half-flashed firmware and
interrupted OTAs produce exactly this class of malformed-but-authenticated
input, so it is worth being strict.

An **init fragment arriving mid-transaction** is also rejected
(`ERR_INVALID_SEQ`). This transport has no channels, so exactly one transaction
is in flight at a time and a second init is a protocol violation, not a second
conversation. Failing closed does not wedge anything: the abort leaves the
reassembler idle, so a host that timed out and retries succeeds on its next
init, at the cost of one round trip.

`CANCEL` is the **one exception**, and it is not a judgement call. CTAP2 §11.4.8:

> Whether a request was cancelled or not, the authenticator MUST NOT reply to
> the cancel message itself.

Every rejection path emits `CMD_ERROR`, so routing a cancel through one violates
that MUST NOT. `CANCEL` is therefore handled before any check that could reply:
it may interrupt a message in flight, its declared length is ignored rather than
validated, and even a truncated or over-long cancel is answered with silence.
The cancelled request replies for itself with `CTAP2_ERR_KEEPALIVE_CANCEL`.

That also settles whether a `CANCEL` carrying a payload should be illegal: it
cannot be. Rejecting it means replying to it, so the strict reading is
unimplementable rather than merely strict.

Both implementations got this wrong in the same direction first — the firmware
by replacing the in-flight transaction, then both by answering `InvalidSeq`
after agreeing with each other. Agreement between the two halves is not
evidence; neither side had read §11.4.8. That is what the shared corpus is for.

## Arbitration: USB and BLE share one CTAP core

`ctap_request()` has no mutex, no re-entrancy guard, and no critical section
anywhere near it. What makes it safe is structural: **one task** (`fido2_task`,
core 0, priority 4) is its only caller.

The obvious NimBLE integration — reassemble in the GATT write callback and call
the CTAP layer from there — runs on the **NimBLE host task**. Two tasks would
then be inside `ctap_request()` at once, and the authenticator's PIN token
state, RK iteration and response buffer are shared mutable state.

So BLE is a second **producer**, never a second consumer:

- USB keeps posting 64-byte reports; `ctaphid.c` reassembles them as it always did.
- BLE reassembles fragments **on the NimBLE task** (pure byte work, safe there),
  then posts one complete message via `fido_ble_submit_request()`.
- The FIDO task sets the active transport before dispatch and clears it after,
  which is what routes the keepalive back out the right door.
- While a transaction is in flight the other transport gets a **busy refusal**
  (`BLE_FIDO_ERR_OTHER`), not a queue slot. Queueing a second transaction that
  will demand its own fingerprint minutes later is worse than a clean refusal.

`fido_ble_request_t` is ~1.2 KB, so the queue carries pointers into a two-buffer
pool rather than copies.

`CMD_CANCEL` is never queued — the FIDO task is normally blocked in the presence
wait when one arrives, so a queued cancel would not be drained until the very
thing it is meant to abort had finished. It calls `ctaphid_cancel_request()`
inline, mirroring `poll_queued_cancel()` on the USB side.

### The security half

`ctap_user_presence_test()` waits on one process-global `_user_confirmed` flag.
With two ceremonies in flight, **one fingerprint touch satisfies whichever check
reads the flag first** — which may not be the one the user meant to approve. A
bonded BLE peer could open an assertion and wait for the user to touch the
sensor for their own unrelated USB operation.

This is not hypothetical and did not need BLE to exist: the CDC console's
`OATH PUT` / `TOTP_DEL` path already calls presence from the Arduino loop while
the FIDO task can be in a WebAuthn ceremony. Ceremonies are now serialized
behind a try-take mutex — the second is refused, not queued. See
[ARCHITECTURE.md](ARCHITECTURE.md#threading-model).

**Any future transport must feed that same gate rather than adding a second
presence flag.**

## Keepalive

`ctap_user_presence_test()` ticks every `CRYPTICK_FIDO_KEEPALIVE_MS` (100 ms),
which suits both transports. It calls `fido_send_keepalive()`, which dispatches
on the active transport: `ctaphid_update_status()` on USB, or a `CMD_KEEPALIVE`
(`0x82`) notification on fidoStatus with a one-byte body — `0x01` PROCESSING or
`0x02` TUP_NEEDED — on BLE.

## Build

Enabled by `-DCRYPTICK_BLE_FIDO=1` (the `${cryptick.ble}` fragment in
`platformio.ini`), which every product env carries. Costs roughly +224 KB flash
and +23 KB RAM over a USB-only image. Set it to `0` for a USB-only build; the
framing layer still compiles and its host tests still run.

## What BLE does *not* carry

BLE is not yet a drop-in replacement for the USB cable. Only CTAP2 crosses it.

| Capability | USB path | BLE path |
| --- | --- | --- |
| FIDO2 / CTAP2 | CTAPHID `CBOR` → `ctap_request()` | **yes** — `MSG` → `ctap_request()` |
| U2F / CTAP1 | CTAPHID `MSG` → `u2f_request()` | no — only `ctap_request()` is wired |
| OATH / TOTP management | `CTAPHID_CRYPTICK_OATH` (`0x63`) | **no** |
| Bootloader entry | `CTAPHID_ENTERBOOT` (`0x51`) | **no** |
| Console / logs | USB CDC | no |
| PIV (Mac login) | USB CCID — written, unverified on hardware | **written, unverified on hardware** — `FBF6EB90-…` service, framing shared with 0xFFFD, not advertised |

The OATH and bootloader gaps are structural, not an oversight. Both are
**vendor CTAPHID commands**, dispatched inside `ctaphid.c` and never reaching
`ctap_request()`. CTAPHID has a vendor command range; the FIDO BLE transport
does not — its command set is fixed at `PING`/`KEEPALIVE`/`MSG`/`CANCEL`/
`ERROR`, with no room to add `0x63`. Carrying OATH over BLE therefore needs a
deliberate choice between:

1. a **second GATT service** with its own UUID and framing, reusing
   `ble_fido.c`'s reassembler but not its service;
2. **CTAP2 vendor CBOR commands**, so the request rides inside `MSG` and
   arrives through `ctap_request()` like everything else — no new service, and
   it inherits the arbitration and presence gate for free; or
3. **the daemon's IPC**, leaving the device FIDO-only over BLE and letting the
   host expose OATH from its own side.

(2) is the cheapest on the device and the only one that needs no new
arbitration. None of the three is implemented.

## Not yet done

- Bench sign-off against Windows' native BLE FIDO stack, Chrome and `libfido2`.
- A request timeout: the spec's `ERR_REQ_TIMEOUT` (`0x05`) is defined here but a
  stalled reassembly is currently only cleared by disconnect, `CANCEL`, or the
  next init fragment.
- PIV over BLE (host-side virtual reader) — see [MAC_LOGIN.md](MAC_LOGIN.md).
  It would inherit the same arbitration and must route through the same single
  consumer rather than inventing a second scheme.
