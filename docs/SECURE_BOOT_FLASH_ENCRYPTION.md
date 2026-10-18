# ESP32-S3 secure boot + flash encryption — implementation plan

**Status: not started.** This is a brief for whoever (human or agent) picks this
up next, not a record of work already done. Nothing in this file has been
built, tested, or verified against real hardware.

## Why this exists

`SECURITY_ROADMAP.md` already names the gap plainly: "the wrap key sits in
NVS on the same flash chip, and flash encryption is not enabled... Anyone who
can read the *whole* flash — physical access with a programmer, or an
`esptool read_flash` over the exposed USB path — recovers both the key and
the ciphertext." That is true of every secret this firmware stores, not just
the TOTP wrap key: the PIV PIN hash, PUK hash, management key, retry
counters, and the FIDO/PIV master secret itself (`AuthenticatorState.key_space`
in NVS namespace `fido2`, key `state` — `core/fido2/hal_esp32.cpp`) all sit in
plain, unencrypted flash today.

The PIV `RESET APPLICATION` work (see `NOTES.md`, "PIV factory reset" and the
two entries after it) built a PIN-gated reset at the *application* layer —
but confirmed in the process that it means nothing against an attacker
willing to go one layer lower: `esptool erase_flash` wipes the same storage
without ever touching the PIV applet's own gate, and `esptool read_flash`
reads every secret in cleartext without needing to run any firmware at all.
This document is the plan for closing *that* gap — the hardware layer the
application-layer gate cannot reach.

**This is explicitly out of scope for whatever pass picks up `RESET
APPLICATION` or any other application-layer PIV/FIDO/OATH work.** It is a
separate project because it is a different kind of risk: irreversible
hardware state (burned eFuses), not software logic a host test suite can
exercise. Treat picking this up as its own deliberate decision, not a
natural follow-on to a feature pass.

## What these two features actually are, on this chip

They are independent and solve different problems; a real product wants
both, and enabling one without the other leaves a real gap:

- **Secure Boot V2.** An eFuse-burned digest of an RSA-3072 public key. The
  ROM bootloader, and then the second-stage bootloader, each refuse to
  execute an image unless it carries a valid signature from the matching
  private key. This stops "flash any firmware you like" at the hardware
  level — without it, nothing stops someone from flashing a *new*, unsigned
  firmware image that happily hands out whatever secrets flash encryption
  was supposed to protect.
- **Flash Encryption.** Flash contents (app, NVS, LittleFS — everything) are
  transparently encrypted with AES-XTS using a key burned into eFuse and
  (in Release Mode) locked against further reads. Firmware itself is
  unaffected — the MMU/flash cache decrypts on the fly — but `esptool
  read_flash`/`erase_flash` from outside the chip now sees ciphertext (read)
  or loses its ability to write plaintext the chip will ever decrypt
  correctly (erase/rewrite without going through the signed bootloader's own
  encrypting write path).

Each has a **Development Mode** (fast iteration; Flash Encryption dev mode
still allows re-flashing in plaintext over UART by design, Secure Boot dev
mode uses a known, non-secret key) and a **Release Mode**, which additionally
burns eFuses that disable the plaintext UART re-flash path and lock the key
read-out. Release Mode is the one that actually closes the gap this
document exists for. **Burning Release Mode eFuses is irreversible on real
hardware** — there is no "turn it back off."

## Known blockers to resolve before writing any code

- **`platformio.ini` currently pins no `platform` version** (`platform =
  espressif32` with nothing after it). eFuse layout, sdkconfig option names,
  and Secure Boot V2 / Flash Encryption defaults all vary across esp-idf
  major versions. Pin an exact version as the first step of this project,
  not something discovered mid-implementation — an unpinned platform means
  "which eFuses get burned" can silently change between two people's builds,
  which is not acceptable for a step this irreversible.
- **Confirm the Arduino-ESP32 framework (not raw esp-idf) actually exposes
  the sdkconfig knobs this needs**, for every environment in
  `platformio.ini` that ships to a real device (`esp32-s3-n16r8`,
  `esp32-s3-n16r8-ship`). If it does not, the real options are switching
  those environments to PlatformIO's `espidf` framework, or maintaining a
  parallel `sdkconfig.defaults` fragment specific to secure builds. Don't
  assume either answer — check against whatever esp-idf version gets pinned
  above.
- **This is not testable the way `piv.c` was.** There is no host build that
  can exercise eFuse behavior; `tests/host`'s whole value (compile the real
  C, drive it from Python) doesn't apply here. The only safe pre-hardware
  testing is esp-idf's own virtual eFuse support (`espefuse.py --virt`, or
  `idf.py` with `ESPTOOL_DEBUG`/virt flags, depending on the pinned IDF
  version) — use it for every iteration before this ever touches a real
  chip's real eFuses.

## Phased plan

### Phase 0 — Research and version pinning
Pin the esp-idf/platform version. Confirm the sdkconfig path (Arduino
framework vs. espidf framework) for the real product environments. Read
Espressif's own Secure Boot V2 and Flash Encryption technical reference
chapters for that exact pinned version — not a different version's docs,
since defaults and option names have changed across esp-idf releases.

### Phase 1 — Development-mode bring-up on a disposable lab unit
Enable both features in Development Mode only, on hardware nobody is
relying on (never the device being used for actual Mac login in the
meantime). Goal: confirm the firmware still boots and the existing test
suites (`tests/host`, the L1 Unity suites) still pass unmodified — flash
encryption in particular should be invisible to application code, since
PlatformIO/esp-idf handle it below the NVS/LittleFS API this firmware
already uses. If anything in `core/` needs to change to accommodate this,
that is a signal something assumed about flash layout was wrong, and it
needs to be understood before Phase 2, not patched around.

### Phase 2 — Key-management design (a product decision, not an engineering one)
Decide, explicitly, and write the decision down the way the PIV
management-key default was written down in `NOTES.md`:

- **Secure Boot signing key.** Where does the private key live, who can
  produce a signed release, and what is the recovery story if it is ever
  lost? Losing it means no device that has already burned the matching
  public-key digest can ever accept a new signed firmware image again —
  a permanent ceiling on every unit already in that state, not just the one
  signing operation that failed.
- **Flash Encryption key.** Per-device, randomly generated and burned on
  each unit's own first boot (esp-idf supports this), or one key shared
  across a batch and flashed in? This project's own PIV management-key
  precedent already picked "per-unit random, nothing to leak at scale"
  over "one shared constant" for exactly this reason (see `NOTES.md`, "PIV
  PUK and management key support" — "The management-key default: a real
  decision, not a default I made silently"). The same reasoning likely
  applies here, but it is being flagged, not assumed, because the
  consequence of a leaked *flash-encryption* key is larger: it exposes
  every secret this device will ever store, not one admin credential.

### Phase 3 — CI / release signing pipeline
Once Secure Boot is enabled anywhere outside a lab unit, every firmware
image that unit will ever accept must be signed with the key from Phase 2.
Update `.github/workflows/release.yml` (or wherever the real release
pipeline ends up) to sign images as part of the build, and decide where the
signing key material itself is held during CI — this is a secrets-handling
question for whatever CI platform is in use, not an esp-idf question.

### Phase 4 — JTAG / debug policy for production vs. lab builds
Release Mode flash encryption typically also burns the eFuse that disables
JTAG. `platformio.ini`'s `esp32-s3-n16r8-jtag` lab environment depends on
JTAG working. Decide explicitly which environments are allowed to ever
reach Release Mode (almost certainly not the JTAG lab environment) and
make sure the project's build matrix can't accidentally burn production
eFuses from a lab-flavored build.

### Phase 5 — Release-mode burn: the irreversible step
Only after Phases 0–4 are each confirmed working in Development Mode /
virtual eFuse emulation. Burn Release Mode eFuses on one real, explicitly
expendable test unit first — not a unit anyone is using — and confirm the
device still boots, still passes its test suites, and that a deliberately
wrong/unsigned image is correctly refused. **Get explicit human sign-off
before burning Release Mode eFuses on any unit a real person will actually
rely on.** This is the same category of decision the PIV reset gate's
"both blocked" removal was — not one an agent should make unilaterally on
a device someone depends on, because unlike that software change, this one
cannot be reverted by a later commit.

### Phase 6 — Docs and rollout
Update `SECURITY_ROADMAP.md`'s "Still open" list to move this item to
"Today," with the same honest "what this does and does not protect
against" framing that section already uses for the TOTP wrap key. Record
the actual implementation (not the plan) in `NOTES.md`, following this
project's existing convention: what changed, what was deliberately not
done, what's verified vs. what needs real hardware.

## What this does not fix, so nobody assumes it does

- **Existing, already-provisioned devices are not retroactively protected.**
  Flash encryption encrypts flash *as it is written* through the encrypting
  bootloader; a device already carrying plaintext NVS needs a full wipe and
  reprovision to adopt it — the same "this destroys the existing identity,
  not just the lock" trade-off the PIV factory-reset conversation already
  covered for a software-level wipe. There is no version of this project
  that protects a unit already in the field without also resetting it.
- **This is not a defense against every physical attack**, only the one
  `SECURITY_ROADMAP.md` names: reading or rewriting flash wholesale via the
  exposed USB/JTAG path. Side-channel and fault-injection attacks against
  the chip itself are a different, harder problem this project does not
  attempt to solve.
- **It does not change anything about the PIV `RESET APPLICATION` gate** or
  any other application-layer logic. Those stay exactly as they are; this
  project only changes what a *lower-level* attacker who skips the
  application layer entirely can do.
