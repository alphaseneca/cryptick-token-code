# Fuzzing the BLE reassembler

`core/ble_fido/ble_fido.c` is where hostile input actually lands. Bonding does
not remove the need for this: an established LESC bond means the controller
decrypts before we see anything, so malformed fragments do not come from an
unbonded attacker injecting into a live connection. They come from

1. **our own firmware** — a bonded device running a half-flashed image, an
   interrupted OTA, or a mismatched version sends garbage that is perfectly
   authenticated, and
2. **pre-bond paths** — service discovery and the `fidoControlPointLength` read
   happen before or outside the bond.

A crash here means the user cannot log in, caused by our own device.

## The two ways to run it

`ble_fuzz_driver.c` compiles both ways from one source.

### Portable — runs everywhere, gates the PR

A standalone binary under ASan + UBSan, fed randomised fragment streams by
`tests/host/test_ble_fido_fuzz.py`. This exists because Apple's Command Line
Tools **do not ship libFuzzer**, so a libFuzzer-only setup would silently not
run on the machine most of this work happens on.

```bash
pytest tests/host/test_ble_fido_fuzz.py -q
```

Tune the volume with `BLE_FUZZ_ITERATIONS` (default 240). Every failure prints
the seed and the full hex stream needed to reproduce it.

### libFuzzer — longer runs, Linux

```bash
clang -std=c11 -g -DBLE_FUZZ_LIBFUZZER \
  -fsanitize=fuzzer,address,undefined \
  -I core/ble_fido \
  -o /tmp/ble_fuzz tests/fuzz/ble_fuzz_driver.c core/ble_fido/ble_fido.c

/tmp/ble_fuzz -max_total_time=60 -max_len=4096
```

This is the `ble_reassembly` target the daemon's `PROJECT.md` §14 asks for,
covering input sources 1 and 2 above.

## Input format

Deliberately trivial, so the interesting logic stays in the Python generator
rather than in the C:

```
byte 0        fragment-size selector (indexes kSizes[] in the driver)
then          repeated: [1-byte length][length bytes of fragment]
```

A truncated trailing record stops the replay rather than erroring — a mutated
tail should still exercise the usable prefix.

## Verifying the harness still works

A fuzz suite that cannot fail is worse than none, because it reads as coverage.
Introduce an off-by-one in the continuation bound:

```c
/* in ble_fido_rx_fragment(), the continuation branch */
if ((uint32_t)_received + chunk > (uint32_t)_declared + 64)   /* was: > _declared */
```

Rebuild and rerun — ASan must report a global-buffer-overflow on `_msg` and the
suite must go red. Revert afterwards. This was checked when the harness was
written; check it again if you change the driver.
