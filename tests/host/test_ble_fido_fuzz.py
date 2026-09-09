"""Randomised fragment streams through ble_fido.c under ASan + UBSan.

Reassembly is the surface hostile input actually reaches: a bonded peer running
a half-flashed image or an interrupted OTA sends malformed-but-authenticated
fragments, and the pre-bond paths are unauthenticated by nature. A panic or an
overflow there means the user cannot log in, caused by our own device.

This is the portable layer: clang ships ASan and UBSan everywhere, including
macOS, where the Command Line Tools do **not** ship libFuzzer. The same driver
compiles as a libFuzzer target with -DBLE_FUZZ_LIBFUZZER for the longer Linux
runs (see tests/fuzz/README.md).

Failures print the exact seed and the hex stream needed to reproduce.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DRIVER_SRC = REPO_ROOT / "tests" / "fuzz" / "ble_fuzz_driver.c"
FRAMING_SRC = REPO_ROOT / "core" / "ble_fido" / "ble_fido.c"

# Mirrors kSizes in the driver.
SIZES = [20, 21, 22, 23, 64, 128, 255, 256, 511, 512]

CMDS = [0x81, 0x82, 0x83, 0xBE, 0xBF]

# How many random streams per case. Kept small enough to stay a PR gate;
# the libFuzzer target is where long runs belong.
ITERATIONS = int(os.environ.get("BLE_FUZZ_ITERATIONS", "240"))


@pytest.fixture(scope="module")
def driver(tmp_path_factory) -> Path:
    cc = shutil.which("clang") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler on PATH")

    out = tmp_path_factory.mktemp("blefuzz") / "ble_drv"
    cmd = [
        cc,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-g",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-I",
        str(REPO_ROOT / "core" / "ble_fido"),
        "-o",
        str(out),
        str(DRIVER_SRC),
        str(FRAMING_SRC),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(f"sanitizer build unavailable:\n{proc.stderr[:800]}")
    return out


def replay(driver: Path, stream: bytes) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    return subprocess.run(
        [str(driver)], input=stream, capture_output=True, env=env, timeout=60
    )


def check(driver: Path, stream: bytes, seed: object = None) -> None:
    proc = replay(driver, stream)
    detail = (
        f"\nseed={seed}\nstream={stream.hex()}\n"
        f"stdout={proc.stdout.decode(errors='replace')}\n"
        f"stderr={proc.stderr.decode(errors='replace')[:4000]}"
    )
    assert proc.returncode == 0, f"driver aborted (rc={proc.returncode}){detail}"
    blob = proc.stdout + proc.stderr
    for marker in (b"AddressSanitizer", b"runtime error", b"INVARIANT"):
        assert marker not in blob, f"sanitizer/invariant failure{detail}"


def record(frag: bytes) -> bytes:
    """One length-prefixed fragment record, as the driver expects."""
    return bytes([len(frag) & 0xFF]) + frag[:255]


def rnd_fragment(rng: random.Random, size: int) -> bytes:
    """A fragment biased toward structurally interesting shapes."""
    kind = rng.random()
    if kind < 0.35:
        # Init fragment, sometimes with a wild declared length.
        cmd = rng.choice(CMDS) if rng.random() < 0.3 else 0x83
        declared = rng.choice(
            [0, 1, 2, 17, 100, 1199, 1200, 1201, 0x7FFF, 0xFFFF, rng.randrange(0x10000)]
        )
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, size - 2)))
        return bytes([cmd, (declared >> 8) & 0xFF, declared & 0xFF]) + body
    if kind < 0.75:
        # Continuation, usually with a plausible sequence number.
        seq = rng.choice([0, 1, 2, 0x7E, 0x7F, rng.randrange(0x80)])
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, size)))
        return bytes([seq & 0x7F]) + body
    # Pure noise, including over-long fragments the device must refuse.
    n = rng.randrange(0, min(size + 8, 255))
    return bytes(rng.randrange(256) for _ in range(n))


def rnd_stream(rng: random.Random) -> bytes:
    sel = rng.randrange(len(SIZES))
    size = SIZES[sel]
    out = bytes([sel])
    for _ in range(rng.randrange(1, 24)):
        out += record(rnd_fragment(rng, size))
    return out


def test_empty_and_degenerate_inputs(driver):
    for stream in (b"", b"\x00", b"\x00\x00", b"\xff", b"\x00\xff", b"\x00\x01"):
        check(driver, stream, seed=f"degenerate:{stream.hex()}")


def test_truncated_tail_is_not_read_past(driver):
    """A record claiming more bytes than remain must stop the replay, not
    read past the buffer. This is the shape a mutated tail always takes."""
    check(driver, b"\x00\x20\x83\x00", seed="truncated-tail")


def test_declared_length_extremes(driver):
    for declared in (0x0000, 0x04B0, 0x04B1, 0x7FFF, 0xFFFF):
        stream = b"\x00" + record(bytes([0x83, declared >> 8, declared & 0xFF, 1, 2, 3]))
        check(driver, stream, seed=f"declared:{declared:#06x}")


@pytest.mark.parametrize("chunk", range(8))
def test_random_streams(driver, chunk):
    """Deterministic per chunk, so a failure reproduces from its seed."""
    for i in range(ITERATIONS // 8):
        seed = chunk * 100_000 + i
        rng = random.Random(seed)
        check(driver, rnd_stream(rng), seed=seed)


def test_long_valid_stream_then_garbage(driver):
    """A well-formed prefix followed by noise: the interesting transitions are
    at the boundary, where state exists to corrupt."""
    rng = random.Random(0xC0FFEE)
    size = 20
    payload = bytes(rng.randrange(256) for _ in range(600))
    stream = bytes([0])  # size selector -> 20
    stream += record(bytes([0x83, len(payload) >> 8, len(payload) & 0xFF]) + payload[:17])
    off, seq = 17, 0
    while off < len(payload):
        stream += record(bytes([seq & 0x7F]) + payload[off : off + 19])
        off += 19
        seq += 1
    for _ in range(12):
        stream += record(rnd_fragment(rng, size))
    check(driver, stream, seed="valid-then-garbage")
