"""Compile a freestanding C source from the firmware tree and load it via ctypes.

L0 tests that re-implement firmware logic in Python only prove the Python copy
is self-consistent. Where a source is freestanding — no Arduino, no ESP-IDF —
the host can compile and call the real thing instead, so a test failure means
the firmware is wrong rather than the test being stale.

Returns a loaded ``ctypes.CDLL``; callers declare argtypes/restype themselves.
"""
from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Shared include roots, mirroring the [cryptick] includes in platformio.ini.
# Keep these in step with that list: a missing root shows up as a fatal
# "file not found" the moment a test compiles a source that spans layers.
INCLUDE_DIRS = (
    "core",
    "core/fido2",
    "core/ble_fido",
    "core/piv",
    "include",
    "drivers",
)

_CACHE: dict[tuple[str, ...], ctypes.CDLL] = {}


def _compiler() -> str:
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc):
            return cc
    pytest.skip("no C compiler on PATH; cannot exercise the firmware C directly")


def build_shared_lib(sources, tmp_path: Path, name: str = "libcryptick") -> ctypes.CDLL:
    """Compile ``sources`` (repo-relative paths) into one shared library."""
    key = tuple(sorted(str(s) for s in sources))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    out = tmp_path / f"{name}{suffix}"
    cmd = [_compiler(), "-shared", "-fPIC", "-O1", "-std=c11", "-Wall", "-o", str(out)]
    for inc in INCLUDE_DIRS:
        cmd += ["-I", str(REPO_ROOT / inc)]
    cmd += [str(REPO_ROOT / s) for s in sources]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"compiling {key} failed:\n{proc.stderr}")

    lib = ctypes.CDLL(str(out))
    _CACHE[key] = lib
    return lib
