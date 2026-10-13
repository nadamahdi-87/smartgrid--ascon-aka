"""
ascon_c.py
==========
Drop-in replacement for ascon_ref.py that calls the OFFICIAL optimized C
implementation of Ascon (https://github.com/ascon/ascon-c, opt64 variant)
through ctypes, instead of the pure-Python reference.

Why
---
The pure-Python reference implementation (pyascon) is written for clarity
and standard conformance, not speed; it is roughly two orders of magnitude
slower than the optimized C code. Competing schemes report timings from
optimized implementations, so benchmarking Ascon in pure Python understates
the protocol's real performance. This module keeps the exact same API and
produces byte-identical output, so it can be swapped in for benchmarking
while ascon_ref.py remains available for conformance checking.

Building the shared libraries
-----------------------------
    git clone --depth 1 https://github.com/ascon/ascon-c.git
    cd ascon-c

    # Linux / macOS
    INC=$PWD/tests
    (cd crypto_hash/asconxof128/opt64   && gcc -O3 -shared -fPIC \
        -o libasconxof.so  hash.c permutations.c printstate.c -I. -I$INC)
    (cd crypto_hash/asconhash256/opt64  && gcc -O3 -shared -fPIC \
        -o libasconhash.so hash.c permutations.c printstate.c -I. -I$INC)
    (cd crypto_aead/asconaead128/opt64  && gcc -O3 -shared -fPIC \
        -o libasconaead.so aead.c permutations.c printstate.c -I. -I$INC)

    # Windows (MinGW-w64 / MSYS2)
    #   replace  gcc -shared -fPIC -o lib*.so   with
    #            gcc -O3 -shared -o ascon*.dll
    # then set ASCON_C_DIR to the folder holding the DLLs.

Point this module at the libraries with the ASCON_C_DIR environment
variable, or drop them next to this file.

Verification
------------
Run this file directly to check that every function reproduces the output
of the pure-Python reference bit-for-bit:

    python ascon_c.py
"""

import ctypes
import os
import sys
import platform

# ---------------------------------------------------------------------------
# Locate and load the shared libraries
# ---------------------------------------------------------------------------
_EXT = ".dll" if platform.system() == "Windows" else ".so"
_SEARCH_DIRS = [
    os.environ.get("ASCON_C_DIR", ""),
    os.path.dirname(os.path.abspath(__file__)),
    "/tmp",
    ".",
]


def _load(basename: str):
    """Find and load one Ascon shared library."""
    names = [f"lib{basename}{_EXT}", f"{basename}{_EXT}"]
    tried = []
    for d in _SEARCH_DIRS:
        if not d:
            continue
        for n in names:
            path = os.path.join(d, n)
            tried.append(path)
            if os.path.exists(path):
                return ctypes.CDLL(path)
    raise OSError(
        f"Could not find {basename}{_EXT}. Build it from ascon-c (see the "
        f"module docstring) and set ASCON_C_DIR.\nSearched:\n  "
        + "\n  ".join(tried)
    )


_xof_lib = _load("asconxof")
_hash_lib = _load("asconhash")
_aead_lib = _load("asconaead")

# ---- signatures ----
for _lib in (_xof_lib, _hash_lib):
    _lib.crypto_hash.restype = ctypes.c_int
    _lib.crypto_hash.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),      # out
        ctypes.POINTER(ctypes.c_ubyte),      # in
        ctypes.c_ulonglong,                  # inlen
    ]

_aead_lib.crypto_aead_encrypt.restype = ctypes.c_int
_aead_lib.crypto_aead_encrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong),  # c, clen
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,                  # m, mlen
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,                  # ad, adlen
    ctypes.POINTER(ctypes.c_ubyte),                                      # nsec (unused)
    ctypes.POINTER(ctypes.c_ubyte),                                      # npub
    ctypes.POINTER(ctypes.c_ubyte),                                      # k
]
_aead_lib.crypto_aead_decrypt.restype = ctypes.c_int
_aead_lib.crypto_aead_decrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong),  # m, mlen
    ctypes.POINTER(ctypes.c_ubyte),                                      # nsec
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,                  # c, clen
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,                  # ad, adlen
    ctypes.POINTER(ctypes.c_ubyte),                                      # npub
    ctypes.POINTER(ctypes.c_ubyte),                                      # k
]

_XOF_MAX = 64      # CRYPTO_BYTES of the XOF api.h
_HASH_LEN = 32     # Ascon-Hash256 digest
_TAG_LEN = 16      # Ascon-AEAD128 tag


def _buf(data: bytes):
    """ctypes buffer from bytes; never zero-length (C would get a null ptr)."""
    if not data:
        return (ctypes.c_ubyte * 1)()
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


# ---------------------------------------------------------------------------
# Key derivation and hashing  (same API as ascon_ref)
# ---------------------------------------------------------------------------
def ascon_xof(message: bytes, output_length: int = 32, domain: str = "") -> bytes:
    """
    Ascon-XOF128 extendable-output function.

    `domain` provides domain separation exactly as in ascon_ref: the label
    and a zero byte are prepended to the message, so distinct labels give
    independent outputs from the same input.
    """
    if output_length > _XOF_MAX:
        raise ValueError(f"output_length must be <= {_XOF_MAX}")
    if domain:
        message = domain.encode() + b"\x00" + message
    out = (ctypes.c_ubyte * _XOF_MAX)()
    _xof_lib.crypto_hash(out, _buf(message), len(message))
    return bytes(out)[:output_length]


def ascon_hash(message: bytes) -> bytes:
    """Ascon-Hash256: fixed 256-bit digest."""
    out = (ctypes.c_ubyte * _HASH_LEN)()
    _hash_lib.crypto_hash(out, _buf(message), len(message))
    return bytes(out)


# ---------------------------------------------------------------------------
# Authenticated encryption (Ascon-AEAD128)
# ---------------------------------------------------------------------------
def _nonce16(nonce: bytes) -> bytes:
    """Pad or truncate a nonce to exactly 16 bytes (matches ascon_ref)."""
    if len(nonce) == 16:
        return nonce
    if len(nonce) < 16:
        return nonce + b"\x00" * (16 - len(nonce))
    return nonce[:16]


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes = b"") -> tuple:
    """Return (ciphertext, tag). Key is 16 bytes; nonce padded to 16."""
    npub = _nonce16(nonce)
    clen = ctypes.c_ulonglong(0)
    out = (ctypes.c_ubyte * (len(plaintext) + _TAG_LEN))()
    _aead_lib.crypto_aead_encrypt(
        out, ctypes.byref(clen),
        _buf(plaintext), len(plaintext),
        _buf(aad), len(aad),
        None, _buf(npub), _buf(key),
    )
    blob = bytes(out)[:clen.value]
    return blob[:-_TAG_LEN], blob[-_TAG_LEN:]


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 tag: bytes, aad: bytes = b"") -> bytes | None:
    """Return the plaintext, or None if the tag does not verify."""
    npub = _nonce16(nonce)
    blob = ciphertext + tag
    mlen = ctypes.c_ulonglong(0)
    out = (ctypes.c_ubyte * max(len(ciphertext), 1))()
    rc = _aead_lib.crypto_aead_decrypt(
        out, ctypes.byref(mlen),
        None,
        _buf(blob), len(blob),
        _buf(aad), len(aad),
        _buf(npub), _buf(key),
    )
    if rc != 0:
        return None
    return bytes(out)[:mlen.value]


# ---------------------------------------------------------------------------
# Conformance check against the pure-Python reference
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import ascon_ref as ref

    passed = total = 0

    def check(name, cond):
        global passed, total
        total += 1
        passed += bool(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    print("=" * 64)
    print("  ascon_c.py  vs  ascon_ref.py  (byte-for-byte conformance)")
    print("=" * 64)

    # --- XOF ---
    for msg, olen, dom in [
        (b"", 16, ""),
        (b"hello world", 32, ""),
        (os.urandom(16), 16, "K0_DERIVE"),
        (os.urandom(32), 16, "AUTH1"),
        (os.urandom(64), 16, "MAC2"),
        (os.urandom(100), 32, "SESSION"),
        (os.urandom(200), 64, "PID_INIT"),
    ]:
        check(f"XOF  len={len(msg):<4} out={olen:<3} dom={dom or '-'}",
              ascon_xof(msg, olen, dom) == ref.ascon_xof(msg, olen, dom))

    # --- Hash ---
    for msg in [b"", b"abc", os.urandom(64), os.urandom(1000)]:
        check(f"Hash len={len(msg)}", ascon_hash(msg) == ref.ascon_hash(msg))

    # --- AEAD ---
    for pt, ad in [(b"", b""), (b"data", b""), (os.urandom(64), b"sid"),
                   (os.urandom(200), os.urandom(32))]:
        k, n = os.urandom(16), os.urandom(16)
        c1, t1 = aead_encrypt(k, n, pt, ad)
        c2, t2 = ref.aead_encrypt(k, n, pt, ad)
        check(f"AEAD enc pt={len(pt)} ad={len(ad)}", (c1, t1) == (c2, t2))
        check(f"AEAD dec pt={len(pt)}", aead_decrypt(k, n, c1, t1, ad) == pt)

    # --- tamper rejection ---
    k, n = os.urandom(16), os.urandom(16)
    c, t = aead_encrypt(k, n, b"secret", b"ad")
    bad = bytes([t[0] ^ 0xFF]) + t[1:]
    check("AEAD rejects bad tag", aead_decrypt(k, n, c, bad, b"ad") is None)

    print("=" * 64)
    print(f"  Result: {passed}/{total} checks passed")
    print("=" * 64)
