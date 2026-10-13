"""
=============================================================
  ASCON-AEAD128 — Authenticated Encryption (NIST SP 800-232)
=============================================================
  Researcher : Nada
  Purpose    : Real ASCON-AEAD128 to replace the AES-GCM
               placeholder, making the protocol 100% ASCON.

  Reference  : NIST SP 800-232 (2023), Ascon family.
               ASCON-AEAD128 parameters:
                 - 320-bit state (5 x 64-bit words)
                 - 128-bit key, 128-bit nonce, 128-bit tag
                 - rate = 128 bits (16 bytes)
                 - init/final permutation: 12 rounds (p^12)
                 - data processing permutation: 8 rounds (p^8)
=============================================================
"""

# -------------------------------------------------------------
#  ASCON permutation (shared core)
# -------------------------------------------------------------
def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _permutation(S, rounds):
    RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
          0x78, 0x69, 0x5a, 0x4b]
    for r in range(12 - rounds, 12):
        # add round constant
        S[2] ^= RC[r]
        # substitution layer (5-bit S-box, bit-sliced)
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [0] * 5
        for i in range(5):
            T[i] = (S[i] ^ (~S[(i + 1) % 5] & 0xFFFFFFFFFFFFFFFF) & S[(i + 2) % 5])
        S[0] = T[0] ^ T[4]; S[1] = T[1] ^ T[0]
        S[2] = (~T[2]) & 0xFFFFFFFFFFFFFFFF; S[2] ^= T[1]
        S[3] = T[3] ^ T[2]; S[4] = T[4] ^ T[3]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]
        # linear diffusion layer
        S[0] ^= _rotr(S[0], 19) ^ _rotr(S[0], 28)
        S[1] ^= _rotr(S[1], 61) ^ _rotr(S[1], 39)
        S[2] ^= _rotr(S[2], 1) ^ _rotr(S[2], 6)
        S[3] ^= _rotr(S[3], 10) ^ _rotr(S[3], 17)
        S[4] ^= _rotr(S[4], 7) ^ _rotr(S[4], 41)
    return S


# -------------------------------------------------------------
#  Helpers: bytes <-> 64-bit words (big-endian)
# -------------------------------------------------------------
def _b2w(b):
    return int.from_bytes(b, "big")


def _w2b(w, n=8):
    return (w & ((1 << (8 * n)) - 1)).to_bytes(n, "big")


# IV for ASCON-AEAD128 (per SP 800-232 / Ascon v1.2 AEAD-128)
# 64-bit IV encoding key length, rate, rounds.
_IV_AEAD = 0x80400c0600000000


def _pad_rate16(block):
    """Pad a partial 16-byte block: append 0x01 then zeros."""
    return block + b"\x01" + b"\x00" * (16 - len(block) - 1)


# -------------------------------------------------------------
#  ASCON-AEAD128 encryption
# -------------------------------------------------------------
def ascon_aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                       associated_data: bytes = b"") -> tuple:
    """
    Returns (ciphertext, tag). key and nonce are 16 bytes each.
    """
    assert len(key) == 16 and len(nonce) == 16
    k0, k1 = _b2w(key[:8]), _b2w(key[8:])
    n0, n1 = _b2w(nonce[:8]), _b2w(nonce[8:])

    # --- Initialization ---
    S = [_IV_AEAD, k0, k1, n0, n1]
    S = _permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1

    # --- Associated data ---
    if len(associated_data) > 0:
        ad = associated_data
        while len(ad) >= 16:
            S[0] ^= _b2w(ad[:8]); S[1] ^= _b2w(ad[8:16])
            S = _permutation(S, 8)
            ad = ad[16:]
        block = _pad_rate16(ad)
        S[0] ^= _b2w(block[:8]); S[1] ^= _b2w(block[8:16])
        S = _permutation(S, 8)
    # domain separation
    S[4] ^= 1

    # --- Plaintext / ciphertext ---
    ct = b""
    pt = plaintext
    while len(pt) >= 16:
        S[0] ^= _b2w(pt[:8]); S[1] ^= _b2w(pt[8:16])
        ct += _w2b(S[0]) + _w2b(S[1])
        S = _permutation(S, 8)
        pt = pt[16:]
    # final partial block
    block = _pad_rate16(pt)
    S[0] ^= _b2w(block[:8]); S[1] ^= _b2w(block[8:16])
    # output only the partial-length bytes
    last = (_w2b(S[0]) + _w2b(S[1]))[:len(pt)]
    ct += last

    # --- Finalization ---
    S[2] ^= k0
    S[3] ^= k1
    S = _permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1
    tag = _w2b(S[3]) + _w2b(S[4])
    return ct, tag


# -------------------------------------------------------------
#  ASCON-AEAD128 decryption
# -------------------------------------------------------------
def ascon_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                       tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Returns plaintext if tag is valid, else None.
    """
    assert len(key) == 16 and len(nonce) == 16 and len(tag) == 16
    k0, k1 = _b2w(key[:8]), _b2w(key[8:])
    n0, n1 = _b2w(nonce[:8]), _b2w(nonce[8:])

    S = [_IV_AEAD, k0, k1, n0, n1]
    S = _permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1

    if len(associated_data) > 0:
        ad = associated_data
        while len(ad) >= 16:
            S[0] ^= _b2w(ad[:8]); S[1] ^= _b2w(ad[8:16])
            S = _permutation(S, 8)
            ad = ad[16:]
        block = _pad_rate16(ad)
        S[0] ^= _b2w(block[:8]); S[1] ^= _b2w(block[8:16])
        S = _permutation(S, 8)
    S[4] ^= 1

    pt = b""
    ct = ciphertext
    while len(ct) >= 16:
        c0, c1 = _b2w(ct[:8]), _b2w(ct[8:16])
        pt += _w2b(S[0] ^ c0) + _w2b(S[1] ^ c1)
        S[0] = c0; S[1] = c1
        S = _permutation(S, 8)
        ct = ct[16:]
    # final partial block
    clen = len(ct)
    s_bytes = _w2b(S[0]) + _w2b(S[1])
    p_last = bytes(a ^ b for a, b in zip(s_bytes[:clen], ct))
    pt += p_last
    # absorb recovered plaintext with padding
    block = _pad_rate16(p_last)
    S[0] ^= _b2w(block[:8]); S[1] ^= _b2w(block[8:16])

    S[2] ^= k0
    S[3] ^= k1
    S = _permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1
    tag_calc = _w2b(S[3]) + _w2b(S[4])

    # constant-time compare
    import hmac
    if hmac.compare_digest(tag_calc, tag):
        return pt
    return None


# -------------------------------------------------------------
#  Tests
# -------------------------------------------------------------
def run_tests():
    import os, time
    print("=" * 60)
    print("  ASCON-AEAD128 — Correctness & Performance Tests")
    print("=" * 60)
    results = []

    key = os.urandom(16)
    nonce = os.urandom(16)

    # Test 1: round-trip correctness
    msg = b"smart_meter_reading_220V_5.2A_1.14kWh"
    aad = b"SID-0001"
    ct, tag = ascon_aead_encrypt(key, nonce, msg, aad)
    rec = ascon_aead_decrypt(key, nonce, ct, tag, aad)
    t1 = (rec == msg)
    print(f"\n  Test 1: encrypt -> decrypt round-trip      : {t1}")
    results.append(("Round-trip correctness", t1))

    # Test 2: tampering detected
    bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
    t2 = (ascon_aead_decrypt(key, nonce, bad_ct, tag, aad) is None)
    print(f"  Test 2: tampered ciphertext rejected       : {t2}")
    results.append(("Tamper detection", t2))

    # Test 3: wrong AAD detected
    t3 = (ascon_aead_decrypt(key, nonce, ct, tag, b"WRONG") is None)
    print(f"  Test 3: wrong associated data rejected     : {t3}")
    results.append(("AAD authentication", t3))

    # Test 4: wrong key detected
    t4 = (ascon_aead_decrypt(os.urandom(16), nonce, ct, tag, aad) is None)
    print(f"  Test 4: wrong key rejected                 : {t4}")
    results.append(("Key authentication", t4))

    # Test 5: empty plaintext
    ct0, tag0 = ascon_aead_encrypt(key, nonce, b"", aad)
    t5 = (ascon_aead_decrypt(key, nonce, ct0, tag0, aad) == b"")
    print(f"  Test 5: empty plaintext handled            : {t5}")
    results.append(("Empty plaintext", t5))

    # Test 6: multi-block (>16 bytes)
    big = os.urandom(100)
    ctb, tagb = ascon_aead_encrypt(key, nonce, big, aad)
    t6 = (ascon_aead_decrypt(key, nonce, ctb, tagb, aad) == big)
    print(f"  Test 6: multi-block (100 bytes) round-trip : {t6}")
    results.append(("Multi-block", t6))

    # Test 7: ciphertext length == plaintext length
    t7 = (len(ct) == len(msg))
    print(f"  Test 7: |ciphertext| == |plaintext|        : {t7}")
    results.append(("Length preservation", t7))

    # Performance
    print("\n" + "-" * 60)
    ITER = 2000
    t0 = time.perf_counter()
    for _ in range(ITER):
        ascon_aead_encrypt(key, nonce, msg, aad)
    enc_ms = (time.perf_counter() - t0) / ITER * 1000
    t0 = time.perf_counter()
    for _ in range(ITER):
        ascon_aead_decrypt(key, nonce, ct, tag, aad)
    dec_ms = (time.perf_counter() - t0) / ITER * 1000
    print(f"  ASCON-AEAD128 encryption: {enc_ms:.5f} ms  (pure Python)")
    print(f"  ASCON-AEAD128 decryption: {dec_ms:.5f} ms  (pure Python)")
    print("  Note: pure-Python timing is relative; on hardware/C,")
    print("        ASCON is far faster (LSEG: 1.79 us on RPi).")

    print("\n" + "=" * 60)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'} : {name}")
    print(f"\n  {passed}/{len(results)} correctness tests passed")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
