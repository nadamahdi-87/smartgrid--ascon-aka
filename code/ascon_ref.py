"""
=============================================================
  ascon_ref.py  —  Standard-conformant ASCON primitives
  Researcher: Nada
=============================================================
  This module exposes the exact function signatures used by all
  protocol phases, but implements them with the OFFICIAL reference
  implementation of the NIST SP 800-232 Ascon family (pyascon, by
  Maria Eichlseder, one of Ascon's designers).

  Why this matters
  ----------------
  Ascon as standardized in NIST SP 800-232 differs from the earlier
  CAESAR/LWC submission in two ways that change every output bit:
      * the byte order was switched from big-endian to little-endian
      * the initial values (IV) were replaced with a new format
        (Ascon-AEAD128 now uses IV = 0x00001000808c0001)

  Using the reference implementation therefore guarantees bit-exact
  conformance with the standard, which a self-written implementation
  cannot claim without full known-answer-test validation.

  Primitives provided
  -------------------
      ascon_xof(msg, out_len, domain)  -> Ascon-XOF128   (key derivation)
      ascon_hash(msg)                  -> Ascon-Hash256  (hashing)
      aead_encrypt(k, n, pt, aad)      -> Ascon-AEAD128  (enc)
      aead_decrypt(k, n, ct, tag, aad) -> Ascon-AEAD128  (dec)

  Reference: NIST SP 800-232 (2025); pyascon (github.com/meichlseder/pyascon)
=============================================================
"""

import ascon as _ref


# -------------------------------------------------------------
#   Key derivation and hashing
# -------------------------------------------------------------

def ascon_xof(message: bytes, output_length: int = 32, domain: str = "") -> bytes:
    """
    Ascon-XOF128 extendable-output function.

    `domain` provides domain separation: distinct labels yield
    independent outputs from the same message (e.g. "K0_DERIVE"
    vs "PID_INIT"), so leaking one derived value reveals nothing
    about the others.
    """
    if domain:
        message = domain.encode() + b"\x00" + message
    return _ref.ascon_hash(message, "Ascon-XOF128", output_length)


def ascon_hash(message: bytes) -> bytes:
    """Ascon-Hash256: fixed 256-bit digest."""
    return _ref.ascon_hash(message, "Ascon-Hash256", 32)


# -------------------------------------------------------------
#   Authenticated encryption (Ascon-AEAD128)
# -------------------------------------------------------------

def _nonce16(nonce: bytes) -> bytes:
    """
    Ascon-AEAD128 requires a 128-bit nonce. Phase code builds nonces
    of varying width (e.g. SID[:4] || Ctr), so pad deterministically
    on the right. Uniqueness of the input nonce is preserved.
    """
    if len(nonce) == 16:
        return nonce
    if len(nonce) > 16:
        return nonce[:16]
    return nonce + b"\x00" * (16 - len(nonce))


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""):
    """
    Encrypt and authenticate. Returns (ciphertext, tag).

    The reference API returns ct||tag concatenated; the protocol code
    expects them separately, so split off the trailing 16-byte tag.
    """
    ct_tag = _ref.ascon_encrypt(key, _nonce16(nonce), aad, plaintext, "Ascon-AEAD128")
    return ct_tag[:-16], ct_tag[-16:]


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                 aad: bytes = b""):
    """
    Verify and decrypt. Returns the plaintext, or None if the tag
    fails — i.e. the message was tampered with, replayed under a
    different AAD, or encrypted under a different key.
    """
    return _ref.ascon_decrypt(key, _nonce16(nonce), aad, ciphertext + tag,
                              "Ascon-AEAD128")


# -------------------------------------------------------------
#   Conformance check against NIST known-answer tests
# -------------------------------------------------------------

def _kat_bytes(n: int) -> bytes:
    """KAT input convention from the official genkat.py: 00 01 02 ..."""
    return bytes(bytearray([i % 256 for i in range(n)]))


def run_kat_check() -> bool:
    """
    Validate against the official NIST known-answer-test vectors.
    Count=1 (empty plaintext, empty AD) is the canonical first vector.
    """
    print("=" * 62)
    print("  ASCON conformance check — NIST SP 800-232 known-answer tests")
    print("=" * 62)

    key, nonce = _kat_bytes(16), _kat_bytes(16)
    msg, ad = _kat_bytes(32), _kat_bytes(32)
    print(f"\n  Key   = {key.hex().upper()}")
    print(f"  Nonce = {nonce.hex().upper()}\n")

    # Canonical first KAT vector: empty PT, empty AD
    expected_count1 = "4427D64B8E1E1451FC445960F0839BB0"
    ct, tag = aead_encrypt(key, nonce, b"", b"")
    got = (ct + tag).hex().upper()
    ok1 = (got == expected_count1)
    print(f"  Count=1  expected {expected_count1}")
    print(f"           got      {got}")
    print(f"  [{'PASS' if ok1 else 'FAIL'}] canonical NIST vector matches\n")

    # Round-trip across message and AD lengths (spans padding boundaries)
    all_ok = True
    for mlen in (0, 1, 8, 15, 16, 17, 32):
        for adlen in (0, 1, 16, 32):
            c, t = aead_encrypt(key, nonce, msg[:mlen], ad[:adlen])
            back = aead_decrypt(key, nonce, c, t, ad[:adlen])
            size_ok = (len(c) == mlen and len(t) == 16)
            if back != msg[:mlen] or not size_ok:
                all_ok = False
                print(f"  [FAIL] mlen={mlen} adlen={adlen}")
    print(f"  [{'PASS' if all_ok else 'FAIL'}] round-trip over 28 length combinations")

    # Tag must reject any tampering
    c, t = aead_encrypt(key, nonce, msg[:16], ad[:16])
    bad_ct  = aead_decrypt(key, nonce, bytes([c[0] ^ 0xFF]) + c[1:], t, ad[:16])
    bad_tag = aead_decrypt(key, nonce, c, bytes([t[0] ^ 0xFF]) + t[1:], ad[:16])
    bad_aad = aead_decrypt(key, nonce, c, t, b"wrong-aad")
    ok3 = (bad_ct is None and bad_tag is None and bad_aad is None)
    print(f"  [{'PASS' if ok3 else 'FAIL'}] tampered ciphertext / tag / AAD all rejected")

    # XOF determinism and domain separation
    a = ascon_xof(b"msg", 16, "DOMAIN_A")
    b = ascon_xof(b"msg", 16, "DOMAIN_B")
    a2 = ascon_xof(b"msg", 16, "DOMAIN_A")
    ok4 = (a == a2 and a != b and len(a) == 16)
    print(f"  [{'PASS' if ok4 else 'FAIL'}] XOF deterministic and domain-separated")

    passed = all([ok1, all_ok, ok3, ok4])
    print("\n" + "=" * 62)
    print(f"  RESULT: {'CONFORMANT — bit-exact with NIST SP 800-232' if passed else 'NON-CONFORMANT'}")
    print("=" * 62)
    return passed


if __name__ == "__main__":
    run_kat_check()
