"""
X25519 conformance test against the known-answer vectors of RFC 7748.

Purpose: establish that the X25519 implementation used by the protocol
(Phase 3, key_management_phase.py) reproduces the vectors published in
RFC 7748, on the same basis as the Ascon conformance test against the
NIST SP 800-232 vectors.

Run:  python3 x25519_rfc7748_kat.py
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization

h2b, b2h = bytes.fromhex, lambda b: b.hex()
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# --- RFC 7748 Section 5.2: X25519(scalar, u-coordinate) ---
SECT_5_2 = [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
]

# --- RFC 7748 Section 6.1: complete Diffie-Hellman exchange ---
A_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
A_PUB  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
B_PRIV = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
B_PUB  = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"


def run():
    ok = []
    print("=" * 66)
    print("  X25519 conformance test  --  RFC 7748 known-answer vectors")
    print("=" * 66)

    print("\n-- Section 5.2: scalar multiplication --")
    for i, (k, u, want) in enumerate(SECT_5_2, 1):
        got = b2h(X25519PrivateKey.from_private_bytes(h2b(k))
                  .exchange(X25519PublicKey.from_public_bytes(h2b(u))))
        p = got == want; ok.append(p)
        print(f"  [{'PASS' if p else 'FAIL'}] vector {i}")
        if not p:
            print(f"        expected {want}\n        got      {got}")

    print("\n-- Section 6.1: Diffie-Hellman exchange --")
    pa = X25519PrivateKey.from_private_bytes(h2b(A_PRIV))
    pb = X25519PrivateKey.from_private_bytes(h2b(B_PRIV))
    ga = b2h(pa.public_key().public_bytes(*RAW))
    gb = b2h(pb.public_key().public_bytes(*RAW))
    for label, got, want in (("Alice public key", ga, A_PUB),
                             ("Bob public key",   gb, B_PUB)):
        p = got == want; ok.append(p)
        print(f"  [{'PASS' if p else 'FAIL'}] {label}")

    sa = b2h(pa.exchange(X25519PublicKey.from_public_bytes(h2b(B_PUB))))
    sb = b2h(pb.exchange(X25519PublicKey.from_public_bytes(h2b(A_PUB))))
    p = sa == SHARED and sb == SHARED; ok.append(p)
    print(f"  [{'PASS' if p else 'FAIL'}] shared secret (both parties agree)")

    print("\n" + "=" * 66)
    print(f"  Result : {sum(ok)}/{len(ok)} vectors reproduced")
    print(f"  Status : {'conformant with RFC 7748' if all(ok) else 'NON-CONFORMANT'}")
    print("=" * 66)
    return all(ok)


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
