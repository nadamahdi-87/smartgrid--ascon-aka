"""
Protocol-level known-answer test vectors for the keyed-sponge
authenticator constructions (A1, K_auth, MAC2, MAC3) used in
merged_auth_keyagr_phase.py (Merged Mutual Authentication + Key
Agreement — the current reference implementation of Phase 2).

These are independent of the primitive-level Ascon-XOF128 KATs (which
only validate conformance of the XOF itself to NIST SP 800-232): this
script validates that the *protocol-level* byte encoding of each
construction is reproducible bit-for-bit by an independent
implementation.

Note on K_auth: merged_auth_keyagr_phase.py derives it via
ascon_xof(k0 + v_i + aG + bG, 16, domain="AUTH"), and ascon_ref's
domain kwarg prepends domain.encode() + b"\\x00" to the message
(i.e. the actual byte string hashed is "AUTH\\x00" + k0 + v_i + aG + bG).
This script reproduces that exact mechanism rather than hand-writing
the prefix, so it stays correct if that convention changes.

Run: python3 generate_protocol_test_vectors.py
"""
from ascon_ref import ascon_xof

# Fixed, documented test inputs (deterministic; not secret -- for
# reproducibility only, never reuse these in the real protocol)
V_i = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 128-bit verifier secret
PID = bytes.fromhex("101112131415161718191a1b1c1d1e1f")  # 128-bit pseudo-identity
T_1 = bytes.fromhex("00000000")                          # 32-bit timestamp
aG  = bytes([0x20] * 32)                                 # 256-bit device ephemeral pub.
bG  = bytes([0x30] * 32)                                 # 256-bit server ephemeral pub.
K0  = bytes([0x40] * 16)                                 # 128-bit registration key

# Mirrors merged_auth_keyagr_phase.py exactly:
#   a_1     = ascon_xof(b"AUTH1" + v_i + pid + t1 + aG, 16)
#   k_auth  = ascon_xof(k0 + v_i + aG + bG, 16, "AUTH")
#   mac2    = ascon_xof(M2_LABEL + k_auth + aG + bG, 16)
#   mac3    = ascon_xof(M3_LABEL + k_auth + bG + aG, 16)
A1     = ascon_xof(b"AUTH1" + V_i + PID + T_1 + aG, 16)
K_auth = ascon_xof(K0 + V_i + aG + bG, 16, "AUTH")
MAC2   = ascon_xof(b"MAC2" + K_auth + aG + bG, 16)
MAC3   = ascon_xof(b"MAC3" + K_auth + bG + aG, 16)

# Eq. 8' (Section 5.2): Ed25519 signing key derived from V_i/PID_0/Ctr_sig.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
SIGN_PUB = Ed25519PrivateKey.from_private_bytes(
    ascon_xof(V_i + PID + (0).to_bytes(4, "big"), 32, "SIGN_DERIVE")
).public_key().public_bytes_raw()

EXPECTED = {
    "SIGN_PUB": "3c6a82e2a322e72fcadb2968fb788cda0d10f8e9ddccdc723ba1b89ccb3af17d",
    "A1":     "212c4c910fad0079769d8144bbf38f42",
    "K_auth": "8d96bb8703fcd78b65ae45cfcb0eb95b",
    "MAC2":   "e8ec46c36daede7e4604a7baa58d6387",
    "MAC3":   "03a315c6cafd4764bc4e12bbbd0ee9ed",
}

if __name__ == "__main__":
    computed = {"SIGN_PUB": SIGN_PUB.hex(), "A1": A1.hex(), "K_auth": K_auth.hex(), "MAC2": MAC2.hex(), "MAC3": MAC3.hex()}
    for name, val in computed.items():
        ok = "OK" if val == EXPECTED[name] else "MISMATCH"
        print(f"{name:8s} = {val}   [{ok}]")
    assert computed == EXPECTED, "Protocol-level test vectors do not match expected values!"
    print("\nAll protocol-level test vectors verified.")
