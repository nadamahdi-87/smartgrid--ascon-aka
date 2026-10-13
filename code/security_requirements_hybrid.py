"""
=============================================================
  Lightweight ASCON-Based Protocol for IoT / Smart Grid
  Security Requirements + Hybrid Non-Repudiation Layer
=============================================================
  Researcher : Nada

  This module does two things:

  (A) Proves, by simulation, the four global security
      requirements of any secure protocol:
        1. Confidentiality
        2. Integrity
        3. Authenticity
        4. Non-repudiation

  (B) Implements a HYBRID model for non-repudiation:
        - Routine messages : ASCON-AEAD128 only
                             (confidentiality + integrity +
                              origin authentication)  -> lightweight
        - Financial / critical messages : ASCON-AEAD128
                             + optional Ed25519 signature
                             -> full, third-party-verifiable
                                non-repudiation

  Rationale (NISTIR 7628): non-repudiation in smart grids is
  required specifically for financial transactions (billing,
  financially-impactful meter readings, control commands with
  monetary effect), not for every message. Signing only the
  messages that need it follows NIST's risk-based methodology
  and is lighter than signing everything (as certificate-based
  schemes such as LSEG do).
=============================================================
"""

import os
import time
import hmac
import importlib.util
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature

from ascon_ref import ascon_xof as _xof

def _derive_sk(v_i=bytes(range(16)), pid0=bytes(range(16,32)), ctr_sig=0):
    """Eq. 8': sk = XOF("SIGN_DERIVE" || V_i || PID_0 || Ctr_sig, 256), derived from
    the PUF root (test constants here), not randomly generated or stored."""
    return Ed25519PrivateKey.from_private_bytes(
        _xof(v_i + pid0 + ctr_sig.to_bytes(4, "big"), 32, "SIGN_DERIVE"))


# -------------------------------------------------------------
#  Load the real ASCON-AEAD128 implementation
# -------------------------------------------------------------
_spec = importlib.util.spec_from_file_location("aead", "ascon_aead.py")
_aead = importlib.util.module_from_spec(_spec)
_src = open("ascon_aead.py").read().split("def run_tests")[0]
exec(_src, _aead.__dict__)
ascon_aead_encrypt = _aead.ascon_aead_encrypt
ascon_aead_decrypt = _aead.ascon_aead_decrypt


# =============================================================
#   Message-class tags
# =============================================================
ROUTINE   = "ROUTINE"     # monitoring, status -> no signature
FINANCIAL = "FINANCIAL"   # billing, financial readings -> signed


# =============================================================
#   Hybrid secure-message layer
# =============================================================
class HybridSecureChannel:
    """
    Wraps ASCON-AEAD128 and adds an OPTIONAL Ed25519 signature
    for messages that require non-repudiation.

    - K_sess     : symmetric session key (from Phase 3)
    - sign_priv  : device's long-term Ed25519 signing key
                   (only needed for FINANCIAL messages)
    """

    def __init__(self, k_sess: bytes,
                 sign_priv: Ed25519PrivateKey = None):
        self.k_sess = k_sess
        self.sign_priv = sign_priv
        self.sign_pub = (sign_priv.public_key()
                         if sign_priv is not None else None)

    # ---- send ------------------------------------------------
    def send(self, plaintext: bytes, nonce: bytes,
             pid: bytes, msg_class: str = ROUTINE) -> dict:
        """
        Encrypt with ASCON-AEAD. If msg_class == FINANCIAL,
        also attach an Ed25519 signature over the ciphertext,
        providing non-repudiation.
        """
        ct, tag = ascon_aead_encrypt(self.k_sess, nonce, plaintext, pid)
        msg = {
            "class": msg_class,
            "nonce": nonce,
            "pid":   pid,
            "ct":    ct,
            "tag":   tag,
            "sig":   None,
        }
        if msg_class == FINANCIAL:
            if self.sign_priv is None:
                raise ValueError("Financial message requires a signing key")
            # sign the ciphertext + tag + context (binds everything)
            to_sign = ct + tag + nonce + pid
            msg["sig"] = self.sign_priv.sign(to_sign)
        return msg

    # ---- receive ---------------------------------------------
    def receive(self, msg: dict, sender_pub: Ed25519PublicKey = None):
        """
        Decrypt + verify. For FINANCIAL messages, also verify
        the Ed25519 signature (non-repudiation check).

        Returns (plaintext, nonrepudiation_bool) or (None, False).
        """
        # 1) AEAD decryption (confidentiality + integrity + origin auth)
        pt = ascon_aead_decrypt(
            self.k_sess, msg["nonce"], msg["ct"], msg["tag"], msg["pid"]
        )
        if pt is None:
            return None, False   # integrity / auth failed

        # 2) For financial messages, verify signature
        if msg["class"] == FINANCIAL:
            if msg["sig"] is None or sender_pub is None:
                return None, False
            to_sign = msg["ct"] + msg["tag"] + msg["nonce"] + msg["pid"]
            try:
                sender_pub.verify(msg["sig"], to_sign)
                return pt, True   # non-repudiation holds
            except InvalidSignature:
                return None, False

        # routine message: no non-repudiation, but origin-authenticated
        return pt, False


# =============================================================
#   PART A — Prove the four security requirements
# =============================================================
def prove_requirements():
    print("=" * 64)
    print("  PART A : GLOBAL SECURITY REQUIREMENTS (by simulation)")
    print("=" * 64)

    K_sess = os.urandom(16)
    nonce  = os.urandom(16)
    pid    = os.urandom(16)
    message = b"meter_reading=1.14kWh"
    results = []

    # 1. Confidentiality
    print("\n  1. CONFIDENTIALITY")
    ct, tag = ascon_aead_encrypt(K_sess, nonce, message, pid)
    conf_ok = message not in ct
    print(f"     plaintext hidden in ciphertext : {conf_ok}")
    print(f"     [{'PASS' if conf_ok else 'FAIL'}]")
    results.append(("Confidentiality", conf_ok))

    # 2. Integrity
    print("\n  2. INTEGRITY")
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    integrity_ok = ascon_aead_decrypt(K_sess, nonce, tampered, tag, pid) is None
    print(f"     tampered ciphertext rejected   : {integrity_ok}")
    print(f"     [{'PASS' if integrity_ok else 'FAIL'}]")
    results.append(("Integrity", integrity_ok))

    # 3. Authenticity
    print("\n  3. AUTHENTICITY")
    wrong_key = os.urandom(16)
    fct, ftag = ascon_aead_encrypt(wrong_key, nonce, message, pid)
    auth_ok = ascon_aead_decrypt(K_sess, nonce, fct, ftag, pid) is None
    print(f"     forgery with wrong key rejected: {auth_ok}")
    print(f"     [{'PASS' if auth_ok else 'FAIL'}]")
    results.append(("Authenticity", auth_ok))

    # 4. Non-repudiation (via hybrid signature layer)
    print("\n  4. NON-REPUDIATION (hybrid Ed25519 layer)")
    sign_priv = _derive_sk()
    chan_dev = HybridSecureChannel(K_sess, sign_priv)
    chan_srv = HybridSecureChannel(K_sess)
    # device sends a FINANCIAL (billing) message
    billing = HybridSecureChannel(K_sess, sign_priv).send(
        b"BILL:month=06,kWh=312.5", os.urandom(16), pid, FINANCIAL)
    pt, nonrep = chan_srv.receive(billing, sign_priv.public_key())
    print(f"     financial message verified     : {pt is not None}")
    print(f"     non-repudiation holds          : {nonrep}")
    # prove the server CANNOT have forged it (no signing key)
    forged = dict(billing)
    forged["sig"] = os.urandom(64)   # server tries a fake signature
    _, forged_ok = chan_srv.receive(forged, sign_priv.public_key())
    print(f"     forged signature rejected      : {not forged_ok}")
    nonrep_ok = nonrep and (not forged_ok)
    print(f"     [{'PASS' if nonrep_ok else 'FAIL'}]")
    results.append(("Non-repudiation (financial msgs)", nonrep_ok))

    return results


# =============================================================
#   PART B — Demonstrate the hybrid model (cost contrast)
# =============================================================
def demo_hybrid():
    print("\n" + "=" * 64)
    print("  PART B : HYBRID MODEL — routine vs financial")
    print("=" * 64)

    K_sess = os.urandom(16)
    sign_priv = _derive_sk()
    dev = HybridSecureChannel(K_sess, sign_priv)
    srv = HybridSecureChannel(K_sess)
    pid = os.urandom(16)

    # routine message (no signature)
    r = dev.send(b"status=OK,voltage=220", os.urandom(16), pid, ROUTINE)
    r_pt, r_nr = srv.receive(r)
    r_bits = (len(r["ct"]) + len(r["tag"]) + len(r["nonce"])) * 8

    # financial message (signed)
    f = dev.send(b"BILL:month=06,kWh=312.5", os.urandom(16), pid, FINANCIAL)
    f_pt, f_nr = srv.receive(f, sign_priv.public_key())
    f_bits = (len(f["ct"]) + len(f["tag"]) + len(f["nonce"]) + len(f["sig"])) * 8

    print(f"\n  ROUTINE message:")
    print(f"     decrypted OK        : {r_pt is not None}")
    print(f"     non-repudiation     : {r_nr}  (origin-auth only)")
    print(f"     size                : {r_bits} bits  (no signature)")

    print(f"\n  FINANCIAL message:")
    print(f"     decrypted OK        : {f_pt is not None}")
    print(f"     non-repudiation     : {f_nr}  (Ed25519 signed)")
    print(f"     size                : {f_bits} bits  (+512-bit signature)")

    print(f"\n  Overhead of non-repudiation : {f_bits - r_bits} bits, only when needed")
    print(f"  -> routine traffic stays lightweight (ASCON-only)")


# =============================================================
#   Tests / report
# =============================================================
def run_tests():
    results = prove_requirements()
    demo_hybrid()

    print("\n" + "=" * 64)
    print("  SUMMARY — Four Global Security Requirements")
    print("=" * 64)
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")
    passed = sum(1 for _, ok in results if ok)
    print(f"\n  {passed}/{len(results)} requirements satisfied")
    print("\n  Note: requirements 1-3 hold for ALL messages via")
    print("  ASCON-AEAD128. Requirement 4 (non-repudiation) holds")
    print("  for FINANCIAL messages via the optional Ed25519 layer,")
    print("  following the NISTIR 7628 risk-based methodology.")
    print("=" * 64)


if __name__ == "__main__":
    run_tests()
