"""
=============================================================
  Lightweight Authentication and Key Management Protocol
  for IoT — Phase 4: Secure Communication
=============================================================
  Researcher : Nada
  Description: Unidirectional encrypted data exchange
               (device -> server) using K_enc from Phase 3.
               Counter-based replay protection.
               ASCON-XOF (KDF) + AEAD (AES-GCM placeholder).
=============================================================
"""

import os
import time
import json
import hmac
import tracemalloc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


# =============================================================
#   ASCON-XOF — Pure Python (NIST SP 800-232) — KDF only
# =============================================================

def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _permutation(S, rounds):
    RC = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
    for r in range(12 - rounds, 12):
        S[2] ^= RC[r]
        S[0]^=S[4]; S[4]^=S[3]; S[2]^=S[1]
        T = [0]*5
        for i in range(5):
            T[i] = S[i] ^ (0xFFFFFFFFFFFFFFFF & (~S[(i+1)%5])) & S[(i+2)%5]
        S[0]=T[0]^T[4]; S[1]=T[1]^T[0]
        S[2]=~T[2]&0xFFFFFFFFFFFFFFFF; S[2]^=T[1]
        S[3]=T[3]^T[2]; S[4]=T[4]^T[3]
        S[1]^=S[0]; S[0]^=S[4]; S[3]^=S[2]
        S[0]^=_rotr(S[0],19)^_rotr(S[0],28)
        S[1]^=_rotr(S[1],61)^_rotr(S[1],39)
        S[2]^=_rotr(S[2], 1)^_rotr(S[2], 6)
        S[3]^=_rotr(S[3],10)^_rotr(S[3],17)
        S[4]^=_rotr(S[4], 7)^_rotr(S[4],41)
    return S


def ascon_xof(message: bytes, output_length: int = 32, domain: str = "") -> bytes:
    """ASCON-XOF128 — used for key derivation"""
    if domain:
        message = message + domain.encode() + bytes([len(domain)])
    S = [0x00400c0000000000, 0, 0, 0, 0]
    S = _permutation(S, 12)
    RATE = 8
    padded = message + b'\x01' + b'\x00' * (RATE - (len(message) % RATE) - 1)
    for i in range(0, len(padded), RATE):
        S[0] ^= int.from_bytes(padded[i:i+RATE], 'big')
        S = _permutation(S, 6)
    S[1] ^= 0x01
    output = b''
    while len(output) < output_length:
        output += S[0].to_bytes(8, 'big')
        if len(output) < output_length:
            S = _permutation(S, 6)
    return output[:output_length]


# =============================================================
#   AEAD wrapper — AES-128-GCM placeholder for ASCON-AEAD128
# =============================================================

# =============================================================
#   ASCON primitives — official NIST SP 800-232 reference impl.
#   (pyascon by M. Eichlseder; bit-exact conformance validated
#    against the official NIST known-answer tests)
# =============================================================
from ascon_c import ascon_xof, ascon_hash, aead_encrypt, aead_decrypt



# =============================================================
#   Ed25519 signing-key derivation (§5.2 lifecycle)
#
#   The device's non-repudiation signing key is NOT generated
#   independently or stored: it is derived on demand from the same
#   registration-time material as K_0 (V_i, PID_0), so it inherits
#   K_0's physical-capture resistance -- nothing beyond the PUF and
#   its helper data hd needs to persist on the device.
#
#       sign_seed = XOF("SIGN_DERIVE" || V_i || PID_0 || Ctr_sig, 32)
#       (sign_priv, sign_pub) = Ed25519.KeyPairFromSeed(sign_seed)
#
#   Ctr_sig defaults to 0 for the key issued at registration; a
#   replacement (compromise, scheduled rotation) re-derives with an
#   incremented Ctr_sig, governed by the same counter mechanism as
#   pseudonym rotation (§5.6) -- no new hardware or out-of-band step
#   is required beyond re-running registration (§5.2).
# =============================================================

# Single source of truth lives in merged_auth_keyagr_phase.py (Eq. 8').
from merged_auth_keyagr_phase import derive_signing_key, derive_signing_pub_bytes


# =============================================================
#   IoT Device — Phase 4 (sender)
# =============================================================

class IoTDevice:
    """
    IoT Device implementing Phase 4: Secure Communication.
    Sends encrypted telemetry to the server (unidirectional).
    Assumes Phase 3 completed → has K_enc, SID, PID.

    Hybrid non-repudiation (NISTIR 7628, risk-based):
      - ROUTINE messages   : ASCON-AEAD only (lightweight)
      - FINANCIAL messages : ASCON-AEAD + Ed25519 signature
                             (third-party-verifiable non-repudiation)
    """

    def __init__(self, k_enc, sid, pid, sign_priv=None):
        self.k_enc = k_enc      # data encryption key (from Phase 3)
        self.sid   = sid         # session identifier
        self.pid   = pid         # current pseudonym
        self.ctr   = 0           # message counter (starts at 0)
        # long-term Ed25519 signing key; needed only for FINANCIAL msgs
        self.sign_priv = sign_priv

    def _make_nonce(self, ctr):
        """
        Build a unique AEAD nonce from SID + counter.
        Ensures each message uses a distinct nonce (critical for AEAD).
        """
        # 12-byte nonce: 4 bytes SID prefix + 8 bytes counter
        return self.sid[:4] + ctr.to_bytes(8, 'big')

    def send_data(self, payload: bytes, msg_class: str = "ROUTINE"):
        """
        Phase 4 — Build an encrypted data message.

        Steps:
        1. Increment counter (Ctr = Ctr + 1)
        2. Build nonce from SID + Ctr
        3. Encrypt payload; bind Ctr + SID + PID + class as associated data
        4. For FINANCIAL messages, add an Ed25519 signature (non-repudiation)
        5. Return DataMsg = { SID, Ctr, Class, C_data, T_data, Sig }
        """
        # Step 1: increment counter — guarantees freshness/ordering
        self.ctr += 1

        # Step 2: unique nonce per message
        nonce = self._make_nonce(self.ctr)

        # Step 3: associated data binds Ctr + SID + PID + message class.
        # Binding the class prevents an attacker downgrading FINANCIAL to
        # ROUTINE (stripping the signature) without breaking the AEAD tag.
        aad = self.ctr.to_bytes(8, 'big') + self.sid + self.pid + msg_class.encode()

        # Encrypt the payload
        c_data, t_data = aead_encrypt(self.k_enc, nonce, payload, aad)

        # Step 4: non-repudiation for financial messages only
        sig = None
        if msg_class == "FINANCIAL":
            if self.sign_priv is None:
                raise ValueError("FINANCIAL message requires an Ed25519 signing key")
            # sign the ciphertext + tag + context: only this device can
            # produce it, so it cannot later deny sending the message.
            to_sign = c_data + t_data + nonce + self.pid
            sig = self.sign_priv.sign(to_sign)

        # Step 5: assemble message (Ctr sent in clear for fast pre-check)
        return {
            "SID"    : self.sid,
            "Ctr"    : self.ctr,
            "Class"  : msg_class,
            "C_data" : c_data,
            "T_data" : t_data,
            "Sig"    : sig,
        }


# =============================================================
#   Server — Phase 4 (receiver)
# =============================================================

class Server:
    """
    Server implementing Phase 4: receives and verifies data.
    Tracks the last accepted counter per session for replay protection.
    Verifies Ed25519 signatures on FINANCIAL messages (non-repudiation).
    """

    def __init__(self, k_enc, sid, pid, sign_pub=None, revoked=False):
        self.k_enc     = k_enc
        self.sid       = sid
        self.pid       = pid
        self.last_ctr  = 0      # highest counter accepted so far
        self.sign_pub  = sign_pub   # device's Ed25519 public key
        # §5.2 revocation: a single flag on the device's server-side
        # record (keyed by the device's stable identity, not the
        # rotating pseudonym), checked before any Ed25519-signed
        # financial message is accepted. Set as soon as compromise or
        # physical capture is suspected -- the same response already
        # assumed for a compromised pseudonym.
        self.revoked   = revoked

    def _make_nonce(self, ctr):
        """Reconstruct the same nonce the device used"""
        return self.sid[:4] + ctr.to_bytes(8, 'big')

    def receive_data(self, msg: dict):
        """
        Phase 4 — Receive and verify a data message.

        Steps:
        1. Verify SID matches this session
        2. Fast replay check on public Ctr (before decryption)
        3. Decrypt + verify tag (binds Ctr + SID + PID + class)
        4. For FINANCIAL messages, verify the Ed25519 signature
        5. Update last_ctr, return payload

        Returns:
            (payload, status, non_repudiable)
            payload is None if rejected; non_repudiable is True only
            when a valid financial signature was verified.
        """
        # Step 1: SID check
        if msg["SID"] != self.sid:
            return None, "wrong SID", False

        ctr = msg["Ctr"]
        msg_class = msg.get("Class", "ROUTINE")

        # Step 2: FAST replay check on public counter (no decryption yet)
        if ctr <= self.last_ctr:
            return None, f"replay/stale (Ctr={ctr} <= last={self.last_ctr})", False

        # Step 3: rebuild nonce + AAD, then decrypt.
        # AAD includes the message class, so a downgrade attack
        # (FINANCIAL -> ROUTINE) breaks the tag.
        nonce = self._make_nonce(ctr)
        aad = ctr.to_bytes(8, 'big') + self.sid + self.pid + msg_class.encode()
        payload = aead_decrypt(self.k_enc, nonce, msg["C_data"], msg["T_data"], aad)

        if payload is None:
            return None, "auth failed (tampered)", False

        # Step 4: non-repudiation check for financial messages
        non_repudiable = False
        if msg_class == "FINANCIAL":
            if self.revoked:
                return None, "device revoked -- financial signature rejected", False
            if msg.get("Sig") is None or self.sign_pub is None:
                return None, "missing signature on financial message", False
            to_verify = msg["C_data"] + msg["T_data"] + nonce + self.pid
            try:
                self.sign_pub.verify(msg["Sig"], to_verify)
                non_repudiable = True
            except Exception:
                return None, "invalid signature (non-repudiation failed)", False

        # Step 5: accept and update last accepted counter
        self.last_ctr = ctr
        return payload, "accepted", non_repudiable


# =============================================================
#   Tests
# =============================================================

def run_tests():
    print("=" * 66)
    print("   Phase 4: Secure Communication + Hybrid Non-Repudiation")
    print("=" * 66)
    results = []

    # Setup: derive K_enc, SID, and PID from a genuine M1-M3 handshake
    # (merged_auth_keyagr_phase.py) rather than generating them in
    # isolation, so this test demonstrates the actual cross-phase link
    # rather than assuming Phase 3's outputs arrive from nowhere.
    import merged_auth_keyagr_phase as MP
    _seed_d = os.urandom(16)
    _v_i    = ascon_xof(_seed_d, 16, "VERIFIER")
    _pid_0  = ascon_xof(_v_i, 16, "PID_INIT")     # PID_0 = XOF(V_i), Eq. 7
    _hsm = MP.ServerHSM()
    _srv = MP.Server(_hsm)
    _srv.register_device(_pid_0, _hsm.protect(_v_i))
    # Section 5.2: device registers pk; server re-derives and binds it.
    _sk = MP.derive_signing_key(_v_i, _pid_0)
    assert _srv.register_signing_key(_pid_0, _sk.public_key().public_bytes_raw()), \
        "signing-key registration failed (Section 5.2 binding)"
    _dev = MP.IoTDevice("SM", _seed_d, _pid_0)
    _m1 = _dev.build_m1()
    _m2, _session = _srv.process_m1(_m1)
    _dev.process_m2(_m2)
    _dev.build_m3()
    assert _session["sid"] == _dev.get_sid(), "SID mismatch between device and server"
    assert _session["k_enc"] == _dev.get_k_enc(), "K_enc mismatch between device and server"

    K_enc = _session["k_enc"]
    SID   = _session["sid"]
    PID   = _pid_0
    # Device long-term Ed25519 signing key — derived from V_i/PID_0
    # (§5.2), not generated independently, so it inherits the same
    # physical-capture resistance as K_0.
    sign_priv = derive_signing_key(_v_i, _pid_0)
    sign_pub  = sign_priv.public_key()

    # Server-side pk comes from its own record (re-derived at registration),
    # not from anything the device transmits per message.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _pk_bytes, _revoked = _session["sign_pub"], _session["revoked"]
    assert _pk_bytes == sign_pub.public_bytes_raw() and _revoked is False
    sign_pub = Ed25519PublicKey.from_public_bytes(_pk_bytes)

    print("\n" + "-" * 66)
    print("  Setup: K_enc, SID, PID derived from a real M1-M3 handshake")
    print("-" * 66)

    # --- Test 1: routine message (ASCON-AEAD only, no signature) ---
    print("\n" + "-" * 66)
    print("  Test 1: Routine message (lightweight, no signature)")
    print("-" * 66)
    dev = IoTDevice(K_enc, SID, PID, sign_priv)
    srv = Server(K_enc, SID, PID, sign_pub)
    payload = json.dumps({"voltage": 220, "current": 5.2, "kWh": 1.14}).encode()
    msg = dev.send_data(payload, "ROUTINE")
    rec, status, nonrep = srv.receive_data(msg)
    t1 = (rec == payload and status == "accepted" and nonrep is False)
    print(f"    class=ROUTINE, signature attached: {msg['Sig'] is not None}")
    print(f"    recovered={rec == payload}, non_repudiable={nonrep}")
    print(f"    [{'PASS' if t1 else 'FAIL'}] routine delivered, no signature needed")
    results.append(("Routine message (no signature)", t1))

    # --- Test 2: financial message (ASCON-AEAD + Ed25519) ---
    print("\n" + "-" * 66)
    print("  Test 2: Financial message (non-repudiation)")
    print("-" * 66)
    bill = json.dumps({"monthly_kWh": 312.5, "amount_USD": 45.20}).encode()
    msg = dev.send_data(bill, "FINANCIAL")
    rec, status, nonrep = srv.receive_data(msg)
    t2 = (rec == bill and status == "accepted" and nonrep is True)
    print(f"    class=FINANCIAL, signature attached: {msg['Sig'] is not None}")
    print(f"    recovered={rec == bill}, non_repudiable={nonrep}")
    print(f"    [{'PASS' if t2 else 'FAIL'}] financial delivered with non-repudiation")
    results.append(("Financial message (non-repudiation)", t2))

    # --- Test 3: server cannot forge a financial message (asymmetry) ---
    print("\n" + "-" * 66)
    print("  Test 3: Server cannot forge device's signature")
    print("-" * 66)
    # server holds only the PUBLIC key, so it cannot produce a valid Sig
    forged = dev.send_data(bill, "FINANCIAL")
    forged["Sig"] = os.urandom(64)   # attacker/server fakes a signature
    srv3 = Server(K_enc, SID, PID, sign_pub)
    rec, status, nonrep = srv3.receive_data(forged)
    t3 = (rec is None and nonrep is False)
    print(f"    forged signature -> status: {status}")
    print(f"    [{'PASS' if t3 else 'FAIL'}] forged financial message rejected")
    results.append(("Forged signature rejected", t3))

    # --- Test 4: downgrade attack (FINANCIAL -> ROUTINE) fails ---
    print("\n" + "-" * 66)
    print("  Test 4: Downgrade attack (strip signature) rejected")
    print("-" * 66)
    msg = dev.send_data(bill, "FINANCIAL")
    # attacker relabels it ROUTINE and drops the signature
    msg["Class"] = "ROUTINE"
    msg["Sig"] = None
    srv4 = Server(K_enc, SID, PID, sign_pub)
    rec, status, nonrep = srv4.receive_data(msg)
    # class is bound in AAD, so decryption fails
    t4 = (rec is None)
    print(f"    relabeled FINANCIAL->ROUTINE -> status: {status}")
    print(f"    [{'PASS' if t4 else 'FAIL'}] downgrade broken by AAD binding")
    results.append(("Downgrade attack rejected", t4))

    # --- Test 5: replay rejected ---
    print("\n" + "-" * 66)
    print("  Test 5: Replay attack rejected")
    print("-" * 66)
    dev5 = IoTDevice(K_enc, SID, PID, sign_priv)
    srv5 = Server(K_enc, SID, PID, sign_pub)
    m = dev5.send_data(b"reading", "ROUTINE")
    r1, s1, _ = srv5.receive_data(m)
    r2, s2, _ = srv5.receive_data(m)   # replay
    t5 = (r1 == b"reading" and r2 is None)
    print(f"    first={s1}, replay={s2}")
    print(f"    [{'PASS' if t5 else 'FAIL'}] replay blocked")
    results.append(("Replay blocked", t5))

    # --- Test 6: tampered ciphertext rejected ---
    print("\n" + "-" * 66)
    print("  Test 6: Tampered payload rejected")
    print("-" * 66)
    dev6 = IoTDevice(K_enc, SID, PID, sign_priv)
    srv6 = Server(K_enc, SID, PID, sign_pub)
    m = dev6.send_data(b"sensor_42", "ROUTINE")
    m["C_data"] = bytes([m["C_data"][0] ^ 0xFF]) + m["C_data"][1:]
    r, s, _ = srv6.receive_data(m)
    t6 = (r is None)
    print(f"    status: {s}")
    print(f"    [{'PASS' if t6 else 'FAIL'}] tampered payload rejected")
    results.append(("Tampered payload rejected", t6))

    # --- Test 7: communication overhead comparison ---
    print("\n" + "-" * 66)
    print("  Test 7: Overhead — routine vs financial")
    print("-" * 66)
    r_msg = dev.send_data(b"x"*32, "ROUTINE")
    f_msg = dev.send_data(b"x"*32, "FINANCIAL")
    r_bits = (len(r_msg["C_data"]) + len(r_msg["T_data"])) * 8
    f_bits = (len(f_msg["C_data"]) + len(f_msg["T_data"]) + len(f_msg["Sig"])) * 8
    print(f"    routine   : {r_bits} bits (no signature)")
    print(f"    financial : {f_bits} bits (+{len(f_msg['Sig'])*8}-bit signature)")
    print(f"    overhead of non-repudiation applies only to financial msgs")
    results.append(("Overhead only on financial", f_bits > r_bits))

    # --- Test 8: performance ---
    print("\n" + "-" * 66)
    print("  Test 8: Performance")
    print("-" * 66)
    ITER = 500
    t0 = time.perf_counter()
    for _ in range(ITER):
        dev.send_data(b"x"*64, "ROUTINE")
    rt_routine = (time.perf_counter()-t0)/ITER*1000
    t0 = time.perf_counter()
    for _ in range(ITER):
        dev.send_data(b"x"*64, "FINANCIAL")
    rt_fin = (time.perf_counter()-t0)/ITER*1000
    print(f"    routine send   : {rt_routine:.4f} ms")
    print(f"    financial send : {rt_fin:.4f} ms (includes signing)")
    results.append(("Performance measured", True))

    # --- Test 9: revoked device's financial message rejected ---
    print("\n" + "-" * 66)
    print("  Test 9: Revoked device's financial signature rejected (§5.2)")
    print("-" * 66)
    dev9 = IoTDevice(K_enc, SID, PID, sign_priv)
    _srv.revoke_signing_key(_pid_0)                         # flag on server record
    _, _rev = _srv.signing_state(_pid_0)
    srv9 = Server(K_enc, SID, PID, sign_pub, revoked=_rev)
    msg9 = dev9.send_data(bill, "FINANCIAL")   # device still signs correctly...
    rec9, status9, nonrep9 = srv9.receive_data(msg9)
    t9 = (rec9 is None and nonrep9 is False)
    print(f"    valid signature, but device revoked -> status: {status9}")
    print(f"    [{'PASS' if t9 else 'FAIL'}] revoked device's financial message rejected")
    results.append(("Revoked device rejected (even with valid Sig)", t9))

    # --- Summary ---
    print("\n" + "=" * 66)
    print("   Test Summary")
    print("=" * 66)
    passed = sum(1 for _, r in results if r)
    for name, r in results:
        print(f"   [{'PASS' if r else 'FAIL'}]  {name}")
    print(f"\n   {passed}/{len(results)} tests passed")
    verdict = "correct and ready" if passed == len(results) else "needs review"
    print(f"   Status: Phase 4 with hybrid non-repudiation is {verdict}")
    print("=" * 66)


if __name__ == "__main__":
    run_tests()
