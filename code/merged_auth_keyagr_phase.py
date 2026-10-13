"""
merged_auth_keyagr_phase.py
===========================
Merged Mutual Authentication + Key Agreement (Scenario 2, piggyback).

The ephemeral X25519 public values aG and bG are carried inside the
authentication messages and double as the session nonces, so no separate
N_1 / N_2 are transmitted and no separate key-agreement round-trip is
needed. Conceptually the protocol still has the two phases; on the wire
they are combined.

Message flow (recurring session):
    M1 (device -> server):  PID, T_1, aG, A_1
        A_1 = Hash(V_i || PID || T_1 || aG)[:16]
    M2 (server -> device):  bG, MAC_2
        K_auth = XOF("AUTH" || K_0 || V_i || aG || bG)
        MAC_2  = Hash(K_auth || aG || bG || 0x01)[:16]
    M3 (device -> server):  MAC_3
        MAC_3  = Hash(K_auth || bG || aG || 0x02)[:16]

    All three authenticators follow the same domain-label||secret||data
    byte order (secret immediately after the label), so A_1 is no longer
    the odd one out: V_i is placed right after "AUTH1", matching how
    K_auth/MAC_2/MAC_3 place K_0/V_i and K_auth right after their labels.

    K_sess = XOF("SESSION" || Z || K_auth || aG || bG),  Z = abG

Security notes:
  * aG, bG are fresh per session (random scalars) -> they provide the
    freshness that N_1, N_2 gave before. Verified in ProVerif
    (proverif_merged_base.pv): secrecy + injective mutual auth all true.
  * MAC replaces AEAD for the authenticators because aG, bG, PID, T_1 are
    public; only proof-of-K_auth and binding are needed, not secrecy.
  * V_i is bound into K_auth, so K_0 compromise alone cannot forge M2
    (KCI resistance).

Requires (same folder): ascon_ref.py, ascon.py, and the `cryptography`
package for X25519 (pip install cryptography).
"""

import os
import time
import hmac

from ascon_c import ascon_xof, ascon_hash
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)

REPLAY_WINDOW_SECONDS = 30
M2_LABEL = b"MAC2"   # domain-separation label for server authenticator
M3_LABEL = b"MAC3"   # domain-separation label for device authenticator


# ---------------------------------------------------------------------------
# Ed25519 signing-key derivation (paper Section 5.2, Eq. 8')
#   sk = XOF("SIGN_DERIVE" || V_i || PID_0 || Ctr_sig, 256)
#   (pk, sk) = Ed25519.KeyPair(sk)
# Derived on demand from the PUF-anchored V_i, never stored. Ctr_sig = 0 for
# the key issued at registration; replacement re-runs registration with an
# incremented Ctr_sig.
# ---------------------------------------------------------------------------
def derive_signing_key(v_i: bytes, pid0: bytes, ctr_sig: int = 0):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = ascon_xof(v_i + pid0 + ctr_sig.to_bytes(4, "big"), 32, "SIGN_DERIVE")
    return Ed25519PrivateKey.from_private_bytes(seed)


def derive_signing_pub_bytes(v_i: bytes, pid0: bytes, ctr_sig: int = 0) -> bytes:
    return derive_signing_key(v_i, pid0, ctr_sig).public_key().public_bytes_raw()


# ---------------------------------------------------------------------------
# X25519 helpers
# ---------------------------------------------------------------------------
def x25519_generate():
    """Return (private_key_object, 32-byte public value)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv, pub


def x25519_shared(priv, peer_pub_bytes):
    """Return the 32-byte shared secret Z."""
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return priv.exchange(peer)


# ---------------------------------------------------------------------------
# Server HSM — protects the stored verifier Enc_s(V_i)
# ---------------------------------------------------------------------------
class ServerHSM:
    def __init__(self):
        self.__s = os.urandom(16)

    def protect(self, v_i: bytes) -> dict:
        from ascon_c import aead_encrypt
        nonce = os.urandom(16)
        c, t = aead_encrypt(self.__s, nonce, v_i, b"VERIFIER")
        return {"C": c, "T": t, "N": nonce}

    def recover(self, verifier: dict) -> bytes | None:
        from ascon_c import aead_decrypt
        return aead_decrypt(self.__s, verifier["N"],
                            verifier["C"], verifier["T"], b"VERIFIER")


# ---------------------------------------------------------------------------
# IoT device
# ---------------------------------------------------------------------------
class IoTDevice:
    def __init__(self, device_id, seed_d, pid):
        self.device_id = device_id
        self._seed_d = seed_d
        self.pid = pid          # current pseudonym; rotates each session
        # PID_0 is NOT stored: it is re-derived on demand from Seed_D with
        # the same formula used at initialization (PID_0 = XOF(Seed_D,
        # "PID_INIT"), see initialization_phase_PUF.py). This mirrors V_i's
        # treatment and keeps device-side persistent storage at PID_i + hd
        # only (384 bits), with nothing else added for K_0's stability.
        # k0 is NOT stored — derived on demand from PUF-backed V_i
        self._priv = None
        self._aG = None
        self._k_auth = None
        self._k_sess = None
        self._sid = None
        self._v_i = None        # transient, per-session cache of V_i;
                                 # computed once in build_m1(), reused in
                                 # process_m2() to avoid a redundant XOF
                                 # call, and cleared in build_m3() once the
                                 # session no longer needs it. This is NOT
                                 # persistent storage: it lives only in
                                 # volatile memory for the duration of one
                                 # handshake, exactly like Seed_D itself.

    def _pid_0(self) -> bytes:
        """Re-derive PID_0 from V_i on demand (never stored). Computed
        from V_i rather than Seed_D so the server -- which never has
        Seed_D but does recover V_i via the HSM -- can derive the same
        value independently (see Server.process_m1)."""
        return ascon_xof(self._v_i, 16, "PID_INIT")

    def _verifier(self) -> bytes:
        return ascon_xof(self._seed_d, 16, "VERIFIER")

    def build_m1(self) -> dict:
        """M1 = { PID, T_1, aG, A_1 }.  aG doubles as the device nonce."""
        self._v_i = self._verifier()   # computed once, cached for process_m2
        self._priv, self._aG = x25519_generate()
        t1 = int(time.time()).to_bytes(4, "big")
        a_1 = ascon_xof(b"AUTH1" + self._v_i + self.pid + t1 + self._aG, 16)
        return {"PID": self.pid, "T_1": t1, "aG": self._aG, "A_1": a_1}

    def process_m2(self, m2: dict) -> bool:
        """Verify MAC_2, derive K_auth and K_sess."""
        v_i = self._v_i         # reuse the value computed in build_m1;
                                 # same session, same Seed_D -> same V_i,
                                 # so recomputing it would be redundant
        bG = m2["bG"]
        # K_0 derived on demand — not stored persistently.
        # Bound to PID_0 (re-derived from Seed_D, fixed), not self.pid
        # (rotates), so K_0 does not change when the pseudonym is updated
        # between sessions.
        k0 = ascon_xof(v_i + self._pid_0(), 16, "K0_DERIVE")
        self._k_auth = ascon_xof(
            k0 + v_i + self._aG + bG, 16, "AUTH"
        )
        mac2_expected = ascon_xof(
            M2_LABEL + self._k_auth + self._aG + bG, 16
        )
        if not hmac.compare_digest(mac2_expected, m2["MAC_2"]):
            return False
        # server authenticated -> compute session key
        z = x25519_shared(self._priv, bG)
        self._k_sess = ascon_xof(
            z + self._k_auth + self._aG + bG, 16, "SESSION"
        )
        # Forward secrecy relies on this erasure: once Z is derived,
        # the ephemeral scalar a must not persist in memory. Overwrite
        # rather than merely drop the reference, since Python does not
        # guarantee immediate reclamation of unreferenced objects.
        self._priv = None
        self._bG = bG
        # Same derivation as the server (§ process_m1): both parties
        # arrive at the identical SID from aG, bG alone.
        self._sid = ascon_xof(self._aG + bG, 8, "SID")
        return True

    def build_m3(self) -> dict:
        """M3 = { MAC_3 }."""
        mac3 = ascon_xof(
            M3_LABEL + self._k_auth + self._bG + self._aG, 16
        )
        self._v_i = None   # authentication complete; drop the transient cache
        return {"MAC_3": mac3}

    def get_k_auth(self): return self._k_auth
    def get_k_sess(self): return self._k_sess
    def get_sid(self): return self._sid

    def get_k_enc(self):
        """Data-encryption key for the Secure Communication phase."""
        return ascon_xof(self._k_sess, 16, "ENC")

    def get_k_upd(self):
        """Update key for the Identity Update phase."""
        return ascon_xof(self._k_sess, 16, "UPD")

    def get_k_res(self):
        """Resynchronization key for desync recovery."""
        return ascon_xof(self._k_sess, 16, "RES")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class Server:
    def __init__(self, hsm: ServerHSM):
        self.hsm = hsm
        self._records = {}                 # PID -> {verifier, k0}
        self._used = {}                    # aG -> timestamp (windowed)

    def register_device(self, pid, verifier):
        """Store only PID and Enc_s(V_i). K_0 and PID_0 are both derived
        on demand -- neither is stored in the record.

        PID_0 = XOF(V_i, "PID_INIT"), so it is recomputed each session
        from the same V_i the HSM already recovers to verify A_1; no
        extra field is needed to keep K_0 stable across pseudonym
        rotations. The dictionary key is the CURRENT pseudonym and is
        re-indexed by the identity-update phase after each rotation.
        """
        self._records[pid] = {"verifier": verifier, "status": "ACTIVE"}   # fresh registration => ACTIVE

    def register_signing_key(self, pid, sign_pub: bytes, ctr_sig: int = 0) -> bool:
        """Section 5.2: bind the device's Ed25519 public key to its identity.

        The server does NOT store the transmitted pk blindly: it re-derives
        the expected pk from Dec_s(Enc_s(V_i)) and PID_0 (Eq. 8') and accepts
        only on a match -- no certificate authority needed. Calling this
        again with a higher ctr_sig is the replacement procedure.
        """
        rec = self._records.get(pid)
        if rec is None or rec.get("status") == "REVOKED":
            return False                      # a revoked device cannot be reactivated here
        v_i = self.hsm.recover(rec["verifier"])
        if v_i is None:
            return False
        pid_0 = ascon_xof(v_i, 16, "PID_INIT")
        if not hmac.compare_digest(derive_signing_pub_bytes(v_i, pid_0, ctr_sig), sign_pub):
            return False
        if ctr_sig < rec.get("ctr_sig", 0):
            return False                      # no rollback to an older key
        rec["sign_pub"] = sign_pub
        rec["ctr_sig"] = ctr_sig
        return True

    def revoke_device(self, pid):
        """Section 5.2 revocation: device-level status ACTIVE -> REVOKED on the
        record (follows it across pseudonym rotation). Checked FIRST in
        process_m1 (and in Phase 5 recovery). Reactivation is NOT possible here:
        only a fresh out-of-band registration (register_verifier) creates an
        ACTIVE record again. No CRL infrastructure."""
        if pid in self._records:
            self._records[pid]["status"] = "REVOKED"

    revoke_signing_key = revoke_device      # backward-compatible name

    def signing_state(self, pid):
        """(sign_pub, revoked) for Phase 5's Server; (None, False) if unset."""
        rec = self._records.get(pid, {})
        return rec.get("sign_pub"), rec.get("status") == "REVOKED"

    def process_m1(self, m1: dict):
        """Verify A_1, build M2 = { bG, MAC_2 }."""
        pid = m1["PID"]
        rec = self._records.get(pid)
        if rec is None:
            return None, None
        if rec.get("status") == "REVOKED":
            return None, None                 # status check BEFORE any authentication work;
                                              # silent drop, indistinguishable from unknown PID

        # timestamp freshness
        now = int(time.time())
        t1 = int.from_bytes(m1["T_1"], "big")
        if abs(now - t1) > REPLAY_WINDOW_SECONDS:
            return None, None

        # windowed replay check on aG (unique per session)
        self._used = {a: ts for a, ts in self._used.items()
                      if now - ts <= REPLAY_WINDOW_SECONDS}
        if m1["aG"] in self._used:
            return None, None

        # recover V_i inside HSM and verify A_1
        v_i = self.hsm.recover(rec["verifier"])
        if v_i is None:
            return None, None
        a1_star = ascon_xof(b"AUTH1" + v_i + pid + m1["T_1"] + m1["aG"], 16)
        if not hmac.compare_digest(a1_star, m1["A_1"]):
            return None, None

        self._used[m1["aG"]] = t1

        # server ephemeral + K_auth
        # K_0 and PID_0 are both derived on demand from V_i -- neither is
        # stored in the record. PID_0 = XOF(V_i, "PID_INIT") is unaffected
        # by pseudonym rotation, since it depends only on V_i (which is
        # itself stable for the device's lifetime), not on the current
        # lookup key pid.
        priv, bG = x25519_generate()
        aG = m1["aG"]
        pid_0 = ascon_xof(v_i, 16, "PID_INIT")
        k0 = ascon_xof(v_i + pid_0, 16, "K0_DERIVE")   # same formula as device
        k_auth = ascon_xof(k0 + v_i + aG + bG, 16, "AUTH")
        mac2 = ascon_xof(M2_LABEL + k_auth + aG + bG, 16)

        z = x25519_shared(priv, aG)
        k_sess = ascon_xof(z + k_auth + aG + bG, 16, "SESSION")
        # Forward secrecy relies on erasing the server's ephemeral
        # scalar b (`priv`) immediately after Z is derived, exactly as
        # the device erases a (process_m2). `priv` is a local variable
        # that Python's reference counter reclaims once this function
        # returns, but we clear it explicitly rather than rely on that
        # implicitly, since CPython's collection behaviour is an
        # implementation detail, not a language guarantee.
        priv = None

        # Session identifier for Phase 5 (Secure Communication) and
        # Phase 6 (Identity Update): derived from the ephemeral values
        # aG, bG rather than generated and transmitted separately, since
        # both parties already know aG and bG once M1/M2 complete. This
        # keeps SID session-unique with no extra bits on the wire.
        sid = ascon_xof(aG + bG, 8, "SID")

        m2 = {"bG": bG, "MAC_2": mac2}
        session = {
            "k_auth": k_auth, "k_sess": k_sess, "aG": aG, "bG": bG,
            "sid": sid,
            "k_enc": ascon_xof(k_sess, 16, "ENC"),
            "k_upd": ascon_xof(k_sess, 16, "UPD"),
            "k_res": ascon_xof(k_sess, 16, "RES"),
        }
        session["sign_pub"], session["revoked"] = self.signing_state(pid)
        return m2, session

    def process_m3(self, m3: dict, session: dict) -> bool:
        """Verify MAC_3 -> device liveness confirmed."""
        mac3_expected = ascon_xof(
            M3_LABEL + session["k_auth"] + session["bG"] + session["aG"], 16
        )
        return hmac.compare_digest(mac3_expected, m3["MAC_3"])


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _bits(x): return len(x) * 8


if __name__ == "__main__":
    passed = 0
    total = 0

    def check(name, cond):
        global passed, total
        total += 1
        if cond:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}")

    print("=" * 64)
    print("  Merged Authentication + Key Agreement — self-test")
    print("=" * 64)

    # setup (from Phases 0-1)
    seed_d = os.urandom(16)
    v_i = ascon_xof(seed_d, 16, "VERIFIER")
    pid = ascon_xof(v_i, 16, "PID_INIT")      # PID_0 = XOF(V_i), Eq. 7
    # K_0 is NOT stored; it is derived on demand from V_i + PID

    hsm = ServerHSM()
    server = Server(hsm)
    server.register_device(pid, hsm.protect(v_i))   # no k0 stored

    # --- honest run ---
    dev = IoTDevice("SM01", seed_d, pid)
    m1 = dev.build_m1()
    check("M1 has aG (32 bytes)", len(m1["aG"]) == 32)
    check("M1 has no N_1 field", "N_1" not in m1)

    m2, session = server.process_m1(m1)
    check("Server accepts valid M1", m2 is not None)
    check("M2 has bG (32 bytes)", m2 and len(m2["bG"]) == 32)

    ok2 = dev.process_m2(m2)
    check("Device accepts valid M2", ok2)

    m3 = dev.build_m3()
    ok3 = server.process_m3(m3, session)
    check("Server accepts valid M3", ok3)

    # --- both sides agree on keys ---
    check("K_auth matches", dev.get_k_auth() == session["k_auth"])
    check("K_sess matches", dev.get_k_sess() == session["k_sess"])
    check("K_enc matches (-> secure comm)", dev.get_k_enc() == session["k_enc"])
    check("K_upd matches (-> identity update)", dev.get_k_upd() == session["k_upd"])

    # --- forged M1 (wrong V_i) rejected ---
    bad = IoTDevice("SM01", os.urandom(16), pid)   # wrong seed_d
    m1b = bad.build_m1()
    m2b, _ = server.process_m1(m1b)
    check("Forged M1 (wrong Seed_D) rejected", m2b is None)

    # --- tampered MAC_2 rejected ---
    dev2 = IoTDevice("SM01", seed_d, pid)
    m1c = dev2.build_m1()
    m2c, _ = server.process_m1(m1c)
    m2c["MAC_2"] = bytes([m2c["MAC_2"][0] ^ 0xFF]) + m2c["MAC_2"][1:]
    check("Tampered MAC_2 rejected", not dev2.process_m2(m2c))

    # --- replayed aG rejected ---
    dev3 = IoTDevice("SM01", seed_d, pid)
    m1d = dev3.build_m1()
    server.process_m1(m1d)
    m2d2, _ = server.process_m1(m1d)   # replay same M1
    check("Replayed aG rejected", m2d2 is None)

    # --- Ed25519 signing-key lifecycle (Section 5.2) ---
    pk0 = derive_signing_pub_bytes(v_i, pid)
    check("pk registration accepted (server re-derives pk)", server.register_signing_key(pid, pk0))
    check("forged pk rejected at registration",
          not server.register_signing_key(pid, derive_signing_pub_bytes(os.urandom(16), pid)))
    pk1 = derive_signing_pub_bytes(v_i, pid, 1)
    check("replacement (Ctr_sig=1) accepted", server.register_signing_key(pid, pk1, 1))
    check("rollback to Ctr_sig=0 rejected", not server.register_signing_key(pid, pk0, 0))
    check("replacement key differs", pk0 != pk1)
    server.revoke_signing_key(pid)
    check("revocation flag set", server.signing_state(pid) == (pk1, True))
    check("device status is REVOKED", server._records[pid]["status"] == "REVOKED")
    check("revoked device: valid M1 is rejected before authentication",
          server.process_m1(dev3.build_m1())[0] is None)
    check("revoked device cannot be reactivated via register_signing_key",
          not server.register_signing_key(pid, pk1, 1))

    # --- message sizes ---
    m1_bits = sum(_bits(v) for v in m1.values())
    m2_bits = sum(_bits(v) for v in m2.values())
    m3_bits = sum(_bits(v) for v in m3.values())
    total_bits = m1_bits + m2_bits + m3_bits
    print(f"\n  M1 = {m1_bits} bits, M2 = {m2_bits} bits, M3 = {m3_bits} bits")
    print(f"  Total (auth + key agreement, piggybacked) = {total_bits} bits")
    check("Total <= 1152 (lighter than Zhang)", total_bits <= 1152)

    print("\n" + "=" * 64)
    print(f"  Result : {passed}/{total} tests passed")
    print("=" * 64)
