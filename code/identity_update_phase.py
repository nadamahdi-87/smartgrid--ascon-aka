"""
Phase 5: Identity (pseudonym) update and desynchronization recovery.
Implements the state machine of paper Sec. 5.6 / Figure 2 (rules R1-R5).

Server record per device : cur, pend (bounded candidate set, |pend| <= Q), EL, last_rec
Device state             : ONE persisted pseudonym, K_res, Ctr_rec

  R1 accept  : M1 with PID in {cur} U pend, A1 verified (done in Phase 2), aG fresh
               -> PID == cur  : add next pseudonym to pend (bounded)
               -> PID in pend : cur := PID, pend := {next}
  R2 failure : bad A1 / unknown PID / replayed aG -> NO state change
  R3 device  : advance to PID_{i+1} only after MAC2 verifies (atomic single write)
  R4 lost M2/M3 : device keeps PID_i (still in {cur} U pend), retries with fresh aG
  R5 recovery: after F silent failures device sends (EL, PID, Ctr_rec, REC);
               server finds the record by EL (not by PID), needs Ctr_rec > last_rec,
               verifies REC = XOF("REC"||K_res||EL||PID||Ctr_rec,128), then cur := PID, pend := {}

Eq.16  PID_{i+1} = XOF("PID_UPDATE" || PID_i || K_upd || Ctr_upd, 128)
Eq.17  REC = XOF("REC" || K_res || EL || PID || Ctr_rec, 128);  EL = XOF("EPOCH_LOC" || K_res, 128)

Revocation (R0): every record has status ACTIVE | REVOKED. The status is checked FIRST, before
A1 verification, candidate matching, PID update or recovery. A REVOKED device is dropped silently
(indistinguishable from an unknown PID). Neither EL nor K_res revokes anything; only the status
check stops a revoked device from recovering. Reactivation is not possible here: it requires a
fresh out-of-band registration (a new record).

Run: python3 identity_update_phase.py
"""
import os, hmac
from ascon_ref import ascon_xof

Q = 8          # max candidate pseudonyms per device
F = 3          # silent failures before the device starts recovery


def next_pid(pid, k_upd, ctr_upd):                                   # Eq. 16
    return ascon_xof(pid + k_upd + ctr_upd.to_bytes(8, "big"), 16, "PID_UPDATE")

def epoch_locator(k_res):
    return ascon_xof(k_res, 16, "EPOCH_LOC")

def rec_tag(k_res, el, pid, ctr_rec):                                # Eq. 17
    return ascon_xof(k_res + el + pid + ctr_rec.to_bytes(8, "big"), 16, "REC")


class Device:
    def __init__(self, pid0, k_res):
        self.pid, self.k_res, self.ctr_rec, self.fail = pid0, k_res, 0, 0

    def on_mac2_verified(self, new_pid):
        """R3: single atomic write of one pseudonym; power loss leaves old OR new."""
        self.pid, self.fail = new_pid, 0

    def on_silent_failure(self):
        self.fail += 1

    def needs_recovery(self):
        return self.fail >= F

    def build_rec(self):
        self.ctr_rec += 1                       # persist before sending
        el = epoch_locator(self.k_res)
        return el, self.pid, self.ctr_rec, rec_tag(self.k_res, el, self.pid, self.ctr_rec)


class Server:
    """Per-device record. A real server holds a dict indexed by cur/pend entries and by EL."""
    def __init__(self, pid0, k_res):
        self.cur, self.pend = pid0, []
        self.k_res, self.el, self.last_rec = k_res, epoch_locator(k_res), 0
        self.seen_aG = set()                    # replay cache (bounded by T1 window in practice)
        self.status = "ACTIVE"                  # R0: ACTIVE | REVOKED

    def revoke(self):
        self.status = "REVOKED"                 # administrator action; no un-revoke method

    def process_m1(self, pid, aG, k_upd, ctr_upd):
        """Call AFTER A1/T1 verification. Returns PID_{i+1} if accepted (M2 is sent), else None."""
        if self.status != "ACTIVE":             # R0: before anything else
            return None
        if aG in self.seen_aG:                  # replay
            return None
        if pid == self.cur:
            newp = next_pid(pid, k_upd, ctr_upd)
            self.pend = (self.pend + [newp])[-Q:]
        elif pid in self.pend:
            newp = next_pid(pid, k_upd, ctr_upd)
            self.cur, self.pend = pid, [newp]
        else:                                   # unknown PID: silent drop, no state change
            return None
        self.seen_aG.add(aG)
        return newp

    def process_recovery(self, el, pid, ctr_rec, rec):
        if self.status != "ACTIVE":             # R0: REC cannot bypass revocation
            return False
        if not hmac.compare_digest(el, self.el) or ctr_rec <= self.last_rec:
            return False
        if not hmac.compare_digest(rec, rec_tag(self.k_res, el, pid, ctr_rec)):
            return False
        self.last_rec, self.cur, self.pend = ctr_rec, pid, []
        return True


def _session(dev, srv, k_upd=None, ctr=1, lose="none"):
    aG, k_upd = os.urandom(32), k_upd or os.urandom(16)
    newp = srv.process_m1(dev.pid, aG, k_upd, ctr)
    if newp is None or lose in ("m1", "m2"):
        dev.on_silent_failure(); return False
    dev.on_mac2_verified(newp); return True


def run_tests():
    k = os.urandom(16); p0 = os.urandom(16); ok_all = True
    def check(name, cond):
        nonlocal ok_all; ok_all &= bool(cond); print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    print("Phase 5 - pseudonym state machine tests")
    d, s = Device(p0, k), Server(p0, k)

    check("normal update rotates device PID and keeps it in {cur}U pend",
          _session(d, s) and (d.pid == s.cur or d.pid in s.pend) and d.pid != p0)
    old = d.pid
    check("next session promotes the pending candidate", _session(d, s) and s.cur == old)

    # lost M2: server added a candidate, device did not advance, retry succeeds
    d, s = Device(p0, k), Server(p0, k)
    _session(d, s, lose="m2")
    check("lost M2: device stays PID_i, still accepted", d.pid == s.cur and _session(d, s))

    # >10 consecutive lost M2
    d, s = Device(p0, k), Server(p0, k)
    for i in range(15): s.process_m1(d.pid, os.urandom(32), os.urandom(16), i + 1)
    check("15 lost M2 then normal session accepted; pend stays <= Q",
          len(s.pend) <= Q and _session(d, s))

    # replay
    d, s = Device(p0, k), Server(p0, k)
    aG, ku = os.urandom(32), os.urandom(16)
    s.process_m1(d.pid, aG, ku, 1); snap = (s.cur, list(s.pend))
    check("replayed M1 (same aG) rejected, no state change",
          s.process_m1(d.pid, aG, ku, 1) is None and (s.cur, s.pend) == snap)

    # delayed M1
    d, s = Device(p0, k), Server(p0, k)
    held = (d.pid, os.urandom(32), os.urandom(16), 1)
    d.on_mac2_verified(s.process_m1(d.pid, os.urandom(32), os.urandom(16), 2))
    s.process_m1(*held)
    check("delayed M1 adds one candidate, device PID still accepted", d.pid in s.pend or d.pid == s.cur)

    # recovery: server restored from an old state, PID unknown
    d = Device(p0, k)
    for _ in range(4): _session(d, Server(p0, k))        # device advanced repeatedly; real server lost this
    s2 = Server(p0, k)                                    # rolled back to p0
    for _ in range(F): d.on_silent_failure()
    check("unknown PID rejected without state change", s2.process_m1(d.pid, os.urandom(32), os.urandom(16), 1) is None and s2.cur == p0)
    msg = d.build_rec()
    check("recovery by EL succeeds", d.needs_recovery() and s2.process_recovery(*msg))
    check("replayed recovery rejected (Ctr_rec)", not s2.process_recovery(*msg))
    check("normal session works after recovery", _session(d, s2))

    # wrong K_res -> hard failure
    bad = Device(d.pid, os.urandom(16)); bad.k_res = os.urandom(16)
    check("REC with wrong K_res rejected (needs out-of-band re-registration)",
          not s2.process_recovery(*bad.build_rec()))
    check("tampered REC rejected", not s2.process_recovery(msg[0], msg[1], msg[2] + 1, msg[3]))
    # revocation (R0)
    d, s = Device(p0, k), Server(p0, k); _session(d, s)
    s.revoke()
    pre = (s.cur, list(s.pend))
    check("REVOKED: valid current-PID M1 rejected", s.process_m1(d.pid, os.urandom(32), os.urandom(16), 9) is None)
    check("REVOKED: old PID / pending PID also rejected", all(
        s.process_m1(x, os.urandom(32), os.urandom(16), 9) is None for x in [p0] + pre[1]))
    for _ in range(F): d.on_silent_failure()
    check("REVOKED: recovery with correct K_res and fresh Ctr_rec rejected", not s.process_recovery(*d.build_rec()))
    check("REVOKED: no state change", (s.cur, s.pend) == pre)
    s_new = Server(d.pid, k)
    check("fresh registration (new record) is ACTIVE and works", s_new.status == "ACTIVE" and _session(d, s_new))
    print("RESULT:", "ALL PASSED" if ok_all else "FAILURES")
    return ok_all


if __name__ == "__main__":
    raise SystemExit(0 if run_tests() else 1)
