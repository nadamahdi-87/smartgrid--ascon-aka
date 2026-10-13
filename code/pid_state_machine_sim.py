"""
Randomized adversarial simulation of the pseudonym state machine (paper Sec. 5.6).

Server record : (cur, pending[<=Q], EL, last_rec)  -- cur + bounded candidate set
Device        : (pid, K_res, ctr_rec)          -- one persisted pseudonym

Rules
 R1  Server changes (cur,next) ONLY after a fresh, A1-verified M1 (replays, bad A1, unknown PID: no change).
 R2  M1 with PID == cur  -> next := PID'   (PID' = XOF(PID_UPDATE||PID||K_upd||Ctr), K_upd from this session)
 R3  M1 with PID == next -> cur := PID, next := PID'
 R4  Device persists PID' (atomically) only after verifying MAC2 of the same session.
 R5  Unknown PID -> no reply; after F consecutive silent failures the device runs Recovery:
        (EL, PID, Ctr_rec, REC = XOF("REC"||K_res||EL||PID||Ctr_rec)); server finds record by EL, requires
        Ctr_rec > last_rec, verifies REC, sets cur := PID, next := none, then a normal session follows.
Invariant I : whenever server state is not rolled back, device.pid in {cur} U pending.
"""
import os, random
from ascon_ref import ascon_xof

def nxt(pid, k_upd, ctr): return ascon_xof(pid + k_upd + ctr.to_bytes(8, "big"), 16, "PID_UPDATE")

class Server:
    def __init__(s, pid0, k_res):
        s.cur, s.pend, s.Q = pid0, [], 8
        s.k_res = k_res; s.EL = ascon_xof(k_res, 16, "EPOCH_LOC"); s.last_rec = 0
        s.seen = set(); s.pending_new = None
    def snapshot(s): return (s.cur, list(s.pend), s.last_rec, set(s.seen))
    def restore(s, sn): s.cur, s.pend, s.last_rec, s.seen = sn[0], list(sn[1]), sn[2], set(sn[3])
    def m1(s, pid, aG, k_upd, ctr):
        """returns pid' if M1 accepted (M2 would be sent), else None. State changes only if accepted."""
        if aG in s.seen: return None                      # replay
        if pid == s.cur:
            newp = nxt(pid, k_upd, ctr); s.pend = (s.pend + [newp])[-s.Q:]   # add candidate, bounded
        elif pid in s.pend:
            newp = nxt(pid, k_upd, ctr); s.cur, s.pend = pid, [newp]         # promote, drop stale candidates
        else: return None                                  # unknown PID
        s.seen.add(aG); return newp
    def recovery(s, EL, pid, ctr_rec, rec):
        if EL != s.EL or ctr_rec <= s.last_rec: return False
        if rec != ascon_xof(s.k_res + EL + pid + ctr_rec.to_bytes(8, "big"), 16, "REC"): return False
        s.last_rec = ctr_rec; s.cur, s.pend = pid, []; return True

class Device:
    def __init__(d, pid0, k_res): d.pid, d.k_res, d.ctr_rec, d.fail = pid0, k_res, 0, 0
    def rec_msg(d):
        d.ctr_rec += 1; EL = ascon_xof(d.k_res, 16, "EPOCH_LOC")
        return EL, d.pid, d.ctr_rec, ascon_xof(d.k_res + EL + d.pid + d.ctr_rec.to_bytes(8, "big"), 16, "REC")

def run(seed, steps=500, F=3):
    R = random.Random(seed); k_res = os.urandom(16); p0 = os.urandom(16)
    S, D = Server(p0, k_res), Device(p0, k_res); ctr = 0; snaps = []; stats = dict(ok=0, recov=0, hard=0)
    rolled = False; old_msgs = []
    for _ in range(steps):
        ev = R.choice(["ok"]*6 + ["lostM1","lostM2","crash_before_persist","replay","snapshot","rollback","recover_only"])
        ctr += 1
        if ev == "snapshot": snaps.append(S.snapshot()); continue
        if ev == "rollback" and snaps: S.restore(R.choice(snaps)); rolled = True; continue
        if ev == "replay" and old_msgs:                    # attacker replays an old M1
            pid, aG, k, c = R.choice(old_msgs); before = (S.cur, list(S.pend)); was_seen = aG in S.seen; S.m1(pid, aG, k, c)
            if was_seen: assert (S.cur, S.pend) == before, 'replay changed state'
            continue
        if ev == "recover_only" or D.fail >= F:
            if S.recovery(*D.rec_msg()): D.fail = 0; stats["recov"] += 1; rolled = False
            else: stats["hard"] += 1                        # needs out-of-band re-registration
            continue
        aG, k = os.urandom(32), os.urandom(16); old_msgs.append((D.pid, aG, k, ctr))
        if ev == "lostM1": D.fail += 1; continue
        newp = S.m1(D.pid, aG, k, ctr)
        if newp is None: D.fail += 1; continue              # unknown pid / replay
        if ev == "lostM2": D.fail += 1; continue            # server advanced next, device did not
        if ev == "crash_before_persist": D.fail += 1; continue
        D.pid = newp; D.fail = 0; stats["ok"] += 1          # MAC2 verified -> persist
        if not rolled: assert D.pid == S.cur or D.pid in S.pend, "invariant I violated"
    return stats, (D.pid == S.cur or D.pid in S.pend)

if __name__ == "__main__":
    tot = dict(ok=0, recov=0, hard=0); bad = 0
    for sd in range(30):
        st, fin = run(sd)
        for k in tot: tot[k] += st[k]
    print("30 randomized runs x 500 events:", tot)
    # focused scenarios
    k = os.urandom(16); p = os.urandom(16)
    S, D = Server(p, k), Device(p, k)
    # (a) >10 consecutive lost M2 : server's pending slot is overwritten each time, device never advanced
    for i in range(15): S.m1(D.pid, os.urandom(32), os.urandom(16), i+1)
    a = S.m1(D.pid, os.urandom(32), os.urandom(16), 99); print("(a) 15 lost M2 then normal session accepted:", a is not None)
    # (b) server loses all state of pid (unknown PID) -> recovery
    S2 = Server(os.urandom(16), k)                          # restored from far older state, K_res (same epoch) survives
    print("(b) unknown PID rejected:", S2.m1(D.pid, os.urandom(32), os.urandom(16), 1) is None,
          "| recovery ok:", S2.recovery(*D.rec_msg()), "| next session ok:", S2.m1(D.pid, os.urandom(32), os.urandom(16), 2) is not None)
    # (d) delayed M1: attacker holds an M1 sent from PID=A, device completes another session, then M1 is delivered
    k2=os.urandom(16); pA=os.urandom(16); S3,D3=Server(pA,k2),Device(pA,k2)
    held=(D3.pid, os.urandom(32), os.urandom(16), 1)
    n=S3.m1(D3.pid, os.urandom(32), os.urandom(16), 2); D3.pid=n          # genuine session, device advances
    S3.m1(*held)                                                           # stale M1 (PID==cur) delivered late
    print("(d) delayed M1 does not desync device:", D3.pid in S3.pend or D3.pid==S3.cur)
    # (c) replayed recovery request rejected
    msg = D.rec_msg(); print("(c) first recovery:", S2.recovery(*msg), "| replay:", S2.recovery(*msg))
