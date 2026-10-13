"""
protocol_operation_trace.py
===========================
Complete, MEASURED operation trace of the reference implementation.

Every Ascon-XOF128 / Ascon-Hash256 / Ascon-AEAD128 call, every X25519 scalar
multiplication and every Ed25519 operation executed by the real protocol code
(merged_auth_keyagr_phase.py, identity_update_phase.py, secure_comm_phase.py)
is recorded with: party, protocol step, operation, domain label, input and
output length. The counts therefore come from running the code, not from
re-deriving them by hand.

Output
------
  1. Step-by-step trace for one normal session (device and server separately)
  2. Operation totals per party and per STAGE:
        A  handshake        (M1-M2-M3: what Table 8 of the paper should cover)
        B  post-handshake   (K_enc, K_upd, K_res, next pseudonym, EL)
        C  per FINANCIAL message (sk re-derivation + Ed25519 sign)
        D  recovery         (REC build + verify)
  3. Estimated primitive-level cost = counts x measured per-op times
     (times are read from OP_TIMES_MS below: paste your own measured values
      from benchmark_operations.py; defaults are Table 7 of the paper)
  4. A check of the counts against what the manuscript states.

Not measured here (hardware dependent, see STAGE 0 note printed at the end):
  PUF read, error-correcting decode of the fuzzy extractor, network, storage I/O.

Run:  python3 protocol_operation_trace.py
Works with the compiled ascon_c if it loads, otherwise with ascon_ref (counts
are identical; only timings differ, and timings are NOT taken from this run).
"""
import os, sys, types, json, time, contextlib

# ---------------------------------------------------------------- tracing core
TRACE, STATE = [], {"party": "-", "step": "-"}

@contextlib.contextmanager
def at(party, step):
    old = dict(STATE); STATE.update(party=party, step=step)
    try: yield
    finally: STATE.update(old)

def rec(op, label="", n_in=0, n_out=0):
    TRACE.append(dict(party=STATE["party"], step=STATE["step"], op=op,
                      label=label, n_in=n_in, n_out=n_out))

try:
    import ascon_c as _impl; _impl.ascon_xof(b"x", 16, "t"); BACKEND = "ascon_c"
except Exception:
    import ascon_ref as _impl; BACKEND = "ascon_ref (pure Python; counts only)"

_X, _H, _E, _D = _impl.ascon_xof, _impl.ascon_hash, _impl.aead_encrypt, _impl.aead_decrypt  # originals
def t_xof(msg, n=32, domain=""):
    lab = domain or next((p.decode() for p in (b"AUTH1", b"MAC2", b"MAC3") if msg.startswith(p)), "(none)")
    rec("XOF", lab, len(msg), n); return _X(msg, n, domain)
def t_hash(msg):
    rec("HASH", "", len(msg), 32); return _H(msg)
def t_enc(k, n, p, a=b""):
    rec("AEAD_ENC", a.decode(errors="ignore"), len(p), len(p) + 16); return _E(k, n, p, a)
def t_dec(k, n, c, t, a=b""):
    rec("AEAD_DEC", a.decode(errors="ignore"), len(c) + 16, len(c)); return _D(k, n, c, t, a)

fake = types.ModuleType("ascon_c")
fake.ascon_xof, fake.ascon_hash, fake.aead_encrypt, fake.aead_decrypt = t_xof, t_hash, t_enc, t_dec
sys.modules["ascon_c"] = fake            # merged phase imports this name
import ascon_ref as _ref_mod             # identity-update phase uses ascon_ref
_ref_mod.ascon_xof = t_xof

import merged_auth_keyagr_phase as MP
import identity_update_phase as IU
IU.ascon_xof = t_xof

_gen, _shr = MP.x25519_generate, MP.x25519_shared
def g():  rec("X25519_MULT", "ephemeral keygen (base point)", 0, 32); return _gen()
MP.x25519_generate = g
def sh(priv, peer): rec("X25519_MULT", "shared secret Z", 32, 32); return _shr(priv, peer)
MP.x25519_shared = sh

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --------------------------------------------------------------- measured costs
# Paste your own results from benchmark_operations.py here (ms per call).
OP_TIMES_MS = {"XOF": 0.00236, "HASH": 0.00189, "AEAD_ENC": 0.00751, "AEAD_DEC": 0.00751,
               "X25519_MULT": 0.02925, "ED25519_SIGN": 0.118 / 2, "ED25519_VERIFY": 0.118 / 2}
# Table 7 reports enc+dec together (0.00751) and sign+verify together (0.11829). Until the
# separate figures are measured, ONE AEAD operation is charged the full enc+dec time (a
# conservative upper bound) and the two Ed25519 operations half each (sign and verify cost
# about the same in OpenSSL). benchmark_operations.py now writes op_times.json with all
# operations measured separately; if that file is present it overrides these defaults.
OP_TIMES_MS.update({"AEAD_ENC": 0.00751, "AEAD_DEC": 0.00751})
try:
    OP_TIMES_MS.update(json.load(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "op_times.json")))); TIMES_SRC = "op_times.json (measured)"
except Exception:
    TIMES_SRC = "defaults from Table 7 of the paper"

# ------------------------------------------------------------------- the run
def run():
    seed_d = os.urandom(16)
    v_i = _X(seed_d, 16, "VERIFIER")
    pid0 = _X(v_i, 16, "PID_INIT")
    hsm = MP.ServerHSM(); srv = MP.Server(hsm)
    srv.register_device(pid0, hsm.protect(v_i))
    dev = MP.IoTDevice("SM", seed_d, pid0)
    TRACE.clear()                                    # registration is not part of a session

    # ---- STAGE A: handshake
    with at("device", "A1 build_m1"):      m1 = dev.build_m1()
    with at("server", "A2 process_m1"):    m2, sess = srv.process_m1(m1)
    with at("device", "A3 process_m2"):    ok = dev.process_m2(m2)
    with at("device", "A4 build_m3"):      m3 = dev.build_m3()
    with at("server", "A5 process_m3"):    ok3 = srv.process_m3(m3, sess)
    assert m2 and ok and ok3, "handshake failed"
    nA = len(TRACE)

    # ---- STAGE B: post-handshake derivations
    for who, obj in (("device", dev),):
        with at(who, "B1 K_enc"): obj.get_k_enc()
        with at(who, "B2 K_upd"): k_upd = obj.get_k_upd()
        with at(who, "B3 K_res"): k_res = obj.get_k_res()
    # NOTE: the server derives K_enc/K_upd/K_res eagerly INSIDE process_m1 (counted in stage A,
    # because that is what the end-to-end measurement executes); the device derives the same three
    # keys lazily, on first use (stage B below). Over a whole session both parties derive all three.
    with at("device", "B4 next pseudonym (Eq.16)"): IU.next_pid(dev.pid, k_upd, 1)
    with at("server", "B4 next pseudonym (Eq.16)"): IU.next_pid(dev.pid, k_upd, 1)
    nB = len(TRACE)

    # ---- STAGE C: one FINANCIAL message, executed through the REAL secure_comm_phase classes
    import secure_comm_phase as SC
    class SignWrap:                       # records Ed25519 sign
        def __init__(s, k): s.k = k
        def sign(s, m): rec("ED25519_SIGN", "", len(m), 64); return s.k.sign(m)
    class VerWrap:                        # records Ed25519 verify
        def __init__(s, k): s.k = k
        def verify(s, sig, m): rec("ED25519_VERIFY", "", len(m), 0); return s.k.verify(sig, m)
    k_enc = dev.get_k_enc(); sid = dev.get_sid()
    sk = MP.derive_signing_key(v_i, pid0)
    TRACE_MARK = len(TRACE)
    sc_dev = SC.IoTDevice(k_enc, sid, dev.pid, SignWrap(sk))
    sc_srv = SC.Server(k_enc, sid, dev.pid, VerWrap(sk.public_key()))
    with at("device", "C1 send_data FINANCIAL"): msg = sc_dev.send_data(b"reading=42", "FINANCIAL")
    with at("server", "C2 receive_data FINANCIAL"): out = sc_srv.receive_data(msg)
    assert out[0] == b"reading=42" and out[2] is True, out
    # design-only cost (NOT executed by the reference code): the paper derives sk on demand, so a
    # device that does not keep the derived key in volatile memory would add these per message.
    with at("device", "C0 (design) re-derive V_i"):     v2 = t_xof(seed_d, 16, "VERIFIER")
    with at("device", "C0 (design) re-derive PID_0"):   p2 = t_xof(v2, 16, "PID_INIT")
    with at("device", "C0 (design) derive sk Eq.8'"):   t_xof(v2 + p2 + (0).to_bytes(4, "big"), 32, "SIGN_DERIVE")
    nC = len(TRACE)

    # ---- STAGE D: recovery (REC build + verify), not part of a normal session
    with at("device", "D0 setup"): d = IU.Device(dev.pid, k_res)
    with at("server", "D0 setup"): s_ = IU.Server(dev.pid, k_res)   # EL computed once per epoch (stage B)
    with at("device", "D1 build REC"): msg = d.build_rec()
    with at("server", "D2 verify REC"): okr = s_.process_recovery(*msg)
    assert okr

    stage = lambda i: "A" if i < nA else "B" if i < nB else ("C0" if TRACE[i]["step"].startswith("C0") else "C") if i < nC else "D"
    for i, r in enumerate(TRACE):
        r["stage"] = stage(i)
        if r["step"] == "D0 setup": r["stage"] = "B"
    return TRACE

def table(rows, party=None, stage=None):
    from collections import Counter
    c = Counter()
    for r in rows:
        if (party is None or r["party"] == party) and (stage is None or r["stage"] == stage):
            c[r["op"]] += 1
    return c

def fmt(c): return ", ".join(f"{v}x{k}" for k, v in sorted(c.items())) or "-"
def cost(c): return sum(OP_TIMES_MS.get(k, 0) * v for k, v in c.items())

if __name__ == "__main__":
    rows = run()
    print("=" * 96); print("  OPERATION TRACE (one normal session, executed by the reference code)")
    print("  backend:", BACKEND); print("=" * 96)
    print(f"{'stage':5} {'party':7} {'step':28} {'op':14} {'label / purpose':32} {'in':>4} {'out':>4}")
    for r in rows:
        print(f"{r['stage']:5} {r['party']:7} {r['step']:28} {r['op']:14} {r['label'][:32]:32} {r['n_in']:>4} {r['n_out']:>4}")

    print("\n" + "=" * 96); print("  TOTALS"); print("=" * 96)
    for stg, name in (("A", "handshake (M1-M2-M3)"), ("B", "post-handshake derivations"),
                      ("C", "per FINANCIAL msg (executed)"), ("C0", "per FINANCIAL msg (design-only)"), ("D", "recovery (only after desync)")):
        for p in ("device", "server"):
            c = table(rows, p, stg)
            print(f"  stage {stg} {name:30} {p:7}: {fmt(c):60} ~ {cost(c):.4f} ms (primitive-level)")
    print()
    A_dev, A_srv = table(rows, "device", "A"), table(rows, "server", "A")
    AB_dev = table(rows, "device", "A") + table(rows, "device", "B")
    AB_srv = table(rows, "server", "A") + table(rows, "server", "B")
    print(f"  Handshake only         device {cost(A_dev):.4f} ms   server {cost(A_srv):.4f} ms   total {cost(A_dev)+cost(A_srv):.4f} ms")
    print(f"  Handshake + stage B    device {cost(AB_dev):.4f} ms   server {cost(AB_srv):.4f} ms   total {cost(AB_dev)+cost(AB_srv):.4f} ms")

    print(f"\n  per-operation times: {TIMES_SRC}")
    print("\n  Stage A, operation list by party (what the paper's Table 8 must account for):")
    for p in ("device", "server"):
        print(f"   {p}: " + ", ".join(f"{r['op']}[{r['label']}]" for r in rows if r['party'] == p and r['stage'] == 'A'))
    print("\n" + "=" * 96); print("  CONSISTENCY WITH THE MANUSCRIPT (Table 8 / Sec. 7)"); print("=" * 96)
    paper = {"device": dict(XOF=7, X25519_MULT=2), "server": dict(XOF=6, X25519_MULT=2, AEAD_DEC=1)}  # v18 text
    for p in ("device", "server"):
        got = dict(table(rows, p, "A"))
        print(f"  {p:7} stated: {paper[p]}   executed (stage A): {got}   -> {'MATCH' if got == paper[p] else 'DIFFERS'}")
    print("""
  Notes
  * Stage 0 (not traced, hardware dependent): PUF read, error-correcting decode of the
    fuzzy extractor, and the XOF("PUF_SEED") inside Rep(.). In the reference code Seed_D is
    passed in; on a real meter every session starts with PUF read + Rep + XOF(VERIFIER).
  * The HSM decryption is the AEAD_DEC counted on the server side of stage A.
  * Network and storage I/O are excluded by construction (functions are called directly).
""")
    json.dump(rows, open("operation_trace.json", "w"), indent=1)
