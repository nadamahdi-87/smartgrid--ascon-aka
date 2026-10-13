"""
measure_layers.py
=================
Layered timing of the protocol, so every reported number states exactly which
operations it contains.  Run on the SAME machine as benchmark_operations.py
(with ASCON_C_DIR set so the compiled ascon_c is used):

    set ASCON_C_DIR=C:\\path\\to\\dlls
    python measure_layers.py

Layers (each one INCLUDES everything above it):
  L0  primitive-level estimate : operation counts from protocol_operation_trace.py x
                                 per-operation times measured by benchmark_operations.py
  L1  protocol logic           : build_m1 / process_m1 / process_m2 / build_m3 / process_m3
                                 timed separately (device and server).  The server's
                                 process_m1 already contains the HSM decryption of Enc_s(V_i),
                                 the record lookup, the T1 window check and the aG replay cache.
  L2  + stage 0 (SIMULATED)    : fuzzy-extractor Rep + XOF(PUF_SEED) + XOF(VERIFIER) as implemented in
                                 initialization_phase_PUF.py.  This is a SOFTWARE SIMULATION
                                 (no ECC decoder, no SRAM): it shows only the XOF/hash cost of
                                 that stage.  Real PUF read time and BCH/RM decode time are
                                 hardware dependent and are NOT measured here.
  L3  + message handling       : byte-level serialisation and parsing of M1, M2, M3
  L4  + post-handshake         : K_enc, K_upd, K_res, next pseudonym (Eq.16), both sides
  L5  recovery (separate)      : REC build (device) + REC verification with status/EL/Ctr_rec
                                 checks (server); only happens after desynchronisation
Network latency, storage I/O and radio are excluded in every layer.
"""
import os, sys, time, platform, statistics as st

try:
    import ascon_c; ascon_c.ascon_xof(b"x", 16, "t"); BACKEND = "ascon_c (compiled)"
except Exception as e:
    import ascon_ref; sys.modules["ascon_c"] = ascon_ref
    BACKEND = "ascon_ref (PURE PYTHON - timings below are NOT comparable to the paper)"

import merged_auth_keyagr_phase as MP
import identity_update_phase as IU
from ascon_c import ascon_xof

N    = int(os.environ.get("LAYER_N", 1000))      # iterations per run
RUNS = int(os.environ.get("LAYER_RUNS", 5))      # measured runs
WARM = 2                                         # discarded runs

def setup():
    seed_d = os.urandom(16)
    v_i = ascon_xof(seed_d, 16, "VERIFIER"); pid0 = ascon_xof(v_i, 16, "PID_INIT")
    hsm = MP.ServerHSM(); srv = MP.Server(hsm); srv.register_device(pid0, hsm.protect(v_i))
    return srv, MP.IoTDevice("SM", seed_d, pid0), seed_d

# ---- tiny wire codec (fixed-width fields, same layout as the paper: 1056 bits) -------------
def pack_m1(m): return m["PID"] + m["T_1"] + m["aG"] + m["A_1"]
def unpack_m1(b): return {"PID": b[:16], "T_1": b[16:20], "aG": b[20:52], "A_1": b[52:68]}
def pack_m2(m): return m["bG"] + m["MAC_2"]
def unpack_m2(b): return {"bG": b[:32], "MAC_2": b[32:48]}
def pack_m3(m): return m["MAC_3"]
def unpack_m3(b): return {"MAC_3": b[:16]}

def one_session(srv, dev, T, wire=False):
    """Run one session, accumulating per-step times (seconds) into dict T."""
    pc = time.perf_counter
    t = pc(); m1 = dev.build_m1();                  T["dev_build_m1"] += pc() - t
    if wire:
        t = pc(); m1 = unpack_m1(pack_m1(m1));      T["wire"] += pc() - t
    t = pc(); m2, sess = srv.process_m1(m1);        T["srv_process_m1"] += pc() - t
    if wire:
        t = pc(); m2 = unpack_m2(pack_m2(m2));      T["wire"] += pc() - t
    t = pc(); dev.process_m2(m2);                   T["dev_process_m2"] += pc() - t
    t = pc(); m3 = dev.build_m3();                  T["dev_build_m3"] += pc() - t
    if wire:
        t = pc(); m3 = unpack_m3(pack_m3(m3));      T["wire"] += pc() - t
    t = pc(); srv.process_m3(m3, sess);             T["srv_process_m3"] += pc() - t
    return sess

def run_layer(fn_build, n=N, runs=RUNS, warm=WARM):
    res = []
    for r in range(runs + warm):
        T = {k: 0.0 for k in ("dev_build_m1", "srv_process_m1", "dev_process_m2", "dev_build_m3",
                              "srv_process_m3", "wire", "stage0", "post_dev", "post_srv", "rec_dev", "rec_srv")}
        fn_build(n, T)
        if r >= warm: res.append({k: v / n * 1000 for k, v in T.items()})   # ms per session
    return res

def stat(res, keys):
    vals = [sum(r[k] for k in keys) for r in res]
    return st.mean(vals), (st.stdev(vals) if len(vals) > 1 else 0.0)

def L1(n, T):
    srv, dev, _ = setup()
    for _ in range(n): one_session(srv, dev, T)

def L2_L3_L4(n, T):
    srv, dev, seed_d = setup()
    from initialization_phase_PUF import SRAMPUF, FuzzyExtractor
    puf = SRAMPUF(); seed, helper, ref = FuzzyExtractor.generate(puf.read())
    pc = time.perf_counter
    for _ in range(n):
        noisy = puf.read()                      # simulation artefact (per-bit os.urandom): NOT timed
        t = pc(); s = FuzzyExtractor.reproduce(noisy, helper, ref); ascon_xof(s, 16, "VERIFIER")
        T["stage0"] += pc() - t
        sess = one_session(srv, dev, T, wire=True)
        t = pc(); k_enc = dev.get_k_enc(); k_upd = dev.get_k_upd(); dev.get_k_res(); IU.next_pid(dev.pid, k_upd, 1)
        T["post_dev"] += pc() - t
        t = pc(); IU.next_pid(dev.pid, sess["k_upd"], 1)
        T["post_srv"] += pc() - t        # server already derived K_enc/K_upd/K_res inside process_m1 (in L1)

def L5(n, T):
    k_res = os.urandom(16); pid = os.urandom(16)
    pc = time.perf_counter
    for _ in range(n):
        d = IU.Device(pid, k_res); s = IU.Server(pid, k_res)
        t = pc(); msg = d.build_rec();            T["rec_dev"] += pc() - t
        t = pc(); ok = s.process_recovery(*msg);  T["rec_srv"] += pc() - t
        assert ok

if __name__ == "__main__":
    print("=" * 84); print("  LAYERED TIMING OF THE PROTOCOL"); print("=" * 84)
    print(f"  Backend  : {BACKEND}\n  Platform : {platform.platform()}\n  Processor: {platform.processor()}")
    print(f"  Python   : {platform.python_version()}   iterations/run: {N}   runs: {RUNS} (+{WARM} warm-up discarded)")
    print("-" * 84)
    r1 = run_layer(L1)
    d1 = stat(r1, ("dev_build_m1", "dev_process_m2", "dev_build_m3"))
    s1 = stat(r1, ("srv_process_m1", "srv_process_m3"))
    t1 = stat(r1, ("dev_build_m1", "dev_process_m2", "dev_build_m3", "srv_process_m1", "srv_process_m3"))
    print("  L1  protocol logic only (no PUF, no wire codec, no post-handshake derivations)")
    for k in ("dev_build_m1", "srv_process_m1", "dev_process_m2", "dev_build_m3", "srv_process_m3"):
        m, sd = stat(r1, (k,)); print(f"        {k:16} {m:9.4f} ms  +/- {sd:.4f}")
    print(f"      device total  {d1[0]:.4f} +/- {d1[1]:.4f} ms | server total {s1[0]:.4f} +/- {s1[1]:.4f} ms | both {t1[0]:.4f} +/- {t1[1]:.4f} ms")
    r2 = run_layer(L2_L3_L4)
    keys_core = ("dev_build_m1", "srv_process_m1", "dev_process_m2", "dev_build_m3", "srv_process_m3")
    L2 = stat(r2, keys_core + ("stage0",)); L3 = stat(r2, keys_core + ("stage0", "wire"))
    L4 = stat(r2, keys_core + ("stage0", "wire", "post_dev", "post_srv"))
    print(f"  L2  + stage 0 (SIMULATED PUF read + Rep + XOF)             : {L2[0]:.4f} +/- {L2[1]:.4f} ms")
    print(f"  L3  + wire serialisation / parsing of M1, M2, M3           : {L3[0]:.4f} +/- {L3[1]:.4f} ms")
    print(f"  L4  + post-handshake keys and next pseudonym (both sides)  : {L4[0]:.4f} +/- {L4[1]:.4f} ms")
    r5 = run_layer(L5)
    print(f"  L5  recovery (separate event): device {stat(r5,('rec_dev',))[0]:.4f} ms, server {stat(r5,('rec_srv',))[0]:.4f} ms")
    print("-" * 84)
    print("  Report L0 (from protocol_operation_trace.py) as the 'primitive-level estimate',")
    print("  L1 as 'protocol logic (excluding PUF/FE hardware, wire, network)', and L4 as the")
    print("  most complete software figure.  PUF read and ECC decode on real hardware are not included.")
    print("=" * 84)
