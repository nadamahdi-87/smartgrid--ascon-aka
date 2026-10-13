"""
measure_e2e.py
==============
Clean end-to-end measurement of the FULL protocol execution
(build_m1 + process_m1 + process_m2 + build_m3 + process_m3),
as opposed to the primitive-level sum (device 9*T_xof + 2*T_dh; server 11*T_xof + 2*T_dh + T_aead) reported
elsewhere.

Run this on the SAME machine and environment used for the other
benchmarks (Windows 11, Intel i5-1140G7, with ASCON_C_DIR pointing
at your DLLs), so all numbers in the paper come from one consistent
setup.

Usage:
    set ASCON_C_DIR=C:\\path\\to\\your\\dlls
    python measure_e2e.py
"""

import time
import os
import statistics as st

import merged_auth_keyagr_phase as MP
from ascon_c import ascon_xof as _xof


def build_setup():
    """One-time setup: NOT part of the timed protocol run."""
    seed_d = os.urandom(16)
    pid = _xof(seed_d, 16, "PID_INIT")
    v_i = _xof(seed_d, 16, "VERIFIER")
    hsm = MP.ServerHSM()
    srv = MP.Server(hsm)
    srv.register_device(pid, hsm.protect(v_i))
    dev = MP.IoTDevice("SM", seed_d, pid)
    return srv, dev


def device_side_work(srv, dev):
    """Everything the smart meter executes in one session:
    build M1, (server processes M1 to produce M2 -- needed to continue),
    process M2, build M3."""
    m1 = dev.build_m1()
    m2, sess = srv.process_m1(m1)
    dev.process_m2(m2)
    dev.build_m3()
    return sess


def server_side_work(srv, dev):
    """Everything the server executes in one session:
    process M1, (device must respond to produce M3 -- needed to continue),
    process M3."""
    m1 = dev.build_m1()
    m2, sess = srv.process_m1(m1)
    dev.process_m2(m2)
    m3 = dev.build_m3()
    srv.process_m3(m3, sess)


def full_handshake(srv, dev):
    """The complete M1-M2-M3 exchange, both sides, start to finish."""
    m1 = dev.build_m1()
    m2, sess = srv.process_m1(m1)
    dev.process_m2(m2)
    m3 = dev.build_m3()
    srv.process_m3(m3, sess)


RAW_ROWS = []     # (measurement, run index, is_warmup, mean ms per call)


def bench(fn, n=1000, runs=5, warmup=2):
    """Runs fn n times per run, 'runs' times total; setup is rebuilt
    fresh for each run (outside the timed loop) so no session state
    leaks between iterations. Discards the first 'warmup' runs."""
    all_means = []
    global RAW_ROWS
    for r in range(runs + warmup):
        srv, dev = build_setup()
        t0 = time.perf_counter()
        for _ in range(n):
            fn(srv, dev)
        elapsed_ms = (time.perf_counter() - t0) / n * 1000
        RAW_ROWS.append((fn.__name__, r, int(r < warmup), elapsed_ms))
        if r >= warmup:
            all_means.append(elapsed_ms)
    return st.mean(all_means), st.stdev(all_means), all_means


if __name__ == "__main__":
    import platform

    print("=" * 68)
    print("  End-to-end protocol execution time (full run, not summed)")
    print("=" * 68)
    print(f"  Platform : {platform.platform()}")
    print(f"  Processor: {platform.processor()}")
    print(f"  Python   : {platform.python_version()}")
    print(f"  Iters/run: 1000   Runs: 5 (+2 warm-up, discarded)")
    print("-" * 68)

    mean_dev, sd_dev, _ = bench(device_side_work, n=1000, runs=5)
    print(f"\n  Device-side work (build M1, process M2, build M3):")
    print(f"    mean = {mean_dev:.4f} ms   stdev = {sd_dev:.4f} ms")

    mean_srv, sd_srv, _ = bench(server_side_work, n=1000, runs=5)
    print(f"\n  Server-side work (process M1, process M3):")
    print(f"    mean = {mean_srv:.4f} ms   stdev = {sd_srv:.4f} ms")

    mean_full, sd_full, _ = bench(full_handshake, n=1000, runs=5)
    print(f"\n  Full handshake, both sides, M1-M2-M3 complete:")
    print(f"    mean = {mean_full:.4f} ms   stdev = {sd_full:.4f} ms")

    # ---- raw samples and configuration, for reproduction (reviewer request) ----
    import csv, json, sys
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw_e2e_run_means.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["measurement", "run", "is_warmup", "mean_ms_per_call"])
        w.writerows(RAW_ROWS)
    # one extra pass: every individual full-handshake iteration timed separately
    srv, dev = build_setup()
    for _ in range(200): full_handshake(srv, dev)            # warm-up
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw_e2e_iterations.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["iteration", "ms"])
        for i in range(5000):
            t0 = time.perf_counter(); full_handshake(srv, dev)
            w.writerow([i, (time.perf_counter() - t0) * 1000])
    try:
        import cryptography; cv = cryptography.__version__
    except Exception:
        cv = "unknown"
    cfg = {"platform": platform.platform(), "processor": platform.processor(),
           "python": platform.python_version(), "cryptography": cv,
           "ascon_impl": "ascon_c (compiled C, opt64)", "iters_per_run": 1000,
           "runs": 5, "warmup_runs": 2, "per_iteration_samples": 5000,
           "randomness": "os.urandom (no PRNG seed); deterministic vectors use a fixed fixture",
           "reported": {"full_handshake_mean_ms": mean_full, "full_handshake_stdev_ms": sd_full}}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_config.json"), "w") as fh: json.dump(cfg, fh, indent=1)
    print("\n  Wrote raw_e2e_run_means.csv, raw_e2e_iterations.csv, run_config.json")
    print("  FILES ARE IN THIS FOLDER:", os.path.dirname(os.path.abspath(__file__)))

    print("\n" + "=" * 68)
    print("  Report ONLY the full-handshake figure (mean_full with stdev) in")
    print("  Section 7 as the MEASURED end-to-end protocol execution time.")
    print("  This is separate from, and should not be confused with,")
    print("  the primitive-level sum (device 9*T_xof + 2*T_dh; server 11*T_xof + 2*T_dh + T_aead) reported elsewhere.")
    print("=" * 68)
