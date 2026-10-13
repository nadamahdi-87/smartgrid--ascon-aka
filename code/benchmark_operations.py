"""
benchmark_operations.py
=======================
Measures the average execution time of the basic cryptographic operations
used by the proposed protocol, so the Performance section can report
figures measured on YOUR hardware rather than borrowed from other papers.

Operations measured:
    T_xof   : Ascon-XOF128   (key derivation)
    T_hash  : Ascon-Hash256  (A_1, verifier)
    T_aead  : Ascon-AEAD128  (encrypt + decrypt of one message)
    T_dh    : X25519 scalar multiplication (one ephemeral op)
    T_sig   : Ed25519 sign + verify (selective non-repudiation)

Requirements (same folder):
    ascon_ref.py, ascon.py
    pip install cryptography      # for X25519 and Ed25519

HOW TO RUN (Windows cmd, in the folder holding these files):
    python benchmark_operations.py

Copy the printed table straight into Table 4 of the Performance section.
Report the CPU and Python version printed in the header alongside it.
"""

import time
import os
import platform
import statistics

# Use the compiled Ascon (ascon_c, opt64) -- the implementation the paper reports (Table 7).
# The pure-Python ascon_ref is ~100x slower and must NOT be used for Table 7 figures.
try:
    from ascon_c import ascon_xof, ascon_hash, aead_encrypt, aead_decrypt
    ASCON_IMPL = "ascon_c (compiled C, opt64)"
except Exception as _e:
    from ascon_ref import ascon_xof, ascon_hash, aead_encrypt, aead_decrypt
    ASCON_IMPL = "ascon_ref (PURE PYTHON FALLBACK)"
    print("\n" + "!" * 68)
    print("  WARNING: ascon_c could not be loaded (%s)" % _e)
    print("  Falling back to pure-Python ascon_ref. These XOF/AEAD/HASH times are")
    print("  ~100x slower than the C build and are NOT valid for Table 7.")
    print("  Build the DLL first (see BUILD_ASCON_C_WINDOWS.md) and run again.")
    print("!" * 68 + "\n")

# X25519 / Ed25519 are optional; the script still runs without them.
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


ITERS = 10000          # inner repetitions per timed operation
RUNS  = 5              # outer runs; we report the mean of these


def time_op(fn, iters=ITERS):
    """Return average milliseconds for one call of fn, over `iters` calls."""
    start = time.perf_counter()
    for _ in range(iters):
        fn()
    end = time.perf_counter()
    return (end - start) / iters * 1000.0     # ms per call


SAMPLE_ROWS = []      # (operation, run index, mean ms per call) -- raw samples for reproduction


def bench(label, fn):
    """Run several outer runs and report mean and stdev in ms."""
    samples = [time_op(fn) for _ in range(RUNS)]
    SAMPLE_ROWS.extend((label.split()[0], i, v) for i, v in enumerate(samples))
    mean = statistics.mean(samples)
    stdev = statistics.pstdev(samples)
    return label, mean, stdev


def main():
    print("=" * 68)
    print("  Basic-operation benchmark for the proposed protocol")
    print("=" * 68)
    print(f"  Platform : {platform.platform()}")
    print(f"  Processor: {platform.processor() or 'n/a'}")
    print(f"  Python   : {platform.python_version()}")
    print(f"  Iters/run: {ITERS}   Runs: {RUNS}")
    print("-" * 68)

    # fixed test inputs
    msg16  = os.urandom(16)
    msg32  = os.urandom(32)
    key    = os.urandom(16)
    nonce  = os.urandom(16)
    aad    = b"BENCH"
    pt     = os.urandom(32)

    results = []

    # T_xof : Ascon-XOF128, 16-byte output with a domain label
    results.append(bench("T_xof  (Ascon-XOF128)",
                         lambda: ascon_xof(msg32, 16, "AUTH")))

    # T_hash : Ascon-Hash256
    results.append(bench("T_hash (Ascon-Hash256)",
                         lambda: ascon_hash(msg32)))

    # T_aead : one encrypt + one decrypt (a full protected message)
    def aead_roundtrip():
        c, t = aead_encrypt(key, nonce, pt, aad)
        aead_decrypt(key, nonce, c, t, aad)
    results.append(bench("T_aead (AEAD enc+dec)", aead_roundtrip))

    # separate enc / dec so that per-operation costs can be applied to the traced counts
    c_, t_ = aead_encrypt(key, nonce, pt, aad)
    results.append(bench("T_enc  (AEAD encrypt only)", lambda: aead_encrypt(key, nonce, pt, aad)))
    results.append(bench("T_dec  (AEAD decrypt only)", lambda: aead_decrypt(key, nonce, c_, t_, aad)))

    if HAVE_CRYPTO:
        # T_dh : one X25519 scalar multiplication (shared-secret computation)
        priv = X25519PrivateKey.generate()
        peer = X25519PrivateKey.generate().public_key()
        results.append(bench("T_dh   (X25519 mult)",
                             lambda: priv.exchange(peer)))

        # T_sig : Ed25519 sign + verify of one message
        sk = Ed25519PrivateKey.generate()
        vk = sk.public_key()
        sig = sk.sign(msg32)
        def sign_verify():
            s = sk.sign(msg32)
            vk.verify(s, msg32)
        results.append(bench("T_sig  (Ed25519 sign+verify)", sign_verify))
        results.append(bench("T_sign (Ed25519 sign only)", lambda: sk.sign(msg32)))
        results.append(bench("T_verf (Ed25519 verify only)", lambda: vk.verify(sig, msg32)))
    else:
        print("  [note] 'cryptography' not installed - X25519/Ed25519 skipped.")
        print("         Install with:  pip install cryptography")
        print("-" * 68)

    # ---- print table ----
    print(f"  Ascon implementation: {ASCON_IMPL}")
    print(f"  {'Operation':32} {'Mean (ms)':>12} {'Stdev (ms)':>12}")
    print("-" * 68)
    for label, mean, stdev in results:
        print(f"  {label:32} {mean:>12.5f} {stdev:>12.5f}")
    print("=" * 68)

    # ---- export per-operation times for protocol_operation_trace.py ----
    # The protocol-level cost is NOT computed here by hand-written operation counts any more
    # (an earlier version of this file hard-coded 6 XOF per side, which did not match the code).
    # protocol_operation_trace.py runs the real protocol, counts every operation actually
    # executed, and multiplies by the times written below.
    import json, csv
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw_op_samples.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["operation", "run", "mean_ms_per_call"]); w.writerows(SAMPLE_ROWS)
    print("\n  Wrote raw_op_samples.csv (raw per-run samples, ITERS=%d calls per run)" % ITERS)
    print("  FILES ARE IN THIS FOLDER:", os.path.dirname(os.path.abspath(__file__)))
    key_of = {"T_xof": "XOF", "T_hash": "HASH", "T_enc": "AEAD_ENC", "T_dec": "AEAD_DEC",
              "T_dh": "X25519_MULT", "T_sign": "ED25519_SIGN", "T_verf": "ED25519_VERIFY"}
    out = {key_of[lbl.split()[0]]: mean for lbl, mean, _ in results if lbl.split()[0] in key_of}
    if not ASCON_IMPL.startswith("ascon_c"):
        print("\n  op_times.json NOT written (pure-Python Ascon).")
    else:
      with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "op_times.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("\n  Wrote op_times.json:", out)
    print("  Next: python protocol_operation_trace.py   (counts x these times)")
    print("=" * 68)


    # ---- OPTIONAL: end-to-end measurement of the real protocol ----
    # This runs the actual merged phase and times each side directly,
    # rather than summing per-operation costs. Requires the merged phase
    # file in the same folder.
    try:
        import merged_auth_keyagr_phase as MP
        from ascon_c import ascon_xof as _xof

        seed_d = os.urandom(16)
        pid    = _xof(seed_d, 16, "PID_INIT")
        v_i    = _xof(seed_d, 16, "VERIFIER")

        def build_setup():
            hsm = MP.ServerHSM()
            srv = MP.Server(hsm)
            srv.register_device(pid, hsm.protect(v_i))
            dev = MP.IoTDevice("SM", seed_d, pid)
            return srv, dev

        # time device-side work: build_m1 + process_m2 + build_m3
        def device_work():
            srv, dev = build_setup()
            m1 = dev.build_m1()
            m2, _ = srv.process_m1(m1)
            dev.process_m2(m2)
            dev.build_m3()

        # time server-side work: process_m1 + process_m3
        def server_work():
            srv, dev = build_setup()
            m1 = dev.build_m1()
            m2, sess = srv.process_m1(m1)
            dev.process_m2(m2)
            m3 = dev.build_m3()
            srv.process_m3(m3, sess)

        dev_meas = time_op(device_work, iters=200)
        all_meas = time_op(server_work, iters=200)

        print("\n" + "=" * 68)
        print("  End-to-end measured timing (real protocol run)")
        print("=" * 68)
        print(f"  Device build+process (M1,M2,M3) : {dev_meas:.4f} ms")
        print(f"  Full handshake (both sides)     : {all_meas:.4f} ms")
        print("  [note] end-to-end includes object setup overhead; the")
        print("         per-operation sums above isolate the crypto cost.")
        print("=" * 68)
    except Exception as e:
        print(f"\n  [end-to-end measurement skipped: {e}]")


if __name__ == "__main__":
    main()
