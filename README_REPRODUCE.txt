REPRODUCIBILITY PACKAGE  -  A unified Ascon-based authentication and key agreement protocol for smart grids

CONTENTS
  code\        reference implementation, tests, benchmarks (Python 3.10+, `pip install cryptography`)
  proverif\    the five ProVerif 2.05 models used in Section 5.2 / Tables 3 and 4, plus a negative control
  run_all.bat  runs everything and collects the outputs in results\

ENVIRONMENT USED FOR THE REPORTED TIMINGS
  Windows 11, Intel Core i5-1140G7, Python 3.14 (see results\run_config.json written by the run),
  Ascon: official ascon-c opt64 compiled to DLLs, loaded by code\ascon_c.py (BUILD_ASCON_C_WINDOWS.md);
  X25519 / Ed25519: Python `cryptography` (OpenSSL).  ascon_ref.py is the pure-Python reference used
  only for conformance tests and must NOT be used for timing (about 100x slower).

PROTOCOL-LEVEL TEST VECTORS (supplementary material)
  python code\generate_protocol_test_vectors.py   -> A1, K_auth, MAC2, MAC3 for the fixed fixture.
  Exact input encodings of every XOF call: Table A.3 of the supplementary material.

PROVERIF MODELS  (run: proverif proverif\<file>.pv)
  proverif_merged_base.pv  attacker(testKauth), attacker(testKsess), attacker(SeedD);
                           inj-event(deviceAccepts) ==> inj-event(serverFinished);
                           inj-event(serverAccepts) ==> inj-event(deviceFinishes)
  proverif_merged_kci.pv   K0 given to the attacker from the start;
                           inj-event(deviceAcceptsServer) ==> inj-event(serverGenuine)
  proverif_merged_pfs.pv   K0 and Vi revealed after the session (phase 1); attacker(testKsess)
  proverif_merged_esl.pv   ephemeral scalars x, y of the tested session revealed; attacker(testKsess)
  proverif_merged_eck.pv   K0 and x, y of the tested session revealed; attacker(testKsess)
  Reveal schedules and freshness conditions: Section 5.1 and Table 3. All messages are on the
  public channel; T1, PID and counters are constants, so the time window, pseudonym rotation and
  recovery are not modeled (argued in Section 5.3). Results are symbolic.
  Expected output for a query that holds:  "RESULT not attacker(testKsess[]) is true."

OPERATION COUNTS (executed by code\protocol_operation_trace.py; Section 6.2)
  one recurring handshake, device: 9 XOF + 2 X25519
                           server: 11 XOF + 1 AEAD decryption + 2 X25519

NEGATIVE CONTROL
  proverif_sanity_control_esl.pv  esl model plus K0 and Vi revealed (violates freshness): the query
                           MUST be falsified ("RESULT not attacker(testKsess[]) is false."), which
                           shows that the "true" results above are not vacuous. Run it by hand.

RANDOMNESS AND SEEDS
  Protocol runs draw nonces and ephemeral keys from os.urandom; there is no PRNG seed. The test
  vectors use a fixed fixture and are deterministic. The timing results do not depend on the
  random values (fixed-size operations).

RAW TIMING DATA (written by the scripts, copied to results\)
  raw_op_samples.csv        per-run mean ms per call for each primitive (benchmark_operations.py)
  raw_e2e_run_means.csv     per-run mean ms per call of the end-to-end runs, warm-up runs flagged
  raw_e2e_iterations.csv    5000 individually timed full handshakes
  run_config.json           platform, Python, library versions, iteration counts, reported mean/stdev
  op_times.json             per-operation means used by the operation trace
