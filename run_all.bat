@echo off
REM Run from this folder on the machine used for the paper (Windows 11, i5-1140G7).
REM Put the compiled Ascon DLLs next to code\ascon_c.py, or set ASCON_C_DIR=C:\path\to\dlls
mkdir results 2>nul
cd code
python check_setup.py > ..\results\00_setup.txt 2>&1
echo ===== 1 Ascon KAT ===== > ..\results\01_correctness.txt
python ascon_ref.py >> ..\results\01_correctness.txt 2>&1
python x25519_rfc7748_kat.py >> ..\results\01_correctness.txt 2>&1
echo ===== 2 protocol test vectors ===== >> ..\results\01_correctness.txt
python generate_protocol_test_vectors.py >> ..\results\01_correctness.txt 2>&1
echo ===== 3 merged auth + key agreement + revocation ===== >> ..\results\01_correctness.txt
python merged_auth_keyagr_phase.py >> ..\results\01_correctness.txt 2>&1
echo ===== 4 secure communication ===== >> ..\results\01_correctness.txt
python secure_comm_phase.py >> ..\results\01_correctness.txt 2>&1
echo ===== 5 pseudonym state machine ===== >> ..\results\01_correctness.txt
python identity_update_phase.py >> ..\results\01_correctness.txt 2>&1
python pid_state_machine_sim.py >> ..\results\01_correctness.txt 2>&1
echo ===== 6 per-operation times (writes op_times.json, raw_op_samples.csv) ===== > ..\results\02_timing.txt
python benchmark_operations.py >> ..\results\02_timing.txt 2>&1
echo ===== 7 operation trace ===== >> ..\results\02_timing.txt
python protocol_operation_trace.py >> ..\results\02_timing.txt 2>&1
echo ===== 8 layered timing ===== >> ..\results\02_timing.txt
python measure_layers.py >> ..\results\02_timing.txt 2>&1
echo ===== 9 end-to-end (writes raw_e2e_run_means.csv, raw_e2e_iterations.csv, run_config.json) ===== >> ..\results\02_timing.txt
python measure_e2e.py >> ..\results\02_timing.txt 2>&1
move /Y op_times.json ..\results\ >nul 2>&1
move /Y raw_*.csv ..\results\ >nul 2>&1
move /Y run_config.json ..\results\ >nul 2>&1
cd ..
echo ===== ProVerif (needs proverif on PATH) ===== > results\03_proverif.txt
for %%m in (base kci pfs esl eck) do (
  echo ----- proverif_merged_%%m.pv ----- >> results\03_proverif.txt
  proverif proverif\proverif_merged_%%m.pv >> results\03_proverif.txt 2>&1
)
echo Done. Results are in the results folder.
