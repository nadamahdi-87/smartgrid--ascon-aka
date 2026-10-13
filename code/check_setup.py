"""check_setup.py - run this first, in the folder that holds the protocol files.
Tells you exactly which file is missing/misnamed or outdated (names must have NO spaces)."""
import os, sys, importlib
here = os.path.dirname(os.path.abspath(__file__)); os.chdir(here); sys.path.insert(0, here)
need = ["ascon_c.py","ascon_ref.py","ascon.py","merged_auth_keyagr_phase.py","identity_update_phase.py",
        "secure_comm_phase.py","protocol_operation_trace.py","measure_e2e.py","benchmark_operations.py"]
print("Folder:", here, "\n")
ok = True
for f in need:
    if os.path.exists(f): print("  OK       ", f, os.path.getsize(f), "bytes")
    else:
        ok = False
        similar = [g for g in os.listdir(".") if g.lower().replace(" ","").replace("_","") .startswith(f.lower().replace("_","")[:10])]
        print("  MISSING  ", f, ("  <-- maybe renamed: %s" % similar) if similar else "")
print()
try:
    import merged_auth_keyagr_phase as M
    for n in ("derive_signing_key","derive_signing_pub_bytes"):
        if not hasattr(M, n): ok=False; print("  OUTDATED merged_auth_keyagr_phase.py: no", n)
    if not hasattr(M.Server, "revoke_device"): ok=False; print("  OUTDATED merged_auth_keyagr_phase.py: no revoke_device")
except Exception as e:
    ok=False; print("  cannot import merged_auth_keyagr_phase:", e)
try:
    import ascon_c; print("  ascon_c loads (compiled DLL found)")
except Exception as e:
    ok=False; print("  ascon_c DOES NOT LOAD:", e)
print("\nRESULT:", "ready to run" if ok else "fix the items above, then run again")
