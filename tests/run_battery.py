#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""VFY acceptance battery for 1v-verify (CC decision 2026-10-23 §9).

Runs the verifier as a subprocess under `python3 -I` for every row, compares
headline, exit code and reason codes, checks output determinism (VFY-11 on
this machine; a second machine repeats this script), and records results to
tests/BATTERY_RESULT.json. Exit 0 only if every row passes.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V = ROOT / "src" / "onev_verify.py"
FIX = ROOT / "fixtures"
ANCHORS = ROOT / "keys" / "trust_anchors.json"

T_VALID = "TEST SIGNATURE VALID — NOT AN RST PRODUCTION ATTESTATION"
P_VALID = "RST PRODUCTION SIGNATURE VALID"
C_ONLY = "CONTENT INTEGRITY ONLY — NO ISSUER, TIME OR TRUTH ESTABLISHED"
NOT_VALID = "RECEIPT NOT VALID"
UNSUP = "UNSUPPORTED ARTIFACT"
INCOMPLETE = "INCOMPLETE PACKAGE"

# (gate, fixture, extra args, expected headline, expected exit, reason codes that must be present)
ROWS = [
    ("VFY-1",   "vfy01_valid_test_signed.json", [], T_VALID, 0, ["ISSUER_TRUST_TEST_ONLY"]),
    ("VFY-1k1", "vfy01k_june_vector_1.json", [], None, None, []),   # June kit r1: expectation computed below
    ("VFY-1k2", "vfy01k_june_vector_2.json", [], None, None, []),
    ("VFY-1k3", "vfy01k_june_vector_3.json", [], None, None, []),   # tampered title
    ("VFY-1k4", "vfy01k_june_vector_4.json", [], None, None, []),   # wrong pubkey
    ("VFY-1k5", "vfy01k_june_vector_5.json", [], None, None, []),   # old sha256-of-canonical scheme
    ("VFY-2",   "vfy02_payload_mutated_digest_stale.json", [], NOT_VALID, 1, ["DIGEST_MISMATCH"]),
    ("VFY-2b",  "vfy02b_payload_mutated_digest_recomputed.json", [], NOT_VALID, 1, ["BAD_SIGNATURE"]),
    ("VFY-3",   "vfy03_signature_mutated.json", [], NOT_VALID, 1, ["BAD_SIGNATURE"]),
    ("VFY-4",   "vfy04_wrong_key_claims_test_kid.json", [], NOT_VALID, 1, ["BAD_SIGNATURE"]),
    ("VFY-5",   "vfy05_unknown_kid.json", [], NOT_VALID, 1, ["UNKNOWN_KEY_ID"]),
    ("VFY-6a",  "vfy06a_unsupported_version.json", [], UNSUP, 2, ["UNSUPPORTED_VERSION"]),
    ("VFY-6b",  "vfy06b_unknown_format.json", [], UNSUP, 2, ["UNKNOWN_FORMAT"]),
    ("VFY-6c",  "vfy06c_unsupported_alg.json", [], UNSUP, 2, ["UNSUPPORTED_ALG"]),
    ("VFY-7a",  "vfy07a_missing_issued_at.json", [], NOT_VALID, 1, ["MISSING_REQUIRED_FIELD"]),
    ("VFY-7b",  "vfy07b_missing_signature.json", [], NOT_VALID, 1, ["MISSING_REQUIRED_FIELD"]),
    ("VFY-7c",  "vfy07c_unexpected_top_level_field.json", [], NOT_VALID, 1, ["UNEXPECTED_FIELD"]),
    ("VFY-7d",  "vfy07d_reserved_field_in_payload.json", [], NOT_VALID, 1, ["RESERVED_FIELD_IN_PAYLOAD"]),
    ("VFY-8",   "vfy08_duplicate_key.json", [], NOT_VALID, 1, ["DUPLICATE_KEY"]),
    ("VFY-9",   "vfy09_whitespace_variation.json", [], T_VALID, 0, ["ISSUER_TRUST_TEST_ONLY"]),
    ("VFY-13",  "vfy13_atlas_unsigned_receipt.json", [], UNSUP, 2, ["UNSIGNED_FAMILY"]),
    ("VFY-14",  "vfy14_1ve_internal_receipt.json", [], UNSUP, 2, ["INTERNAL_FAMILY"]),
    ("VFY-15",  "vfy15_float_in_payload.json", [], NOT_VALID, 1, ["NON_CANONICAL_NUMBER"]),
    ("VFY-15b", "vfy15b_nan_in_payload.json", [], NOT_VALID, 1, ["NON_CANONICAL_NUMBER"]),
    ("VFY-16",  "vfy01_valid_test_signed.json", ["--anchors", "fixtures/anchors_tampered_vfy16.json"], INCOMPLETE, 3, ["TRUST_ANCHORS_INVALID"]),
    ("VFY-16b", "vfy01_valid_test_signed.json", ["--anchors-sha256", "00" * 32], INCOMPLETE, 3, ["TRUST_ANCHORS_HASH_MISMATCH"]),
    ("VFY-16c", "vfy01_valid_test_signed.json", ["--anchors", "fixtures/does_not_exist.json"], INCOMPLETE, 3, ["TRUST_ANCHORS_UNREADABLE"]),
    ("VFY-17",  "vfy03_signature_mutated.json", ["--profile", "content-integrity"], C_ONLY, 4, ["CONTENT_INTEGRITY_ONLY"]),
    ("VFY-17b", "vfy02_payload_mutated_digest_stale.json", ["--profile", "content-integrity"], NOT_VALID, 1, ["DIGEST_MISMATCH"]),
    ("MISC-1",  "misc_not_json.txt", [], UNSUP, 2, ["NOT_JSON"]),
    ("MISC-2",  "misc_json_array.json", [], UNSUP, 2, ["NOT_OBJECT"]),
    ("MISC-3",  "does_not_exist.json", [], INCOMPLETE, 3, ["RECEIPT_UNREADABLE"]),
    ("MISC-4",  "vfy01_valid_test_signed.json", ["--anchors", "fixtures/anchors_test_key_revoked.json"], NOT_VALID, 1, ["KEY_REVOKED"]),
    # VFY-R1: operator-supplied PRODUCTION status must be refused in this release (PRODUCTION_AUTHORITY is empty).
    ("VFY-R1a", "vfy01_valid_test_signed.json", ["--anchors", "fixtures/anchors_prod_promoted_TEST_HARNESS_ONLY.json"], INCOMPLETE, 3, ["TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION"]),
    ("VFY-R1b", "vfy01_valid_test_signed.json", ["--anchors", "fixtures/anchors_r1_prod_kid_premature.json"], INCOMPLETE, 3, ["TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION"]),
    # VFY-R2: resource bounds produce typed refusals, never tracebacks.
    ("VFY-R2a", "r2a_nested_1100.json", [], NOT_VALID, 1, ["NESTING_TOO_DEEP"]),
    ("VFY-R2b", "r2b_nested_depth_80_signed.json", [], NOT_VALID, 1, ["NESTING_TOO_DEEP"]),
    ("VFY-R2c", "r2c_nested_depth_30_signed.json", [], T_VALID, 0, ["ISSUER_TRUST_TEST_ONLY"]),
    ("VFY-R2d", "r2d_oversized.json", [], UNSUP, 2, ["INPUT_TOO_LARGE"]),
    ("VFY-R2e", "vfy01_valid_test_signed.json", ["--anchors", "fixtures/anchors_r2_deep.json"], INCOMPLETE, 3, ["TRUST_ANCHORS_INVALID"]),
]

# June vector expectations: the June payloads have decision_id/issued_at/title but no receipt_id,
# so the 1.0 schema rejects them before signature verification (MISSING_REQUIRED_FIELD).
# To still prove cross-implementation parity, the battery ALSO verifies the raw June signatures
# directly through the verifier's own canonicalizer + key (see parity_check below).


def run(fixture: str, extra: list[str], as_json: bool = True) -> tuple[int, str]:
    # All paths relative to ROOT (cwd) so recorded results carry no machine-specific paths (VFY-R7).
    cmd = [sys.executable, "-I", "src/onev_verify.py", f"fixtures/{fixture}", "--anchors", "keys/trust_anchors.json"]
    if "--anchors" in extra:
        cmd = [sys.executable, "-I", "src/onev_verify.py", f"fixtures/{fixture}"]
    cmd += extra + (["--json"] if as_json else [])
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "PYTHONHASHSEED": "0"}
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT))
    if "Traceback" in p.stderr:
        return p.returncode, p.stdout + "\n__TRACEBACK__"
    return p.returncode, p.stdout


def production_path_unit() -> dict:
    import importlib
    sys.path.insert(0, str(ROOT / "src"))
    ov = importlib.import_module("onev_verify")
    anchors_path = "fixtures/anchors_prod_promoted_TEST_HARNESS_ONLY.json"
    os.chdir(ROOT)
    raw = (FIX / "vfy01_valid_test_signed.json").read_bytes()
    # 1) empty authority -> file refused
    a, _, err = ov.load_trust_anchors(anchors_path, None)
    refused = err == "TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION"
    # 2) authority pinned to the TEST key fp (simulating a post-ceremony release) -> production headline
    test_fp = json.loads((ROOT / "keys" / "trust_anchors.json").read_text())[1]["sha256"]
    saved = ov.PRODUCTION_AUTHORITY
    try:
        ov.PRODUCTION_AUTHORITY = frozenset({("1v_test_001", test_fp)})
        a2, _, err2 = ov.load_trust_anchors(anchors_path, None)
        r = ov.verify_bytes(raw, a2, ov.PROFILE_ISSUER_SIGNATURE, ov.new_result(ov.PROFILE_ISSUER_SIGNATURE)) if not err2 else {"headline": err2}
        reachable = r.get("headline") == P_VALID and r.get("exit_code") == 0
        # 3) authority pinned to a DIFFERENT kid -> still refused
        ov.PRODUCTION_AUTHORITY = frozenset({("1v_other", test_fp)})
        _, _, err3 = ov.load_trust_anchors(anchors_path, None)
        wrong_kid_refused = err3 == "TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION"
    finally:
        ov.PRODUCTION_AUTHORITY = saved
    return {"empty_authority_refused": refused, "pinned_authority_reaches_prod_headline": reachable,
            "wrong_kid_refused": wrong_kid_refused, "pass": refused and reachable and wrong_kid_refused}


def parity_check() -> dict:
    """Verify the five June kit vectors with the verifier module's verbatim canonicalizer."""
    import base64
    sys.path.insert(0, str(ROOT / "src"))
    from onev_verify import canonical_receipt_bytes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    kit = json.loads((ROOT / "tests" / "june_kit_vectors.json").read_text(encoding="utf-8"))
    out = []
    for vec in kit["vectors"]:
        obj = json.loads(vec["input"])
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(vec["pubkey_hex"])).verify(
                base64.b64decode(obj["signature"]), canonical_receipt_bytes(obj["receipt"]))
            got = True
        except InvalidSignature:
            got = False
        out.append({"vector": vec["name"], "expect": vec["expect"], "got": got, "pass": got == vec["expect"]})
    return {"june_kit_parity": out, "pass": all(o["pass"] for o in out)}


def main() -> int:
    results = []
    all_ok = True
    for gate, fixture, extra, exp_head, exp_exit, exp_reasons in ROWS:
        code, out = run(fixture, extra)
        try:
            obj = json.loads(out)
        except json.JSONDecodeError:
            obj = {"headline": None, "reason_codes": [], "_raw": out[:400]}
        head = obj.get("headline"); reasons = obj.get("reason_codes", [])
        if gate.startswith("VFY-1k"):
            # June vectors wrapped into 1.0: schema requires receipt_id which June payloads lack.
            exp_head, exp_exit, exp_reasons = NOT_VALID, 1, ["MISSING_REQUIRED_FIELD"]
        ok = (head == exp_head) and (code == exp_exit) and all(r in reasons for r in exp_reasons)
        # Invariants on every run
        text_code, text_out = run(fixture, extra, as_json=False)
        bare_valid = any(line.strip() == "VALID" for line in text_out.splitlines())
        tb = ("__TRACEBACK__" in out) or ("__TRACEBACK__" in text_out)
        net_ok = obj.get("network_used") == "NO"
        inv_ok = (not bare_valid) and net_ok and (text_code == code) and (not tb) and (code == 0) == (head in (T_VALID, P_VALID))
        # Determinism (VFY-11, same machine): run again, compare bytes
        code2, out2 = run(fixture, extra)
        det_ok = (out2 == out) and (code2 == code)
        row_ok = ok and inv_ok and det_ok
        all_ok &= row_ok
        results.append({"gate": gate, "fixture": fixture, "args": extra, "expected": {"headline": exp_head, "exit": exp_exit, "reasons": exp_reasons},
                        "got": {"headline": head, "exit": code, "reasons": reasons}, "invariants_ok": inv_ok, "deterministic": det_ok, "pass": row_ok})
        print(f"{'PASS' if row_ok else 'FAIL':4} {gate:<22} exit={code} {head} {reasons}")

    # Production path unit check (in-process): headline reachable ONLY when the (kid, fp) pair is compiled in.
    prod_unit = production_path_unit()
    print(("PASS" if prod_unit["pass"] else "FAIL"), "VFY-R1-UNIT", prod_unit)
    all_ok &= prod_unit["pass"]

    parity = parity_check()
    print(("PASS" if parity["pass"] else "FAIL"), "JUNE-KIT-PARITY", [(o["vector"], o["pass"]) for o in parity["june_kit_parity"]])
    all_ok &= parity["pass"]

    # VFY-10: run with the network namespace removed when the host allows it.
    net = {"attempted": False, "available": False, "pass": None}
    if shutil.which("unshare"):
        net["attempted"] = True
        cmd = ["unshare", "-rn", sys.executable, "-I", "src/onev_verify.py", "fixtures/vfy01_valid_test_signed.json", "--anchors", "keys/trust_anchors.json", "--json"]
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        if p.returncode in (0, 1, 2, 3) and p.stdout.strip().startswith("{"):
            net["available"] = True
            net["pass"] = json.loads(p.stdout).get("headline") == T_VALID
        else:
            net["stderr"] = p.stderr[:300]
    print("VFY-10 network-namespace run:", net)
    if net["pass"] is not None:
        all_ok &= bool(net["pass"])

    (ROOT / "tests" / "BATTERY_RESULT.json").write_text(json.dumps({
        "all_pass": all_ok, "rows": results, "june_kit_parity": parity, "vfy10_network_namespace": net,
        "python": sys.version.split()[0], "platform": sys.platform,
        "note": "Generated evidence. Not part of MANIFEST.sha256. Contains no absolute paths; compare byte-for-byte across hosts with the same Python minor version."},
        indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("ALL PASS" if all_ok else "BATTERY FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
