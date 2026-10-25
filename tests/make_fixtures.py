#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the TEST key, trust anchors and the VFY fixture set for 1v-verify.

Run from the repository root:  python3 -I tests/make_fixtures.py
Everything written here is synthetic and labelled TEST. The private key it
creates is a TEST key and lives only under tests/test_keys/. It has no
relationship to any RST production signer.

Deterministic test key: derived from a fixed 32-byte seed so fixtures are
reproducible across machines (Ed25519 private keys are 32-byte seeds).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from onev_verify import canonical_receipt_bytes  # noqa: E402  (verbatim June kit function)

FIX = ROOT / "fixtures"
KEYS = ROOT / "keys"
TKEYS = ROOT / "tests" / "test_keys"
KIT_VECTORS = ROOT / "tests" / "june_kit_vectors.json"

TEST_KID = "1v_test_001"
KIT_KID = "1v_kit_test_20260611"
PROD_KID = "1v_rog_prod_001"
PROD_PUB_B64 = "KHlriZV+Pjo26VB9ry+sMUKfHImMoudrRypVc1LrguY="  # public half only; copied from the HQ signing-key record (read-only)

# Fixed seed => reproducible TEST key. Not secret. Not production.
TEST_SEED = hashlib.sha256(b"1v-verify TEST KEY 1v_test_001 - NOT PRODUCTION - 2026-10-23").digest()
WRONG_SEED = hashlib.sha256(b"1v-verify WRONG KEY for VFY-4 - NOT PRODUCTION").digest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_json(path: Path, obj, pretty=False) -> None:
    text = json.dumps(obj, indent=2 if pretty else None, separators=None if pretty else (",", ":"), ensure_ascii=False, sort_keys=False)
    path.write_text(text + ("\n" if pretty else ""), encoding="utf-8")


def envelope(priv: Ed25519PrivateKey, kid: str, payload: dict, alg: str = "Ed25519", fmt: str = "1v-receipt/1.0") -> dict:
    canon = canonical_receipt_bytes(payload)
    return {
        "format": fmt,
        "kid": kid,
        "alg": alg,
        "payload": payload,
        "payload_sha256": sha256_hex(canon),
        "signature": base64.b64encode(priv.sign(canon)).decode("ascii"),
    }


def main() -> int:
    FIX.mkdir(exist_ok=True)
    KEYS.mkdir(exist_ok=True)
    TKEYS.mkdir(parents=True, exist_ok=True)

    test_priv = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    wrong_priv = Ed25519PrivateKey.from_private_bytes(WRONG_SEED)
    test_pub = test_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # TEST private key, labelled, tests/ only.
    pem = test_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (TKEYS / f"{TEST_KID}.TEST_ONLY.private.pem").write_bytes(pem)
    (TKEYS / "README.md").write_text(
        "# TEST keys\n\nThe private key in this directory is a TEST key derived from a fixed, public seed.\n"
        "It is NOT a production key, proves nothing about RST, and must never be referenced by a\n"
        "PRODUCTION trust anchor. It exists so the fixture set is reproducible.\n", encoding="utf-8")

    # June kit public key (from vectors.json pubkey_hex).
    kit = json.loads(KIT_VECTORS.read_text(encoding="utf-8"))
    kit_pub = bytes.fromhex(kit["vectors"][0]["pubkey_hex"])
    prod_pub = base64.b64decode(PROD_PUB_B64)

    anchors = [
        {"kid": PROD_KID, "alg": "Ed25519", "public_key_b64_raw": PROD_PUB_B64,
         "sha256": sha256_hex(prod_pub), "status": "PROVENANCE_PENDING", "revoked": False},
        {"kid": TEST_KID, "alg": "Ed25519", "public_key_b64_raw": base64.b64encode(test_pub).decode("ascii"),
         "sha256": sha256_hex(test_pub), "status": "TEST_ONLY", "revoked": False},
        {"kid": KIT_KID, "alg": "Ed25519", "public_key_b64_raw": base64.b64encode(kit_pub).decode("ascii"),
         "sha256": sha256_hex(kit_pub), "status": "TEST_ONLY", "revoked": False},
    ]
    write_json(KEYS / "trust_anchors.json", anchors, pretty=True)

    # Tampered anchors for VFY-16: flip one byte of the TEST public key, leave sha256 stale.
    tampered = json.loads(json.dumps(anchors))
    bad = bytearray(test_pub); bad[0] ^= 0x01
    tampered[1]["public_key_b64_raw"] = base64.b64encode(bytes(bad)).decode("ascii")
    write_json(FIX / "anchors_tampered_vfy16.json", tampered, pretty=True)
    # Anchors that would promote the prod key without a ceremony (operator-replaceable file; hash pin guards it).
    promoted = json.loads(json.dumps(anchors)); promoted[1]["status"] = "PRODUCTION"  # TEST key promoted in the harness only; the prod kid is never promoted by any fixture
    write_json(FIX / "anchors_prod_promoted_TEST_HARNESS_ONLY.json", promoted, pretty=True)

    payload = {
        "receipt_id": "rcp_test_0000000000000001",
        "issued_at": "2026-10-23T18:00:00Z",
        "issuer": "RST 1V — TEST FIXTURE",
        "subject": {"kind": "fixture", "label": "VFY-1 valid test receipt", "count": 3, "nested": {"z": 1, "a": "α — unicode ok"}},
        "amount_cents": 7900,
        "claims": ["This is a synthetic test receipt.", "It establishes no business fact."],
    }

    # VFY-1 valid (TEST key)
    valid = envelope(test_priv, TEST_KID, payload)
    write_json(FIX / "vfy01_valid_test_signed.json", valid)
    # VFY-9 whitespace-only variation of VFY-1
    write_json(FIX / "vfy09_whitespace_variation.json", valid, pretty=True)
    # VFY-1 (June kit cross-implementation): wrap kit vectors r1/r2 (signed June 11 with the kit key)
    for i, vec in enumerate(kit["vectors"]):
        obj = json.loads(vec["input"])
        env = {"format": "1v-receipt/1.0", "kid": KIT_KID, "alg": "Ed25519", "payload": obj["receipt"],
               "payload_sha256": sha256_hex(canonical_receipt_bytes(obj["receipt"])), "signature": obj["signature"]}
        if vec["name"] == "wrong pubkey -> reject":
            env["kid"] = TEST_KID  # same signature, claimed under a different anchor
        # kit receipts carry decision_id/issued_at/title; add receipt_id when absent so the schema passes
        if "receipt_id" not in env["payload"]:
            # cannot add fields without breaking the June signature; keep as-is -> expected MISSING_REQUIRED_FIELD
            pass
        write_json(FIX / f"vfy01k_june_vector_{i+1}.json", env)

    # VFY-2 one-byte payload mutation (digest left as signed => DIGEST_MISMATCH)
    m = json.loads(json.dumps(valid)); m["payload"]["amount_cents"] = 7901
    write_json(FIX / "vfy02_payload_mutated_digest_stale.json", m)
    # VFY-2b payload mutated AND digest recomputed => BAD_SIGNATURE
    m2 = json.loads(json.dumps(m)); m2["payload_sha256"] = sha256_hex(canonical_receipt_bytes(m2["payload"]))
    write_json(FIX / "vfy02b_payload_mutated_digest_recomputed.json", m2)
    # VFY-3 signature mutation
    s = json.loads(json.dumps(valid)); sig = bytearray(base64.b64decode(s["signature"])); sig[5] ^= 0x10
    s["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    write_json(FIX / "vfy03_signature_mutated.json", s)
    # VFY-4 wrong key: signed by WRONG key, claims TEST kid
    w = envelope(wrong_priv, TEST_KID, payload)
    write_json(FIX / "vfy04_wrong_key_claims_test_kid.json", w)
    # VFY-5 unknown kid (valid signature by TEST key but kid not in anchors)
    u = envelope(test_priv, "1v_unknown_999", payload)
    write_json(FIX / "vfy05_unknown_kid.json", u)
    # VFY-6 unsupported schema version / unknown format / unsupported alg
    write_json(FIX / "vfy06a_unsupported_version.json", envelope(test_priv, TEST_KID, payload, fmt="1v-receipt/0.9"))
    write_json(FIX / "vfy06b_unknown_format.json", envelope(test_priv, TEST_KID, payload, fmt="acme-receipt/1"))
    write_json(FIX / "vfy06c_unsupported_alg.json", envelope(test_priv, TEST_KID, payload, alg="RSA-PSS"))
    # VFY-7 missing required fields
    p7 = dict(payload); del p7["issued_at"]
    write_json(FIX / "vfy07a_missing_issued_at.json", envelope(test_priv, TEST_KID, p7))
    m7 = json.loads(json.dumps(valid)); del m7["signature"]
    write_json(FIX / "vfy07b_missing_signature.json", m7)
    # VFY-7c extra top-level field (fail closed)
    x7 = json.loads(json.dumps(valid)); x7["note"] = "smuggled"
    write_json(FIX / "vfy07c_unexpected_top_level_field.json", x7)
    # VFY-7d reserved field inside payload (would be silently stripped by the kit canonicalizer)
    p7d = dict(payload); p7d["signature"] = "smuggled"
    env7d = envelope(test_priv, TEST_KID, p7d)
    write_json(FIX / "vfy07d_reserved_field_in_payload.json", env7d)
    # VFY-8 duplicate key (raw text)
    raw = json.dumps(valid, separators=(",", ":"), ensure_ascii=False)
    dup = raw.replace('"receipt_id":"rcp_test_0000000000000001",', '"receipt_id":"rcp_test_0000000000000001","receipt_id":"rcp_test_0000000000000002",', 1)
    assert dup != raw
    (FIX / "vfy08_duplicate_key.json").write_text(dup, encoding="utf-8")
    # VFY-13 live-shaped unsigned Atlas accountability receipt (synthetic values)
    write_json(FIX / "vfy13_atlas_unsigned_receipt.json", {
        "idempotency_key": "idem_synthetic_001", "receipt_id": "R-SYNTH01", "decision": "DENY",
        "reasons": ["scope_denied"], "evidence_ref": "ev://synthetic", "billed": True,
        "workspace_id": "ws_synthetic", "principal": "agent/synthetic", "decided_at": "2026-10-23T18:00:00Z"}, pretty=True)
    # VFY-14 1Ve internal treatment receipt shape (synthetic)
    write_json(FIX / "vfy14_1ve_internal_receipt.json", {
        "run_id": "RUN-SYNTH", "mission": "SYNTHETIC", "lane": "INTEL", "receipt": {"id": "x"}, "provider": {}, "outcome": "SYNTH"}, pretty=True)
    # VFY-15 float in payload (raw text; signature cannot be meaningful)
    f15 = raw.replace('"amount_cents":7900', '"amount_cents":79.00', 1)
    assert f15 != raw
    (FIX / "vfy15_float_in_payload.json").write_text(f15, encoding="utf-8")
    # VFY-15b NaN constant
    f15b = raw.replace('"amount_cents":7900', '"amount_cents":NaN', 1)
    (FIX / "vfy15b_nan_in_payload.json").write_text(f15b, encoding="utf-8")
    # misc: not JSON
    (FIX / "misc_not_json.txt").write_text("this is not a receipt\n", encoding="utf-8")
    # misc: JSON array
    (FIX / "misc_json_array.json").write_text("[1,2,3]\n", encoding="utf-8")
    # VFY-17 uses vfy03 (bad signature) with --profile content-integrity
    # misc: revoked key — anchors variant with TEST key revoked
    revoked = json.loads(json.dumps(anchors)); revoked[1]["revoked"] = True
    write_json(FIX / "anchors_test_key_revoked.json", revoked, pretty=True)

    # VFY-R1 adversarial anchors: (a) prod kid prematurely PRODUCTION (correct fp, no ceremony); (b) unrelated TEST key PRODUCTION
    premature = json.loads(json.dumps(anchors)); premature[0]["status"] = "PRODUCTION"
    write_json(FIX / "anchors_r1_prod_kid_premature.json", premature, pretty=True)
    # (anchors_prod_promoted_TEST_HARNESS_ONLY.json above covers (b))
    # VFY-R2 adversarial receipts
    deep = '{"format":"1v-receipt/1.0","kid":"1v_test_001","alg":"Ed25519","payload":' + '{"receipt_id":"x","issued_at":"y","n":' * 1100 + '1' + '}' * 1100 + ',"payload_sha256":"' + '0' * 64 + '","signature":"' + base64.b64encode(b'\x00' * 64).decode() + '"}'
    (FIX / "r2a_nested_1100.json").write_text(deep, encoding="utf-8")
    def nested_payload(depth: int) -> dict:
        inner: dict = {"leaf": 1}
        for _ in range(depth):
            inner = {"n": inner}
        return {"receipt_id": "rcp_test_nested", "issued_at": "2026-10-23T18:00:00Z", "tree": inner}
    write_json(FIX / "r2b_nested_depth_80_signed.json", envelope(test_priv, TEST_KID, nested_payload(80)))
    write_json(FIX / "r2c_nested_depth_30_signed.json", envelope(test_priv, TEST_KID, nested_payload(30)))
    big = json.loads(json.dumps(valid)); big["payload"]["pad"] = "A" * (1_048_576 + 100)
    (FIX / "r2d_oversized.json").write_text(json.dumps(big, separators=(",", ":")), encoding="utf-8")
    deep_anchors = '[' * 2000 + ']' * 2000
    (FIX / "anchors_r2_deep.json").write_text(deep_anchors, encoding="utf-8")

    manifest = {p.name: sha256_hex(p.read_bytes()) for p in sorted(FIX.iterdir()) if p.is_file() and p.name != "FIXTURES.sha256.json"}
    manifest["keys/trust_anchors.json"] = sha256_hex((KEYS / "trust_anchors.json").read_bytes())
    write_json(FIX / "FIXTURES.sha256.json", manifest, pretty=True)
    print("fixtures:", len(manifest) - 1, "| trust_anchors.json sha256:", manifest["keys/trust_anchors.json"])
    print("TEST pubkey sha256:", sha256_hex(test_pub))
    return 0


if __name__ == "__main__":
    sys.exit(main())
