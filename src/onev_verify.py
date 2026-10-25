#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reliant Scale Technologies Inc.
"""1V receipt verifier — V-2, artifact family 1v-receipt/1.0.

Standalone, offline, single file. Verifies an Ed25519 signature over the
canonical bytes of a receipt payload against a local trust-anchor file.

Authority: CC decision "AM-2 RECEIPT FORMAT AND VERIFIER V-2 AUTHORIZATION"
(2026-10-23). This program verifies artifact properties only. It does not
establish business truth, independent time, or issuer authority beyond the
status recorded for the key in the trust-anchor file supplied by the operator.

Headlines (exact, fixed by the decision):
  TEST SIGNATURE VALID — NOT AN RST PRODUCTION ATTESTATION   exit 0
  RST PRODUCTION SIGNATURE VALID                             exit 0
  RECEIPT NOT VALID                                          exit 1
  UNSUPPORTED ARTIFACT                                       exit 2
  INCOMPLETE PACKAGE                                         exit 3
  CONTENT INTEGRITY ONLY — NO ISSUER, TIME OR TRUTH ESTABLISHED  exit 4 (content-integrity profile only)
Exit 0 is produced only by the issuer-signature profile.

No network code path exists in this file. Dependencies: Python standard
library and the `cryptography` package (Ed25519 only).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc:  # pragma: no cover - exercised only on a broken install
    sys.stdout.write("INCOMPLETE PACKAGE\nReason codes: DEPENDENCY_MISSING (%s)\n" % exc)
    sys.exit(3)

TOOL_NAME = "1V Receipt Verifier"
TOOL_VERSION = "0.1.3-test"
# Resource bounds (VFY-R2): inputs beyond these are refused with a typed result, never a traceback.
MAX_RECEIPT_BYTES = 1_048_576      # 1 MiB
MAX_ANCHORS_BYTES = 65_536         # 64 KiB
MAX_NESTING_DEPTH = 64             # whole document; payload sits at depth 2
# Production authority (VFY-R1): a trust anchor may carry status PRODUCTION only if its
# (kid, sha256-of-raw-public-key) pair is compiled into this release. An operator-supplied
# anchors file can therefore never create a production trust claim on its own. This set is
# EMPTY until the ROG #1 key-custody ceremony is accepted; a later release pins the pair.
PRODUCTION_AUTHORITY: frozenset[tuple[str, str]] = frozenset()
SUPPORTED_FORMAT = "1v-receipt/1.0"
SUPPORTED_ALG = "Ed25519"
PROFILE_ISSUER_SIGNATURE = "ISSUER_SIGNATURE"
PROFILE_CONTENT_INTEGRITY = "CONTENT_INTEGRITY"
PROFILE_FLAGS = {
    "issuer-signature": PROFILE_ISSUER_SIGNATURE,
    "content-integrity": PROFILE_CONTENT_INTEGRITY,
}
ANCHOR_STATUSES = ("PRODUCTION", "PROVENANCE_PENDING", "TEST_ONLY")
ENVELOPE_KEYS = ("format", "kid", "alg", "payload", "payload_sha256", "signature")
PAYLOAD_REQUIRED = ("receipt_id", "issued_at")
KID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

H_TEST_VALID = "TEST SIGNATURE VALID — NOT AN RST PRODUCTION ATTESTATION"
H_PROD_VALID = "RST PRODUCTION SIGNATURE VALID"
H_CONTENT_ONLY = "CONTENT INTEGRITY ONLY — NO ISSUER, TIME OR TRUTH ESTABLISHED"
H_NOT_VALID = "RECEIPT NOT VALID"
H_UNSUPPORTED = "UNSUPPORTED ARTIFACT"
H_INCOMPLETE = "INCOMPLETE PACKAGE"
EXIT_FOR_HEADLINE = {
    H_TEST_VALID: 0,
    H_PROD_VALID: 0,
    H_NOT_VALID: 1,
    H_UNSUPPORTED: 2,
    H_INCOMPLETE: 3,
    H_CONTENT_ONLY: 4,
}

DISCLAIMER = (
    "This verdict verifies receipt artifact integrity and signature against the\n"
    "trust anchors supplied to this program. It is not an audit, certification,\n"
    "compliance determination, legal opinion, tax opinion, financial opinion, or\n"
    "statement that the underlying business state was correct. Time shown is as\n"
    "asserted by the issuer."
)

# ---------------------------------------------------------------------------
# Canonicalization — copied VERBATIM from the June 2026 1V Attestation
# Conformance Kit (`kit/canonical_receipt.py`, Downloads/1V_ATTESTATION_CONFORMANCE_KIT.zip,
# 2026-06-11). Do not edit. The verifier refuses payloads that carry any of
# EXCLUDE_FIELDS so that the strip step can never hide an unsigned field.
# ---------------------------------------------------------------------------
EXCLUDE_FIELDS = ("receipt_hash", "signature", "kid")
_I64_MIN = -(2 ** 63); _I64_MAX = (2 ** 63) - 1


class NonCanonicalNumber(ValueError):
    """A value the i64 kernel can't represent (float / out-of-range int)."""


def _assert_kernel_safe(value, path="receipt"):
    if isinstance(value, bool): return
    if isinstance(value, float):
        raise NonCanonicalNumber(f"float at {path}: {value!r} — kernel is i64-only; stringify or scale to int.")
    if isinstance(value, int):
        if not (_I64_MIN <= value <= _I64_MAX):
            raise NonCanonicalNumber(f"int out of i64 range at {path}: {value!r}")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise NonCanonicalNumber(f"non-string key at {path}: {k!r}")
            _assert_kernel_safe(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value): _assert_kernel_safe(v, f"{path}[{i}]")
        return
    if value is None or isinstance(value, str): return
    raise NonCanonicalNumber(f"unsupported type at {path}: {type(value).__name__}")


def canonical_receipt_bytes(receipt: dict) -> bytes:
    if not isinstance(receipt, dict): raise TypeError("receipt must be a dict")
    stripped = {k: v for k, v in receipt.items() if k not in EXCLUDE_FIELDS}
    _assert_kernel_safe(stripped)
    return json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
# ----------------------------- end verbatim copy -----------------------------


class DuplicateKey(ValueError):
    pass


def _reject_duplicates(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        if k in seen:
            raise DuplicateKey(k)
        seen.add(k)
        out[k] = v
    return out


def _reject_float_constants(name):
    # NaN / Infinity are not JSON; fail closed.
    raise NonCanonicalNumber(f"non-finite number {name}")


def strict_json_loads(data: bytes) -> Any:
    text = data.decode("utf-8")  # UnicodeDecodeError propagates to caller
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_float_constants,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def max_depth(obj: Any) -> int:
    """Iterative nesting depth of a parsed JSON value (no recursion)."""
    deepest = 0
    stack = [(obj, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > deepest:
            deepest = depth
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return deepest


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------
def new_result(profile: str) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "profile": profile,
        "artifact_format": "UNKNOWN",
        "schema_valid": "NOT_CHECKED",
        "digest_match": "NOT_CHECKED",
        "signature_valid": "NOT_CHECKED",
        "issuer_trust": "NOT_CHECKED",
        "chain_contract_valid": "NOT_CHECKED",
        "independent_time_valid": "NOT_CHECKED",
        "underlying_claim_verified": "NOT_CHECKED",
        "key_id": None,
        "key_status": None,
        "issued_at_asserted": None,
        "receipt_id": None,
        "receipt_sha256": None,
        "trust_anchors_sha256": None,
        "network_used": "NO",
        "test_only": True,
        "reason_codes": [],
        "headline": None,
        "exit_code": None,
    }


def finish(result: dict[str, Any], headline: str, *reasons: str) -> dict[str, Any]:
    for r in reasons:
        if r and r not in result["reason_codes"]:
            result["reason_codes"].append(r)
    result["headline"] = headline
    result["exit_code"] = EXIT_FOR_HEADLINE[headline]
    result["test_only"] = result["issuer_trust"] != "PRODUCTION"
    return result


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------
def load_trust_anchors(path: str, expected_sha256: str | None) -> tuple[dict[str, dict], str, str | None]:
    """Return (anchors_by_kid, file_sha256, error_reason)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_ANCHORS_BYTES + 1)
    except OSError:
        return {}, "", "TRUST_ANCHORS_UNREADABLE"
    if len(raw) > MAX_ANCHORS_BYTES:
        return {}, "", "TRUST_ANCHORS_TOO_LARGE"
    digest = sha256_hex(raw)
    if expected_sha256 is not None and expected_sha256.lower() != digest:
        return {}, digest, "TRUST_ANCHORS_HASH_MISMATCH"
    try:
        doc = strict_json_loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return {}, digest, "TRUST_ANCHORS_INVALID"
    if not isinstance(doc, list) or not doc or max_depth(doc) > 3:
        return {}, digest, "TRUST_ANCHORS_INVALID"
    anchors: dict[str, dict] = {}
    for entry in doc:
        if not isinstance(entry, dict):
            return {}, digest, "TRUST_ANCHORS_INVALID"
        required = ("kid", "alg", "public_key_b64_raw", "sha256", "status", "revoked")
        if set(entry.keys()) != set(required):
            return {}, digest, "TRUST_ANCHORS_INVALID"
        kid = entry["kid"]
        if not isinstance(kid, str) or not KID_RE.match(kid) or kid in anchors:
            return {}, digest, "TRUST_ANCHORS_INVALID"
        if entry["alg"] != SUPPORTED_ALG:
            return {}, digest, "TRUST_ANCHORS_INVALID"
        if entry["status"] not in ANCHOR_STATUSES or not isinstance(entry["revoked"], bool):
            return {}, digest, "TRUST_ANCHORS_INVALID"
        try:
            pub = base64.b64decode(entry["public_key_b64_raw"], validate=True)
        except (binascii.Error, TypeError, ValueError):
            return {}, digest, "TRUST_ANCHORS_INVALID"
        if len(pub) != 32:
            return {}, digest, "TRUST_ANCHORS_INVALID"
        if not isinstance(entry["sha256"], str) or sha256_hex(pub) != entry["sha256"].lower():
            # fingerprint mismatch = tampered or corrupted anchor file
            return {}, digest, "TRUST_ANCHORS_INVALID"
        try:
            Ed25519PublicKey.from_public_bytes(pub)
        except ValueError:
            return {}, digest, "TRUST_ANCHORS_INVALID"
        if entry["status"] == "PRODUCTION" and (kid, entry["sha256"].lower()) not in PRODUCTION_AUTHORITY:
            # VFY-R1: production status is a release property, not a file property. Fail closed.
            return {}, digest, "TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION"
        anchors[kid] = {"public_key": pub, "status": entry["status"], "revoked": entry["revoked"]}
    return anchors, digest, None


# ---------------------------------------------------------------------------
# Artifact family classification (fail closed)
# ---------------------------------------------------------------------------
def classify_family(doc: Any) -> tuple[str, str | None]:
    """Return (artifact_format_label, unsupported_reason_or_None)."""
    if not isinstance(doc, dict):
        return "NOT_OBJECT", "NOT_OBJECT"
    fmt = doc.get("format")
    if isinstance(fmt, str):
        if fmt == SUPPORTED_FORMAT:
            return SUPPORTED_FORMAT, None
        if fmt.startswith("1v-receipt/"):
            return fmt, "UNSUPPORTED_VERSION"
        return fmt, "UNKNOWN_FORMAT"
    keys = set(doc.keys())
    # Live public Atlas accountability receipt: unsigned by design.
    if {"idempotency_key", "receipt_id", "decision"} <= keys and "signature" not in keys:
        return "atlas-accountability-receipt (unsigned)", "UNSIGNED_FAMILY"
    # 1Ve internal treatment / intel receipts: not a public verification family.
    if ({"run_id", "mission", "receipt"} <= keys) or ("treatment_id" in keys) or ("treatments" in keys):
        return "1ve-internal-receipt", "INTERNAL_FAMILY"
    return "UNKNOWN", "UNKNOWN_FORMAT"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def verify_bytes(raw: bytes, anchors: dict[str, dict], profile: str, result: dict[str, Any]) -> dict[str, Any]:
    if len(raw) > MAX_RECEIPT_BYTES:
        result["artifact_format"] = "UNKNOWN"
        return finish(result, H_UNSUPPORTED, "INPUT_TOO_LARGE")
    result["receipt_sha256"] = sha256_hex(raw)
    try:
        doc = strict_json_loads(raw)
    except RecursionError:
        result["artifact_format"] = "UNKNOWN"
        result["schema_valid"] = "FAIL"
        return finish(result, H_NOT_VALID, "NESTING_TOO_DEEP")
    except DuplicateKey:
        result["artifact_format"] = "UNKNOWN"
        result["schema_valid"] = "FAIL"
        return finish(result, H_NOT_VALID, "DUPLICATE_KEY")
    except NonCanonicalNumber:
        result["artifact_format"] = "UNKNOWN"
        result["schema_valid"] = "FAIL"
        return finish(result, H_NOT_VALID, "NON_CANONICAL_NUMBER")
    except (ValueError, UnicodeDecodeError):
        result["artifact_format"] = "NOT_JSON"
        return finish(result, H_UNSUPPORTED, "NOT_JSON")

    if max_depth(doc) > MAX_NESTING_DEPTH:
        result["artifact_format"] = "UNKNOWN"
        result["schema_valid"] = "FAIL"
        return finish(result, H_NOT_VALID, "NESTING_TOO_DEEP")

    label, unsupported = classify_family(doc)
    result["artifact_format"] = label
    if unsupported:
        result["schema_valid"] = "UNSUPPORTED"
        return finish(result, H_UNSUPPORTED, unsupported)

    # --- schema (strict: exactly the six envelope keys) ---
    reasons: list[str] = []
    keys = set(doc.keys())
    missing = [k for k in ENVELOPE_KEYS if k not in keys]
    extra = sorted(keys - set(ENVELOPE_KEYS))
    if missing:
        reasons.append("MISSING_REQUIRED_FIELD")
    if extra:
        reasons.append("UNEXPECTED_FIELD")
    if reasons:
        result["schema_valid"] = "FAIL"
        return finish(result, H_NOT_VALID, *reasons)

    alg = doc["alg"]
    if alg != SUPPORTED_ALG:
        result["schema_valid"] = "UNSUPPORTED"
        return finish(result, H_UNSUPPORTED, "UNSUPPORTED_ALG")

    kid = doc["kid"]
    payload = doc["payload"]
    payload_sha256 = doc["payload_sha256"]
    signature_b64 = doc["signature"]

    if not isinstance(kid, str) or not KID_RE.match(kid):
        reasons.append("MALFORMED_KEY_ID")
    if not isinstance(payload, dict):
        reasons.append("PAYLOAD_NOT_OBJECT")
    else:
        for req in PAYLOAD_REQUIRED:
            v = payload.get(req)
            if not isinstance(v, str) or not v:
                reasons.append("MISSING_REQUIRED_FIELD")
                break
        if any(k in payload for k in EXCLUDE_FIELDS):
            reasons.append("RESERVED_FIELD_IN_PAYLOAD")
    if not isinstance(payload_sha256, str) or not HEX64_RE.match(payload_sha256):
        reasons.append("MALFORMED_DIGEST")
    sig: bytes | None = None
    if isinstance(signature_b64, str):
        try:
            sig = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            sig = None
    if sig is None or len(sig) != 64:
        reasons.append("MALFORMED_SIGNATURE")
    if reasons:
        result["schema_valid"] = "FAIL"
        result["key_id"] = kid if isinstance(kid, str) else None
        return finish(result, H_NOT_VALID, *reasons)
    result["schema_valid"] = "PASS"
    result["key_id"] = kid
    result["receipt_id"] = payload["receipt_id"]
    result["issued_at_asserted"] = payload["issued_at"]

    # --- canonical bytes + digest ---
    try:
        canon = canonical_receipt_bytes(payload)
    except NonCanonicalNumber:
        result["digest_match"] = "FAIL"
        return finish(result, H_NOT_VALID, "NON_CANONICAL_NUMBER")
    except RecursionError:  # unreachable after the depth bound; kept as a typed backstop
        result["digest_match"] = "FAIL"
        return finish(result, H_NOT_VALID, "NESTING_TOO_DEEP")
    if sha256_hex(canon) != payload_sha256:
        result["digest_match"] = "FAIL"
        return finish(result, H_NOT_VALID, "DIGEST_MISMATCH")
    result["digest_match"] = "PASS"

    if profile == PROFILE_CONTENT_INTEGRITY:
        # Explicit operator choice only. Signature and issuer deliberately NOT checked.
        result["signature_valid"] = "NOT_CHECKED"
        result["issuer_trust"] = "NOT_CHECKED"
        return finish(result, H_CONTENT_ONLY, "CONTENT_INTEGRITY_ONLY")

    # --- key lookup (fail closed) ---
    anchor = anchors.get(kid)
    if anchor is None:
        result["signature_valid"] = "FAIL"
        result["issuer_trust"] = "UNKNOWN"
        return finish(result, H_NOT_VALID, "UNKNOWN_KEY_ID")
    result["key_status"] = anchor["status"]
    if anchor["revoked"]:
        result["signature_valid"] = "FAIL"
        result["issuer_trust"] = "UNKNOWN"
        return finish(result, H_NOT_VALID, "KEY_REVOKED")

    # --- signature ---
    try:
        Ed25519PublicKey.from_public_bytes(anchor["public_key"]).verify(sig, canon)
        result["signature_valid"] = "PASS"
    except InvalidSignature:
        result["signature_valid"] = "FAIL"
        result["issuer_trust"] = "UNKNOWN"
        return finish(result, H_NOT_VALID, "BAD_SIGNATURE")

    # --- issuer trust: PRODUCTION only for a PRODUCTION-status anchor ---
    if anchor["status"] == "PRODUCTION":
        result["issuer_trust"] = "PRODUCTION"
        return finish(result, H_PROD_VALID)
    result["issuer_trust"] = "TEST_ONLY"
    return finish(result, H_TEST_VALID, "ISSUER_TRUST_TEST_ONLY")


# ---------------------------------------------------------------------------
# Rendering (deterministic: no timestamps, no absolute paths)
# ---------------------------------------------------------------------------
def render_text(result: dict[str, Any]) -> str:
    def row(label: str, value: Any) -> str:
        return f"{label:<22}{value}"

    lines = [
        f"{TOOL_NAME} {TOOL_VERSION} ({SUPPORTED_FORMAT})",
        row("Trust anchors sha256:", result["trust_anchors_sha256"] or "NOT_LOADED"),
        row("Receipt sha256:", result["receipt_sha256"] or "NOT_READ"),
        row("Profile:", result["profile"]),
        "",
        row("Artifact format:", result["artifact_format"]),
        row("Schema:", result["schema_valid"]),
        row("Digest match:", result["digest_match"]),
        row("Signature:", result["signature_valid"]),
    ]
    trust = result["issuer_trust"]
    if result["key_id"]:
        trust = f"{trust} (kid {result['key_id']}" + (f", anchor status {result['key_status']})" if result["key_status"] else ")")
    lines.append(row("Issuer trust:", trust))
    lines.append(row("Chain contract:", result["chain_contract_valid"]))
    t = result["independent_time_valid"]
    if result["issued_at_asserted"]:
        t = f"{t} (issued_at as asserted by the issuer: {result['issued_at_asserted']})"
    lines.append(row("Independent time:", t))
    lines.append(row("Underlying claim:", result["underlying_claim_verified"]))
    lines.append(row("Network used:", result["network_used"]))
    lines.append(row("Test only:", "YES" if result["test_only"] else "NO"))
    lines.append(row("Reason codes:", ", ".join(result["reason_codes"]) if result["reason_codes"] else "-"))
    lines.append("")
    lines.append("Overall:")
    lines.append(result["headline"])
    if result["headline"] == H_CONTENT_ONLY:
        lines.append("Self-consistency only; no issuer, time or truth established.")
        lines.append("WARNING: content-integrity profile. Signature and issuer were NOT checked. Exit code 4, never 0.")
    lines.append("")
    lines.append(DISCLAIMER)
    return "\n".join(lines) + "\n"


def render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="onev_verify",
        description="Verify a 1v-receipt/1.0 artifact offline against local trust anchors.",
    )
    parser.add_argument("receipt", help="path to the receipt JSON file")
    parser.add_argument("--anchors", default="keys/trust_anchors.json", help="trust-anchor file (default: keys/trust_anchors.json)")
    parser.add_argument("--anchors-sha256", default=None, help="refuse to run unless the anchors file has this sha256")
    parser.add_argument("--profile", choices=sorted(PROFILE_FLAGS), default="issuer-signature")
    parser.add_argument("--json", action="store_true", help="emit the result object as JSON instead of text")
    args = parser.parse_args(argv)

    profile = PROFILE_FLAGS[args.profile]
    result = new_result(profile)

    try:
        anchors, anchors_digest, anchor_error = load_trust_anchors(args.anchors, args.anchors_sha256)
        result["trust_anchors_sha256"] = anchors_digest or None
        if anchor_error:
            finish(result, H_INCOMPLETE, anchor_error)
        else:
            try:
                with open(args.receipt, "rb") as fh:
                    raw = fh.read(MAX_RECEIPT_BYTES + 1)
            except OSError:
                finish(result, H_INCOMPLETE, "RECEIPT_UNREADABLE")
            else:
                verify_bytes(raw, anchors, profile, result)
    except (RecursionError, MemoryError, Exception):  # last-resort typed refusal; never a traceback
        result["reason_codes"] = [r for r in result["reason_codes"]]
        finish(result, H_INCOMPLETE, "INTERNAL_ERROR")

    sys.stdout.write(render_json(result) if args.json else render_text(result))
    sys.stdout.flush()
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
