# Result contract (`--json`)

| Field | Values |
|---|---|
| `profile` | `ISSUER_SIGNATURE` · `CONTENT_INTEGRITY` |
| `artifact_format` | the recognised format label, or `UNKNOWN`, `NOT_JSON`, `NOT_OBJECT` |
| `schema_valid` | `PASS` · `FAIL` · `UNSUPPORTED` · `NOT_CHECKED` |
| `digest_match` | `PASS` · `FAIL` · `NOT_CHECKED` |
| `signature_valid` | `PASS` · `FAIL` · `NOT_CHECKED` |
| `issuer_trust` | `PRODUCTION` · `TEST_ONLY` · `UNKNOWN` · `NOT_CHECKED` |
| `chain_contract_valid` | always `NOT_CHECKED` in V-2 |
| `independent_time_valid` | always `NOT_CHECKED` in V-2 |
| `underlying_claim_verified` | always `NOT_CHECKED` |
| `key_id`, `key_status` | the receipt's `kid` and the anchor status found for it, or null |
| `receipt_id`, `issued_at_asserted` | copied from the payload once the schema passes |
| `receipt_sha256`, `trust_anchors_sha256` | sha256 of the raw input files |
| `network_used` | always `NO` |
| `test_only` | `true` unless `issuer_trust` is `PRODUCTION` |
| `reason_codes` | ordered list; see below |
| `headline`, `exit_code` | one of the six fixed headlines; 0 / 1 / 2 / 3 / 4. Exit 0 only from the issuer-signature profile |

Reason codes: `ISSUER_TRUST_TEST_ONLY`, `CONTENT_INTEGRITY_ONLY`, `DIGEST_MISMATCH`, `BAD_SIGNATURE`, `UNKNOWN_KEY_ID`,
`KEY_REVOKED`, `MISSING_REQUIRED_FIELD`, `UNEXPECTED_FIELD`, `RESERVED_FIELD_IN_PAYLOAD`, `MALFORMED_KEY_ID`,
`MALFORMED_DIGEST`, `MALFORMED_SIGNATURE`, `PAYLOAD_NOT_OBJECT`, `DUPLICATE_KEY`, `NON_CANONICAL_NUMBER`,
`UNSUPPORTED_VERSION`, `UNKNOWN_FORMAT`, `UNSUPPORTED_ALG`, `UNSIGNED_FAMILY`, `INTERNAL_FAMILY`, `NOT_JSON`,
`NOT_OBJECT`, `TRUST_ANCHORS_INVALID`, `TRUST_ANCHORS_HASH_MISMATCH`, `TRUST_ANCHORS_UNREADABLE`, `TRUST_ANCHORS_TOO_LARGE`,
`TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION`, `RECEIPT_UNREADABLE`, `INPUT_TOO_LARGE`, `NESTING_TOO_DEEP`, `INTERNAL_ERROR`.

Output is deterministic: no timestamps, no absolute paths, sorted JSON keys. Two runs on two machines with the same
inputs must produce identical bytes (VFY-11).
