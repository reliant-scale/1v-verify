# `1v-receipt/1.0`

Fixed by the CC decision "AM-2 receipt format and verifier V-2 authorization" (2026-10-23).

```json
{
  "format": "1v-receipt/1.0",
  "kid": "<key id, ^[A-Za-z0-9_.-]{1,64}$>",
  "alg": "Ed25519",
  "payload": { "receipt_id": "<non-empty string>", "issued_at": "<string, as asserted>", "...": "issuer fields" },
  "payload_sha256": "<64 lowercase hex: sha256 of the canonical payload bytes>",
  "signature": "<base64 of the 64-byte Ed25519 signature over the canonical payload bytes>"
}
```

Rules, as implemented:

1. Exactly these six top-level keys. A missing key is `MISSING_REQUIRED_FIELD`; an extra key is `UNEXPECTED_FIELD`. Both fail closed.
2. `format` other than `1v-receipt/1.0` → `UNSUPPORTED ARTIFACT` (`UNSUPPORTED_VERSION` for other `1v-receipt/*`, else `UNKNOWN_FORMAT`).
3. `alg` other than `Ed25519` → `UNSUPPORTED ARTIFACT / UNSUPPORTED_ALG`.
4. Unknown `kid` → `RECEIPT NOT VALID / UNKNOWN_KEY_ID`. Never "unsupported".
5. **Signed bytes** = canonical serialization of `payload` only, using the June 2026 conformance-kit function verbatim:
   recursively sorted keys, UTF-8 (`ensure_ascii=false`), separators `,` and `:`, integers within i64, **no floats**,
   no NaN/Infinity, booleans/null/strings/arrays/objects only. Duplicate keys anywhere in the document are rejected at parse (`DUPLICATE_KEY`).
6. The kit function strips `receipt_hash`, `signature` and `kid` before serializing. The verifier therefore refuses any payload that
   contains one of those keys (`RESERVED_FIELD_IN_PAYLOAD`) so a field can never ride in the payload unsigned.
7. `payload_sha256` is informational and is always recomputed. Mismatch → `DIGEST_MISMATCH`.
8. `issued_at` is never checked against any clock. It is displayed as asserted by the issuer.

Not in 1.0: chain/replay contracts, batch inclusion (reserved for `1v-receipt/1.1`), any network lookup.
