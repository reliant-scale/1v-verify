# Changelog

## 0.1.3-test — 2026-10-23 (source candidate, not released) — cure for Codex package review VFY-R8

- **R8:** `requirements.txt` pinned only the CPython 3.12 `cffi` wheel while claiming 3.11+. Now pins the cp311, cp312 and cp313
  manylinux x86_64 wheel hashes, and the supported range is stated exactly as what was installed from hashes and battery-tested:
  CPython 3.11, 3.12, 3.13 on Linux x86_64, glibc 2.34+. No other version is claimed.

## 0.1.2-test — 2026-10-23 (source candidate, not released) — cures for Codex re-review VFY-R5..R7

- **R5:** README example and SECURITY version strings updated; the "does not" section and headline table now state the
  two-condition production rule (compiled-in pair **and** anchor status) everywhere.
- **R6:** `cryptography` repinned 41.0.7 → **50.0.2** (cffi 2.1.1, pycparser 3.12), all hash-pinned; the earlier wheel bundled an
  OpenSSL in the GHSA-537c-gmf6-5ccf affected range. Platform scope narrowed accordingly: CPython 3.11+, glibc 2.34+.
  Ed25519 API unchanged; full battery rerun on the new wheel in a clean venv.
- **R7:** battery runs every command with paths relative to the repository root and records only relative arguments;
  `tests/BATTERY_RESULT.json` is declared generated evidence outside `MANIFEST.sha256` (gitignored, excluded from the tarball)
  and is now byte-comparable across extraction roots on the same Python minor version.

## 0.1.1-test — 2026-10-23 (source candidate, not released) — cures for Codex review VFY-R1..R4

- **R1 (BLOCKER) cured:** `PRODUCTION` anchor status is honoured only for a `(kid, fingerprint)` pair compiled into the
  release (`PRODUCTION_AUTHORITY`, empty in this candidate). Any operator-supplied `PRODUCTION` entry refuses the whole
  anchors file (`TRUST_ANCHORS_UNAUTHORIZED_PRODUCTION`). Battery VFY-R1a/R1b + in-process unit check that the production
  headline is reachable only when the pair is pinned, and not for a different kid.
- **R2 (MAJOR) cured:** 1 MiB receipt bound, 64 KiB anchors bound, 64-level nesting bound (iterative depth check),
  `RecursionError`/`MemoryError`/any exception caught into typed results; battery asserts no traceback on any row.
  VFY-R2a (1,100 levels), R2b (80 levels, validly signed), R2c (30 levels passes), R2d (oversized), R2e (deep anchors).
- **R3 (DECISION) resolved:** content-integrity profile exits **4**, never 0; warning line printed; battery asserts
  exit 0 ⇔ a green headline.
- **R4 (RELEASE GATE):** candidate declared Linux x86_64 only; hash-pinned install proven in a clean venv on this machine;
  second-machine run still owed.
- Fixture manifest no longer includes itself; regeneration is byte-identical across runs.

## 0.1.0-test — 2026-10-23 (source candidate, not released)

- First implementation of the `1v-receipt/1.0` verifier per the CC AM-2 decision of 2026-10-23.
- Profiles: `issuer-signature` (default) and explicit `content-integrity`.
- Trust anchors shipped with `1v_rog_prod_001` as `PROVENANCE_PENDING`; no `PRODUCTION` anchor.
- Acceptance battery VFY-1..VFY-17 plus June-kit parity and a network-namespace run; VFY-18 tree scan.
- Spec amendment recorded for review: a sixth fixed headline for the content-integrity profile
  (`CONTENT INTEGRITY ONLY — NO ISSUER, TIME OR TRUTH ESTABLISHED`), because the profile needs a headline that is never green.
