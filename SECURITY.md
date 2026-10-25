# Security Policy

## Supported versions

`0.1.3-test` is a source candidate under independent review (Linux x86_64; CPython 3.11, 3.12, 3.13). No binary has been released.

## Reporting

Send reports to `admin@reliantscale.com`. Do not include private keys, live customer data,
or sensitive third-party data in an initial report.

## Trust boundary

- This repository never contains private signing material. The only private key present is
  the labelled TEST key under `tests/test_keys/`, derived from a fixed public seed.
- `keys/trust_anchors.json` is operator-replaceable. Its SHA-256 is printed at the start of
  every run, and `--anchors-sha256` refuses to run against any other file. Pin it.
- No key ships with status `PRODUCTION`, and an anchors file cannot grant it: production trust also requires the key's
  `(kid, fingerprint)` pair to be compiled into the release (`PRODUCTION_AUTHORITY`, empty in this candidate). RST pins it
  only after the signer's custody ceremony is accepted. Until then every verdict is `TEST_ONLY`.
- Dependency: `cryptography` 50.0.2 (>= 48.0.1 required, GHSA-537c-gmf6-5ccf).
- Unknown formats, algorithms, key ids, duplicate JSON keys and non-integer numbers fail closed.
- The verifier has no network code path. `network_used` is always `NO`.
