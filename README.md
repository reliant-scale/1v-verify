# 1V Verify

**Independent verification. Inspectable evidence.**

An open-source, offline verification utility from **Reliant Scale Technologies — A Boutique Technology Company**. It checks supported `1v-receipt/1.0` test artifacts against local trust anchors and reports exactly what it checked.

**TEST-ONLY RELEASE — NOT A PRODUCTION ATTESTATION VERIFIER**

A successful test verification does not establish an RST production attestation or prove that the underlying information is factually true.

`v0.1.3-test` is a **source release** for Linux x86_64, glibc 2.34 or newer, and CPython 3.11, 3.12 or 3.13. Dependencies are hash-pinned. No production trust anchor is included. The verifier performs no network requests; installing dependencies may require access to PyPI.

## Run a test receipt

Download and extract the [v0.1.3-test source archive](https://github.com/reliant-scale/1v-verify/releases/download/v0.1.3-test/1v-verify-0.1.3-test-src.tar.gz). Verify its SHA-256 before extraction:

```text
245465a9f14f9d1ff95ceca9cb1dee93600cff87564039a20151fbfe526607de
```

From the extracted `1v-verify/` directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
sha256sum -c MANIFEST.sha256
python -I src/onev_verify.py fixtures/vfy01_valid_test_signed.json --anchors keys/trust_anchors.json
python -I src/onev_verify.py fixtures/vfy03_signature_mutated.json --anchors keys/trust_anchors.json
```

The first receipt reports `TEST SIGNATURE VALID — NOT AN RST PRODUCTION ATTESTATION` and exits `0`. The modified receipt reports `RECEIPT NOT VALID` and exits `1`. An anchors file that tries to promote the test key to production is refused with `INCOMPLETE PACKAGE` and exits `3`. These examples use synthetic test material.

The [source archive attached to the release](https://github.com/reliant-scale/1v-verify/releases/tag/v0.1.3-test) retains its technical `README.md` verbatim. The repository landing README is the sole declared presentation difference from the archive. Use the archive for its full technical instructions and qualified fixture set.

## Reproduce the acceptance checks

```bash
python -I tests/make_fixtures.py
python -I tests/run_battery.py
python -I tests/scan_tree.py
```

The regenerated `fixtures/FIXTURES.sha256.json` has SHA-256 `21f3b3ee1a45c52230961046a2908193bbae05c8ced8de0dff09bc94eb36ab8b`. The acceptance battery covers valid and invalid signatures, malformed and unsupported inputs, trust-anchor refusal, content-integrity exit semantics, and five June conformance vectors. The documented result fields and exit codes are in [`docs/result-contract.md`](docs/result-contract.md); the supported artifact is in [`docs/receipt-format.md`](docs/receipt-format.md).

The default `issuer-signature` profile verifies a supported signature against a supplied local trust anchor. The optional `content-integrity` profile checks the canonical digest only; it does not verify the signature or issuer and exits `4`. Neither profile establishes independent time or the truth of an underlying business claim.

## Reliant Scale Technologies

RST develops practical products and considers scoped technical work involving data, workflows, operational evidence, and accountable decisions. **Atlas is its flagship platform; 1V is its governed technical foundation; 1V Verify is one public utility within that broader institution.**

| If you want to… | Start here |
|---|---|
| Explore Atlas | [Atlas](https://reliantscale.com/atlas) |
| Read public developer documentation | [Atlas agent-accountability repository](https://github.com/reliant-scale/atlas-agent-accountability) |
| Bring a bounded business problem | [Work With RST](https://reliantscale.com/work-with-rst) |
| See RST's finished informational products | [RST Press products](https://reliantscale.com/products) |

## License and security

Apache License 2.0 applies to this standalone verifier distribution. See [`LICENSE`](LICENSE), [`LICENSE_SCOPE.md`](LICENSE_SCOPE.md), and [`SECURITY.md`](SECURITY.md). **License covers this standalone verifier only; it does not cover RST's issuing systems, keys, Atlas, or marks.**
