# LoopGrid Verify

**Standalone offline verification for LoopGrid evidence bundles.**

`loopgrid-verify` verifies exported LoopGrid evidence without connecting to a LoopGrid server. It is designed for design partners, reviewers, auditors, operators, and engineering teams that want to inspect a portable evidence bundle independently of the running LoopGrid service.

Current package: **0.1.0 design preview**

## Install

```bash
pip install loopgrid-verify
```

Python 3.10–3.13 is supported.

## Verify a bundle

```bash
loopgrid-verify evidence.zip
```

For higher-assurance verification, pin signer identity using an out-of-band trusted public key:

```bash
loopgrid-verify evidence.zip \
  --trusted-public-key trusted-public-key.pem
```

Or pin the expected LoopGrid signer key ID:

```bash
loopgrid-verify evidence.zip \
  --expected-key-id ed25519:0123456789abcdef
```

For an RFC3161 timestamp token, the verifier validates the timestamp status, SHA-256 message imprint, and imprint match locally. To additionally validate the timestamp signer certificate chain, provide a trusted CA bundle and ensure `openssl` is available:

```bash
loopgrid-verify evidence.zip \
  --tsa-ca-file tsa-ca.pem
```

## Verification result

A valid attested bundle prints:

```text
LOOPGRID EVIDENCE VERIFICATION
[OK] VERIFIED
```

A modified or otherwise invalid bundle prints:

```text
LOOPGRID EVIDENCE VERIFICATION
[FAIL] INVALID
```

and exits with status code `2`.

Legacy Evidence Bundle v2 exports created before signed file attestation remain ledger-verifiable. They are explicitly labeled:

```text
[OK] LEDGER VERIFIED
[WARN] Legacy/unattested bundle: exported file bytes are not covered by a signed bundle attestation.
```

## What is verified

For current attested Evidence Bundle v2 exports, the verifier checks:

- the signed bundle-attestation digest;
- the attestation signature;
- SHA-256 digests for attested exported files;
- missing, duplicate, and unexpected archive entries;
- the embedded signer key identity;
- optional out-of-band public-key or key-ID pinning;
- signed event content hashes and signatures;
- workspace hash-chain continuity across events and proof-only witnesses;
- disclosed payload commitments when disclosures are included;
- policy digest consistency;
- lifecycle and verification-document consistency;
- checkpoint signatures and linkage when present;
- RFC3161 timestamp imprint validity when present;
- optional RFC3161 signer certificate-chain trust when `--tsa-ca-file` is supplied.

## Trust model

The public key embedded in an evidence bundle proves that the bundle is internally consistent under that key. It does **not**, by itself, establish who controls that key.

When signer authenticity matters, pin trust out of band using:

```text
--trusted-public-key
```

or:

```text
--expected-key-id
```

This distinction is intentional: bundle integrity and signer authenticity are separate questions.

## Python API

```python
from loopgrid_verify import verify_bundle

result = verify_bundle(
    "evidence.zip",
    trusted_public_key="trusted-public-key.pem",
)

if result["valid"]:
    print("verified")
else:
    print(result["failures"])
```

The API is:

```python
verify_bundle(
    path,
    tsa_ca_file=None,
    expected_key_id=None,
    trusted_public_key=None,
) -> dict
```

## What this verifier does not determine

`loopgrid-verify` checks cryptographic and structural evidence properties. It does not determine whether an AI decision was correct, safe, fair, lawful, compliant, or otherwise appropriate. It is evidence-verification infrastructure, not a legal or regulatory compliance determination.

## Server-independent by design

Verification does not require:

- a LoopGrid server;
- a database;
- Docker;
- an API key;
- an MCP server;
- a network connection.

The only optional external executable is `openssl`, and only when certificate-chain trust validation is requested for an RFC3161 timestamp using `--tsa-ca-file`.

## Development

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m pytest -q
python scripts/release_check.py
```

macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m pytest -q
python scripts/release_check.py
```

Build:

```bash
python -m build
python -m twine check dist/*
```

## Fixture coverage

The test suite includes:

- a current signed-file-attested Evidence Bundle v2;
- the same bundle with `report.html` modified;
- a legacy/unattested Evidence Bundle v2;
- the correct trusted public key;
- a deliberately incorrect trusted public key.

The tampered bundle must fail verification. The legacy bundle may pass signed-ledger verification only with the explicit `legacy_unattested` status/warning.

## Release posture

`0.1.0` is a design-preview verifier release. The package is intended for technical evaluation and design-partner workflows. It is not a legal-compliance certification tool.

## Related projects

- LoopGrid core: `https://github.com/cybertechsoft/loopgrid`
- LoopGrid MCP: `https://github.com/loopgridio/loopgrid-mcp`
- Website: `https://loopgrid.io`

## License

Apache-2.0. See `LICENSE`.
