# Changelog

All notable changes to `loopgrid-verify` are documented here.

## 0.1.0 - 2026-09-20

Initial design-preview release.

- Standalone offline verification for LoopGrid Evidence Bundle v2.
- Signed bundle-file attestation verification.
- SHA-256 verification of attested exported files.
- Ed25519 and ECDSA SHA-256 signature verification used by supported LoopGrid signer profiles.
- Workspace ledger-chain verification.
- Trusted public-key and expected key-ID pinning.
- Checkpoint verification.
- RFC3161 timestamp imprint verification with optional OpenSSL CA-chain validation.
- Disclosure commitment, policy digest, lifecycle, and verification-document checks.
- Explicit `legacy_unattested` behavior for older Evidence Bundle v2 exports.
- Windows-safe ASCII CLI status output.
