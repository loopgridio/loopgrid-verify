# Validation Record — 0.1.0

`loopgrid-verify` 0.1.0 is derived from the verifier used by LoopGrid core `0.8.1-design-partner` after the signed evidence bundle file-attestation hardening.

The repository test fixtures cover:

| Scenario | Expected result |
| --- | --- |
| Current attested bundle + matching trusted public key | `valid=true`, `bundle_integrity.status=attested` |
| Current bundle with `report.html` modified | `valid=false`, `bundle_file_digest_mismatch` |
| Legacy/unattested Evidence Bundle v2 | signed ledger valid + explicit `legacy_unattested` warning |
| Current attested bundle + wrong trusted public key | `valid=false`, `trusted_public_key_mismatch` |
| Current attested bundle + wrong expected key ID | `valid=false`, `expected_key_id_mismatch` |

The source package is also validated by CI across Python 3.10–3.13 on Ubuntu and Python 3.12 on Windows and macOS, plus a package-build check.

This validation demonstrates software behavior for the included fixtures and tests. It does not establish legal compliance or production certification.
