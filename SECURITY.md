# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability.

Use GitHub Private Vulnerability Reporting for this repository when available. Include:

- the affected `loopgrid-verify` version;
- the evidence bundle type or schema involved;
- a minimal reproduction or proof of concept;
- the expected and observed verification result;
- whether signer pinning, checkpoints, disclosures, or timestamps are involved.

## Verification boundary

`loopgrid-verify` verifies cryptographic and structural properties of LoopGrid evidence bundles. An embedded public key establishes integrity under that key, not external authenticity of the key owner. Use `--trusted-public-key` or `--expected-key-id` when signer identity must be established out of band.

Verification does not determine legal compliance or the correctness of the underlying AI decision.

## Supported release

Security fixes are targeted at the latest published package version unless otherwise stated.
