from __future__ import annotations

import argparse
import json

from .verifier import verify_bundle
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loopgrid-verify",
        description="Offline verifier for LoopGrid evidence bundles",
    )
    parser.add_argument("bundle", help="Path to a LoopGrid evidence ZIP bundle")
    parser.add_argument(
        "--tsa-ca-file",
        default=None,
        help="Trusted CA bundle for RFC3161 signer validation via OpenSSL",
    )
    parser.add_argument(
        "--expected-key-id",
        default=None,
        help="Pin the expected LoopGrid signer key id, e.g. ed25519:abc123...",
    )
    parser.add_argument(
        "--trusted-public-key",
        default=None,
        help="Pin signer identity to an out-of-band trusted PEM public key",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = verify_bundle(
        args.bundle,
        args.tsa_ca_file,
        args.expected_key_id,
        args.trusted_public_key,
    )

    # Keep CLI status text ASCII-only. On Windows, redirected stdout may inherit
    # a legacy code page even when verification itself succeeds.
    print("LOOPGRID EVIDENCE VERIFICATION")
    if result["valid"] and (result.get("bundle_integrity") or {}).get("attested"):
        print("[OK] VERIFIED")
    elif result["valid"]:
        print("[OK] LEDGER VERIFIED")
        print(
            "[WARN] Legacy/unattested bundle: exported file bytes are not covered "
            "by a signed bundle attestation."
        )
    else:
        print("[FAIL] INVALID")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["valid"] else 2)


if __name__ == "__main__":
    main()
