from __future__ import annotations

import argparse

from .verifier import verify_bundle
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loopgrid-verify",
        description="Offline verifier for LoopGrid evidence bundles",
    )
    parser.add_argument(
        "bundle",
        help="Path to a LoopGrid evidence ZIP bundle",
    )
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
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _has_failure(result: dict, reason: str) -> bool:
    return any(
        isinstance(item, dict) and item.get("reason") == reason
        for item in (result.get("failures") or [])
    )


def main() -> None:
    args = build_parser().parse_args()

    result = verify_bundle(
        args.bundle,
        args.tsa_ca_file,
        args.expected_key_id,
        args.trusted_public_key,
    )

    # Keep CLI output intentionally concise and avoid printing the full
    # verification object. Detailed structured results remain available
    # through the Python verify_bundle() API.
    print("LOOPGRID EVIDENCE VERIFICATION")

    bundle_integrity = result.get("bundle_integrity") or {}

    if result["valid"] and bundle_integrity.get("attested"):
        print("[OK] VERIFIED")
        print("[DETAIL] Bundle integrity: attested")

    elif result["valid"]:
        print("[OK] LEDGER VERIFIED")
        print(
            "[WARN] Legacy/unattested bundle: exported file bytes are not "
            "covered by a signed bundle attestation."
        )

    else:
        print("[FAIL] INVALID")

        if _has_failure(result, "bundle_file_digest_mismatch"):
            print("[DETAIL] Bundle file digest mismatch.")
        elif _has_failure(result, "trusted_public_key_mismatch"):
            print("[DETAIL] Trusted public key mismatch.")
        elif _has_failure(result, "expected_key_id_mismatch"):
            print("[DETAIL] Expected signer key ID mismatch.")
        elif _has_failure(result, "bundle_attestation_signature_invalid"):
            print("[DETAIL] Bundle attestation signature is invalid.")
        elif _has_failure(result, "bundle_attestation_digest_mismatch"):
            print("[DETAIL] Bundle attestation digest mismatch.")
        else:
            print("[DETAIL] Verification checks failed.")

    raise SystemExit(0 if result["valid"] else 2)


if __name__ == "__main__":
    main()
