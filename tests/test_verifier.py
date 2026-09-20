from pathlib import Path

from loopgrid_verify import verify_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def test_attested_bundle_verifies_with_trusted_key():
    result = verify_bundle(
        str(FIXTURES / "attested-valid.zip"),
        trusted_public_key=str(FIXTURES / "attested-trusted-public-key.pem"),
    )
    assert result["valid"] is True
    assert result["bundle_schema"] == "loopgrid/evidence-bundle/2"
    assert result["bundle_integrity"]["status"] == "attested"
    assert result["bundle_integrity"]["attested"] is True
    assert result["bundle_integrity"]["signature_valid"] is True
    assert result["bundle_integrity"]["attestation_digest_valid"] is True
    assert result["key_identity"]["trusted_public_key_match"] is True


def test_tampered_report_is_rejected():
    result = verify_bundle(
        str(FIXTURES / "attested-tampered-report.zip"),
        trusted_public_key=str(FIXTURES / "attested-trusted-public-key.pem"),
    )
    assert result["valid"] is False
    assert result["bundle_integrity"]["status"] == "invalid"
    assert any(
        failure.get("reason") == "bundle_file_digest_mismatch"
        and failure.get("file") == "report.html"
        for failure in result["failures"]
    )


def test_legacy_unattested_bundle_remains_ledger_verifiable():
    result = verify_bundle(
        str(FIXTURES / "legacy-unattested.zip"),
        trusted_public_key=str(FIXTURES / "legacy-trusted-public-key.pem"),
    )
    assert result["valid"] is True
    assert result["bundle_integrity"]["status"] == "legacy_unattested"
    assert result["bundle_integrity"]["attested"] is False
    assert any(
        warning.get("reason") == "bundle_file_attestation_unavailable"
        for warning in result["warnings"]
    )


def test_wrong_trusted_public_key_is_rejected():
    result = verify_bundle(
        str(FIXTURES / "attested-valid.zip"),
        trusted_public_key=str(FIXTURES / "wrong-public-key.pem"),
    )
    assert result["valid"] is False
    assert any(
        failure.get("reason") == "trusted_public_key_mismatch"
        for failure in result["failures"]
    )


def test_wrong_expected_key_id_is_rejected():
    result = verify_bundle(
        str(FIXTURES / "attested-valid.zip"),
        expected_key_id="ed25519:0000000000000000",
    )
    assert result["valid"] is False
    assert any(
        failure.get("reason") == "expected_key_id_mismatch"
        for failure in result["failures"]
    )
