from pathlib import Path
import subprocess
import sys

FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "loopgrid_verify", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_attested_bundle_exit_zero():
    proc = run_cli(
        str(FIXTURES / "attested-valid.zip"),
        "--trusted-public-key",
        str(FIXTURES / "attested-trusted-public-key.pem"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "[OK] VERIFIED" in proc.stdout
    assert "[DETAIL] Bundle integrity: attested" in proc.stdout


def test_cli_tampered_bundle_exit_two():
    proc = run_cli(
        str(FIXTURES / "attested-tampered-report.zip"),
        "--trusted-public-key",
        str(FIXTURES / "attested-trusted-public-key.pem"),
    )
    assert proc.returncode == 2
    assert "[FAIL] INVALID" in proc.stdout
    assert "[DETAIL] Bundle file digest mismatch." in proc.stdout


def test_cli_legacy_bundle_is_explicitly_labeled():
    proc = run_cli(
        str(FIXTURES / "legacy-unattested.zip"),
        "--trusted-public-key",
        str(FIXTURES / "legacy-trusted-public-key.pem"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "[OK] LEDGER VERIFIED" in proc.stdout
    assert "[WARN] Legacy/unattested bundle" in proc.stdout


def test_cli_version():
    proc = run_cli("--version")
    assert proc.returncode == 0
    assert "loopgrid-verify 0.1.0" in proc.stdout
