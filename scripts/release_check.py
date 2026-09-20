from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "MANIFEST.in",
    "src/loopgrid_verify/__init__.py",
    "src/loopgrid_verify/cli.py",
    "src/loopgrid_verify/verifier.py",
    "src/loopgrid_verify/version.py",
    "tests/fixtures/attested-valid.zip",
    "tests/fixtures/attested-tampered-report.zip",
    "tests/fixtures/legacy-unattested.zip",
    "tests/fixtures/attested-trusted-public-key.pem",
    "tests/fixtures/legacy-trusted-public-key.pem",
]

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
}

SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
]


def main() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        print("[FAIL] Missing required files:")
        for path in missing:
            print(f"  - {path}")
        return 1

    version_text = (ROOT / "src/loopgrid_verify/version.py").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', version_text)
    if not match or f'version = "{match.group(1)}"' not in pyproject:
        print("[FAIL] Version mismatch between version.py and pyproject.toml")
        return 1

    scan_suffixes = {".py", ".md", ".toml", ".yml", ".yaml", ".txt"}
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if any(part in IGNORED_DIRS for part in rel.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in scan_suffixes:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                print(f"[FAIL] Possible secret-like token in {path.relative_to(ROOT)}")
                return 1

    for fixture in [
        ROOT / "tests/fixtures/attested-valid.zip",
        ROOT / "tests/fixtures/attested-tampered-report.zip",
        ROOT / "tests/fixtures/legacy-unattested.zip",
    ]:
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        print(f"[INFO] {fixture.name}: sha256:{digest}")

    print("[OK] Repository hygiene check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
