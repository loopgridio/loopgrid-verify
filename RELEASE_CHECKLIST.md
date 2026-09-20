# Release Checklist

## Before publishing

- [ ] Version updated in `pyproject.toml` and `src/loopgrid_verify/version.py`.
- [ ] `CHANGELOG.md` updated.
- [ ] `python -m pytest -q` passes.
- [ ] `python scripts/release_check.py` passes.
- [ ] `python -m build` succeeds.
- [ ] `python -m twine check dist/*` succeeds.
- [ ] Fresh virtual-environment install from the built wheel succeeds.
- [ ] Valid attested fixture exits `0` and prints `[OK] VERIFIED`.
- [ ] Tampered fixture exits `2` and prints `[FAIL] INVALID`.
- [ ] Legacy fixture exits `0` and prints the `Legacy/unattested` warning.
- [ ] GitHub Actions and CodeQL are green.

## PyPI Trusted Publishing

Configure a Trusted Publisher for:

- PyPI project: `loopgrid-verify`
- GitHub owner: `loopgridio`
- Repository: `loopgrid-verify`
- Workflow: `release.yml`
- Environment: `pypi`

Do not store a PyPI API token in repository secrets when Trusted Publishing is configured.

## After publishing

- [ ] Create a fresh virtual environment.
- [ ] `pip install loopgrid-verify==<version>` from PyPI.
- [ ] `loopgrid-verify --version` reports the expected version.
- [ ] Verify a valid fixture using an out-of-band trusted public key.
- [ ] Confirm the tampered fixture fails with exit code `2`.
- [ ] Update LoopGrid core/website documentation only after the package is publicly installable.
