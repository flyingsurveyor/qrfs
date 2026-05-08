# Changelog

All notable changes to QRFS are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

## Version note

**App version** (this file) and **format version** are tracked independently.
The on-wire format versions — `QFSP v1`, `QFSC v5`, `QRC3` — follow the
semantics described in [`docs/FORMAT.md`](docs/FORMAT.md) and bump only on
breaking or incompatible format changes, independently from the app version.

---

## [Unreleased]

### Added

- **CI** (`.github/workflows/ci.yml`): three-job GitHub Actions workflow —
  `test` (Python 3.11 / 3.12 / 3.13 matrix), `lint` (`ruff check .`), and
  `security` (`bandit -r qrfs/core`). Runs on every push to `main` and on
  every pull request.
- **`pyproject.toml`**: PEP 621 package metadata, `pip install -e .[dev]`
  support, `qrfs` console script (`qrfs.__main__:main`), and tool
  configuration for `ruff`, `pytest`, and `bandit`.
- **`qrfs/__main__.py`**: entry point module enabling `python -m qrfs`; shares
  identical logic with the existing `qrfs.py` entry point.
- **`SECURITY.md`**: threat model, cryptographic primitives table, known
  limitations, and private vulnerability reporting instructions — aligned with
  `docs/FORMAT.md`.
- **`tools/rescue.js`**: moved from repo root to `tools/`; added header comment
  explaining its purpose as a standalone offline browser rescue tool.
- **`tools/README.md`**: documents the tools in the `tools/` directory.
- **Development section in `README.md`**: explains `pip install -e .[dev]`,
  `pytest`, `ruff check .`, and CI.
- **CI badge in `README.md`**.

### Changed

- **`qrfs.py`**: now delegates to `qrfs.__main__:main`; all CLI flags and
  environment variables are unchanged.
- **`requirements.txt`**: added a compatibility comment at the top pointing to
  `pyproject.toml` as the canonical dependency list.
- **`.gitignore`**: extended to cover `*.bak`, `.venv/`, `venv/`,
  `__pycache__/`, `*.pyc`, `dist/`, `build/`, `*.egg-info/`,
  `.pytest_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`, and
  `data/` subdirectories.

### Removed

- **`qrfs.py.bak`**: stale backup file removed from the repository.
- **`rescue.js`** (repo root): moved to `tools/rescue.js` (see above).

### Format versions (unchanged)

`QFSP v1` · `QFSC v5` · `QRC3` — no on-wire format changes in this release.
