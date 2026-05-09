# Changelog

All notable changes to QRFS are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

> ## ⚠️ Pre‑1.0 notice
>
> QRFS is in active design. Until version **1.0**, format versions
> (`QFSP`, `QFSC`, `QRC*`) may be **replaced wholesale** rather than
> evolved with backward compatibility. Decoders are not required to
> parse legacy versions during this phase.
>
> Backward compatibility commitments — and the corresponding
> immutable test vectors under `tests/vectors/` — start at QRFS 1.0.
>
> Until then, the only stable contract is: **the latest release of
> QRFS can decode anything produced by the same release.**

---

## Version note

**App version** (this file) and **format version** are tracked independently.
The on-wire format versions — `QFSP v1`, `QFSC v6`, `QRC3` — follow the
semantics described in [`docs/FORMAT.md`](docs/FORMAT.md) and bump only on
breaking or incompatible format changes, independently from the app version.

---

## [Unreleased]

### Breaking changes

- QFSC envelope format bumped from v5 to v6. v5 envelopes are no longer readable.
  Pre-1.0, no migration provided.

### Added

- Explicit KDF parameters in `QFSC v6` envelope header.
- Three pre-defined KDF profiles: `interactive`, `default`, `sensitive`.
- CLI flags `--kdf-profile` and `--kdf-memory/--kdf-time/--kdf-parallel`.
- Flask UI dropdown for selecting KDF profile during encryption.
- **Official byte-level test vectors** for `QFSP v1`, `QFSC v6`, and `QRC3`
  under `tests/vectors/`, plus a conformance test in `tests/test_vectors.py`.
  Vectors include all four QFSC modes (clear, clear-signed, password, pubkey)
  for six representative input files (empty, one-byte, ASCII text, UTF-8/emoji,
  incompressible, compressible), plus QRC chunk sets for `small_text` with and
  without XOR FEC.  The manifest `tests/vectors/manifest.json` records the
  SHA-256 of every file; deterministic files are invariant — any byte change
  is a format break.  See `tests/vectors/README.md` for the full specification.
- **`tests/vectors/generate.py`**: standalone generator that reproduces the
  entire vector tree from fixed fixtures in a single command
  (`python tests/vectors/generate.py`); supports `--check` mode for CI
  idempotency verification.
- **Optional kw-only parameters** added to `qrfs/core/crypto_utils.py`
  (`encrypt_file_payload_password`: `_salt`, `_nonce`) and
  `qrfs/core/chunker.py` (`make_chunks`: `_file_id`) to allow injection of
  fixed entropy for vector generation.  Defaults preserve existing production
  behaviour (fresh randomness from `os.urandom`).  No call site was changed.
- **`slow` pytest mark** registered in `pyproject.toml` for tests dominated
  by Argon2id key derivation.  Fast local iteration: `pytest -m 'not slow'`. (`qrfs/__main__.py`): QRFS now binds
  to loopback by default.  A fresh `python qrfs.py` is not reachable from the
  network unless the user opts in.  **Migration:** users who relied on the old
  `0.0.0.0` default must now pass `--lan` (or `QRFS_LAN=1`) explicitly.
- **`--lan` / `QRFS_LAN=1`** flag: convenience shorthand for `--host 0.0.0.0`.
  If both `--host` and `--lan` are supplied, `--host` wins and a warning is
  printed to stderr.
- **`--https` / `QRFS_HTTPS=1`** flag: enables TLS via Flask's built-in server
  with an `ssl.SSLContext`.  Auto-generates an Ed25519 self-signed certificate
  under `data/tls/` (key mode `0o600`) on first run; reuses it thereafter;
  regenerates it if it expires within 30 days.  Supply `--cert`/`--key` to use
  a custom certificate instead.  The SHA-256 fingerprint is printed at startup.
- **Startup security banner**: printed to stderr before the server starts,
  summarising the bind address, protocol, and (for LAN+plain-HTTP) a prominent
  WARNING about network exposure.
- **`qrfs/core/ratelimit.py`**: in-memory per-IP sliding-window rate limiter
  (5 attempts / 60 s) for KDF (Argon2id) endpoints.  No new runtime dependency
  — uses stdlib `threading.Lock` + `collections.deque` + `time.monotonic`.
  No-op when `app.config['TESTING']` is true.
- **Rate limiting on unlock endpoints** (`qrfs/routes/decode.py`): the
  password-decode `action == 'unlock'` branches in `decode_view` and
  `rescue_view` now check the rate limiter and return HTTP 429 + `Retry-After`
  when the limit is exceeded.
- **`resolve_host(argv, env)` and `ensure_self_signed_cert(cert_dir, hostnames)`**
  extracted from `qrfs/__main__.py` as pure testable functions.
- **`tests/test_transport.py`**: hermetic tests for host resolution, LAN flag,
  HTTPS cert provisioning, and rate limiter (no real sockets bound).
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
  limitations, private vulnerability reporting instructions, network-exposure
  documentation, and rate-limiting documentation — aligned with
  `docs/FORMAT.md`.
- **`tools/rescue.js`**: moved from repo root to `tools/`; added header comment
  explaining its purpose as a standalone offline browser rescue tool.
- **`tools/README.md`**: documents the tools in the `tools/` directory.
- **Development section in `README.md`**: explains `pip install -e .[dev]`,
  `pytest`, `ruff check .`, and CI.
- **CI badge in `README.md`**.

### Changed

- Default KDF cost raised from 64 MiB / 3 iter to **256 MiB / 3 iter**
  (OWASP-baseline aligned).
- **Chunk parity index semantics (`QRC3`)**: parity chunks now carry the correct
  local `parity_index` within each FEC group instead of reusing `group_index`.
  **Pre-1.0 break, no migration provided.**
- **Chunk page footer labels** now distinguish data and parity chunks:
  `D{index+1}/{total}` for data and
  `P{parity_index+1}/{parity_count} G{group_index+1}` for parity.
- **Chunk encoding/decoding paths** are now `QRC3`-only in Python and browser
  rescue paths.
- **Default bind host**: changed from `0.0.0.0` to `127.0.0.1`.
  **Breaking change for users who relied on the old default.**
  Migration: pass `--lan` or set `QRFS_LAN=1` to restore the previous
  all-interfaces behaviour.
- **`qrfs.py`**: now delegates to `qrfs.__main__:main`; all CLI flags and
  environment variables are unchanged.
- **`requirements.txt`**: added a compatibility comment at the top pointing to
  `pyproject.toml` as the canonical dependency list.
- **`.gitignore`**: extended to cover `*.bak`, `.venv/`, `venv/`,
  `__pycache__/`, `*.pyc`, `dist/`, `build/`, `*.egg-info/`,
  `.pytest_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`, and
  `data/` subdirectories.
- **CI lint policy**: `.github/workflows/ci.yml` lint job is blocking again
  (`Lint`, without `continue-on-error`).

### Fixed

- Cleared the pre-1.0 repository-wide ruff debt and removed broad
  per-file ignores, keeping only a narrow `tests/vectors/generate.py`
  exception for intentional import-order behavior.

### Removed

- QFSC v5 reading.
- **`qrfs.py.bak`**: stale backup file removed from the repository.
- **`rescue.js`** (repo root): moved to `tools/rescue.js` (see above).
- Legacy chunk-format support (`QRC1`, `QRC2`) in decoders and chunk-header
  parsing paths.

### Format versions

`QFSP v1` · `QFSC v6` · `QRC3`.
