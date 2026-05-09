"""Conformance tests for QRFS byte-level test vectors.

These tests pin specific bytes that QRFS must produce (or be able to consume),
today and forever within the current format versions (QFSP v1, QFSC v5, QRC3).

The vectors live in ``tests/vectors/`` and are described in full in
``tests/vectors/README.md``.  The manifest ``manifest.json`` records the
SHA-256 of every file and a ``"deterministic"`` flag.

Pubkey envelopes (``envelopes/pubkey/``) are marked ``"deterministic": false``
because PyNaCl's ``SealedBox`` uses a random ephemeral key internally.  Those
files are tested by decryption only, not byte identity.
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO_ROOT  = Path(__file__).parent.parent
VECTORS_DIR = Path(__file__).parent / "vectors"
MANIFEST_PATH = VECTORS_DIR / "manifest.json"

# ---------------------------------------------------------------------------
# Ensure qrfs.core.* is importable without triggering qrfs/__init__.py
# (which pulls in Flask and pyzbar — not needed for conformance tests).
# ---------------------------------------------------------------------------
sys.path.insert(0, str(_REPO_ROOT))

if "qrfs" not in sys.modules:
    _qrfs_stub = types.ModuleType("qrfs")
    _qrfs_stub.__path__ = [str(_REPO_ROOT / "qrfs")]
    _qrfs_stub.__package__ = "qrfs"
    sys.modules["qrfs"] = _qrfs_stub

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 1. Manifest completeness
# ---------------------------------------------------------------------------


def test_manifest_lists_every_file() -> None:
    """Every file in vectors/ (except manifest.json and README.md) must appear in manifest.json."""
    manifest = _load_manifest()
    recorded_paths = {f["path"] for f in manifest["files"]}

    actual_paths: set[str] = set()
    for root, dirs, files in os.walk(VECTORS_DIR):
        # Skip Python cache directories
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fname in files:
            if fname in ("manifest.json", "README.md", "generate.py"):
                continue
            rel = Path(root, fname).relative_to(VECTORS_DIR)
            actual_paths.add(str(rel).replace(os.sep, "/"))

    missing_from_manifest = actual_paths - recorded_paths
    extra_in_manifest = recorded_paths - actual_paths

    assert not missing_from_manifest, f"Files not in manifest: {sorted(missing_from_manifest)}"
    assert not extra_in_manifest, f"Manifest entries with no file: {sorted(extra_in_manifest)}"


# ---------------------------------------------------------------------------
# 2. SHA-256 invariance for deterministic files
# ---------------------------------------------------------------------------


def test_deterministic_files_match_recorded_sha256() -> None:
    """For every deterministic file the on-disk SHA-256 must match the manifest.

    This is the invariance test: any accidental on-wire format change will
    cause at least one hash mismatch here.
    """
    manifest = _load_manifest()
    failures: list[str] = []
    for entry in manifest["files"]:
        if not entry["deterministic"]:
            continue
        path = VECTORS_DIR / entry["path"]
        actual = _sha256(path.read_bytes())
        if actual != entry["sha256"]:
            failures.append(
                f"{entry['path']}:\n  expected {entry['sha256']}\n  got      {actual}"
            )
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# 3. QFSP unpack
# ---------------------------------------------------------------------------


def test_qfsp_vectors_unpack_to_inputs() -> None:
    """Each packaged/*.qfsp must unpack to the exact bytes of inputs/*."""
    from qrfs.core.packaging import unpack_file_payload  # noqa: PLC0415

    manifest = _load_manifest()
    qfsp_entries = [f for f in manifest["files"] if f["path"].startswith("packaged/")]
    assert qfsp_entries, "No packaged entries in manifest"

    for entry in qfsp_entries:
        stem = Path(entry["path"]).stem
        qfsp_bytes = (VECTORS_DIR / entry["path"]).read_bytes()
        result = unpack_file_payload(qfsp_bytes)

        # Locate the corresponding input file (extension may vary)
        input_files = list((VECTORS_DIR / "inputs").glob(f"{stem}.*"))
        assert len(input_files) == 1, (
            f"Expected exactly one input for {stem!r}, found: {input_files}"
        )
        expected = input_files[0].read_bytes()
        assert result["file_bytes"] == expected, f"QFSP unpack mismatch for {stem!r}"


# ---------------------------------------------------------------------------
# 4. Clear envelopes
# ---------------------------------------------------------------------------


def test_clear_envelopes_unwrap_to_qfsp() -> None:
    """Each envelopes/clear/*.qfsc must unwrap to the corresponding packaged/*.qfsp."""
    from qrfs.core.crypto_utils import decrypt_file_payload_clear  # noqa: PLC0415

    for qfsc_path in sorted((VECTORS_DIR / "envelopes/clear").glob("*.qfsc")):
        stem = qfsc_path.stem
        expected = (VECTORS_DIR / "packaged" / f"{stem}.qfsp").read_bytes()
        payload, sig_info = decrypt_file_payload_clear(qfsc_path.read_bytes())
        assert payload == expected, f"Clear envelope mismatch for {stem!r}"
        assert sig_info is None, f"Unexpected signature for unsigned clear envelope {stem!r}"


# ---------------------------------------------------------------------------
# 5. Clear-signed envelopes
# ---------------------------------------------------------------------------


def test_clear_signed_envelopes_verify_and_unwrap() -> None:
    """Signed envelopes must pass Ed25519 verification and unwrap to the QFSP."""
    from qrfs.core.crypto_utils import decrypt_file_payload_clear  # noqa: PLC0415

    for qfsc_path in sorted((VECTORS_DIR / "envelopes/clear_signed").glob("*.qfsc")):
        stem = qfsc_path.stem
        expected = (VECTORS_DIR / "packaged" / f"{stem}.qfsp").read_bytes()
        payload, sig_info = decrypt_file_payload_clear(qfsc_path.read_bytes())
        assert payload == expected, f"Clear-signed envelope mismatch for {stem!r}"
        assert sig_info is not None, f"Missing signature info for {stem!r}"
        assert sig_info["verified"], f"Signature not verified for {stem!r}"


# ---------------------------------------------------------------------------
# 6. Password envelopes
# ---------------------------------------------------------------------------


def test_password_envelopes_decrypt_with_fixed_password() -> None:
    """Password envelopes must decrypt to the QFSP using the manifest's fixed password."""
    from qrfs.core.crypto_utils import decrypt_file_payload_password  # noqa: PLC0415

    manifest = _load_manifest()
    password = manifest["fixtures"]["password"]

    for qfsc_path in sorted((VECTORS_DIR / "envelopes/password").glob("*.qfsc")):
        stem = qfsc_path.stem
        expected = (VECTORS_DIR / "packaged" / f"{stem}.qfsp").read_bytes()
        payload, _ = decrypt_file_payload_password(qfsc_path.read_bytes(), password)
        assert payload == expected, f"Password envelope mismatch for {stem!r}"


# ---------------------------------------------------------------------------
# 7. Pubkey envelopes (decryption only — not byte-deterministic)
# ---------------------------------------------------------------------------


def test_pubkey_envelopes_decrypt_with_fixed_recipient() -> None:
    """Pubkey envelopes must decrypt to the QFSP using keys/recipient_x25519.sk.

    No byte-identity check is performed on the envelope itself because
    SealedBox is non-deterministic (random ephemeral key per encryption).
    """
    from qrfs.core.crypto_utils import decrypt_file_payload_pubkey  # noqa: PLC0415

    sk_bytes = (VECTORS_DIR / "keys/recipient_x25519.sk").read_bytes()
    sk_b64 = base64.b64encode(sk_bytes).decode("ascii")

    for qfsc_path in sorted((VECTORS_DIR / "envelopes/pubkey").glob("*.qfsc")):
        stem = qfsc_path.stem
        expected = (VECTORS_DIR / "packaged" / f"{stem}.qfsp").read_bytes()
        payload, _, _ = decrypt_file_payload_pubkey(qfsc_path.read_bytes(), sk_b64)
        assert payload == expected, f"Pubkey envelope mismatch for {stem!r}"


# ---------------------------------------------------------------------------
# 8. QRC chunk reconstruction
# ---------------------------------------------------------------------------


def test_qrc3_chunks_reconstruct_envelopes() -> None:
    """Chunks in chunks/small_text/ must reconstruct to envelopes/clear/small_text.qfsc."""
    from qrfs.core.chunker import reconstruct_from_chunks  # noqa: PLC0415

    chunks_dir = VECTORS_DIR / "chunks/small_text"
    expected = (VECTORS_DIR / "envelopes/clear/small_text.qfsc").read_bytes()

    raw_chunks = [p.read_bytes() for p in sorted(chunks_dir.glob("*.qrc"))]
    assert raw_chunks, "No chunks found in chunks/small_text/"

    blob, _info = reconstruct_from_chunks(raw_chunks)
    assert blob == expected, "Chunk reconstruction mismatch"


# ---------------------------------------------------------------------------
# 9. FEC XOR reconstruction after simulated loss
# ---------------------------------------------------------------------------


def test_qrc3_chunks_reconstruct_with_xor_fec_after_loss() -> None:
    """Drop one data chunk per FEC group, then verify XOR parity recovers the full blob."""
    from qrfs.core.chunker import (  # noqa: PLC0415
        KIND_DATA,
        parse_chunk,
        reconstruct_from_chunks,
    )

    chunks_dir = VECTORS_DIR / "chunks/small_text_fec_xor"
    expected   = (VECTORS_DIR / "envelopes/clear/small_text.qfsc").read_bytes()

    # Load all chunk files
    all_files = sorted(chunks_dir.glob("*.qrc"))
    assert all_files, "No chunks found in chunks/small_text_fec_xor/"
    chunk_map: dict[str, bytes] = {f.name: f.read_bytes() for f in all_files}

    # Identify the first data chunk in each group (by group_index)
    group_first_data: dict[int, str] = {}
    for name, raw in sorted(chunk_map.items()):
        c = parse_chunk(raw)
        if c.kind == KIND_DATA and c.group_index not in group_first_data:
            group_first_data[c.group_index] = name

    assert group_first_data, "No data chunks found in chunks/small_text_fec_xor/"
    to_drop = set(group_first_data.values())

    # Supply remaining chunks (data survivors + all parity) to reconstruct
    surviving = [raw for name, raw in chunk_map.items() if name not in to_drop]
    blob, info = reconstruct_from_chunks(surviving)

    assert blob == expected, "FEC XOR recovery mismatch"
    assert info["fec_recovered_chunks"] >= len(to_drop), (
        f"Expected at least {len(to_drop)} recovered chunks, "
        f"got {info['fec_recovered_chunks']}"
    )


# ---------------------------------------------------------------------------
# 10. Generator idempotency
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_generator_is_idempotent(tmp_path: Path) -> None:
    """Regenerate vectors into tmp_path and assert deterministic files match committed vectors.

    Marked ``slow`` because it reruns Argon2id for all password envelopes.
    Skip for fast local iteration with ``pytest -m 'not slow'``.
    """
    gen_path = VECTORS_DIR / "generate.py"
    spec = importlib.util.spec_from_file_location("vector_generator", str(gen_path))
    assert spec is not None and spec.loader is not None
    gen_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen_mod)  # type: ignore[union-attr]

    # check_vectors() regenerates into tmp_path and raises AssertionError on mismatch
    gen_mod.check_vectors(reference=VECTORS_DIR, tmp=tmp_path)
