#!/usr/bin/env python3
"""QRFS test vector generator.

Produces the complete tests/vectors/ tree from scratch.  Every file in the
tree is listed in manifest.json with its SHA-256 digest and a
``"deterministic"`` flag.

Usage::

    python tests/vectors/generate.py                     # write in-place
    python tests/vectors/generate.py --out /tmp/vecs     # write elsewhere
    python tests/vectors/generate.py --check             # verify committed vectors

Determinism notes
-----------------
All files except ``envelopes/pubkey/*.qfsc`` are byte-for-byte reproducible
when run with the same Python and library versions.  The pubkey envelopes use
PyNaCl's ``SealedBox``, which generates a random ephemeral X25519 keypair
internally and exposes no public API to inject one.  Those files are marked
``"deterministic": false`` in manifest.json, and the conformance test verifies
decryption only (not byte identity).

See tests/vectors/README.md for the full specification.
"""

import argparse
import base64
import hashlib
import json
import random
import shutil
import sys
import tempfile
import types as _types
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path.
# We also stub ``qrfs`` in sys.modules so that importing ``qrfs.core.*``
# does NOT execute ``qrfs/__init__.py`` (which pulls in Flask and pyzbar,
# neither of which is needed here).
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent  # tests/vectors/
_REPO_ROOT = _HERE.parent.parent  # repo root
sys.path.insert(0, str(_REPO_ROOT))
if "qrfs" not in sys.modules:
    _qrfs_stub = _types.ModuleType("qrfs")
    _qrfs_stub.__path__ = [str(_REPO_ROOT / "qrfs")]
    _qrfs_stub.__package__ = "qrfs"
    sys.modules["qrfs"] = _qrfs_stub

from qrfs.core.packaging import pack_file_payload  # noqa: E402
from qrfs.core.crypto_utils import (  # noqa: E402
    encrypt_file_payload_clear,
    encrypt_file_payload_password,
    encrypt_file_payload_pubkey,
)
from qrfs.core.chunker import make_chunks  # noqa: E402
from nacl.public import PrivateKey as _PrivateKey  # noqa: E402
from nacl.signing import SigningKey as _SigningKey  # noqa: E402

# ---------------------------------------------------------------------------
# Fixed fixtures — NEVER change without bumping the format version
# ---------------------------------------------------------------------------

FILE_ID_HEX = "00112233445566778899aabbccddeeff"
SALT_HEX = "0123456789abcdef0123456789abcdef"
NONCE_HEX = "deadbeefcafebabedeadbeef"
PASSWORD = "correct horse battery staple xx"
ARGON2_OPSLIMIT = 3
ARGON2_MEMLIMIT_MIB = 64

# 32-byte raw keys (fixed for reproducibility)
_RECIPIENT_SK_RAW = bytes([0xEC] * 32)  # X25519 private key seed
_SIGNER_SEED_RAW = bytes([0xED] * 32)  # Ed25519 seed

# Derived key material (computed once at import time)
_RECIPIENT_SK_OBJ = _PrivateKey(_RECIPIENT_SK_RAW)
_RECIPIENT_PK_RAW = bytes(_RECIPIENT_SK_OBJ.public_key)
RECIPIENT_SK_B64 = base64.b64encode(_RECIPIENT_SK_RAW).decode("ascii")
RECIPIENT_PK_B64 = base64.b64encode(_RECIPIENT_PK_RAW).decode("ascii")

_SIGNER_SK_OBJ = _SigningKey(_SIGNER_SEED_RAW)
_SIGNER_VK_RAW = bytes(_SIGNER_SK_OBJ.verify_key)
SIGNER_SK_B64 = base64.b64encode(_SIGNER_SEED_RAW).decode("ascii")
SIGNER_VK_B64 = base64.b64encode(_SIGNER_VK_RAW).decode("ascii")

FILE_ID = bytes.fromhex(FILE_ID_HEX)
SALT = bytes.fromhex(SALT_HEX)
NONCE = bytes.fromhex(NONCE_HEX)

# Chunk size used for the QRC chunk vectors.
# 100 bytes keeps file count small while guaranteeing several data chunks
# from the small_text clear envelope (~500 bytes compressed + headers).
CHUNK_SIZE_FOR_VECTORS = 100

# ---------------------------------------------------------------------------
# Fixed input file contents
# ---------------------------------------------------------------------------

# One byte: 0x41 = ASCII 'A'
ONE_BYTE = b"\x41"

# Fixed ASCII text; long enough for ≥ 3 data chunks at CHUNK_SIZE_FOR_VECTORS
SMALL_TEXT = (
    "QRFS test vector: small text file.\n"
    "\n"
    "This file is a fixed ASCII input for the QRFS on-wire format test vectors.\n"
    "It is designed to be long enough to produce multiple QRC chunks when chunked\n"
    "at a small chunk size, so that the FEC recovery tests can be exercised with\n"
    "at least one full group.\n"
    "\n"
    "The QRFS pipeline:\n"
    "  1. Pack this file into a QFSP payload (packaging layer).\n"
    "  2. Wrap in a QFSC envelope (cryptographic layer).\n"
    "  3. Split into QRC chunks (chunk/FEC layer).\n"
    "  4. Encode chunks as Base45 for QR symbol transport.\n"
    "\n"
    "See docs/FORMAT.md for the wire format specification.\n"
    "See tests/vectors/README.md for how to use these vectors.\n"
).encode("ascii")

# Multi-byte UTF-8 text including emoji and non-Latin scripts
UTF8_EMOJI = (
    "QRFS emoji test \U0001f510\n"
    "Greek: \u03b1 \u03b2 \u03b3\n"
    "Japanese: \u3053\u3093\u306b\u3061\u306f\n"
    "Emoji: \U0001f4c4 \u2705 \U0001f680\n"
    "Arabic: \u0645\u0631\u062d\u0628\u0627\n"
    "End of UTF-8 test.\n"
).encode("utf-8")

# 4096 bytes of incompressible pseudo-random data from a fixed seed
_rng = random.Random(0xC0FFEE)
INCOMPRESSIBLE = bytes(_rng.randint(0, 255) for _ in range(4096))

# 4096 bytes of highly compressible repeating pattern
COMPRESSIBLE = (b"QRFS_PATTERN" * 342)[:4096]

# (filename, mime_type, raw_bytes)
INPUTS: list[tuple[str, str, bytes]] = [
    ("empty.bin", "application/octet-stream", b""),
    ("one_byte.bin", "application/octet-stream", ONE_BYTE),
    ("small_text.txt", "text/plain", SMALL_TEXT),
    ("utf8_emoji.txt", "text/plain; charset=utf-8", UTF8_EMOJI),
    ("incompressible.bin", "application/octet-stream", INCOMPRESSIBLE),
    ("compressible.bin", "application/octet-stream", COMPRESSIBLE),
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        data
    )  # codeql[py/clear-text-storage-sensitive-data] - test fixtures; password is public


def _stem(filename: str) -> str:
    return Path(filename).stem


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate(out: Path) -> dict[str, Any]:
    """Generate the complete vector tree under *out* and return the manifest dict."""

    manifest_files: list[dict] = []

    def record(relpath: str, data: bytes, *, deterministic: bool, note: str = "") -> None:
        entry: dict[str, Any] = {
            "path": relpath,
            "sha256": _sha256(data),
            "size": len(data),
            "deterministic": deterministic,
        }
        if note:
            entry["note"] = note
        manifest_files.append(entry)
        _write(out / relpath, data)

    # -- key material ---------------------------------------------------------
    record("keys/recipient_x25519.sk", _RECIPIENT_SK_RAW, deterministic=True)
    record("keys/recipient_x25519.pk", _RECIPIENT_PK_RAW, deterministic=True)
    record("keys/signer_ed25519.sk", _SIGNER_SEED_RAW, deterministic=True)
    record("keys/signer_ed25519.pk", _SIGNER_VK_RAW, deterministic=True)

    # -- inputs ---------------------------------------------------------------
    for filename, _mime, data in INPUTS:
        record(f"inputs/{filename}", data, deterministic=True)

    # -- packaged (QFSP) ------------------------------------------------------
    qfsp_map: dict[str, bytes] = {}
    for filename, mime, data in INPUTS:
        stem = _stem(filename)
        qfsp = pack_file_payload(filename, mime, data)
        qfsp_map[stem] = qfsp
        record(f"packaged/{stem}.qfsp", qfsp, deterministic=True)

    # -- envelopes (QFSC) -----------------------------------------------------
    for filename, _mime, _data in INPUTS:
        stem = _stem(filename)
        qfsp = qfsp_map[stem]

        # mode 0 — clear (no signing)
        clear = encrypt_file_payload_clear(qfsp)
        record(f"envelopes/clear/{stem}.qfsc", clear, deterministic=True)

        # mode 0 — clear + Ed25519 signature
        clear_signed = encrypt_file_payload_clear(qfsp, SIGNER_SK_B64)
        record(f"envelopes/clear_signed/{stem}.qfsc", clear_signed, deterministic=True)

        # mode 1 — password, fixed salt + nonce → fully deterministic
        pw_env = encrypt_file_payload_password(qfsp, PASSWORD, _salt=SALT, _nonce=NONCE)
        record(f"envelopes/password/{stem}.qfsc", pw_env, deterministic=True)

        # mode 2 — pubkey; SealedBox ephemeral key is non-deterministic
        pk_env = encrypt_file_payload_pubkey(qfsp, RECIPIENT_PK_B64)
        record(
            f"envelopes/pubkey/{stem}.qfsc",
            pk_env,
            deterministic=False,
            note=(
                "SealedBox ephemeral key is non-deterministic; "
                "conformance test verifies decryption only."
            ),
        )

    # -- QRC chunks for small_text --------------------------------------------
    # Chunk the clear envelope of small_text with a fixed file_id.
    small_text_clear = (out / "envelopes/clear/small_text.qfsc").read_bytes()

    # No FEC — simple chunk set
    chunks_no_fec = make_chunks(
        small_text_clear,
        chunk_size=CHUNK_SIZE_FOR_VECTORS,
        _file_id=FILE_ID,
    )
    assert chunks_no_fec, "Expected at least one chunk for small_text (no FEC)"
    for c in chunks_no_fec:
        record(f"chunks/small_text/{c.index:03d}.qrc", c.to_bytes(), deterministic=True)

    # XOR FEC, group_size=3 — includes parity chunks
    chunks_xor = make_chunks(
        small_text_clear,
        chunk_size=CHUNK_SIZE_FOR_VECTORS,
        fec_group_size=3,
        fec_type="xor",
        _file_id=FILE_ID,
    )
    assert chunks_xor, "Expected at least one chunk for small_text_fec_xor"
    from qrfs.core.chunker import KIND_DATA  # noqa: PLC0415

    for c in chunks_xor:
        if c.kind == KIND_DATA:
            name = f"{c.index:03d}.qrc"
        else:  # KIND_PARITY
            name = f"p{c.group_index:03d}.qrc"
        record(f"chunks/small_text_fec_xor/{name}", c.to_bytes(), deterministic=True)

    # -- manifest.json --------------------------------------------------------
    manifest: dict[str, Any] = {
        "qrfs_format_versions": {"QFSP": 1, "QFSC": 5, "QRC": 3},
        "generated_at": "2026-05-09T00:00:00Z",
        "generator": "tests/vectors/generate.py",
        "fixtures": {
            "file_id_hex": FILE_ID_HEX,
            "argon2_salt_hex": SALT_HEX,
            "aes_gcm_nonce_hex": NONCE_HEX,
            "password": PASSWORD,
            "argon2id_opslimit": ARGON2_OPSLIMIT,
            "argon2id_memlimit_mib": ARGON2_MEMLIMIT_MIB,
            "chunk_size_for_vectors": CHUNK_SIZE_FOR_VECTORS,
        },
        "files": manifest_files,
    }
    manifest_json = json.dumps(manifest, indent=2) + "\n"
    _write(out / "manifest.json", manifest_json.encode("utf-8"))
    return manifest


def check_vectors(reference: Path, tmp: "Path | None" = None) -> None:
    """Regenerate vectors into *tmp* and compare deterministic files against *reference*.

    Raises :class:`AssertionError` if any deterministic file differs.
    """
    own_tmp = tmp is None
    if own_tmp:
        tmp = Path(tempfile.mkdtemp(prefix="qrfs_vectors_"))
    try:
        manifest = generate(tmp)
        mismatches: list[str] = []
        for entry in manifest["files"]:
            if not entry["deterministic"]:
                continue
            ref_file = reference / entry["path"]
            new_file = tmp / entry["path"]
            if not ref_file.exists():
                mismatches.append(f"MISSING in reference: {entry['path']}")
                continue
            if ref_file.read_bytes() != new_file.read_bytes():
                ref_digest = _sha256(ref_file.read_bytes())
                new_digest = entry["sha256"]
                mismatches.append(
                    f"MISMATCH: {entry['path']}\n"
                    f"  reference: {ref_digest}\n"
                    f"  generated: {new_digest}"
                )
        if mismatches:
            for m in mismatches:
                print(f"  {m}", file=sys.stderr)
            raise AssertionError(
                f"{len(mismatches)} deterministic file(s) differ from committed vectors."
            )
    finally:
        if own_tmp:
            shutil.rmtree(str(tmp), ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        default=None,
        help="Output directory (default: tests/vectors/ in the repo root).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Regenerate into a temporary directory and verify that all "
            "deterministic files match the committed vectors.  "
            "Exits non-zero on any mismatch."
        ),
    )
    args = parser.parse_args()

    default_vectors_dir = _REPO_ROOT / "tests" / "vectors"
    out = Path(args.out) if args.out else default_vectors_dir

    if args.check:
        print(f"Checking vectors against {out} …")
        check_vectors(reference=out)
        print("All deterministic files match. OK.")
    else:
        print(f"Generating vectors into {out} …")
        manifest = generate(out)
        det = sum(1 for f in manifest["files"] if f["deterministic"])
        non_det = len(manifest["files"]) - det
        total_size = sum(f["size"] for f in manifest["files"])
        print(
            f"  {len(manifest['files'])} files written "
            f"({det} deterministic, {non_det} non-deterministic)"
        )
        print(f"  Total payload size: {total_size} bytes")
        print(f"  Manifest: {out / 'manifest.json'}")


if __name__ == "__main__":
    _main()
