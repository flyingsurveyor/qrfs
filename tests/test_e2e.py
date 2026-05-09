#!/usr/bin/env python3
"""QRFS End-to-End test — no Flask, no browser.

Tests the full pipeline:
  1. Pack a test file
  2. Encrypt it
  3. Split into chunks
  4. Generate QR images (base45 encoded)
  5. Decode each QR image back
  6. Reconstruct blob
  7. Decrypt
  8. Unpack and compare
  9. Full PDF round-trip (skipped if pdftoppm is not available)
"""

import os
import shutil
import sys
import tempfile

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def test_e2e_pack_encrypt_chunk_qr():
    """Steps 1–9: pack → encrypt → chunk → QR encode → decode → reconstruct → decrypt → unpack."""
    test_filename = "test_data.csv"
    test_content = ("name,quantity,price\n" * 50).encode("utf-8")
    test_mime = "text/csv"

    # Pack
    from qrfs.core.packaging import pack_file_payload, unpack_file_payload

    packed = pack_file_payload(test_filename, test_mime, test_content, compress=True)
    assert packed

    # Encrypt
    from qrfs.core.crypto_utils import decrypt_file_payload_auto, encrypt_file_payload_password

    password = "testpassword14chars!"
    encrypted = encrypt_file_payload_password(packed, password)
    assert encrypted

    # Chunk
    from qrfs.core.chunker import make_chunks, parse_chunk, reconstruct_from_chunks

    chunks = make_chunks(encrypted, chunk_size=900)
    assert len(chunks) > 0

    # QR encode
    import qrcode

    from qrfs.core.utils import b45decode, b45encode

    qr_images = []
    for c in chunks:
        raw = c.to_bytes()
        encoded = b45encode(raw)
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(encoded, optimize=0)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        qr_images.append(img)
    assert len(qr_images) == len(chunks)

    # QR decode
    from pyzbar.pyzbar import decode as zbar_decode

    decoded_chunks = []
    for img in qr_images:
        results = zbar_decode(img)
        qrs = [o.data for o in results if o.type == "QRCODE"]
        assert qrs, "QR decode returned no results"
        raw_b45 = qrs[0].decode("ascii")
        raw_bin = b45decode(raw_b45)
        parse_chunk(raw_bin)  # validates header
        decoded_chunks.append(raw_bin)

    assert len(decoded_chunks) == len(chunks)

    # Reconstruct
    blob, _ = reconstruct_from_chunks(decoded_chunks)
    assert blob == encrypted

    # Decrypt
    decrypted, enc_mode, _, _ = decrypt_file_payload_auto(blob, password=password)
    assert decrypted

    # Unpack
    recovered = unpack_file_payload(decrypted)
    assert recovered["file_bytes"] == test_content


@pytest.mark.skipif(
    shutil.which("pdftoppm") is None,
    reason="pdftoppm (poppler-utils) not installed",
)
def test_e2e_pdf_roundtrip():
    """Step 10: full PDF round-trip encode → PDF → decode → reconstruct."""
    test_filename = "test_data.csv"
    test_content = ("name,quantity,price\n" * 50).encode("utf-8")
    test_mime = "text/csv"

    from qrfs.core.chunker import make_chunks, reconstruct_from_chunks
    from qrfs.core.crypto_utils import encrypt_file_payload_password
    from qrfs.core.packaging import pack_file_payload

    packed = pack_file_payload(test_filename, test_mime, test_content, compress=True)
    password = "testpassword14chars!"
    encrypted = encrypt_file_payload_password(packed, password)
    chunks = make_chunks(encrypted, chunk_size=900)

    tmp_dir = tempfile.mkdtemp(prefix="qrfs_test_")
    try:
        pdf_path = os.path.join(tmp_dir, "test.pdf")
        from qrfs.core.pdfgen import build_qr_pdf

        build_qr_pdf(chunks, pdf_path, original_filename=test_filename)
        assert os.path.getsize(pdf_path) > 0

        from qrfs.core.qrdecode import decode_qr_bytes_from_pdf

        pdf_chunks, _ = decode_qr_bytes_from_pdf(pdf_path, return_stats=True)
        assert len(pdf_chunks) == len(chunks)

        blob2, _ = reconstruct_from_chunks(pdf_chunks)
        assert blob2 == encrypted
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    # Legacy direct execution: python tests/test_e2e.py
    import subprocess

    sys.exit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
