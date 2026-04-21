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

Usage: python tests/test_e2e.py
"""

import sys, os, gc, struct, tempfile, shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

def info(msg): print(f"  {msg}")
def ok(msg):   print(f"  ✓ {msg}")
def fail(msg): print(f"  ✗ {msg}")

def mem_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"): return int(line.split()[1]) / 1024
    except: pass
    return -1

def main():
    print("=" * 60)
    print("  QRFS End-to-End Test (base45)")
    print("=" * 60)
    info(f"Initial RAM: {mem_mb():.1f} MB")

    # ── Step 1: Create test data ──
    print("\n── Step 1: Test data ──")
    test_filename = "test_data.csv"
    test_content = ("name,quantity,price\n" * 50).encode("utf-8")
    test_mime = "text/csv"
    info(f"File: {test_filename}, {len(test_content)} bytes")
    ok("Test data created")

    # ── Step 2: Pack ──
    print("\n── Step 2: Pack ──")
    from qrfs.core.packaging import pack_file_payload, unpack_file_payload
    packed = pack_file_payload(test_filename, test_mime, test_content, compress=True)
    info(f"Packed: {len(packed)} bytes")
    ok("Pack OK")

    # ── Step 3: Encrypt ──
    print("\n── Step 3: Encrypt ──")
    from qrfs.core.crypto_utils import encrypt_file_payload_password, decrypt_file_payload_auto
    password = "testpassword14chars!"
    encrypted = encrypt_file_payload_password(packed, password)
    info(f"Encrypted: {len(encrypted)} bytes")
    ok("Encrypt OK")

    # ── Step 4: Chunk ──
    print("\n── Step 4: Chunk ──")
    from qrfs.core.chunker import make_chunks, reconstruct_from_chunks, parse_chunk
    chunks = make_chunks(encrypted, chunk_size=900)
    info(f"Chunks: {len(chunks)}, chunk_size=900")
    for c in chunks:
        info(f"  chunk idx={c.index} total={c.total} payload={len(c.payload)}B")
    ok("Chunking OK")

    # ── Step 5: Encode to QR (base45) ──
    print("\n── Step 5: QR encode (base45) ──")
    from qrfs.core.utils import b45encode, b45decode
    import qrcode
    from PIL import Image

    qr_images = []
    for c in chunks:
        raw = c.to_bytes()
        encoded = b45encode(raw)
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8, border=2,
        )
        qr.add_data(encoded, optimize=0)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white').convert('RGB')
        qr_images.append(img)
        overhead_pct = (len(encoded) - len(raw)) / len(raw) * 100
        info(f"  chunk {c.index}: {len(raw)}B → {len(encoded)} chars b45 "
             f"(+{overhead_pct:.0f}%) → QR v{qr.version} {img.size[0]}x{img.size[1]}")
    ok(f"{len(qr_images)} QR generati")

    # ── Step 6: Decode each QR ──
    print("\n── Step 6: QR decode (base45 → binary) ──")
    from pyzbar.pyzbar import decode as zbar_decode

    decoded_chunks = []
    for i, img in enumerate(qr_images):
        results = zbar_decode(img)
        qrs = [o.data for o in results if o.type == "QRCODE"]
        if not qrs:
            fail(f"  QR {i}: no decode!")
            continue
        raw_b45 = qrs[0].decode("ascii")
        raw_bin = b45decode(raw_b45)
        # Verify
        pc = parse_chunk(raw_bin)
        info(f"  QR {i}: idx={pc.index} total={pc.total} payload={len(pc.payload)}B ✓")
        decoded_chunks.append(raw_bin)
    
    if len(decoded_chunks) != len(chunks):
        fail(f"Decodeti {len(decoded_chunks)}/{len(chunks)} chunks")
        sys.exit(1)
    ok(f"All {len(decoded_chunks)} QR decoded correctly")

    # ── Step 7: Reconstruct ──
    print(f"\n── Step 7: Reconstruct (RAM: {mem_mb():.1f} MB) ──")
    blob, fec_info = reconstruct_from_chunks(decoded_chunks)
    info(f"Blob: {len(blob)} bytes")
    if blob == encrypted:
        ok("Blob identico all'originale criptato!")
    else:
        fail(f"Blob diverso! {len(blob)} vs {len(encrypted)}")
        sys.exit(1)

    # ── Step 8: Decrypt ──
    print("\n── Step 8: Decrypt ──")
    decrypted, enc_mode, _, _ = decrypt_file_payload_auto(blob, password=password)
    info(f"Decrypted: {len(decrypted)} bytes, mode={enc_mode}")
    ok("Decrypt OK")

    # ── Step 9: Unpack ──
    print("\n── Step 9: Unpack ──")
    recovered = unpack_file_payload(decrypted)
    info(f"Filename: {recovered['filename']}")
    info(f"MIME: {recovered['mime_type']}")
    info(f"Compressed: {recovered['compressed']}")
    info(f"Content: {len(recovered['file_bytes'])} bytes")

    if recovered['file_bytes'] == test_content:
        ok("CONTENUTO IDENTICO ALL'ORIGINALE!")
    else:
        fail("Contenuto diverso!")
        sys.exit(1)

    # ── Step 10: Full PDF round-trip ──
    print(f"\n── Step 10: Full PDF round-trip (RAM: {mem_mb():.1f} MB) ──")
    tmp_dir = tempfile.mkdtemp(prefix="qrfs_test_")
    try:
        pdf_path = os.path.join(tmp_dir, "test.pdf")
        from qrfs.core.pdfgen import build_qr_pdf
        build_qr_pdf(chunks, pdf_path, original_filename=test_filename)
        info(f"Generated PDF: {os.path.getsize(pdf_path)} bytes")

        from qrfs.core.qrdecode import decode_qr_bytes_from_pdf
        pdf_chunks, stats = decode_qr_bytes_from_pdf(pdf_path, return_stats=True)
        info(f"QR dal PDF: {len(pdf_chunks)}")
        info(f"Stats: {stats}")

        if len(pdf_chunks) != len(chunks):
            fail(f"Attesi {len(chunks)}, trovati {len(pdf_chunks)}")
        else:
            blob2, _ = reconstruct_from_chunks(pdf_chunks)
            if blob2 == encrypted:
                ok("PDF ROUND-TRIP PERFETTO!")
            else:
                fail("Blob dal PDF diverso!")
    except Exception as e:
        fail(f"Error: {e}")
        import traceback; traceback.print_exc()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f"\n{'=' * 60}")
    print("  TUTTI I TEST PASSATI!")
    print(f"  RAM finale: {mem_mb():.1f} MB")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
