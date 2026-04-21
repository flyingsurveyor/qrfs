#!/usr/bin/env python3
"""QRFS Diagnose PDF — test decode of an existing PDF.

Usage: python tools/diagnose_pdf.py /path/to/file.pdf [password]
"""

import sys, os, subprocess, tempfile, shutil, gc, struct

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

def info(msg): print(f"  {msg}")

def mem_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"): return int(line.split()[1]) / 1024
    except: pass
    return -1

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/diagnose_pdf.py file.pdf [password]")
        sys.exit(1)

    pdf_path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else None

    info(f"File: {pdf_path} ({os.path.getsize(pdf_path)} bytes)")
    info(f"RAM: {mem_mb():.1f} MB")

    print("\n── Decode QR dal PDF ──")
    from qrfs.core.qrdecode import decode_qr_bytes_from_pdf
    chunks, stats = decode_qr_bytes_from_pdf(pdf_path, return_stats=True)
    info(f"Chunks trovati: {len(chunks)}")
    info(f"Stats: {stats}")
    info(f"RAM: {mem_mb():.1f} MB")

    if not chunks:
        info("ERROR: no chunk found")
        sys.exit(1)

    print("\n── Parse chunk headers ──")
    from qrfs.core.chunker import parse_chunk
    for i, raw in enumerate(chunks):
        c = parse_chunk(raw)
        info(f"  #{i}: idx={c.index} total={c.total} payload={len(c.payload)}B kind={c.kind}")

    print(f"\n── Reconstruct (RAM: {mem_mb():.1f} MB) ──")
    from qrfs.core.chunker import reconstruct_from_chunks
    blob, fec_info = reconstruct_from_chunks(chunks)
    info(f"Blob: {len(blob)} bytes")
    info(f"FEC: {fec_info}")
    info(f"RAM: {mem_mb():.1f} MB")

    if password:
        print("\n── Decrypt ──")
        from qrfs.core.crypto_utils import decrypt_file_payload_auto
        from qrfs.core.packaging import unpack_file_payload
        decrypted, mode, kid, sig = decrypt_file_payload_auto(blob, password=password)
        recovered = unpack_file_payload(decrypted)
        info(f"File: {recovered['filename']} ({len(recovered['file_bytes'])} bytes)")
        info(f"MIME: {recovered['mime_type']}")

        out = os.path.join(os.path.dirname(pdf_path), f"recovered_{recovered['filename']}")
        with open(out, 'wb') as f:
            f.write(recovered['file_bytes'])
        info(f"Saved: {out}")

    info(f"\nRAM finale: {mem_mb():.1f} MB")
    info("OK!")

if __name__ == "__main__":
    main()
