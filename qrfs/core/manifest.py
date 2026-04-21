import hashlib
import json
import os
from typing import List
from .chunker import Chunk, CHUNK_HEADER_LEN

MANIFEST_VERSION = 1


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest_dict(
    *,
    original_filename: str,
    mime_type: str,
    original_bytes: bytes,
    packed_bytes: bytes,
    encrypted_bytes: bytes,
    chunks: List[Chunk],
    compress_requested: bool,
    preset: str,
    chunk_size: int,
    encryption_mode: str,
    signed: bool = False,
    fec_group_size: int = 0,
    fec_type: str = 'xor',
    fec_parity_count: int = 1,
) -> dict:
    file_id_hex = chunks[0].file_id.hex() if chunks else None
    chunk_entries = []
    for chunk in chunks:
        raw = chunk.to_bytes()
        chunk_entries.append({
            'index': chunk.index,
            'payload_length': len(chunk.payload),
            'raw_length': len(raw),
            'sha256': _sha256_hex(raw),
        })

    return {
        'manifest_version': MANIFEST_VERSION,
        'app': 'QR Filesystem',
        'original_filename': original_filename,
        'mime_type': mime_type,
        'compress_requested': compress_requested,
        'encryption_mode': encryption_mode,
        'signed': signed,
        'original_size': len(original_bytes),
        'packed_size': len(packed_bytes),
        'encrypted_size': len(encrypted_bytes),
        'original_sha256': _sha256_hex(original_bytes),
        'packed_sha256': _sha256_hex(packed_bytes),
        'encrypted_sha256': _sha256_hex(encrypted_bytes),
        'chunking': {
            'file_id_hex': file_id_hex,
            'total_chunks': len(chunks),
            'chunk_size_target': chunk_size,
            'chunk_header_length': CHUNK_HEADER_LEN,
            'preset': preset,
            'fec_group_size': fec_group_size,
            'fec_type': fec_type,
            'fec_parity_count': fec_parity_count,
        },
        'chunks': chunk_entries,
    }


def save_manifest_json(manifest: dict, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
