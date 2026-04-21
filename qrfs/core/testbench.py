import hashlib
import math
import os
import random
from dataclasses import dataclass
from typing import List, Dict, Any

from .chunker import make_chunks, reconstruct_from_chunks
from .crypto_utils import (
    encrypt_file_payload_password,
    encrypt_file_payload_pubkey,
    decrypt_file_payload_auto,
)
from .key_utils import generate_key_materials
from .packaging import pack_file_payload, unpack_file_payload
from .pdfgen import PER_PAGE


@dataclass
class TestbenchResult:
    ok: bool
    seed: int
    file_size: int
    packed_size: int
    encrypted_size: int
    total_qr: int
    total_pages: int
    removed_indexes: List[int]
    removed_count: int
    removed_data_count: int
    removed_parity_count: int
    fec_recovered_chunks: int
    encryption_mode: str
    signed: bool
    compressed: bool
    digest_original: str
    digest_restored: str
    error: str | None = None
    recipient_key_id: str | None = None
    signature_info: dict | None = None
    fec_info: dict | None = None


def build_synthetic_payload(size: int, seed: int, pattern: str = 'mixed') -> bytes:
    if size < 0:
        raise ValueError('size must be >= 0')
    rng = random.Random(seed)
    if pattern == 'random':
        return bytes(rng.randrange(0, 256) for _ in range(size))
    if pattern == 'text':
        words = [
            b'qrfs', b'paper', b'crypto', b'chunk', b'route', b'reticulum', b'optical', b'filesystem',
            b'packet', b'public-key', b'parity', b'field', b'payload', b'archive'
        ]
        out = bytearray()
        while len(out) < size:
            out.extend(rng.choice(words))
            out.extend(b' ')
        return bytes(out[:size])
    # mixed
    out = bytearray()
    while len(out) < size:
        mode = rng.randrange(0, 3)
        if mode == 0:
            out.extend(bytes(rng.randrange(0, 256) for _ in range(min(128, size - len(out)))))
        elif mode == 1:
            sentence = f'QRFS seed={seed} offset={len(out)} pattern=mixed '.encode('utf-8')
            out.extend(sentence)
        else:
            repeated = bytes([rng.randrange(32, 127)]) * min(96, size - len(out))
            out.extend(repeated)
    return bytes(out[:size])


def _choose_removed_indexes(chunks: List, remove_mode: str, rng: random.Random) -> List[int]:
    total_chunks = len(chunks)
    if total_chunks <= 0 or remove_mode == 'none':
        return []
    if remove_mode == 'single_any':
        return [rng.randrange(total_chunks)]

    groups: dict[int, dict[str, list[int]]] = {}
    for idx, chunk in enumerate(chunks):
        group_key = chunk.group_index if chunk.group_size else -1
        info = groups.setdefault(group_key, {'data': [], 'parity': []})
        if chunk.kind == 0:
            info['data'].append(idx)
        else:
            info['parity'].append(idx)

    if remove_mode == 'single_per_group':
        removed: List[int] = []
        for gi in sorted(k for k in groups.keys() if k >= 0):
            candidates = groups[gi]['data']
            if candidates:
                removed.append(rng.choice(candidates))
        return removed or [rng.randrange(total_chunks)]

    if remove_mode == 'double_same_group':
        eligible = [gi for gi, info in groups.items() if gi >= 0 and len(info['data']) >= 2]
        if not eligible:
            return [rng.randrange(total_chunks)]
        gi = rng.choice(eligible)
        return sorted(rng.sample(groups[gi]['data'], 2))

    if remove_mode == 'parity_only':
        removed: List[int] = []
        for gi in sorted(k for k in groups.keys() if k >= 0):
            removed.extend(groups[gi]['parity'])
        return removed

    return [rng.randrange(total_chunks)]


def run_single_test(
    *,
    file_size: int,
    seed: int,
    encryption_mode: str,
    password: str,
    chunk_size: int,
    fec_group_size: int,
    compress: bool,
    sign: bool,
    remove_mode: str,
    pattern: str,
    fec_type: str = 'xor',
    fec_parity_count: int = 1,
) -> TestbenchResult:
    data = build_synthetic_payload(file_size, seed, pattern=pattern)
    packed = pack_file_payload(
        filename=f'test_{seed}.bin',
        mime_type='application/octet-stream',
        file_bytes=data,
        compress=compress,
    )

    key_materials = generate_key_materials()
    signing_private_key = key_materials['signing_private_key_b64'] if sign else None

    if encryption_mode == 'pubkey':
        encrypted = encrypt_file_payload_pubkey(
            packed,
            key_materials['encryption_public_key_b64'],
            sender_signing_private_key_b64=signing_private_key,
        )
        decode_kwargs = {'private_key_b64': key_materials['encryption_private_key_b64']}
    else:
        encrypted = encrypt_file_payload_password(
            packed,
            password,
            sender_signing_private_key_b64=signing_private_key,
        )
        decode_kwargs = {'password': password}

    chunks = make_chunks(encrypted, chunk_size=chunk_size, fec_group_size=fec_group_size, fec_parity_count=fec_parity_count, fec_type=fec_type)
    rng = random.Random(seed ^ 0x5A17)
    removed_indexes = _choose_removed_indexes(chunks, remove_mode, rng)
    kept_raw_chunks = []
    removed_data_count = 0
    removed_parity_count = 0
    for idx, chunk in enumerate(chunks):
        if idx in removed_indexes:
            if chunk.kind == 0:
                removed_data_count += 1
            else:
                removed_parity_count += 1
            continue
        kept_raw_chunks.append(chunk.to_bytes())

    try:
        rebuilt_encrypted, fec_info = reconstruct_from_chunks(kept_raw_chunks)
        packed_restored, _, recipient_key_id, signature_info = decrypt_file_payload_auto(rebuilt_encrypted, **decode_kwargs)
        restored = unpack_file_payload(packed_restored)
        restored_bytes = restored['file_bytes']
        digest_original = hashlib.sha256(data).hexdigest()
        digest_restored = hashlib.sha256(restored_bytes).hexdigest()
        ok = digest_original == digest_restored
        error = None if ok else 'Final hash mismatch.'
    except Exception as exc:
        digest_original = hashlib.sha256(data).hexdigest()
        digest_restored = ''
        ok = False
        error = str(exc)
        recipient_key_id = None
        signature_info = None
        fec_info = None

    result = TestbenchResult(
        ok=ok,
        seed=seed,
        file_size=len(data),
        packed_size=len(packed),
        encrypted_size=len(encrypted),
        total_qr=len(chunks),
        total_pages=math.ceil(len(chunks) / PER_PAGE),
        removed_indexes=removed_indexes,
        removed_count=len(removed_indexes),
        removed_data_count=removed_data_count,
        removed_parity_count=removed_parity_count,
        fec_recovered_chunks=(fec_info or {}).get('fec_recovered_chunks', 0),
        encryption_mode=encryption_mode,
        signed=sign,
        compressed=compress,
        digest_original=digest_original,
        digest_restored=digest_restored,
        error=error,
        recipient_key_id=recipient_key_id,
        signature_info=signature_info,
        fec_info=fec_info,
    )
    result.fec_info = (result.fec_info or {}) | {'fec_type': fec_type, 'fec_parity_count': fec_parity_count}
    return result


def run_testbench(
    *,
    file_size: int,
    trials: int,
    encryption_mode: str,
    password: str,
    chunk_size: int,
    fec_group_size: int,
    compress: bool,
    sign: bool,
    remove_mode: str,
    pattern: str,
    base_seed: int | None = None,
    fec_type: str = 'xor',
    fec_parity_count: int = 1,
) -> Dict[str, Any]:
    if trials < 1:
        raise ValueError('trials must be >= 1')
    if file_size < 1:
        raise ValueError('file_size must be >= 1')
    if chunk_size <= 64:
        raise ValueError('chunk_size too small')

    base_seed = base_seed if base_seed is not None else int.from_bytes(os.urandom(4), 'big')
    results: List[TestbenchResult] = []
    for i in range(trials):
        seed = base_seed + i
        results.append(run_single_test(
            file_size=file_size,
            seed=seed,
            encryption_mode=encryption_mode,
            password=password,
            chunk_size=chunk_size,
            fec_group_size=fec_group_size,
            compress=compress,
            sign=sign,
            remove_mode=remove_mode,
            pattern=pattern,
            fec_type=fec_type,
            fec_parity_count=fec_parity_count,
        ))

    successes = sum(1 for r in results if r.ok)
    failures = len(results) - successes
    recovered_total = sum(r.fec_recovered_chunks for r in results)
    return {
        'summary': {
            'trials': len(results),
            'successes': successes,
            'failures': failures,
            'success_rate': successes / len(results),
            'file_size': file_size,
            'chunk_size': chunk_size,
            'fec_group_size': fec_group_size,
            'remove_mode': remove_mode,
            'encryption_mode': encryption_mode,
            'signed': sign,
            'compress': compress,
            'pattern': pattern,
            'base_seed': base_seed,
            'fec_type': fec_type,
            'fec_parity_count': fec_parity_count,
            'fec_recovered_total': recovered_total,
        },
        'results': [r.__dict__ for r in results],
    }
