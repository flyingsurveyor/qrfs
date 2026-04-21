import math
from dataclasses import dataclass

QR_PER_PAGE = 30
CHUNK_HEADER_LEN = 40  # conservative estimate for QRC3 with extended FEC fields
CRYPTO_HEADER_LEN = 33  # QFSC + version + salt + nonce
AEAD_TAG_LEN = 16


@dataclass
class EncodeEstimate:
    input_size: int
    packed_size: int
    encrypted_size: int
    chunk_size: int
    qr_count: int
    page_count: int
    chunk_header_total: int
    overhead_total: int
    overhead_ratio: float
    fec_parity_chunks: int


def estimate_encode_sizes(input_size: int, packed_size: int, encrypted_size: int, chunk_size: int, fec_group_size: int = 0, fec_parity_count: int = 1) -> EncodeEstimate:
    if chunk_size <= 0:
        raise ValueError('chunk_size must be positive.')
    data_chunk_count = max(1, math.ceil(encrypted_size / chunk_size)) if encrypted_size else 1
    fec_parity_chunks = (math.ceil(data_chunk_count / fec_group_size) * fec_parity_count) if fec_group_size else 0
    qr_count = data_chunk_count + fec_parity_chunks
    page_count = math.ceil(qr_count / QR_PER_PAGE)
    chunk_header_total = qr_count * CHUNK_HEADER_LEN
    crypto_overhead = CRYPTO_HEADER_LEN + AEAD_TAG_LEN
    overhead_total = max(0, encrypted_size - input_size) + chunk_header_total
    overhead_ratio = (overhead_total / input_size) if input_size > 0 else 0.0
    return EncodeEstimate(
        input_size=input_size,
        packed_size=packed_size,
        encrypted_size=encrypted_size,
        chunk_size=chunk_size,
        qr_count=qr_count,
        page_count=page_count,
        chunk_header_total=chunk_header_total,
        overhead_total=overhead_total + crypto_overhead,
        overhead_ratio=overhead_ratio,
        fec_parity_chunks=fec_parity_chunks,
    )
