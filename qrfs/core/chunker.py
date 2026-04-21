import math
import os
import struct
from dataclasses import dataclass
from typing import Iterable, List, Dict, Tuple

try:
    from reedsolo import RSCodec
except Exception:  # pragma: no cover
    RSCodec = None

MAGIC_V1 = b'QRC1'
MAGIC_V2 = b'QRC2'
MAGIC_V3 = b'QRC3'
VERSION_V1 = 1
VERSION_V2 = 2
VERSION_V3 = 3
FILE_ID_LEN = 16
CHUNK_HEADER_LEN_V1 = 4 + 1 + FILE_ID_LEN + 4 + 4 + 2
CHUNK_HEADER_LEN_V2 = 4 + 1 + FILE_ID_LEN + 1 + 4 + 4 + 2 + 4 + 2
CHUNK_HEADER_LEN_V3 = 4 + 1 + FILE_ID_LEN + 1 + 1 + 4 + 4 + 2 + 4 + 2 + 2 + 2
CHUNK_HEADER_LEN = CHUNK_HEADER_LEN_V3
FEC_NONE = 0
FEC_XOR = 1
FEC_RS = 2
KIND_DATA = 0
KIND_PARITY = 1


@dataclass
class Chunk:
    file_id: bytes
    index: int
    total: int
    payload: bytes
    kind: int = KIND_DATA
    group_index: int = 0
    group_size: int = 0
    fec_type: int = FEC_NONE
    parity_count: int = 0
    parity_index: int = 0

    def to_bytes(self) -> bytes:
        if self.fec_type == FEC_NONE and self.group_size == 0:
            return (
                MAGIC_V1
                + struct.pack('>B', VERSION_V1)
                + self.file_id
                + struct.pack('>IIH', self.index, self.total, len(self.payload))
                + self.payload
            )
        if self.parity_count == 0 and self.fec_type in (FEC_NONE, FEC_XOR) and self.kind in (KIND_DATA, KIND_PARITY):
            return (
                MAGIC_V2
                + struct.pack('>B', VERSION_V2)
                + self.file_id
                + struct.pack('>BIIHIH', self.kind, self.index, self.total, len(self.payload), self.group_index, self.group_size)
                + self.payload
            )
        return (
            MAGIC_V3
            + struct.pack('>B', VERSION_V3)
            + self.file_id
            + struct.pack(
                '>BBIIHIHH',
                self.kind,
                self.fec_type,
                self.index,
                self.total,
                len(self.payload),
                self.group_index,
                self.group_size,
                self.parity_count,
            )
            + struct.pack('>H', self.parity_index)
            + self.payload
        )



def parse_chunk(raw: bytes) -> Chunk:
    magic = raw[:4]
    if magic == MAGIC_V1:
        version = raw[4]
        if version != VERSION_V1:
            raise ValueError(f'Unsupported chunk version: {version}')
        file_id = raw[5:5 + FILE_ID_LEN]
        start = 5 + FILE_ID_LEN
        index, total, payload_len = struct.unpack('>IIH', raw[start:start + 10])
        payload = raw[start + 10:start + 10 + payload_len]
        return Chunk(file_id=file_id, index=index, total=total, payload=payload)
    if magic == MAGIC_V2:
        version = raw[4]
        if version != VERSION_V2:
            raise ValueError(f'Unsupported chunk version: {version}')
        file_id = raw[5:5 + FILE_ID_LEN]
        start = 5 + FILE_ID_LEN
        kind, index, total, payload_len, group_index, group_size = struct.unpack('>BIIHIH', raw[start:start + 17])
        payload = raw[start + 17:start + 17 + payload_len]
        return Chunk(file_id=file_id, index=index, total=total, payload=payload, kind=kind, group_index=group_index, group_size=group_size, fec_type=FEC_XOR if kind == KIND_PARITY else FEC_NONE)
    if magic == MAGIC_V3:
        version = raw[4]
        if version != VERSION_V3:
            raise ValueError(f'Unsupported chunk version: {version}')
        file_id = raw[5:5 + FILE_ID_LEN]
        start = 5 + FILE_ID_LEN
        header_len = struct.calcsize('>BBIIHIHH')
        if len(raw) < start + header_len + 2:
            raise ValueError(
                f'QRC3 chunk too short: expected at least {start + header_len + 2} bytes, got {len(raw)}.'
            )
        kind, fec_type, index, total, payload_len, group_index, group_size, parity_count = struct.unpack(
            '>BBIIHIHH', raw[start:start + header_len]
        )
        parity_index = struct.unpack('>H', raw[start + header_len:start + header_len + 2])[0]
        payload = raw[start + header_len + 2:start + header_len + 2 + payload_len]
        return Chunk(
            file_id=file_id,
            index=index,
            total=total,
            payload=payload,
            kind=kind,
            group_index=group_index,
            group_size=group_size,
            fec_type=fec_type,
            parity_count=parity_count,
            parity_index=parity_index,
        )
    raise ValueError('QR payload has an invalid magic header.')



def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))



def _build_xor_parity_chunk(file_id: bytes, group_index: int, total_data: int, group_chunks: List[Chunk], chunk_size: int, nominal_group_size: int) -> Chunk:
    lengths = [len(c.payload) for c in group_chunks]
    parity = bytes(chunk_size)
    for c in group_chunks:
        padded = c.payload.ljust(chunk_size, b'\x00')
        parity = _xor_bytes(parity, padded)
    meta = struct.pack('>H', len(group_chunks)) + b''.join(struct.pack('>H', ln) for ln in lengths)
    return Chunk(
        file_id=file_id,
        index=group_index,
        total=total_data,
        payload=meta + parity,
        kind=KIND_PARITY,
        group_index=group_index,
        group_size=nominal_group_size,
        fec_type=FEC_XOR,
        parity_count=1,
        parity_index=0,
    )



def _build_rs_parity_chunks(file_id: bytes, group_index: int, total_data: int, group_chunks: List[Chunk], chunk_size: int, parity_count: int, nominal_group_size: int) -> List[Chunk]:
    if RSCodec is None:
        raise RuntimeError('reedsolo not installed: cannot generate Reed-Solomon FEC.')
    if parity_count < 1:
        return []
    lengths = [len(c.payload) for c in group_chunks]
    k = len(group_chunks)
    data_vectors = [c.payload.ljust(chunk_size, b'\x00') for c in group_chunks]
    parity_vectors = [bytearray(chunk_size) for _ in range(parity_count)]
    rsc = RSCodec(parity_count)
    for pos in range(chunk_size):
        msg = bytes(vec[pos] for vec in data_vectors)
        codeword = rsc.encode(msg)
        parity_bytes = codeword[-parity_count:]
        for pi in range(parity_count):
            parity_vectors[pi][pos] = parity_bytes[pi]
    meta = struct.pack('>H', k) + b''.join(struct.pack('>H', ln) for ln in lengths)
    return [
        Chunk(
            file_id=file_id,
            index=group_index,
            total=total_data,
            payload=meta + bytes(parity_vectors[pi]),
            kind=KIND_PARITY,
            group_index=group_index,
            group_size=nominal_group_size,
            fec_type=FEC_RS,
            parity_count=parity_count,
            parity_index=pi,
        )
        for pi in range(parity_count)
    ]



def make_chunks(blob: bytes, chunk_size: int = 900, fec_group_size: int = 0, fec_parity_count: int = 1, fec_type: str = 'xor') -> List[Chunk]:
    if chunk_size <= 64:
        raise ValueError('chunk_size too small.')
    if fec_group_size not in (0, 2, 3, 4, 5, 6, 8):
        raise ValueError('Unsupported fec_group_size.')
    if fec_type not in ('xor', 'rs'):
        raise ValueError('Unsupported fec_type.')
    if fec_group_size == 0:
        fec_parity_count = 0
    if fec_parity_count < 0 or fec_parity_count > 4:
        raise ValueError('Unsupported fec_parity_count.')
    if fec_type == 'xor' and fec_parity_count not in (0, 1):
        raise ValueError('XOR supports only 1 parity chunk.')
    if fec_type == 'rs' and fec_group_size and fec_parity_count >= fec_group_size:
        raise ValueError('With RS, parity must be smaller than the number of data chunks per group.')

    file_id = os.urandom(FILE_ID_LEN)
    total = math.ceil(len(blob) / chunk_size)
    data_chunks: List[Chunk] = []
    fec_marker = FEC_NONE if not fec_group_size else (FEC_RS if fec_type == 'rs' else FEC_XOR)
    for index in range(total):
        start = index * chunk_size
        end = start + chunk_size
        group_index = (index // fec_group_size) if fec_group_size else 0
        data_chunks.append(Chunk(
            file_id=file_id,
            index=index,
            total=total,
            payload=blob[start:end],
            kind=KIND_DATA,
            group_index=group_index,
            group_size=fec_group_size or 0,
            fec_type=fec_marker,
            parity_count=fec_parity_count if fec_group_size else 0,
            parity_index=0,
        ))

    if not fec_group_size:
        return data_chunks

    output: List[Chunk] = []
    for gi in range(math.ceil(total / fec_group_size)):
        group = data_chunks[gi * fec_group_size:(gi + 1) * fec_group_size]
        output.extend(group)
        if fec_type == 'rs':
            output.extend(_build_rs_parity_chunks(file_id, gi, total, group, chunk_size, fec_parity_count, fec_group_size))
        else:
            output.append(_build_xor_parity_chunk(file_id, gi, total, group, chunk_size, fec_group_size))
    return output



def _reconstruct_v1(parsed: List[Chunk]) -> bytes:
    total = parsed[0].total
    by_index: Dict[int, Chunk] = {c.index: c for c in parsed}
    missing = [idx for idx in range(total) if idx not in by_index]
    if missing:
        raise ValueError(f'Missing chunks: {missing[:10]}')
    return b''.join(by_index[idx].payload for idx in range(total))



def _decode_lengths_from_parity_payload(payload: bytes) -> tuple[list[int], bytes]:
    meta_count = struct.unpack('>H', payload[:2])[0]
    lengths = [struct.unpack('>H', payload[2 + i * 2:4 + i * 2])[0] for i in range(meta_count)]
    data = payload[2 + 2 * meta_count:]
    return lengths, data



def _recover_group_xor(group_chunks: List[Chunk], total_data: int, chunk_size: int, nominal_group_size: int) -> Dict[int, bytes]:
    data_map = {c.index: c.payload for c in group_chunks if c.kind == KIND_DATA}
    parity_chunks = [c for c in group_chunks if c.kind == KIND_PARITY]
    if not parity_chunks:
        return data_map

    parity = parity_chunks[0]
    lengths, parity_blob = _decode_lengths_from_parity_payload(parity.payload)
    start_index = parity.group_index * nominal_group_size
    expected_indexes = [start_index + i for i in range(len(lengths)) if start_index + i < total_data]
    missing = [idx for idx in expected_indexes if idx not in data_map]
    if not missing:
        return data_map
    if len(missing) > 1:
        raise ValueError(f'FEC group {parity.group_index}: too many missing chunks ({missing}).')

    recovered = parity_blob
    for idx in expected_indexes:
        if idx in data_map:
            recovered = _xor_bytes(recovered, data_map[idx].ljust(chunk_size, b'\x00'))
    missing_idx = missing[0]
    rel = missing_idx - start_index
    data_map[missing_idx] = recovered[:lengths[rel]]
    return data_map



def _recover_group_rs(group_chunks: List[Chunk], total_data: int, chunk_size: int, nominal_group_size: int) -> Dict[int, bytes]:
    if RSCodec is None:
        raise RuntimeError('reedsolo not installed: cannot decode Reed-Solomon FEC.')
    data_chunks = [c for c in group_chunks if c.kind == KIND_DATA]
    parity_chunks = sorted([c for c in group_chunks if c.kind == KIND_PARITY], key=lambda c: c.parity_index)
    data_map = {c.index: c.payload for c in data_chunks}
    if not parity_chunks:
        return data_map

    lengths, _ = _decode_lengths_from_parity_payload(parity_chunks[0].payload)
    start_index = parity_chunks[0].group_index * nominal_group_size
    expected_indexes = [start_index + i for i in range(len(lengths)) if start_index + i < total_data]
    missing_data = [idx for idx in expected_indexes if idx not in data_map]
    total_parity = max((c.parity_count for c in parity_chunks), default=0)
    if total_parity < 1:
        return data_map
    if not missing_data:
        return data_map

    parity_map: Dict[int, bytes] = {}
    for p in parity_chunks:
        _, blob = _decode_lengths_from_parity_payload(p.payload)
        parity_map[p.parity_index] = blob

    missing_parity = [pi for pi in range(total_parity) if pi not in parity_map]
    total_erasures = len(missing_data) + len(missing_parity)
    if total_erasures > total_parity:
        raise ValueError(
            f'RS group {parity_chunks[0].group_index}: too many erasures '
            f'(missing data={missing_data}, missing parity={missing_parity}).'
        )

    rsc = RSCodec(total_parity)
    for pos in range(chunk_size):
        symbols = bytearray()
        erase_positions = []

        for rel, global_idx in enumerate(expected_indexes):
            if global_idx in data_map:
                symbols.append(data_map[global_idx].ljust(chunk_size, b'\x00')[pos])
            else:
                symbols.append(0)
                erase_positions.append(rel)

        for parity_rel in range(total_parity):
            blob = parity_map.get(parity_rel)
            if blob is None:
                symbols.append(0)
                erase_positions.append(len(expected_indexes) + parity_rel)
            else:
                symbols.append(blob[pos])

        decoded = rsc.decode(bytes(symbols), erase_pos=erase_positions)[0]
        for rel, global_idx in enumerate(expected_indexes):
            if global_idx not in data_map:
                data_map.setdefault(global_idx, bytearray(chunk_size))
                data_map[global_idx][pos] = decoded[rel]

    for rel, global_idx in enumerate(expected_indexes):
        if isinstance(data_map.get(global_idx), bytearray):
            data_map[global_idx] = bytes(data_map[global_idx][:lengths[rel]])
    return data_map



def reconstruct_from_chunks(raw_chunks: Iterable[bytes]) -> Tuple[bytes, dict]:
    parsed = [parse_chunk(raw) for raw in raw_chunks]
    if not parsed:
        raise ValueError('No chunks available.')

    file_ids = {c.file_id for c in parsed}
    if len(file_ids) != 1:
        raise ValueError('Chunks belong to different files.')

    totals = {c.total for c in parsed}
    if len(totals) != 1:
        raise ValueError('Inconsistent total chunk count.')

    total_data = parsed[0].total
    max_version_magic = max((raw[:4] for raw in raw_chunks), default=MAGIC_V1)
    if max_version_magic == MAGIC_V1:
        return _reconstruct_v1(parsed), {
            'fec_enabled': False,
            'fec_group_size': 0,
            'fec_parity_chunks': 0,
            'fec_recovered_chunks': 0,
            'data_chunks_expected': total_data,
            'data_chunks_seen': len(parsed),
            'fec_type': 'none',
            'fec_parity_count': 0,
        }

    data_chunks = [c for c in parsed if c.kind == KIND_DATA]
    parity_chunks = [c for c in parsed if c.kind == KIND_PARITY]
    by_index: Dict[int, bytes] = {c.index: c.payload for c in data_chunks}
    recovered_count = 0
    fec_group_size = max((c.group_size for c in parsed), default=0)
    fec_parity_count = max((c.parity_count for c in parsed), default=0)
    fec_type_code = max((c.fec_type for c in parsed), default=FEC_NONE)
    fec_type_name = {FEC_NONE: 'none', FEC_XOR: 'xor', FEC_RS: 'rs'}.get(fec_type_code, 'unknown')

    groups: Dict[int, List[Chunk]] = {}
    for c in parsed:
        groups.setdefault(c.group_index, []).append(c)

    chunk_size = 0
    for c in data_chunks:
        chunk_size = max(chunk_size, len(c.payload))
    for p in parity_chunks:
        lengths, parity_blob = _decode_lengths_from_parity_payload(p.payload)
        chunk_size = max(chunk_size, len(parity_blob))

    for _, group_items in groups.items():
        before = len(by_index)
        parity_sample = next((c for c in group_items if c.kind == KIND_PARITY), None)
        if parity_sample and parity_sample.fec_type == FEC_RS:
            recovered_map = _recover_group_rs(group_items, total_data, chunk_size, fec_group_size)
        elif parity_sample:
            recovered_map = _recover_group_xor(group_items, total_data, chunk_size, fec_group_size)
        else:
            recovered_map = {c.index: c.payload for c in group_items if c.kind == KIND_DATA}
        by_index.update(recovered_map)
        recovered_count += max(0, len(by_index) - before)

    missing = [idx for idx in range(total_data) if idx not in by_index]
    if missing:
        raise ValueError(f'Missing chunks: {missing[:10]}')

    return b''.join(by_index[idx] for idx in range(total_data)), {
        'fec_enabled': bool(parity_chunks),
        'fec_group_size': fec_group_size,
        'fec_parity_chunks': len(parity_chunks),
        'fec_recovered_chunks': recovered_count,
        'data_chunks_expected': total_data,
        'data_chunks_seen': len(data_chunks),
        'fec_type': fec_type_name,
        'fec_parity_count': fec_parity_count,
    }
