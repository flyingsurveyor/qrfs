import json
import struct
import zlib

MAGIC = b'QFSP'
VERSION = 1


def pack_file_payload(filename: str, mime_type: str, file_bytes: bytes, compress: bool = True) -> bytes:
    original_bytes = file_bytes
    compressed_flag = 0
    if compress:
        compressed = zlib.compress(file_bytes, level=9)
        if len(compressed) < len(file_bytes):
            file_bytes = compressed
            compressed_flag = 1

    metadata = {
        'filename': filename,
        'mime_type': mime_type,
        'compressed': bool(compressed_flag),
        'original_size': len(original_bytes),
    }
    metadata_bytes = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
    header = MAGIC + struct.pack('>BII', VERSION, len(metadata_bytes), len(file_bytes))
    return header + metadata_bytes + file_bytes



def unpack_file_payload(payload: bytes) -> dict:
    if payload[:4] != MAGIC:
        raise ValueError('Invalid payload magic.')
    version, metadata_len, data_len = struct.unpack('>BII', payload[4:13])
    if version != VERSION:
        raise ValueError(f'Unsupported payload version: {version}')

    metadata_start = 13
    metadata_end = metadata_start + metadata_len
    data_end = metadata_end + data_len
    metadata = json.loads(payload[metadata_start:metadata_end].decode('utf-8'))
    file_bytes = payload[metadata_end:data_end]

    if metadata.get('compressed'):
        file_bytes = zlib.decompress(file_bytes)

    metadata['file_bytes'] = file_bytes
    metadata['qr_count'] = None
    return metadata
