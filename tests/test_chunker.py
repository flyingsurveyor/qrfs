import pytest

from qrfs.core.chunker import KIND_PARITY, make_chunks, parse_chunk


def test_make_chunks_emits_qrc3_without_fec():
    chunks = make_chunks(b"hello world" * 20, chunk_size=100, _file_id=b"\x01" * 16)

    assert chunks
    for chunk in chunks:
        raw = chunk.to_bytes()
        assert raw[:4] == b"QRC3"
        parsed = parse_chunk(raw)
        assert parsed.fec_type == 0
        assert parsed.group_size == 0
        assert parsed.parity_count == 0


def test_parse_chunk_rejects_legacy_magics():
    with_legacy_v1 = bytes([0x51, 0x52, 0x43, 0x31, 0x01]) + b"\x00" * 26
    with_legacy_v2 = bytes([0x51, 0x52, 0x43, 0x32, 0x02]) + b"\x00" * 33

    for raw in (with_legacy_v1, with_legacy_v2):
        with pytest.raises(ValueError, match="invalid chunk magic header"):
            parse_chunk(raw)


def test_parity_index_semantics_for_xor_and_rs():
    blob = (b"QRFS parity index semantics test payload." * 20) + b"!"
    file_id = b"\x11" * 16

    xor_chunks = make_chunks(
        blob, chunk_size=100, fec_group_size=3, fec_type="xor", _file_id=file_id
    )
    xor_parity = [c for c in xor_chunks if c.kind == KIND_PARITY]
    assert xor_parity
    assert all(c.parity_index == 0 for c in xor_parity)

    rs_chunks = make_chunks(
        blob,
        chunk_size=100,
        fec_group_size=3,
        fec_parity_count=2,
        fec_type="rs",
        _file_id=file_id,
    )
    rs_parity = [c for c in rs_chunks if c.kind == KIND_PARITY]
    assert rs_parity

    by_group: dict[int, set[int]] = {}
    for chunk in rs_parity:
        by_group.setdefault(chunk.group_index, set()).add(chunk.parity_index)
    assert all(indexes == {0, 1} for indexes in by_group.values())
