from __future__ import annotations

from pathlib import Path

from badlib import CompressReader, CompressWriter, is_badd_obj, is_trans_obj


def test_badd_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "sample.badd"
    data = b"MZ" + (b"test-data" * 200)

    with CompressWriter(str(path)) as writer:
        writer.write(data)

    assert is_badd_obj(path)
    assert is_trans_obj(path)
    with CompressReader(str(path), verify=True) as reader:
        assert reader.read() == data
        assert reader[:2] == b"MZ"
