from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import badlib.badd_obj as badd_obj
from badlib import (
    CompressReader,
    CompressWriter,
    QuickID,
    Type,
    is_badd_obj,
    is_trans_obj,
)
from badlib.quickid import RTF_MARKER_SCAN_LIMIT


def _footer(size: int) -> bytes:
    return badd_obj._TransCodec.build_footer(size, b"\x00" * 32)


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


@pytest.mark.parametrize("operation", ["read", "bytes", "iteration"])
def test_default_compressed_reader_returns_original_bytes(
    tmp_path: Path,
    operation: str,
) -> None:
    path = tmp_path / "default-reader.badd"
    data = b"MZ" + bytes((index % 251) + 1 for index in range(12_000))
    with CompressWriter(path) as writer:
        writer.write(data)

    with CompressReader(path) as reader:
        if operation == "read":
            result = reader.read()
        elif operation == "bytes":
            result = bytes(reader)
        else:
            result = bytes(iter(reader))

    assert result == data


def test_default_compressed_reader_sized_read_and_slice(tmp_path: Path) -> None:
    path = tmp_path / "range-reader.badd"
    data = b"PK\x03\x04" + (b"range-data" * 2_000)
    with CompressWriter(path) as writer:
        writer.write(data)

    with CompressReader(path) as reader:
        assert reader.read(2_048) == data[:2_048]
        assert reader[500:4_500] == data[500:4_500]


def test_declared_output_limit_rejects_before_read(tmp_path: Path) -> None:
    path = tmp_path / "oversized-footer.badd"
    path.write_bytes((b"\x00" * 1_024) + _footer(1 << 40))

    with pytest.raises(ValueError, match="max_output_size"):
        CompressReader(path)


def test_invalid_block_layout_rejects_before_full_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "invalid-layout.badd"
    path.write_bytes((b"\x00" * 1_024) + _footer(2 * 1024 * 1024))
    allocation_attempted = False

    def guarded_bytearray(*_args, **_kwargs):
        nonlocal allocation_attempted
        allocation_attempted = True
        raise AssertionError("full output allocated before block validation")

    monkeypatch.setattr(badd_obj, "bytearray", guarded_bytearray, raising=False)
    with CompressReader(path) as reader:
        with pytest.raises(ValueError, match="Compressed blocks"):
            reader.read()

    assert not allocation_attempted


def test_declared_block_count_limit_is_configurable(tmp_path: Path) -> None:
    path = tmp_path / "too-many-blocks.badd"
    declared_size = (
        badd_obj._TransCodec.SMALL_LIMIT
        + (2 * badd_obj._TransCodec.BLOCK_SIZE)
        + 1
    )
    path.write_bytes((b"\x00" * 1_024) + _footer(declared_size))

    with pytest.raises(ValueError, match="max_blocks"):
        CompressReader(path, max_blocks=2)


def test_declared_compression_ratio_limit_is_configurable(tmp_path: Path) -> None:
    path = tmp_path / "excessive-ratio.badd"
    path.write_bytes((b"\x00" * 1_024) + _footer(2 * 1024 * 1024))

    with pytest.raises(ValueError, match="max_compression_ratio"):
        CompressReader(path, max_compression_ratio=100)


class _SparseRTF:
    virtual_size = 1 << 40
    prefix = b"{\\rtf1 \\object}"

    def __init__(self) -> None:
        self.largest_slice = 0

    def __len__(self) -> int:
        return self.virtual_size

    def size(self) -> int:
        return self.virtual_size

    def __bytes__(self) -> bytes:
        raise AssertionError("RTF identification materialized the complete input")

    def __getitem__(self, key):
        if isinstance(key, int):
            index = key if key >= 0 else self.virtual_size + key
            return self.prefix[index] if 0 <= index < len(self.prefix) else 0
        start, stop, step = key.indices(self.virtual_size)
        if step != 1:
            raise AssertionError("unexpected non-unit slice")
        length = max(0, stop - start)
        self.largest_slice = max(self.largest_slice, length)
        if length > RTF_MARKER_SCAN_LIMIT:
            raise AssertionError("RTF identification exceeded its scan limit")
        result = bytearray(length)
        overlap_start = max(start, 0)
        overlap_end = min(stop, len(self.prefix))
        if overlap_start < overlap_end:
            target_start = overlap_start - start
            target_end = target_start + overlap_end - overlap_start
            result[target_start:target_end] = self.prefix[overlap_start:overlap_end]
        return bytes(result)

    def find(self, needle, start=0, end=None):
        end = self.virtual_size if end is None else min(end, self.virtual_size)
        return self.prefix.find(needle, start, min(end, len(self.prefix)))


def test_rtf_marker_scan_is_bounded() -> None:
    data = _SparseRTF()
    target = SimpleNamespace(_filetype=Type.UNK, _path=None)

    QuickID(target).identify(data)

    assert target._filetype & Type.RTF
    assert target._filetype & Type.ROBJ
    assert data.largest_slice <= RTF_MARKER_SCAN_LIMIT


def test_compressed_rtf_quickid_path_uses_bounded_reader_slice(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sample.rtf.badd"
    data = b"{\\rtf1 " + (b"A" * 8_192) + b" \\object}"
    with CompressWriter(path) as writer:
        writer.write(data)
    target = SimpleNamespace(_filetype=Type.UNK, _path=path)

    with CompressReader(path) as reader:
        QuickID(target).identify(reader)

    assert target._filetype & Type.RTF
    assert target._filetype & Type.ROBJ
