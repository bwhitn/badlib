import hashlib
import inspect
import lzma
import math
from collections import OrderedDict
from dataclasses import dataclass
from mmap import ACCESS_READ, mmap
from pathlib import Path
from typing import Callable, Optional

__all__ = [
    "CompressObj",
    "CompressReader",
    "CompressWriter",
    "is_badd_obj",
    "is_trans_obj",
]

# format:
# - size <= 1024: data xor 0x55 + footer
# - size > 1024: 512 xor 0x55 + lzma2 raw blocks (3-byte size header) + 512 xor 0x55 + footer
# - footer: BADD magic + uint64le uncompressed size + sha256 bytes


@dataclass(frozen=True)
class _Block:
    comp_offset: int
    comp_len: int
    u_offset: int
    u_len: int


class _TransCodec:
    MAGIC = b"\xBA\xDD"
    FOOTER_LEN = 2 + 8 + 32
    HEAD_SIZE = 512
    TAIL_SIZE = 512
    SMALL_LIMIT = HEAD_SIZE + TAIL_SIZE
    BLOCK_SIZE = 0x300000
    MAX_BLOCK_LEN = 0xFFFFFF
    XOR_TABLE = bytes(i ^ 0x55 for i in range(256))

    def __init__(self, compress: Optional[Callable[[bytes], bytes]] = None,
                 decompress: Optional[Callable[..., bytes]] = None):
        self.compress = compress or self._lzma2_compress
        self.decompress = decompress or self._lzma2_decompress
        try:
            self._decompress_accepts_limit = len(inspect.signature(self.decompress).parameters) > 1
        except (TypeError, ValueError):
            self._decompress_accepts_limit = False

    @classmethod
    def xor(cls, data: bytes) -> bytes:
        return data.translate(cls.XOR_TABLE)

    @classmethod
    def parse_footer(cls, data: mmap) -> tuple[int, bytes, int]:
        if len(data) < cls.FOOTER_LEN:
            raise ValueError("File is too small")
        footer = data[-cls.FOOTER_LEN:]
        if footer[:2] != cls.MAGIC:
            raise ValueError("Incorrect footer magic")
        size = int.from_bytes(footer[2:10], byteorder="little")
        sha256 = footer[10:42]
        footer_offset = len(data) - cls.FOOTER_LEN
        return size, sha256, footer_offset

    @classmethod
    def build_footer(cls, size: int, sha256: bytes) -> bytes:
        return cls.MAGIC + size.to_bytes(8, byteorder="little") + sha256

    def decompress_block(self, data: bytes, expected: int) -> bytes:
        if self._decompress_accepts_limit:
            return self.decompress(data, expected)
        return self.decompress(data)

    @staticmethod
    def _lzma2_compress(data: bytes) -> bytes:
        comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2}])
        return comp.compress(data) + comp.flush()

    @staticmethod
    def _lzma2_decompress(data: bytes, expected: Optional[int] = None) -> bytes:
        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2}])
        if expected is None:
            return decomp.decompress(data)
        return decomp.decompress(data, max_length=expected)


def is_badd_obj(path: str | Path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            if size < _TransCodec.FOOTER_LEN:
                return False
            fh.seek(-_TransCodec.FOOTER_LEN, 2)
            footer = fh.read(_TransCodec.FOOTER_LEN)
            return len(footer) == _TransCodec.FOOTER_LEN and footer[:2] == _TransCodec.MAGIC
    except OSError:
        return False


is_trans_obj = is_badd_obj


class CompressReader:
    DEFAULT_MAX_OUTPUT_SIZE = 256 * 1024 * 1024
    DEFAULT_MAX_BLOCKS = 128
    DEFAULT_MAX_COMPRESSION_RATIO = 100_000.0

    def __init__(self, file: str, decompress: Optional[Callable[..., bytes]] = None,
                 cache_blocks: int = 4, verify: bool = False,
                 max_output_size: Optional[int] = DEFAULT_MAX_OUTPUT_SIZE,
                 max_blocks: Optional[int] = DEFAULT_MAX_BLOCKS,
                 max_compression_ratio: Optional[float] = DEFAULT_MAX_COMPRESSION_RATIO):
        self.file = str(file)
        self._codec = _TransCodec(decompress=decompress)
        self._fh = None
        self._mh = None
        self._max_output_size = self._validate_int_limit(
            max_output_size, "max_output_size"
        )
        self._max_blocks = self._validate_int_limit(max_blocks, "max_blocks")
        self._max_compression_ratio = self._validate_ratio_limit(
            max_compression_ratio
        )
        try:
            self._fh = open(self.file, "rb")
            self._mh = mmap(self._fh.fileno(), 0, access=ACCESS_READ)
            self._size, self._sha256, self._footer_offset = self._codec.parse_footer(self._mh)
            self._validate_declared_limits()
            self._compressed = self._size > self._codec.SMALL_LIMIT
            self._blocks: list[_Block] = []
            self._blocks_ready = False
            self._block_cache = OrderedDict()
            self._cache_blocks = max(0, int(cache_blocks))
            self._full_data: Optional[bytes] = None
            self._tail_offset: Optional[int] = None
            self._middle_len: int = 0
            self._expected_blocks: int = 0
            if self._compressed:
                if self._size <= (self._codec.HEAD_SIZE + self._codec.TAIL_SIZE):
                    raise ValueError("Invalid uncompressed size for compressed file")
                self._tail_offset = self._footer_offset - self._codec.TAIL_SIZE
                if self._tail_offset < self._codec.HEAD_SIZE:
                    raise ValueError("Invalid layout for compressed file")
                self._middle_len = self._size - self._codec.HEAD_SIZE - self._codec.TAIL_SIZE
                self._expected_blocks = (
                    self._middle_len + self._codec.BLOCK_SIZE - 1
                ) // self._codec.BLOCK_SIZE
                if self._max_blocks is not None and self._expected_blocks > self._max_blocks:
                    raise ValueError(
                        f"Declared block count exceeds max_blocks "
                        f"({self._expected_blocks} > {self._max_blocks})"
                    )
            elif self._footer_offset != self._size:
                raise ValueError("Unexpected data length for uncompressed file")
            if verify:
                self.verify(raise_on_fail=True)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _validate_int_limit(value: Optional[int], name: str) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int or None")
        if value < 0:
            raise ValueError(f"{name} must be non-negative")
        return value

    @staticmethod
    def _validate_ratio_limit(value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("max_compression_ratio must be a number or None")
        ratio = float(value)
        if not math.isfinite(ratio) or ratio <= 0:
            raise ValueError("max_compression_ratio must be finite and positive")
        return ratio

    def _validate_declared_limits(self) -> None:
        if self._max_output_size is not None and self._size > self._max_output_size:
            raise ValueError(
                f"Declared output size exceeds max_output_size "
                f"({self._size} > {self._max_output_size})"
            )
        if self._max_compression_ratio is not None and self._size:
            ratio = self._size / max(1, self._footer_offset)
            if ratio > self._max_compression_ratio:
                raise ValueError(
                    f"Declared compression ratio exceeds max_compression_ratio "
                    f"({ratio:.2f} > {self._max_compression_ratio:.2f})"
                )

    def _build_blocks(self) -> None:
        if self._blocks_ready:
            return
        comp_end = self._tail_offset
        offset = self._codec.HEAD_SIZE
        remaining = self._middle_len
        u_offset = 0
        blocks: list[_Block] = []
        while offset < comp_end and remaining > 0:
            if self._max_blocks is not None and len(blocks) >= self._max_blocks:
                raise ValueError("Compressed block count exceeds max_blocks")
            if offset + 3 > comp_end:
                raise ValueError("Truncated compressed block header")
            comp_len = int.from_bytes(self._mh[offset:offset + 3], byteorder="little")
            offset += 3
            if comp_len <= 0:
                raise ValueError("Invalid compressed block size")
            if offset + comp_len > comp_end:
                raise ValueError("Truncated compressed block data")
            u_size = min(self._codec.BLOCK_SIZE, remaining)
            blocks.append(_Block(offset, comp_len, u_offset, u_size))
            offset += comp_len
            u_offset += u_size
            remaining -= u_size
        if remaining != 0:
            raise ValueError("Compressed blocks do not match expected size")
        if offset != comp_end:
            raise ValueError("Unexpected trailing compressed data")
        if len(blocks) != self._expected_blocks:
            raise ValueError("Compressed block count does not match expected size")
        self._blocks = blocks
        self._blocks_ready = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self):
        return self._size

    @property
    def sha256_bytes(self) -> bytes:
        return self._sha256

    @property
    def sha256_hex(self) -> str:
        return self._sha256.hex()

    def __bytes__(self):
        return self.read()

    def __iter__(self):
        return iter(self.read())

    def __getitem__(self, item):
        if isinstance(item, slice):
            start, stop, step = item.indices(self._size)
            if step != 1:
                return self.read()[item]
            if start >= stop:
                return b""
            return self._read_range(start, stop)
        if isinstance(item, int):
            idx = item
            if idx < 0:
                idx += self._size
            if idx < 0 or idx >= self._size:
                raise IndexError("index out of range")
            return self._read_range(idx, idx + 1)[0]
        raise TypeError("Invalid index type")

    def _get_block(self, index: int) -> bytes:
        if self._full_data is not None:
            block = self._blocks[index]
            start = self._codec.HEAD_SIZE + block.u_offset
            end = start + block.u_len
            return self._full_data[start:end]
        if not self._blocks_ready:
            self._build_blocks()
        if index in self._block_cache:
            data = self._block_cache.pop(index)
            self._block_cache[index] = data
            return data
        block = self._blocks[index]
        comp = self._mh[block.comp_offset:block.comp_offset + block.comp_len]
        data = self._codec.decompress_block(comp, block.u_len)
        if len(data) != block.u_len:
            raise ValueError("Decompressed block size mismatch")
        if self._cache_blocks > 0:
            self._block_cache[index] = data
            if len(self._block_cache) > self._cache_blocks:
                self._block_cache.popitem(last=False)
        return data

    def _iter_uncompressed_chunks(self, start: int, end: int):
        if not self._compressed:
            if start < end:
                yield start, self._codec.xor(self._mh[start:end])
            return
        mid_start = self._codec.HEAD_SIZE
        mid_end = self._size - self._codec.TAIL_SIZE
        if start < mid_start:
            head_end = min(end, mid_start)
            if start < head_end:
                yield start, self._codec.xor(self._mh[start:head_end])
        if end > mid_start and start < mid_end:
            if not self._blocks_ready:
                self._build_blocks()
            m_start = max(start, mid_start) - mid_start
            m_end = min(end, mid_end) - mid_start
            for i, block in enumerate(self._blocks):
                block_start = block.u_offset
                block_end = block_start + block.u_len
                if block_end <= m_start:
                    continue
                if block_start >= m_end:
                    break
                data = self._get_block(i)
                s = max(m_start, block_start) - block_start
                e = min(m_end, block_end) - block_start
                seg_start = mid_start + block_start + s
                yield seg_start, data[s:e]
        if end > mid_end:
            tail_start = max(start, mid_end)
            tail_end = min(end, self._size)
            if tail_start < tail_end:
                offset = self._tail_offset + (tail_start - mid_end)
                yield tail_start, self._codec.xor(self._mh[offset:offset + (tail_end - tail_start)])

    def _read_range(self, start: int, stop: int) -> bytes:
        if self._full_data is not None:
            return self._full_data[start:stop]
        if not self._compressed:
            return self._codec.xor(self._mh[start:stop])
        out = bytearray()
        for _, chunk in self._iter_uncompressed_chunks(start, stop):
            out.extend(chunk)
        return bytes(out)

    def read(self, size: int = 0):
        if size and size > 0 and self._full_data is None:
            size = min(size, self._size)
            return self._read_range(0, size)
        if self._full_data is not None:
            data = self._full_data
        else:
            if not self._compressed:
                self._full_data = self._codec.xor(self._mh[:self._size])
                data = self._full_data
            else:
                self._build_blocks()
                out = bytearray(self._size)
                out[:self._codec.HEAD_SIZE] = self._codec.xor(self._mh[:self._codec.HEAD_SIZE])
                tail_start = self._tail_offset
                tail_end = self._tail_offset + self._codec.TAIL_SIZE
                out[-self._codec.TAIL_SIZE:] = self._codec.xor(self._mh[tail_start:tail_end])
                pos = self._codec.HEAD_SIZE
                for i in range(len(self._blocks)):
                    data_block = self._get_block(i)
                    out[pos:pos + len(data_block)] = data_block
                    pos += len(data_block)
                self._full_data = bytes(out)
                data = self._full_data
        if size and size > 0:
            return data[:size]
        return data

    def iter_chunks(self, start: int = 0, end: Optional[int] = None):
        if end is None:
            end = self._size
        start, end, _ = slice(start, end, 1).indices(self._size)
        if start >= end:
            return
        for _, chunk in self._iter_uncompressed_chunks(start, end):
            if chunk:
                yield chunk

    def find(self, sub: bytes | bytearray | memoryview | int, start: int = 0,
             end: Optional[int] = None) -> int:
        if isinstance(sub, int):
            if sub < 0 or sub > 255:
                raise ValueError("byte must be in range(0, 256)")
            needle = bytes([sub])
        elif isinstance(sub, (bytes, bytearray, memoryview)):
            needle = bytes(sub)
        else:
            raise TypeError("sub must be bytes-like or int")
        if end is None:
            end = self._size
        start, end, _ = slice(start, end, 1).indices(self._size)
        if start > end:
            return -1
        if not needle:
            return start
        if end - start < len(needle):
            return -1
        if self._full_data is not None:
            return self._full_data.find(needle, start, end)
        if not self._compressed and self._size <= self._codec.SMALL_LIMIT:
            data = self._codec.xor(self._mh[start:end])
            idx = data.find(needle)
            return start + idx if idx >= 0 else -1
        nlen = len(needle)
        carry = b""
        prev_end = start
        for seg_start, chunk in self._iter_uncompressed_chunks(start, end):
            if not chunk:
                continue
            if seg_start != prev_end:
                carry = b""
            data = carry + chunk
            data_start = seg_start - len(carry)
            idx = data.find(needle)
            while idx != -1:
                global_idx = data_start + idx
                if global_idx >= start and global_idx + nlen <= end:
                    return global_idx
                idx = data.find(needle, idx + 1)
            if nlen > 1:
                if len(data) >= nlen - 1:
                    carry = data[-(nlen - 1):]
                else:
                    carry = data
            else:
                carry = b""
            prev_end = seg_start + len(chunk)
        return -1

    def close(self):
        try:
            if self._mh is not None:
                self._mh.close()
        finally:
            self._mh = None
        try:
            if self._fh is not None:
                self._fh.close()
        finally:
            self._fh = None

    def verify(self, raise_on_fail: bool = False) -> bool:
        if self._full_data is not None:
            digest = hashlib.sha256(self._full_data).digest()
        else:
            hasher = hashlib.sha256()
            expected_offset = 0
            for offset, chunk in self._iter_uncompressed_chunks(0, self._size):
                if offset != expected_offset:
                    raise ValueError("Unexpected gap while hashing")
                hasher.update(chunk)
                expected_offset += len(chunk)
            if expected_offset != self._size:
                raise ValueError("Unexpected data length while hashing")
            digest = hasher.digest()
        ok = digest == self._sha256
        if not ok and raise_on_fail:
            raise ValueError("SHA256 mismatch")
        return ok

class CompressWriter:
    def __init__(self, file: str, compress: Optional[Callable[[bytes], bytes]] = None):
        self.file = str(file)
        self._codec = _TransCodec(compress=compress)
        self._fh = open(self.file, "wb")
        self._size = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __getitem__(self, item):
        raise TypeError("write-only object does not support indexing")

    def read(self, size: int = 0):
        raise ValueError("read is only valid in rb mode")

    def find(self, *args, **kwargs):
        raise ValueError("find is only valid in rb mode")

    def write(self, data: bytes | bytearray | memoryview):
        view = memoryview(data)
        self._size = len(view)
        sha256 = hashlib.sha256(view).digest()
        footer = self._codec.build_footer(self._size, sha256)
        if self._size <= self._codec.SMALL_LIMIT:
            self._fh.write(self._codec.xor(view.tobytes()))
            self._fh.write(footer)
            self._fh.flush()
            return
        head = self._codec.xor(view[:self._codec.HEAD_SIZE].tobytes())
        tail = self._codec.xor(view[-self._codec.TAIL_SIZE:].tobytes())
        self._fh.write(head)
        middle = view[self._codec.HEAD_SIZE:-self._codec.TAIL_SIZE]
        for offset in range(0, len(middle), self._codec.BLOCK_SIZE):
            block = middle[offset:offset + self._codec.BLOCK_SIZE].tobytes()
            comp = self._codec.compress(block)
            comp_len = len(comp)
            if comp_len > self._codec.MAX_BLOCK_LEN:
                raise ValueError("Compressed block too large")
            self._fh.write(comp_len.to_bytes(3, byteorder="little"))
            self._fh.write(comp)
        self._fh.write(tail)
        self._fh.write(footer)
        self._fh.flush()

    def close(self):
        try:
            if self._fh is not None:
                self._fh.close()
        finally:
            self._fh = None


class CompressObj:
    def __init__(self, file: str, mode: str = "rb",
                 compress: Optional[Callable[[bytes], bytes]] = None,
                 decompress: Optional[Callable[..., bytes]] = None,
                 cache_blocks: int = 4,
                 verify: bool = False,
                 max_output_size: Optional[int] = CompressReader.DEFAULT_MAX_OUTPUT_SIZE,
                 max_blocks: Optional[int] = CompressReader.DEFAULT_MAX_BLOCKS,
                 max_compression_ratio: Optional[float] = CompressReader.DEFAULT_MAX_COMPRESSION_RATIO):
        self.mode = mode
        if mode == "rb":
            self._impl = CompressReader(file=file, decompress=decompress, cache_blocks=cache_blocks,
                                        verify=verify, max_output_size=max_output_size,
                                        max_blocks=max_blocks,
                                        max_compression_ratio=max_compression_ratio)
        elif mode == "wb":
            self._impl = CompressWriter(file=file, compress=compress)
        else:
            raise ValueError("mode must be one of 'wb' or 'rb'")

    def __enter__(self):
        self._impl.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._impl.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name: str):
        return getattr(self._impl, name)

    def __len__(self):
        return len(self._impl)

    def __bytes__(self):
        return bytes(self._impl)

    def __iter__(self):
        return iter(self._impl)

    def __getitem__(self, item):
        return self._impl[item]

    def read(self, size: int = 0):
        return self._impl.read(size)

    def write(self, data: bytes | bytearray | memoryview):
        return self._impl.write(data)

    def find(self, sub: bytes | bytearray | memoryview | int, start: int = 0,
             end: Optional[int] = None) -> int:
        return self._impl.find(sub, start=start, end=end)

    def close(self):
        return self._impl.close()
