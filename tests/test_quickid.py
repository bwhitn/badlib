from __future__ import annotations

import lzma
import pickle
import py_compile
from pathlib import Path

from badlib import Type, identify, identify_path, type_names

NSIS_FIRSTHEADER = (
    b"\x00\x00\x00\x00"
    b"\xef\xbe\xad\xde"
    b"NullsoftInst"
    b"\x04\x00\x00\x00"
    b"\x04\x00\x00\x00"
    b"DATA"
)


def _minimal_pe(*, section_payload: bytes = b"", overlay: bytes = b"") -> bytes:
    pe_offset = 0x80
    optional_header_size = 0xE0
    section_table = pe_offset + 24 + optional_header_size
    raw_offset = 0x200
    raw_size = 0x200
    data = bytearray(raw_offset + raw_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    data[pe_offset + 4:pe_offset + 6] = (0x14C).to_bytes(2, "little")
    data[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    data[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    data[pe_offset + 24:pe_offset + 26] = (0x10B).to_bytes(2, "little")
    data[section_table:section_table + 8] = b".text\x00\x00\x00"
    data[section_table + 16:section_table + 20] = raw_size.to_bytes(4, "little")
    data[section_table + 20:section_table + 24] = raw_offset.to_bytes(4, "little")
    data[raw_offset:raw_offset + len(section_payload)] = section_payload[:raw_size]
    return bytes(data) + overlay


def test_identify_bytes() -> None:
    result = identify(b"PK\x03\x04" + (b"\x00" * 32))

    assert result & Type.ZIP
    assert "ZIP Compressed Archive" in type_names(result)


def test_identify_path(tmp_path: Path) -> None:
    path = tmp_path / "sample.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00" + (b"\x00" * 32))

    assert identify_path(path) & Type.GZ


def test_identify_svg_plain_markup() -> None:
    result = identify(b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>')

    assert result & Type.SVG
    assert "Scalable Vector Graphics" in type_names(result)


def test_identify_svg_xml_declaration() -> None:
    result = identify(
        b'<?xml version="1.0"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'
    )

    assert result & Type.SVG
    assert not result & Type.XML


def test_identify_binary_pickle_protocols() -> None:
    for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
        result = identify(pickle.dumps({"payload": protocol}, protocol=protocol))

        assert result & Type.PICKLE
        assert "Python Pickle" in type_names(result)


def test_identify_text_pickle_protocol_without_magic_as_unknown() -> None:
    assert identify(pickle.dumps({"payload": 0}, protocol=0)) == Type.UNK


def test_identify_tnef_magic() -> None:
    result = identify(b"\x78\x9f\x3e\x22" + (b"\x00" * 32))

    assert result & Type.TNEF
    assert "Transport Neutral Encapsulation Format" in type_names(result)


def test_identify_lz4_frame_magic() -> None:
    result = identify(b"\x04\x22\x4d\x18\x60\x40\x82" + (b"\x00" * 32))

    assert result & Type.LZ4
    assert "LZ4 Compressed" in type_names(result)


def test_identify_legacy_lz4_frame_magic() -> None:
    result = identify(b"\x02\x21\x4c\x18" + (b"\x00" * 32))

    assert result & Type.LZ4


def test_identify_lzma_alone_stream() -> None:
    result = identify(lzma.compress(b"payload", format=lzma.FORMAT_ALONE))

    assert result & Type.LZMA
    assert "LZMA Compressed" in type_names(result)


def test_identify_wasm_requires_version() -> None:
    assert identify(b"\x00asm\x01\x00\x00\x00") & Type.WASM
    assert not identify(b"\x00asmBAD!") & Type.WASM


def test_identify_current_python_bytecode(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    bytecode = tmp_path / "sample.pyc"
    source.write_text("value = 1\n")
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)

    result = identify_path(bytecode)

    assert result & Type.PYC
    assert "Python Bytecode" in type_names(result)


def test_identify_iqy_text() -> None:
    result = identify(b"WEB\n1\nhttps://example.invalid/query\nSelection=EntirePage\n")

    assert result & Type.IQY
    assert "Microsoft Internet Query" in type_names(result)


def test_identify_library_ms_xml() -> None:
    result = identify(
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">\n'
        b"</libraryDescription>\n"
    )

    assert result & Type.XML
    assert result & Type.LIBRARYMS
    assert "Windows Library Description" in type_names(result)


def test_identify_eml_headers() -> None:
    result = identify(
        b"From: analyst@example.invalid\r\n"
        b"To: inbox@example.invalid\r\n"
        b"Subject: sample\r\n"
        b"Date: Wed, 01 Jul 2026 12:00:00 -0400\r\n"
        b"Message-ID: <sample@example.invalid>\r\n"
        b"\r\n"
        b"body\r\n"
    )

    assert result & Type.EML
    assert "Email Message" in type_names(result)


def test_identify_autoit_compiled_a3x_marker() -> None:
    data = bytearray(32)
    data[:16] = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")
    data[20:24] = b"EA06"

    result = identify(bytes(data))

    assert result & Type.A3X
    assert result & Type.AU326
    assert "AutoIt Compiled Script" in type_names(result)


def test_identify_nsis_pe_overlay_firstheader() -> None:
    result = identify(_minimal_pe(overlay=(b"\x00" * 64) + NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert result & Type.X86
    assert result & Type.NSIS
    assert "Nullsoft Scriptable Install System Installer" in type_names(result)


def test_identify_nsis_signature_inside_pe_section_is_ignored() -> None:
    result = identify(_minimal_pe(section_payload=NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert not result & Type.NSIS


def test_identify_nsis_signature_too_far_from_overlay_is_ignored() -> None:
    result = identify(_minimal_pe(overlay=(b"\x00" * 4097) + NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert not result & Type.NSIS
