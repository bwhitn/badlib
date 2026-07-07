from __future__ import annotations

import io
import lzma
import pickle
import py_compile
import struct
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from badlib import OOXML_CONTENT_TYPES, Type, identify, identify_path, type_names
from badlib.quickid import OOXML_CONTENT_MAP

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MSI_ROOT_ENTRY = (
    b"\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00"
    b"\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00"
)
MSI_CLSID = b"\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
NSIS_FIRSTHEADER = (
    b"\x00\x00\x00\x00"
    b"\xef\xbe\xad\xde"
    b"NullsoftInst"
    b"\x04\x00\x00\x00"
    b"\x20\x00\x00\x00"
    b"DATA"
)


def _bytes_at(offset: int, marker: bytes, *, size: int | None = None) -> bytes:
    data = bytearray(max(offset + len(marker), size or 0))
    data[offset:offset + len(marker)] = marker
    return bytes(data)


def _minimal_pe(
    *,
    machine: int = 0x14C,
    dotnet: bool = False,
    section_payload: bytes = b"",
    overlay: bytes = b"",
) -> bytes:
    pe_offset = 0x80
    optional_header_size = 0xE0
    section_table = pe_offset + 24 + optional_header_size
    raw_offset = 0x200
    raw_size = 0x200
    data = bytearray(raw_offset + raw_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    data[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    data[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    data[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    data[pe_offset + 24:pe_offset + 26] = (0x10B).to_bytes(2, "little")
    if dotnet:
        clr_directory = pe_offset + 24 + 208
        data[clr_directory:clr_directory + 8] = struct.pack("<II", 0x1000, 0x48)
    data[section_table:section_table + 8] = b".text\x00\x00\x00"
    data[section_table + 16:section_table + 20] = raw_size.to_bytes(4, "little")
    data[section_table + 20:section_table + 24] = raw_offset.to_bytes(4, "little")
    payload = section_payload[:raw_size]
    data[raw_offset:raw_offset + len(payload)] = payload
    return bytes(data) + overlay


def _minimal_elf(machine: int) -> bytes:
    data = bytearray(20)
    data[0:4] = b"\x7fELF"
    data[5] = 1
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data)


def _minimal_macho(cpu_type: int) -> bytes:
    return b"\xce\xfa\xed\xfe" + cpu_type.to_bytes(4, "little") + (b"\x00" * 20)


def _zip_with_names(*names: str) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for name in names:
            archive.writestr(name, b"")
    return payload.getvalue()


def _uleb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _wasm_limits(flags: int, minimum: int, maximum: int | None = None) -> bytes:
    payload = bytes([flags]) + _uleb(minimum)
    if flags & 0x01:
        if maximum is None:
            maximum = minimum
        payload += _uleb(maximum)
    return payload


def _wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _minimal_wasm_memory(flags: int) -> bytes:
    memory_section = _wasm_section(5, b"\x01" + _wasm_limits(flags, 1, 2))
    return b"\x00asm\x01\x00\x00\x00" + memory_section


def _minimal_wasm_imported_memory(flags: int) -> bytes:
    import_entry = (
        _uleb(3)
        + b"env"
        + _uleb(6)
        + b"memory"
        + b"\x02"
        + _wasm_limits(flags, 1, 2)
    )
    import_section = _wasm_section(2, b"\x01" + import_entry)
    return b"\x00asm\x01\x00\x00\x00" + import_section


def _ar_archive(member_name: str) -> bytes:
    header = bytearray(b" " * 60)
    encoded_name = member_name.encode("ascii")
    header[:len(encoded_name)] = encoded_name
    header[58:60] = b"`\n"
    return b"!<arch>\n" + bytes(header)


def _minimal_dib() -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 0, 0, 0, 0, 0)
    return header + (b"\x00" * 4)


def _minimal_ico() -> bytes:
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = (
        b"\x01\x01\x00\x00"
        + (1).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + (1).to_bytes(4, "little")
        + (22).to_bytes(4, "little")
    )
    return header + entry + b"\x00"


def _minimal_msi() -> bytes:
    return OLE_MAGIC + (b"\x00" * 8) + MSI_ROOT_ENTRY + (b"\x00" * 8) + MSI_CLSID


def _minimal_dmg() -> bytes:
    return b"koly" + (b"\x00" * 508)


def _autoit_marker(version: bytes) -> bytes:
    data = bytearray(32)
    data[:16] = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")
    data[20:24] = version
    return bytes(data)


BYTE_FILETYPE_CASES = [
    ("UNK", b"not a known file type", Type.UNK),
    ("PE32-X86", _minimal_pe(), Type.PE32 | Type.X86),
    ("PE32-AMD64", _minimal_pe(machine=0x8664), Type.PE32 | Type.AMD64),
    ("PE32-ARM32", _minimal_pe(machine=0x01C0), Type.PE32 | Type.ARM32),
    ("PE32-AARCH64", _minimal_pe(machine=0xAA64), Type.PE32 | Type.AARCH64),
    ("DOTNET", _minimal_pe(dotnet=True), Type.PE32 | Type.X86 | Type.DOTNET),
    ("NSIS", _minimal_pe(overlay=NSIS_FIRSTHEADER), Type.PE32 | Type.X86 | Type.NSIS),
    ("ELF-SPARC", _minimal_elf(0x02), Type.ELF | Type.SPARC),
    ("ELF-M68K", _minimal_elf(0x04), Type.ELF | Type.M68K),
    ("ELF-MIPS", _minimal_elf(0x08), Type.ELF | Type.MIPS),
    ("ELF-MIPS64", _minimal_elf(0x0A), Type.ELF | Type.MIPS64),
    ("ELF-HPPA", _minimal_elf(0x0F), Type.ELF | Type.HPPA),
    ("ELF-PPC", _minimal_elf(0x14), Type.ELF | Type.PPC),
    ("ELF-PPC64", _minimal_elf(0x15), Type.ELF | Type.PPC64),
    ("ELF-S390", _minimal_elf(0x16), Type.ELF | Type.S390),
    ("ELF-ALPHA", _minimal_elf(0x29), Type.ELF | Type.ALPHA),
    ("ELF-SUPH", _minimal_elf(0x2A), Type.ELF | Type.SUPH),
    ("ELF-SPARC64", _minimal_elf(0x2B), Type.ELF | Type.SPARC64),
    ("ELF-ARC", _minimal_elf(0x2D), Type.ELF | Type.ARC),
    ("ELF-IA64", _minimal_elf(0x32), Type.ELF | Type.IA64),
    ("ELF-VAX", _minimal_elf(0x4B), Type.ELF | Type.VAX),
    ("ELF-M32R", _minimal_elf(0x58), Type.ELF | Type.M32R),
    ("ELF-OPENR", _minimal_elf(0x5C), Type.ELF | Type.OPENR),
    ("ELF-ARCC", _minimal_elf(0x5D), Type.ELF | Type.ARCC),
    ("ELF-XTEN", _minimal_elf(0x5E), Type.ELF | Type.XTEN),
    ("ELF-TILEPRO", _minimal_elf(0xBC), Type.ELF | Type.TILEPRO),
    ("ELF-TILEGX", _minimal_elf(0xBF), Type.ELF | Type.TILEGX),
    ("ELF-RISCV", _minimal_elf(0xF3), Type.ELF | Type.RISCV),
    ("ELF-CSKY", _minimal_elf(0xFC), Type.ELF | Type.CSKY),
    ("ELF-LOONG", _minimal_elf(0x102), Type.ELF | Type.LOONG),
    ("MACHO-X86", _minimal_macho(0x7), Type.MACHO | Type.X86),
    ("MFAT", b"\xca\xfe\xba\xbe\x00\x00\x00\x01", Type.MACHO | Type.MFAT),
    ("RIFF", b"RIFF" + (b"\x00" * 8), Type.RIFF),
    ("LNK", b"L\x00\x00\x00\x01\x14\x02\x00", Type.LNK),
    ("APK", _zip_with_names("AndroidManifest.xml"), Type.ZIP | Type.APK),
    ("PDF", b"%PDF-1.7\n", Type.PDF),
    (
        "RTF-markers",
        b"{\\rtf1 \\object \\objdata ddeauto includetext hyperlink \\bin \\field}",
        Type.RTF | Type.ROBJ | Type.RDDE | Type.RINC | Type.RHYP | Type.RBIN,
    ),
    ("OLE", OLE_MAGIC, Type.OLE),
    ("OXML", _zip_with_names("[Content_Types].xml"), Type.ZIP | Type.OXML),
    ("MSI", _minimal_msi(), Type.MSI),
    ("ZIP", _zip_with_names("file.txt"), Type.ZIP),
    ("RAR", b"Rar!" + (b"\x00" * 4), Type.RAR),
    ("GZ", b"\x1f\x8b\x08\x00", Type.GZ),
    ("UDF", _bytes_at(0x8001, b"NSR02"), Type.UDF),
    ("ISO", _bytes_at(0x8001, b"CD001"), Type.ISO),
    ("JAR", _zip_with_names("META-INF/MANIFEST.MF"), Type.ZIP | Type.JAR),
    ("SEVENZIP", b"7z\xbc\xaf\x27\x1c", Type.SEVENZIP),
    ("ACE", _bytes_at(7, b"**ACE*"), Type.ACE),
    ("CAB", b"MSCF" + (b"\x00" * 4), Type.CAB),
    ("ARJ", b"\x60\xea", Type.ARJ),
    ("AR", _ar_archive("file.txt/"), Type.AR),
    ("XZ", b"\xfd7zXZ\x00", Type.XZ),
    ("TAR", _bytes_at(257, b"ustar"), Type.TAR),
    ("DMG", _minimal_dmg(), Type.DMG),
    ("Z", b"\x1f\x9d", Type.Z),
    ("LZH", b"\x00\x00-lh0-", Type.LZH),
    ("VHD", b"conectix", Type.VHD),
    ("VHDX", b"vhdxfile", Type.VHDX),
    ("BZ2", b"BZh9", Type.BZ2),
    ("ONE", b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d", Type.ONE),
    ("CLASS", b"\xca\xfe\xba\xbe\x00\x00\x00\x34", Type.CLASS),
    ("JSER", b"\xac\xed\x00\x05", Type.JSER),
    ("DEB", _ar_archive("debian-binary"), Type.AR | Type.DEB),
    ("RPM", b"\xed\xab\xee\xdb", Type.RPM),
    ("DSSTORE", b"\x00\x00\x00\x01Bud1", Type.DSSTORE),
    ("UUE", b"begin 644 sample.txt\n", Type.UUE),
    ("DEX", b"dex\x0a035\x00", Type.DEX),
    ("ZLIB", b"\x78\x9c", Type.ZLIB),
    ("XAR", b"xar!" + (b"\x00" * 4), Type.XAR),
    ("CHM", b"ITSF" + (b"\x00" * 4), Type.CHM),
    ("CRX", b"Cr24" + (b"\x00" * 4), Type.CRX),
    ("MSES", b"#@~^" + (b"\x00" * 4), Type.MSES),
    ("SZDD", b"\x53\x5a\x44\x44\x88\xf0\x27\x33", Type.SZDD),
    ("HLP", b"\x3f\x5f\x03\x00", Type.HLP),
    ("WIM", b"MSWIM\x00\x00\x00", Type.WIM),
    ("WMF", b"\xd7\xcd\xc6\x9a", Type.WMF),
    ("ZST", b"\x28\xb5\x2f\xfd", Type.ZST),
    ("WASM", b"\x00asm\x01\x00\x00\x00", Type.WASM),
    ("WASM32", _minimal_wasm_memory(0x00), Type.WASM | Type.WASM32),
    ("WASM64", _minimal_wasm_memory(0x04), Type.WASM | Type.WASM64),
    ("ARSC", b"\x02\x00\x0c\x00", Type.ARSC),
    ("BXML", b"\x03\x00\x08\x00", Type.BXML),
    ("ASN1", b"\x30\x82", Type.ASN1),
    ("TTF", b"\x00\x01\x00\x00", Type.TTF),
    ("GIF", b"GIF89a", Type.GIF),
    ("ID3", b"ID3\x04\x00\x00", Type.ID3),
    ("JKS", b"\xfe\xed\xfe\xed", Type.JKS),
    ("PYC", b"\xcb\x0d\x0d\x0a\x00\x00\x00\x00c", Type.PYC),
    ("JPEG", b"\xff\xd8\xff\xe0", Type.JPEG),
    ("PRI", b"mrm_pri2", Type.PRI),
    ("CMS", b"PKCX", Type.CMS),
    ("OGG", b"OggS", Type.OGG),
    ("MP4", b"\x00\x00\x00\x18ftypisom", Type.MP4),
    ("PNG", b"\x89PNG\x0d\x0a\x1a\x0a", Type.PNG),
    ("MP3", b"\xff\xfb\x90\x64", Type.MP3),
    ("TORR", b"d8:announce13:http://x4:infod4:name1:xe", Type.TORR),
    ("WOF2", b"wOF2", Type.WOF2),
    ("HTML", b"<html><body></body></html>", Type.HTML),
    ("APPD", b"\x00\x05\x16\x07", Type.APPD),
    ("SQLITE", b"SQLite format 3\x00", Type.SQLITE),
    ("PHP", b"<?php echo 1;", Type.PHP),
    ("ASP", b"<%=" + b" Response.Write(1) %>", Type.ASP),
    ("JSP", b"<%@ page language='java' %>", Type.JSP),
    ("SAVW", b"<!-- saved from url=http://example.invalid -->", Type.SAVW),
    ("PEMC", b"-----BEGIN CERTIFICATE-----\nMIIB", Type.PEMC),
    ("XML", b"<?xml version='1.0'?><root/>", Type.XML),
    ("BPLS", b"bplist00", Type.BPLS),
    ("IURL", b"[InternetShortcut]\nURL=https://example.invalid\n", Type.IURL),
    ("DAA", b"DAA\x00", Type.DAA),
    ("LZIP", b"LZIP", Type.LZIP),
    ("TIF", b"II\x2a\x00", Type.TIF),
    ("BMP", b"BM", Type.BMP),
    ("DIB", _minimal_dib(), Type.DIB),
    ("AU", b".snd", Type.AU),
    ("AIF", b"FORM\x00\x00\x00\x00AIFF", Type.AIF),
    ("AIFC", b"FORM\x00\x00\x00\x00AIFC", Type.AIFC),
    ("ICO", _minimal_ico(), Type.ICO),
    ("SH", b"#!/bin/sh\n", Type.SH),
    ("CPIO", b"070701", Type.CPIO),
    ("WAR", _zip_with_names("WEB-INF/web.xml"), Type.ZIP | Type.WAR),
    ("APPS", b"\x00\x05\x16\x00", Type.APPS),
    ("BOM", b"BOMStore", Type.BOM),
    ("AU300", _autoit_marker(b"EA05"), Type.A3X | Type.AU300),
    ("AU326", _autoit_marker(b"EA06"), Type.A3X | Type.AU326),
    ("U8BOM", b"\xef\xbb\xbftext", Type.U8BOM),
    ("U16LEBOM", b"\xff\xfet\x00", Type.U16LEBOM),
    ("U16BEBOM", b"\xfe\xff\x00t", Type.U16BEBOM),
    ("U32LEBOM", b"\xff\xfe\x00\x00t\x00\x00\x00", Type.U32LEBOM),
    ("U32BEBOM", b"\x00\x00\xfe\xff\x00\x00\x00t", Type.U32BEBOM),
    ("SVG", b"<svg xmlns='http://www.w3.org/2000/svg'/>", Type.SVG),
    ("PICKLE", pickle.dumps({"payload": 2}, protocol=2), Type.PICKLE),
    ("TNEF", b"\x78\x9f\x3e\x22" + (b"\x00" * 4), Type.TNEF),
    ("LZMA", lzma.compress(b"payload", format=lzma.FORMAT_ALONE), Type.LZMA),
    ("LZ4", b"\x04\x22\x4d\x18\x60\x40\x82", Type.LZ4),
    (
        "EML",
        b"From: analyst@example.invalid\r\n"
        b"To: inbox@example.invalid\r\n"
        b"Subject: sample\r\n"
        b"Date: Wed, 01 Jul 2026 12:00:00 -0400\r\n"
        b"Message-ID: <sample@example.invalid>\r\n"
        b"\r\nbody\r\n",
        Type.EML,
    ),
    ("IQY", b"WEB\n1\nhttps://example.invalid/query\nSelection=EntirePage\n", Type.IQY),
    (
        "LIBRARYMS",
        b"<?xml version='1.0'?>\n"
        b"<libraryDescription xmlns='http://schemas.microsoft.com/windows/2009/library'/>",
        Type.XML | Type.LIBRARYMS,
    ),
]

OOXML_FILETYPE_CASES = [
    (
        "DOCX",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Type.OXML | Type.DOCX,
        ".docx",
    ),
    (
        "DOCM",
        "application/vnd.ms-word.document.macroEnabled.12",
        Type.OXML | Type.DOCM,
        ".docm",
    ),
    (
        "DOTX",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        Type.OXML | Type.DOTX,
        ".dotx",
    ),
    (
        "DOTM",
        "application/vnd.ms-word.template.macroEnabled.12",
        Type.OXML | Type.DOTM,
        ".dotm",
    ),
    (
        "XLSX",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Type.OXML | Type.XLSX,
        ".xlsx",
    ),
    (
        "XLSM",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        Type.OXML | Type.XLSM,
        ".xlsm",
    ),
    (
        "XLTX",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        Type.OXML | Type.XLTX,
        ".xltx",
    ),
    (
        "XLTM",
        "application/vnd.ms-excel.template.macroEnabled.12",
        Type.OXML | Type.XLTM,
        ".xltm",
    ),
    (
        "XLAM",
        "application/vnd.ms-excel.addin.macroEnabled.12",
        Type.OXML | Type.XLAM,
        ".xlam",
    ),
    (
        "PPTX",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Type.OXML | Type.PPTX,
        ".pptx",
    ),
    (
        "PPTM",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        Type.OXML | Type.PPTM,
        ".pptm",
    ),
    (
        "PPSX",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        Type.OXML | Type.PPSX,
        ".ppsx",
    ),
    (
        "PPSM",
        "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
        Type.OXML | Type.PPSM,
        ".ppsm",
    ),
    (
        "POTX",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
        Type.OXML | Type.POTX,
        ".potx",
    ),
    (
        "POTM",
        "application/vnd.ms-powerpoint.template.macroEnabled.12",
        Type.OXML | Type.POTM,
        ".potm",
    ),
    (
        "PPAM",
        "application/vnd.ms-powerpoint.addin.macroEnabled.12",
        Type.OXML | Type.PPAM,
        ".ppam",
    ),
]

OLE_CLSID_FILETYPE_CASES = [
    ("DOC", "00020906-0000-0000-c000-000000000046", Type.DOC),
    ("XLS", "00020810-0000-0000-c000-000000000046", Type.XLS),
    ("PPT", "00020905-0000-0000-c000-000000000046", Type.PPT),
    ("VSD", "00021a14-0000-0000-c000-000000000046", Type.VSD),
    ("MSG", "00020901-0000-0000-c000-000000000046", Type.MSG),
    ("PWZ", "817246f0-720a-11cf-8718-00aa0060263b", Type.PWZ),
    ("XLCH", "00020820-0000-0000-c000-000000000046", Type.XLCH),
    ("OLEL", "00000300-0000-0000-c000-000000000046", Type.OLEL),
    ("FRMF", "8bd21d10-ec42-11ce-9e0d-00aa006002f3", Type.FRMF),
    ("MSP", "00021201-0000-0000-00c0-000000000046", Type.MSP),
    ("MSXML", "88d96a0c-f192-11d4-a65f-0040963251e5", Type.MSXML),
    ("FHTML", "5512d112-5cc6-11cf-8d67-00aa00bdce1d", Type.FHTML),
]


class _FakeOleFile:
    def __init__(self, clsid: str):
        self.direntries = [SimpleNamespace(clsid=clsid)]

    def close(self) -> None:
        return None


def _write_ooxml_file(tmp_path: Path, content_type: str, suffix: str) -> Path:
    path = tmp_path / f"sample{suffix}"
    content = (
        "<Types>"
        f'<Override PartName="/document.xml" ContentType="{content_type}"/>'
        "</Types>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", content)
    return path


def _covered_flags(values: list[Type]) -> set[Type]:
    return {flag for value in values for flag in Type if value & flag}


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(data, expected, id=case_id)
        for case_id, data, expected in BYTE_FILETYPE_CASES
    ],
)
def test_identify_filetype_signatures(data: bytes, expected: Type) -> None:
    result = identify(data)

    assert result & expected == expected


@pytest.mark.parametrize(
    ("content_type", "expected", "suffix"),
    [
        pytest.param(content_type, expected, suffix, id=case_id)
        for case_id, content_type, expected, suffix in OOXML_FILETYPE_CASES
    ],
)
def test_identify_ooxml_filetypes(
    tmp_path: Path,
    content_type: str,
    expected: Type,
    suffix: str,
) -> None:
    path = _write_ooxml_file(tmp_path, content_type, suffix)

    result = identify_path(path)

    assert result & expected == expected


def test_identify_android_package_bundle_path(tmp_path: Path) -> None:
    path = tmp_path / "sample.apks"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("base.apk", b"")

    result = identify_path(path)

    assert result & Type.APKX


def test_identify_webassembly_imported_memory_bitness() -> None:
    result = identify(_minimal_wasm_imported_memory(0x04))

    assert result & (Type.WASM | Type.WASM64) == Type.WASM | Type.WASM64


@pytest.mark.parametrize(
    ("clsid", "expected"),
    [
        pytest.param(clsid, expected, id=case_id)
        for case_id, clsid, expected in OLE_CLSID_FILETYPE_CASES
    ],
)
def test_identify_ole_clsid_filetypes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clsid: str,
    expected: Type,
) -> None:
    path = tmp_path / "sample.ole"
    path.write_bytes(OLE_MAGIC)

    def ole_file_io(_path: str) -> _FakeOleFile:
        return _FakeOleFile(clsid)

    monkeypatch.setitem(sys.modules, "olefile", SimpleNamespace(OleFileIO=ole_file_io))

    result = identify_path(path)

    assert result & (Type.OLE | expected) == Type.OLE | expected


def test_identification_cases_cover_every_filetype() -> None:
    expected_values = [expected for _, _, expected in BYTE_FILETYPE_CASES]
    expected_values.extend(expected for _, _, expected, _ in OOXML_FILETYPE_CASES)
    expected_values.extend(expected for _, _, expected in OLE_CLSID_FILETYPE_CASES)
    expected_values.append(Type.APKX)

    missing = set(Type) - _covered_flags(expected_values)

    assert missing == set()


def test_ooxml_content_type_exports_cover_detector_map() -> None:
    assert set(OOXML_CONTENT_MAP) <= OOXML_CONTENT_TYPES


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
    result = identify(_minimal_pe(overlay=NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert result & Type.X86
    assert result & Type.NSIS
    assert "Nullsoft Scriptable Install System Installer" in type_names(result)


def test_identify_nsis_all_data_len_includes_firstheader() -> None:
    header_len = 4
    payload = b"DATA"
    all_data_len = 28 + len(payload)
    firstheader = (
        b"\x00\x00\x00\x00"
        b"\xef\xbe\xad\xde"
        b"NullsoftInst"
        + header_len.to_bytes(4, "little")
        + all_data_len.to_bytes(4, "little")
        + payload
    )
    result = identify(_minimal_pe(overlay=firstheader))

    assert result & Type.PE32
    assert result & Type.X86
    assert result & Type.NSIS


def test_identify_nsis_signature_inside_pe_section_is_ignored() -> None:
    result = identify(_minimal_pe(section_payload=NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert not result & Type.NSIS


def test_identify_nsis_unaligned_firstheader_is_ignored() -> None:
    result = identify(_minimal_pe(overlay=(b"\x00" * 64) + NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert not result & Type.NSIS


def test_identify_nsis_aligned_firstheader_beyond_legacy_wiggle() -> None:
    result = identify(_minimal_pe(overlay=(b"\x00" * 4608) + NSIS_FIRSTHEADER))

    assert result & Type.PE32
    assert result & Type.NSIS
