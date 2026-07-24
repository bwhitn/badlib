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

from badlib import (
    OOXML_CONTENT_TYPES,
    Type,
    format_ids,
    identify,
    identify_path,
    resolve_format_id,
    type_names,
)
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
    section_name: bytes = b".text",
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
    data[section_table:section_table + 8] = section_name[:8].ljust(8, b"\0")
    data[section_table + 16:section_table + 20] = raw_size.to_bytes(4, "little")
    data[section_table + 20:section_table + 24] = raw_offset.to_bytes(4, "little")
    payload = section_payload[:raw_size]
    data[raw_offset:raw_offset + len(payload)] = payload
    return bytes(data) + overlay


def _minimal_pe_with_sections(
    section_names: list[bytes],
    section_payload: bytes = b"",
) -> bytes:
    pe_offset = 0x80
    optional_header_size = 0xE0
    section_table = pe_offset + 24 + optional_header_size
    raw_offset = 0x200
    raw_size = 0x200
    data = bytearray(raw_offset + (raw_size * len(section_names)))
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    data[pe_offset + 4:pe_offset + 6] = (0x14C).to_bytes(2, "little")
    data[pe_offset + 6:pe_offset + 8] = len(section_names).to_bytes(2, "little")
    data[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    data[pe_offset + 24:pe_offset + 26] = (0x10B).to_bytes(2, "little")
    for index, section_name in enumerate(section_names):
        section = section_table + (index * 40)
        section_raw_offset = raw_offset + (index * raw_size)
        data[section:section + 8] = section_name[:8].ljust(8, b"\0")
        data[section + 16:section + 20] = raw_size.to_bytes(4, "little")
        data[section + 20:section + 24] = section_raw_offset.to_bytes(4, "little")
    payload = section_payload[:raw_size]
    data[raw_offset:raw_offset + len(payload)] = payload
    return bytes(data)


def _minimal_elf(machine: int) -> bytes:
    data = bytearray(20)
    data[0:4] = b"\x7fELF"
    data[5] = 1
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data)


def _minimal_elf_with_load(
    *,
    machine: int,
    bits: int,
    endian: str,
    stub: bytes,
    stub_delta: int = 0,
    entry_delta: int = 0,
    segment_flags: int = 5,
) -> bytes:
    endian_flag = 1 if endian == "little" else 2
    elf_class = 2 if bits == 64 else 1
    phoff = 0x40 if bits == 64 else 0x34
    phentsize = 56 if bits == 64 else 32
    raw_offset = 0x100
    vaddr = 0x400000
    segment_size = max(0x200, stub_delta + len(stub), entry_delta + 1)
    data = bytearray(raw_offset + segment_size)

    def put(offset: int, value: int, size: int) -> None:
        data[offset:offset + size] = value.to_bytes(size, endian)

    data[0:4] = b"\x7fELF"
    data[4] = elf_class
    data[5] = endian_flag
    data[6] = 1
    put(16, 2, 2)
    put(18, machine, 2)
    put(20, 1, 4)

    entry = vaddr + entry_delta
    if bits == 64:
        put(24, entry, 8)
        put(32, phoff, 8)
        put(52, 64, 2)
        put(54, phentsize, 2)
        put(56, 1, 2)
        put(phoff, 1, 4)
        put(phoff + 4, segment_flags, 4)
        put(phoff + 8, raw_offset, 8)
        put(phoff + 16, vaddr, 8)
        put(phoff + 24, vaddr, 8)
        put(phoff + 32, segment_size, 8)
        put(phoff + 40, segment_size, 8)
        put(phoff + 48, 0x1000, 8)
    else:
        put(24, entry, 4)
        put(28, phoff, 4)
        put(40, 52, 2)
        put(42, phentsize, 2)
        put(44, 1, 2)
        put(phoff, 1, 4)
        put(phoff + 4, raw_offset, 4)
        put(phoff + 8, vaddr, 4)
        put(phoff + 12, vaddr, 4)
        put(phoff + 16, segment_size, 4)
        put(phoff + 20, segment_size, 4)
        put(phoff + 24, segment_flags, 4)
        put(phoff + 28, 0x1000, 4)

    start = raw_offset + stub_delta
    data[start:start + len(stub)] = stub
    return bytes(data)


def _minimal_macho(cpu_type: int) -> bytes:
    return b"\xce\xfa\xed\xfe" + cpu_type.to_bytes(4, "little") + (b"\x00" * 20)


def _zip_with_names(*names: str) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for name in names:
            archive.writestr(name, b"")
    return payload.getvalue()


def _write_zip(
    path: Path,
    entries: dict[str, bytes | str],
    *,
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, content in entries.items():
            payload = content.encode("utf-8") if isinstance(content, str) else content
            archive.writestr(name, payload)
    return path


def _write_ooxml_package(
    tmp_path: Path,
    suffix: str,
    content_type: str,
    extra: dict[str, bytes | str],
) -> Path:
    content_types = (
        "<Types>"
        f'<Override PartName="/xl/workbook.bin" ContentType="{content_type}"/>'
        "</Types>"
    )
    entries: dict[str, bytes | str] = {
        "[Content_Types].xml": content_types,
        "_rels/.rels": "",
    }
    entries.update(extra)
    return _write_zip(tmp_path / f"sample{suffix}", entries)


def _write_odf_package(tmp_path: Path, suffix: str, mimetype: str) -> Path:
    return _write_zip(
        tmp_path / f"sample{suffix}",
        {
            "mimetype": mimetype,
            "content.xml": "<office:document-content/>",
        },
    )


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
    (
        "UPX-PE-info",
        _minimal_pe(
            section_payload=(
                b"$Info: This file is packed with the UPX executable "
                b"packer"
            ),
        ),
        Type.PE32 | Type.X86 | Type.UPX,
    ),
    (
        "UPX-PE-section-marker",
        _minimal_pe(section_name=b"UPX1", section_payload=b"\x00UPX!\x00"),
        Type.PE32 | Type.X86 | Type.UPX,
    ),
    (
        "actual-installer",
        _minimal_pe(section_payload=b"Actual Installer package"),
        Type.PE32 | Type.X86 | Type.ACTUAL_INSTALLER,
    ),
    (
        "advanced-installer",
        _minimal_pe(section_payload=b"Advanced Installer bootstrapper"),
        Type.PE32 | Type.X86 | Type.ADVANCED_INSTALLER,
    ),
    (
        "inno-setup",
        _minimal_pe(section_payload=b"Inno Setup Setup Data"),
        Type.PE32 | Type.X86 | Type.INNO_SETUP,
    ),
    (
        "installanywhere",
        _minimal_pe(section_payload=b"InstallAnywhere Zero G"),
        Type.PE32 | Type.X86 | Type.INSTALLANYWHERE,
    ),
    (
        "installshield",
        _minimal_pe(section_payload=b"InstallShield ISSetup setup.inx data1.cab"),
        Type.PE32 | Type.X86 | Type.INSTALLSHIELD,
    ),
    (
        "wise-installer",
        _minimal_pe(section_payload=b"Wise Installation System"),
        Type.PE32 | Type.X86 | Type.WISE_INSTALLER,
    ),
    (
        "wix",
        _minimal_pe(section_payload=b"WiX Toolset Burn Bootstrapper WixBundle"),
        Type.PE32 | Type.X86 | Type.WIX,
    ),
    (
        "nodejs-pkg",
        _minimal_pe(section_payload=b"pkg/prelude/bootstrap.js package.json node.js"),
        Type.PE32 | Type.X86 | Type.NODEJS_PKG,
    ),
    (
        "sfx-peexe",
        _minimal_pe(overlay=b"PK\x03\x04payload"),
        Type.PE32 | Type.X86 | Type.SFX_PEEXE,
    ),
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
    (
        "UPX-ELF-info",
        _minimal_elf(0x3E)
        + b"$Info: This file is packed with the UPX executable packer",
        Type.ELF | Type.AMD64 | Type.UPX,
    ),
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
    ("HWP", OLE_MAGIC + b"FileHeader HWP Document File", Type.OLE | Type.HWP),
    ("PUB", OLE_MAGIC + b"Microsoft Publisher document", Type.OLE | Type.PUB),
    (
        "DOC95",
        OLE_MAGIC + b"Word.Document.6 Word 6.0",
        Type.OLE | Type.DOC | Type.DOC95,
    ),
    ("DOT95", OLE_MAGIC + b"Word.Template.6 dot95", Type.OLE | Type.DOC | Type.DOT95),
    (
        "XLS95",
        OLE_MAGIC + b"Workbook BIFF5 \x09\x08\x10\x00\x00\x05",
        Type.OLE | Type.XLS | Type.XLS95,
    ),
    (
        "PPT95",
        OLE_MAGIC + b"PowerPoint Document PowerPoint 95",
        Type.OLE | Type.PPT | Type.PPT95,
    ),
    (
        "MSC",
        OLE_MAGIC + b"MMC_ConsoleFile Microsoft Management Console",
        Type.OLE | Type.MSC,
    ),
    ("MSO-CFB", OLE_MAGIC + b"ActiveMime embedded office object", Type.OLE | Type.MSO),
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
    (
        "MSU",
        b"MSCF update.mum package.xml Windows6.1-KB.cab Microsoft update",
        Type.CAB | Type.MSU,
    ),
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
    ("H5", _bytes_at(512, b"\x89HDF\r\n\x1a\n"), Type.H5),
    ("DWG", b"AC1027" + (b"\x00" * 16), Type.DWG),
    (
        "ASF",
        b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
        Type.ASF,
    ),
    (
        "WMV",
        b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"
        b"Windows Media Video WMV",
        Type.ASF | Type.WMV,
    ),
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
    ("CSV", b"name,age\nalice,30\nbob,40\n", Type.CSV),
    (
        "ICS",
        b"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nEND:VEVENT\nEND:VCALENDAR\n",
        Type.ICS,
    ),
    (
        "MBOX",
        b"From sender@example.invalid Thu Jul  9 12:00:00 2026\n"
        b"From: sender@example.invalid\n"
        b"Subject: sample\n\nbody\n",
        Type.MBOX,
    ),
    (
        "RDP",
        b"screen mode id:i:2\n"
        b"full address:s:host.example.invalid\n"
        b"username:s:analyst\n",
        Type.RDP,
    ),
    (
        "MHTML",
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/related; boundary=x\n\n"
        b"--x\nContent-Type: text/html\nContent-Location: https://example.invalid/\n\n<html/>",
        Type.MHTML,
    ),
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
    (
        "SCT",
        b"<?xml version='1.0'?><scriptlet><registration progid='x'/>"
        b"<script language='JScript'></script></scriptlet>",
        Type.XML | Type.SCT,
    ),
    ("PICKLE", pickle.dumps({"payload": 2}, protocol=2), Type.PICKLE),
    (
        "PYTORCH-PICKLE",
        b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\n.",
        Type.PICKLE | Type.PYTORCH_MODEL,
    ),
    (
        "TENSORFLOW-PB",
        b"\x0a\x0bSavedModel tensorflow serving_default tensor node_def",
        Type.TENSORFLOW_PB,
    ),
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
    (
        "FLAT-ODT",
        b"<office:document office:mimetype='application/vnd.oasis.opendocument.text'/>",
        Type.XML | Type.ODT,
    ),
    ("MSO", b"ActiveMime\x00\x00\x00", Type.MSO),
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

ODF_PACKAGE_CASES = [
    ("ODT", ".odt", "application/vnd.oasis.opendocument.text", Type.ZIP | Type.ODT),
    (
        "ODS",
        ".ods",
        "application/vnd.oasis.opendocument.spreadsheet",
        Type.ZIP | Type.ODS,
    ),
    ("ODC", ".odc", "application/vnd.oasis.opendocument.chart", Type.ZIP | Type.ODC),
    ("ODF", ".odf", "application/vnd.oasis.opendocument.formula", Type.ZIP | Type.ODF),
    ("ODG", ".odg", "application/vnd.oasis.opendocument.graphics", Type.ZIP | Type.ODG),
    ("ODI", ".odi", "application/vnd.oasis.opendocument.image", Type.ZIP | Type.ODI),
    (
        "ODP",
        ".odp",
        "application/vnd.oasis.opendocument.presentation",
        Type.ZIP | Type.ODP,
    ),
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


def test_identify_xlsb_package(tmp_path: Path) -> None:
    path = _write_ooxml_package(
        tmp_path,
        ".xlsb",
        "application/vnd.ms-excel.sheet.binary.macroEnabled.main",
        {"xl/workbook.bin": b"\x00"},
    )

    result = identify_path(path)

    expected = Type.ZIP | Type.OXML | Type.XLSB
    assert result & expected == expected


@pytest.mark.parametrize(
    ("suffix", "mimetype", "expected"),
    [
        pytest.param(suffix, mimetype, expected, id=case_id)
        for case_id, suffix, mimetype, expected in ODF_PACKAGE_CASES
    ],
)
def test_identify_odf_packages(
    tmp_path: Path,
    suffix: str,
    mimetype: str,
    expected: Type,
) -> None:
    path = _write_odf_package(tmp_path, suffix, mimetype)

    result = identify_path(path)

    assert result & expected == expected


def test_identify_android_package_bundle_path(tmp_path: Path) -> None:
    path = tmp_path / "sample.apks"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("base.apk", b"")

    result = identify_path(path)

    assert result & Type.APKX


def test_identify_msix_package(tmp_path: Path) -> None:
    path = _write_zip(
        tmp_path / "sample.msix",
        {
            "[Content_Types].xml": "<Types/>",
            "AppxManifest.xml": "<Package/>",
        },
    )

    result = identify_path(path)

    expected = Type.ZIP | Type.OXML | Type.MSIX
    assert result & expected == expected


def test_identify_vsix_package(tmp_path: Path) -> None:
    path = _write_zip(
        tmp_path / "sample.vsix",
        {
            "[Content_Types].xml": "<Types/>",
            "extension.vsixmanifest": "<PackageManifest/>",
        },
    )

    result = identify_path(path)

    expected = Type.ZIP | Type.OXML | Type.VSIX
    assert result & expected == expected


def test_identify_wheel_package(tmp_path: Path) -> None:
    path = _write_zip(
        tmp_path / "badlib-0.1.0-py3-none-any.whl",
        {
            "badlib-0.1.0.dist-info/WHEEL": "Wheel-Version: 1.0\n",
            "badlib-0.1.0.dist-info/RECORD": "",
            "badlib/__init__.py": "",
        },
    )

    result = identify_path(path)

    assert result & (Type.ZIP | Type.WHL) == Type.ZIP | Type.WHL


def test_identify_xpi_package(tmp_path: Path) -> None:
    path = _write_zip(
        tmp_path / "extension.xpi",
        {
            "manifest.json": "{}",
        },
    )

    result = identify_path(path)

    assert result & (Type.ZIP | Type.XPI) == Type.ZIP | Type.XPI


def test_identify_zipx_by_extension(tmp_path: Path) -> None:
    path = _write_zip(tmp_path / "archive.zipx", {"file.txt": "payload"})

    result = identify_path(path)

    assert result & (Type.ZIP | Type.ZIPX) == Type.ZIP | Type.ZIPX


def test_identify_pytorch_zip_package(tmp_path: Path) -> None:
    path = _write_zip(
        tmp_path / "model.pt",
        {
            "archive/data.pkl": b"torch._utils\n",
            "archive/version": "3\n",
            "archive/constants.pkl": b"",
        },
    )

    result = identify_path(path)

    assert result & (Type.ZIP | Type.PYTORCH_MODEL) == Type.ZIP | Type.PYTORCH_MODEL


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


def test_generic_zip_does_not_match_specific_package_formats(tmp_path: Path) -> None:
    path = _write_zip(tmp_path / "generic.zip", {"file.txt": "payload"})

    result = identify_path(path)

    specific = (
        Type.XLSB
        | Type.ODT
        | Type.ODS
        | Type.ODC
        | Type.ODF
        | Type.ODG
        | Type.ODI
        | Type.ODP
        | Type.WHL
        | Type.VSIX
        | Type.MSIX
        | Type.XPI
        | Type.ZIPX
        | Type.PYTORCH_MODEL
    )
    assert result & Type.ZIP
    assert not result & specific


def test_generic_cfb_does_not_match_specific_ole_formats() -> None:
    result = identify(OLE_MAGIC)

    specific = (
        Type.HWP
        | Type.PUB
        | Type.DOC95
        | Type.DOT95
        | Type.XLS95
        | Type.PPT95
        | Type.MSC
        | Type.MSO
    )
    assert result & Type.OLE
    assert not result & specific


def test_generic_pe_does_not_match_installer_node_sfx_or_packers() -> None:
    result = identify(_minimal_pe())

    specific = (
        Type.ACTUAL_INSTALLER
        | Type.ADVANCED_INSTALLER
        | Type.INNO_SETUP
        | Type.INSTALLANYWHERE
        | Type.INSTALLSHIELD
        | Type.WISE_INSTALLER
        | Type.WIX
        | Type.NODEJS_PKG
        | Type.SFX_PEEXE
        | Type.UPX
        | Type.EVB
        | Type.ASPACK
        | Type.FSG
        | Type.THEMIDA
        | Type.VMPROTECT
        | Type.WINUPACK
        | Type.PETITE
        | Type.PESPIN
        | Type.ARMADILLO
        | Type.PECOMPACT
        | Type.NSPACK
        | Type.MPRESS
    )
    assert result & Type.PE32
    assert not result & specific


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        pytest.param(
            _minimal_pe_with_sections([b".aspack"]),
            Type.ASPACK,
            id="aspack-section",
        ),
        pytest.param(
            _minimal_pe(section_payload=b"\x00ASProtect\x00"),
            Type.ASPACK,
            id="asprotect-marker",
        ),
        pytest.param(
            _minimal_pe_with_sections([b"FSG!"]),
            Type.FSG,
            id="fsg-section",
        ),
        pytest.param(
            _minimal_pe(section_payload=b"\x00Themida\x00"),
            Type.THEMIDA,
            id="themida-marker",
        ),
        pytest.param(
            _minimal_pe(section_payload=b"\x00WinLicense\x00"),
            Type.THEMIDA,
            id="winlicense-marker",
        ),
        pytest.param(
            _minimal_pe_with_sections([b".vmp0"]),
            Type.VMPROTECT,
            id="vmprotect-section",
        ),
        pytest.param(
            _minimal_pe_with_sections([b".wpack"]),
            Type.WINUPACK,
            id="winupack-section",
        ),
        pytest.param(
            _minimal_pe_with_sections([b".petite"]),
            Type.PETITE,
            id="petite-section",
        ),
        pytest.param(
            _minimal_pe_with_sections([b".pespin"]),
            Type.PESPIN,
            id="pespin-section",
        ),
        pytest.param(
            _minimal_pe(section_payload=b"\x00Armadillo\x00"),
            Type.ARMADILLO,
            id="armadillo-marker",
        ),
        pytest.param(
            _minimal_pe_with_sections([b"PEC1"]),
            Type.PECOMPACT,
            id="pecompact-section",
        ),
        pytest.param(
            _minimal_pe_with_sections([b"NSP0"]),
            Type.NSPACK,
            id="nspack-section",
        ),
        pytest.param(
            _minimal_pe_with_sections([b"MPRESS1"]),
            Type.MPRESS,
            id="mpress-section",
        ),
    ],
)
def test_identify_pe_packer_profile_markers(sample: bytes, expected: Type) -> None:
    result = identify(sample)

    assert result & Type.PE32
    assert result & expected


def test_ambiguous_adata_section_does_not_match_aspack_or_armadillo() -> None:
    result = identify(_minimal_pe_with_sections([b".adata"]))

    assert result & Type.PE32
    assert not result & (Type.ASPACK | Type.ARMADILLO)


def test_identify_enigma_virtual_box_pe() -> None:
    result = identify(
        _minimal_pe_with_sections([b".enigma1", b".enigma2"], section_payload=b"EVB\0"),
    )

    assert result & Type.PE32
    assert result & Type.EVB


def test_enigma_virtual_box_requires_sections_and_magic() -> None:
    with_sections = identify(_minimal_pe_with_sections([b".enigma1", b".enigma2"]))
    with_magic = identify(_minimal_pe(section_payload=b"EVB\0"))

    assert with_sections & Type.PE32
    assert with_magic & Type.PE32
    assert not with_sections & Type.EVB
    assert not with_magic & Type.EVB


def test_upx_magic_string_alone_does_not_match_upx() -> None:
    result = identify(
        _minimal_pe(section_payload=b"this executable mentions UPX! but is not packed"),
    )

    assert result & Type.PE32
    assert not result & Type.UPX


def test_upx_section_names_alone_do_not_match_upx() -> None:
    result = identify(_minimal_pe_with_sections([b"UPX0", b"UPX1"]))

    assert result & Type.PE32
    assert not result & Type.UPX


@pytest.mark.parametrize(
    ("machine", "bits", "endian", "stub", "expected_arch"),
    [
        pytest.param(
            0x03,
            32,
            "little",
            b"\x50\xe8"
            + (b"\x00" * 4)
            + b"\xeb\x0e\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9"
            + (b"\x00" * 4)
            + b"\x60",
            Type.X86,
            id="x86",
        ),
        pytest.param(
            0x3E,
            64,
            "little",
            b"\x50\x52\xe8"
            + (b"\x00" * 4)
            + b"\x55\x53\x51\x52\x48\x01\xfe\x56\x48\x89\xfe\x48\x89\xd7"
            + b"\x31\xdb\x31\xc9\x48\x83\xcd\xff\xe8",
            Type.AMD64,
            id="x86-64",
        ),
        pytest.param(
            0x28,
            32,
            "little",
            b"\x1c\xc0\x4f\xe2\x06\x4c\x9c\xe8\x02\x00\xa0\xe1\x0c\xb0\x8b\xe0"
            b"\x0c\xa0\x8a\xe0\x00\x30\x9b\xe5\x01\x90\x4c\xe0\x01\x20\xa0\xe1",
            Type.ARM32,
            id="arm",
        ),
        pytest.param(
            0x08,
            32,
            "little",
            (b"\x00" * 2)
            + b"\x11\x04\x00\x00\xfe\x27\xfc\xff\xbd\x27\x00\x00\xbf\xaf"
            + b"\x20\x28\xa4\x00\x00\x00\xe6\xac\x00\x80\x0d\x3c\x21\x48\xa0\x01"
            + b"\x01\x00\x0b\x24"
            + (b"\x00" * 2)
            + b"\x11\x04",
            Type.MIPS,
            id="mips-le",
        ),
        pytest.param(
            0x08,
            32,
            "big",
            b"\x04\x11"
            + (b"\x00" * 2)
            + b"\x27\xfe\x00\x00\x27\xbd\xff\xfc\xaf\xbf\x00\x00\x00\xa4"
            + b"\x28\x20\xac\xe6\x00\x00\x3c\x0d\x80\x00\x01\xa0\x48\x21"
            + b"\x24\x0b\x00\x01\x04\x11",
            Type.MIPS,
            id="mips-be",
        ),
        pytest.param(
            0x14,
            32,
            "big",
            b"\x48\x00\x00\x00\x7c\x00\x29\xec\x7d\xa8\x02\xa6\x28\x07\x00\x02"
            b"\x40\x82\x00\xe4\x90\xa6\x00\x00",
            Type.PPC,
            id="powerpc",
        ),
    ],
)
def test_identify_upx_elf_entrypoint_stub_patterns(
    machine: int,
    bits: int,
    endian: str,
    stub: bytes,
    expected_arch: Type,
) -> None:
    result = identify(
        _minimal_elf_with_load(
            machine=machine,
            bits=bits,
            endian=endian,
            stub=stub,
        ),
    )

    expected = Type.ELF | expected_arch | Type.UPX
    assert result & expected == expected


def test_identify_upx_elf_init_code_not_at_entrypoint() -> None:
    x86_stub = (
        b"\x50\xe8"
        + (b"\x00" * 4)
        + b"\xeb\x0e\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9"
        + (b"\x00" * 4)
        + b"\x60"
    )

    result = identify(
        _minimal_elf_with_load(
            machine=0x03,
            bits=32,
            endian="little",
            stub=x86_stub,
            stub_delta=0x80,
            entry_delta=0,
        ),
    )

    expected = Type.ELF | Type.X86 | Type.UPX
    assert result & expected == expected


def test_identify_upx_elf_relocated_init_requires_executable_segment() -> None:
    x86_stub = (
        b"\x50\xe8"
        + (b"\x00" * 4)
        + b"\xeb\x0e\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9"
        + (b"\x00" * 4)
        + b"\x60"
    )

    result = identify(
        _minimal_elf_with_load(
            machine=0x03,
            bits=32,
            endian="little",
            stub=x86_stub,
            stub_delta=0x80,
            entry_delta=0,
            segment_flags=4,
        ),
    )

    assert result & Type.ELF
    assert not result & Type.UPX


def test_identify_upx_elf_relocated_init_scan_is_capped() -> None:
    x86_stub = (
        b"\x50\xe8"
        + (b"\x00" * 4)
        + b"\xeb\x0e\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9"
        + (b"\x00" * 4)
        + b"\x60"
    )

    result = identify(
        _minimal_elf_with_load(
            machine=0x03,
            bits=32,
            endian="little",
            stub=x86_stub,
            stub_delta=0x20000,
            entry_delta=0,
        ),
    )

    assert result & Type.ELF
    assert not result & Type.UPX


def test_random_text_does_not_match_structured_text_formats() -> None:
    result = identify(b"this is some random text\nwith two lines\nand no structure\n")

    specific = Type.CSV | Type.ICS | Type.MBOX | Type.RDP | Type.SCT | Type.MHTML
    assert not result & specific


def test_arbitrary_protobuf_or_pickle_do_not_match_model_formats() -> None:
    assert not identify(b"\x08\x01\x12\x03abc") & Type.TENSORFLOW_PB
    assert not (
        identify(pickle.dumps({"payload": "not torch"}, protocol=2))
        & Type.PYTORCH_MODEL
    )


def test_identification_cases_cover_every_filetype() -> None:
    expected_values = [expected for _, _, expected in BYTE_FILETYPE_CASES]
    expected_values.extend(expected for _, _, expected, _ in OOXML_FILETYPE_CASES)
    expected_values.extend(expected for _, _, expected in OLE_CLSID_FILETYPE_CASES)
    expected_values.extend(expected for _, _, _, expected in ODF_PACKAGE_CASES)
    expected_values.extend([
        Type.APKX,
        Type.XLSB,
        Type.MSIX,
        Type.VSIX,
        Type.WHL,
        Type.XPI,
        Type.ZIPX,
        Type.PYTORCH_MODEL,
        Type.EVB,
        Type.ASPACK,
        Type.FSG,
        Type.THEMIDA,
        Type.VMPROTECT,
        Type.WINUPACK,
        Type.PETITE,
        Type.PESPIN,
        Type.ARMADILLO,
        Type.PECOMPACT,
        Type.NSPACK,
        Type.MPRESS,
    ])

    missing = set(Type) - _covered_flags(expected_values)

    assert missing == set()


def test_ooxml_content_type_exports_cover_detector_map() -> None:
    assert set(OOXML_CONTENT_MAP) <= OOXML_CONTENT_TYPES


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("asprotect", "aspack"),
        ("enigma-vb", "enigma-virtual-box"),
        ("evb", "enigma-virtual-box"),
        ("mht", "mhtml"),
        ("mhtml", "mhtml"),
        ("mht/mhtml", "mhtml"),
        ("pec", "pecompact"),
        ("sfx-peexe", "sfx-peexe"),
        ("sfx/peexe", "sfx-peexe"),
        ("peexe-sfx", "sfx-peexe"),
        ("self-extracting-pe", "sfx-peexe"),
        ("vmp", "vmprotect"),
        ("vmprotect64", "vmprotect"),
        ("winlicense", "themida"),
        ("winlice", "themida"),
        ("winupack0", "winupack"),
    ],
)
def test_format_id_aliases(alias: str, canonical: str) -> None:
    assert resolve_format_id(alias) == canonical


def test_format_ids_are_lowercase() -> None:
    result = Type.ZIP | Type.WHL | Type.MHTML | Type.SFX_PEEXE

    assert format_ids(result) == ["sfx-peexe", "whl", "mhtml"]


def test_identify_bytes() -> None:
    result = identify(b"PK\x03\x04" + (b"\x00" * 32))

    assert result & Type.ZIP
    assert "ZIP Compressed Archive" in type_names(result)


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("pe", b"MZ", Type.UNK),
        ("elf", b"\x7fELF", Type.ELF),
        ("macho", b"\xce\xfa\xed\xfe", Type.MACHO),
    ],
)
def test_identify_truncated_executable_header(
    tmp_path: Path,
    name: str,
    data: bytes,
    expected: Type,
) -> None:
    path = tmp_path / name
    path.write_bytes(data)

    assert identify(data) == expected
    assert identify_path(path) == expected


def test_identify_truncated_pe_keeps_established_type() -> None:
    pe_offset = 0x40
    data = bytearray(pe_offset + 26)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    data[pe_offset + 4:pe_offset + 6] = (0x14C).to_bytes(2, "little")
    data[pe_offset + 24:pe_offset + 26] = (0x10B).to_bytes(2, "little")

    assert identify(bytes(data)) == Type.PE32 | Type.X86


@pytest.mark.parametrize(
    "data",
    [_minimal_pe(), _minimal_elf(0x3E), _minimal_macho(0x7)],
    ids=["pe", "elf", "macho"],
)
def test_identify_executable_prefixes_do_not_raise(data: bytes) -> None:
    for length in range(len(data) + 1):
        identify(data[:length])


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
