import struct
from enum import IntFlag, auto, unique
from mmap import ACCESS_READ, mmap
from pathlib import Path
from typing import Any, List

__all__ = [
    "COMMONTYPE",
    "FORMAT_ALIASES",
    "FORMAT_IDS",
    "OOXML_CONTENT_TYPES",
    "QuickID",
    "Type",
    "format_ids",
    "identify",
    "identify_path",
    "resolve_format_id",
    "type_names",
]

NSIS_SIGNATURE = b"\xef\xbe\xad\xdeNullsoftInst"
NSIS_FIRSTHEADER_SIZE = 28
NSIS_FLAGS_MASK = 0xF
NSIS_SCAN_ALIGNMENT = 512
UPX_INFO_MARKER = b"$info: this file is packed with the upx executable packer"
UPX_MAGIC = b"upx!"
UPX_SECTION_NAMES = {b"upx0", b"upx1", b"upx2"}
ELF_MARKER_SCAN_LIMIT = 524288
UPX_ELF_EXEC_SEGMENT_SCAN_LIMIT = 131072

# ELF UPX entry stub patterns ported from NozomiNetworks/upx-recovery-tool
# YARA rules, BSD-3-Clause: https://github.com/NozomiNetworks/upx-recovery-tool
UPX_ELF_STUB_PATTERNS = (
    (b"\x50\xe8", 4, b"\xeb\x0e\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9", 4, b"\x60"),
    (b"\x50\x52\xe8", 4, b"\x55\x53\x51\x52\x48\x01\xfe\x56\x48\x89\xfe\x48\x89\xd7\x31\xdb\x31\xc9\x48\x83\xcd\xff\xe8"),
    (b"\x50\x52\xe8", 4, b"\x55\x53\x51\x52\x48\x01\xfe\x56\x41\x80\xf8\x0e\x0f", 5, b"\x55\x48\x89\xe5\x44\x8b\x09"),
    (b"\x1c\xc0\x4f\xe2\x06\x4c\x9c\xe8\x02\x00\xa0\xe1\x0c\xb0\x8b\xe0\x0c\xa0\x8a\xe0\x00\x30\x9b\xe5\x01\x90\x4c\xe0\x01\x20\xa0\xe1",),
    (b"\x18\xd0\x4d\xe2", 1, b"\x02\x00\xeb\x00\xc0\xdd\xe5\x0e\x00\x5c\xe3", 1, b"\x02\x00\x1a\x0c\x48\x2d\xe9\x00\xb0\xd0\xe5\x06\xcc\xa0\xe3"),
    (b"\x00\x18\xd0\x4d\xe2\x9c\x00\x00\xeb\x00\x10\x81\xe0\x3e\x40\x2d\xe9\x00\x50\xe0\xe3\x02\x41\xa0\xe3\x19\x00\x00\xea\x1a\x00\xbd",),
    (b"\x04\x11", 2, b"\x27\xfe\x00\x00\x27\xbd\xff\xfc\xaf\xbf\x00\x00\x00\xa4\x28\x20\xac\xe6\x00\x00\x3c\x0d\x80\x00\x01\xa0\x48\x21\x24\x0b\x00\x01\x04\x11"),
    (b"\x04\x11", 2, b"\x27\xf7\x00\x00\x90\x99\x00\x00\x24\x01\xfa\x00\x90\x98\x00\x01\x33\x22\x00\x07\x00\x19\xc8\xc2\x03\x21\x08\x04"),
    (2, b"\x11\x04\x00\x00\xfe\x27\xfc\xff\xbd\x27\x00\x00\xbf\xaf\x20\x28\xa4\x00\x00\x00\xe6\xac\x00\x80\x0d\x3c\x21\x48\xa0\x01\x01\x00\x0b\x24", 2, b"\x11\x04"),
    (2, b"\x11\x04\x00\x00\xf7\x27\x00\x00\x99\x90\x00\xfa\x01\x24\x01\x00\x98\x90\x07\x00\x22\x33\xc2\xc8\x19\x00\x04\x08\x21\x03"),
    (b"\x48\x00", 2, b"\x7c\x00\x29\xec\x7d\xa8\x02\xa6\x28\x07\x00\x02\x40\x82\x00\xe4\x90\xa6\x00\x00"),
    (b"\x48\x00", 2, b"\x28\x07\x00\x0e\x40\x82\x0a\x4c\x94\x21\xff\xe8\x7c\x08\x02\xa6\x7c\xc9\x33\x78\x81\x06\x00\x00\x7c\xa7\x2b\x78"),
)


@unique
class Type(IntFlag):
    UNK = auto()  # saving for unknown filetype
    PE32 = auto()  # - blint, floss, capa (ARM or INTEL) (32) (DOTNET or NATIVE)
    ELF = auto()  # - blint, floss, capa (ARM or INTEL) (32 or 64) (DOTNET or NATIVE)
    MACHO = auto()  # - blint, floss, capa (ARM or INTEL) (32 or 64) (DOTNET or NATIVE)
    RIFF = auto()  # - RIFF container format (WAV/WEBP/etc.)
    LNK = auto()  # - LnkParse3
    APK = auto()  # - blint, apkfile
    PDF = auto()  # - PDFid
    RTF = auto()  # - oletools?
    OLE = auto()  # - oletools: oletimes: get times of sections, olemeta: get all the meta-info, oleobject: data
    OXML = auto()  # - oletools?
    ARM32 = auto()  # - blint, floss
    AARCH64 = auto()  # - blint, floss
    X86 = auto()  # - blint, floss, capa
    AMD64 = auto()  # - blint, floss, capa
    DOTNET = auto()  # - dnfile
    MSI = auto()  # - olefile/msidump?
    ZIP = auto()  # - pyzipper/python-javatools
    RAR = auto()  # - rarfile
    GZ = auto()  # - gzip
    UDF = auto()  # - pycdlib
    ISO = auto()  # - pycdlib
    JAR = auto()  # - pyzipper
    SEVENZIP = auto()  # - py7zr
    ACE = auto()  # - acefile
    CAB = auto()  # - cabinet
    ARJ = auto()  # - pyunpack
    AR = auto()  # - ar archive
    XZ = auto()  # - lzma
    TAR = auto()  # - tarfile
    DMG = auto()  # - libfshfs?
    Z = auto()  # - custom methods...to old https://rosettacode.org/wiki/LZW_compression#Python
    LZH = auto()  # - lhafile
    VHD = auto()  # - libvhdi-python
    VHDX = auto()  # - libvhdi-python
    BZ2 = auto()  # - bzip2
    ONE = auto()  # - pyOneNote
    CLASS = auto()  # - python-javatools
    JSER = auto()  # - Java serialization
    DEB = auto()  # - apt.debfile/python-debian
    RPM = auto()  # - RPM package
    DSSTORE = auto()  # - https://github.com/dmgbuild/ds_store
    UUE = auto()  # - UU Encoded....
    DEX = auto()  # dex android dalvik executable
    ZLIB = auto()  # zlib
    XAR = auto()  # apple xar
    CHM = auto()  # Microsoft Compiled HTML Help
    CRX = auto()  # Chrome extension file
    MSES = auto()  # Encoded Microsoft Script
    SZDD = auto()  # MS Expand/compress format
    HLP = auto()  # MS Help file format
    WIM = auto()  # Windows image file format
    ZST = auto()  # Zstandard compressed
    WASM = auto()  # WebAssembly binary
    ARSC = auto()  # Android Resource
    BXML = auto()  # Binary XML.
    ASN1 = auto()  # ASN.1 sequence
    TTF = auto()  # TrueType font
    GIF = auto()  # GIF image
    ID3 = auto()  # ID3 tag (MP3)
    JKS = auto()  # Java KeyStore
    PYC = auto()  # Python bytecode
    JPEG = auto()  # JPEG image
    PRI = auto()  # Windows PRI resource index
    CMS = auto()  # Cryptographic Message Syntax (PKCS#7/CMS)
    OGG = auto()  # Ogg container (Vorbis/Opus/etc.)
    MP4 = auto()  # MP4/ISOBMFF container
    PNG = auto()  # PNG image
    MP3 = auto()  # MP3 audio
    TORR = auto()  # BitTorrent seed (.torrent)
    WOF2 = auto()  # WOFF2 font
    HTML = auto()  # HTML document
    APPD = auto()  # AppleDouble metadata
    SQLITE = auto()  # SQLite database
    PHP = auto()  # PHP script
    ASP = auto()  # ASP script
    JSP = auto()  # JSP script
    SAVW = auto()  # Saved web page watermark
    PEMC = auto()  # PEM certificate
    XML = auto()  # XML document
    BPLS = auto()  # Apple binary plist
    IURL = auto()  # Windows Internet Shortcut
    DAA = auto()  # PowerISO Direct-Access-Archive
    LZIP = auto()  # LZIP compressed
    ROBJ = auto()  # RTF embedded object markers
    RDDE = auto()  # RTF DDE/DDEAUTO field
    RINC = auto()  # RTF INCLUDETEXT/INCLUDEPICTURE field
    RHYP = auto()  # RTF HYPERLINK field
    RBIN = auto()  # RTF \\bin data
    TIF = auto()  # TIFF image
    BMP = auto()  # Bitmap image
    AU = auto()  # Sun/NeXT AU audio
    AIF = auto()  # AIFF audio
    AIFC = auto()  # AIFC audio
    ICO = auto()  # Windows icon/cursor
    SH = auto()  # Shell script
    MFAT = auto()  # Mach-O Fat Binary
    WMF = auto()  # Windows Metafile
    DOC = auto()  # OLE Word Document
    XLS = auto()  # OLE Excel Workbook
    PPT = auto()  # OLE PowerPoint Presentation
    VSD = auto()  # OLE Visio Document
    MSG = auto()  # Outlook Message
    PWZ = auto()  # PowerPoint Wizard/Add-in
    XLCH = auto()  # Excel Chart
    OLEL = auto()  # OLE Link Object
    FRMF = auto()  # Forms Frame
    APKX = auto()  # APK bundle (APKX/APKS/APKM)
    SPARC = auto()  # SPARC
    SPARC64 = auto()  # SPARC64
    MIPS = auto()  # MIPS
    MIPS64 = auto()  # MIPS64
    PPC = auto()  # PowerPC
    PPC64 = auto()  # PowerPC64
    S390 = auto()  # S390
    SUPH = auto()  # SuperH
    IA64 = auto()  # IA-64
    ALPHA = auto()  # Alpha
    M68K = auto()  # Motorola 68k
    VAX = auto()  # VAX
    HPPA = auto()  # HP PA-RISC
    M32R = auto()  # M32R
    ARC = auto()  # ARC
    TILEGX = auto()  # TILE-Gx
    TILEPRO = auto()  # TILEPro
    LOONG = auto()  # LoongArch
    RISCV = auto()  # RISC-V
    OPENR = auto()  # OpenRISC
    ARCC = auto()  # ARC Compact
    XTEN = auto()  # Xtensa
    CSKY = auto()  # C-SKY
    DOCX = auto()  # OOXML Word Document
    DOCM = auto()  # OOXML Word Macro-Enabled
    DOTX = auto()  # OOXML Word Template
    DOTM = auto()  # OOXML Word Macro Template
    XLSX = auto()  # OOXML Excel Workbook
    XLSM = auto()  # OOXML Excel Macro-Enabled
    XLTX = auto()  # OOXML Excel Template
    XLTM = auto()  # OOXML Excel Macro Template
    XLAM = auto()  # OOXML Excel Add-in
    PPTX = auto()  # OOXML PowerPoint Presentation
    PPTM = auto()  # OOXML PowerPoint Macro-Enabled
    PPSX = auto()  # OOXML PowerPoint Slideshow
    PPSM = auto()  # OOXML PowerPoint Macro Slideshow
    POTX = auto()  # OOXML PowerPoint Template
    POTM = auto()  # OOXML PowerPoint Macro Template
    PPAM = auto()  # OOXML PowerPoint Add-in
    MSP = auto()  # Microsoft Project
    DIB = auto()  # Device Independent Bitmap
    MSXML = auto()  # MSXML SAXXMLReader OLE control
    FHTML = auto()  # Forms.HTML Image OLE control
    CPIO = auto()  # CPIO archive
    WAR = auto()  # Java Web Archive (WAR)
    APPS = auto()  # AppleSingle metadata
    BOM = auto()  # Apple Bill of Materials
    AU300 = auto()  # AutoIt 3.00 - 3.25
    AU326 = auto()  # AutoIt 3.26+
    U8BOM = auto()  # UTF-8 BOM text
    U16LEBOM = auto()  # UTF-16 LE BOM text
    U16BEBOM = auto()  # UTF-16 BE BOM text
    U32LEBOM = auto()  # UTF-32 LE BOM text
    U32BEBOM = auto()  # UTF-32 BE BOM text
    SVG = auto()  # Scalable Vector Graphics
    PICKLE = auto()  # Python pickle serialization
    TNEF = auto()  # Transport Neutral Encapsulation Format
    LZMA = auto()  # LZMA-alone compressed data
    LZ4 = auto()  # LZ4 compressed data
    EML = auto()  # RFC 5322 email message
    IQY = auto()  # Microsoft Internet Query
    LIBRARYMS = auto()  # Windows Library Description
    A3X = auto()  # AutoIt compiled script
    NSIS = auto()  # Nullsoft Scriptable Install System installer
    WASM32 = auto()  # WebAssembly with 32-bit linear memory
    WASM64 = auto()  # WebAssembly with 64-bit linear memory
    XLSB = auto()  # Excel Binary Workbook
    ODT = auto()  # OpenDocument Text
    ODS = auto()  # OpenDocument Spreadsheet
    ODC = auto()  # OpenDocument Chart
    ODF = auto()  # OpenDocument Formula
    ODG = auto()  # OpenDocument Graphics
    ODI = auto()  # OpenDocument Image
    ODP = auto()  # OpenDocument Presentation
    HWP = auto()  # Hangul Word Processor
    PUB = auto()  # Microsoft Publisher
    DOC95 = auto()  # Word 6/95 document
    DOT95 = auto()  # Word 6/95 template
    XLS95 = auto()  # Excel 95 workbook
    PPT95 = auto()  # PowerPoint 95 presentation
    ACTUAL_INSTALLER = auto()  # Actual Installer package
    ADVANCED_INSTALLER = auto()  # Advanced Installer package
    INNO_SETUP = auto()  # Inno Setup installer
    INSTALLANYWHERE = auto()  # InstallAnywhere installer
    INSTALLSHIELD = auto()  # InstallShield installer
    WISE_INSTALLER = auto()  # Wise installer
    WIX = auto()  # WiX/Burn installer
    CSV = auto()  # Comma-separated values
    ICS = auto()  # iCalendar data
    MBOX = auto()  # Unix mbox mailbox
    RDP = auto()  # Remote Desktop connection settings
    NODEJS_PKG = auto()  # Node.js pkg executable
    SFX_PEEXE = auto()  # PE self-extracting executable
    MSU = auto()  # Windows Update Standalone package
    VSIX = auto()  # Visual Studio extension
    WHL = auto()  # Python wheel
    XPI = auto()  # Firefox extension package
    H5 = auto()  # HDF5 data
    MHTML = auto()  # MIME HTML archive
    MSC = auto()  # Microsoft Management Console
    MSO = auto()  # Office ActiveMime/MSO data
    SCT = auto()  # Windows Scriptlet Component
    TENSORFLOW_PB = auto()  # TensorFlow protobuf model
    PYTORCH_MODEL = auto()  # PyTorch model/checkpoint
    DWG = auto()  # AutoCAD DWG
    ASF = auto()  # Advanced Systems Format
    WMV = auto()  # Windows Media Video
    MSIX = auto()  # MSIX/AppX package
    ZIPX = auto()  # WinZip extended ZIP archive
    UPX = auto()  # UPX packed executable
    EVB = auto()  # Enigma Virtual Box packed executable
    ASPACK = auto()  # ASPack/ASProtect packed executable
    FSG = auto()  # FSG packed executable
    THEMIDA = auto()  # Themida/WinLicense protected executable
    VMPROTECT = auto()  # VMProtect protected executable
    WINUPACK = auto()  # WinUpack packed executable
    PETITE = auto()  # Petite packed executable
    PESPIN = auto()  # PESpin packed executable
    ARMADILLO = auto()  # Armadillo protected executable
    PECOMPACT = auto()  # PECompact packed executable
    NSPACK = auto()  # NSPack packed executable
    MPRESS = auto()  # MPRESS packed executable


COMMONTYPE = {
    Type.UNK: "Unknown",
    Type.PE32: "Portable Executable",
    Type.ELF: "Extensable Linkable Format",
    Type.MACHO: "Macho Executable",
    Type.RIFF: "RIFF Container",
    Type.LNK: "Windows Shortcut Link",
    Type.APK: "Android Package",
    Type.PDF: "Portable Document Format",
    Type.RTF: "Rich Text Format",
    Type.OLE: "Microsoft Compound File Binary",
    Type.OXML: "Microsoft Office 2007+ Document",
    Type.ARM32: "32 Bit ARM",
    Type.AARCH64: "64 Bit ARM",
    Type.X86: "32 Bit Intel",
    Type.AMD64: "64 Bit Intel",
    Type.DOTNET: ".NET",
    Type.MSI: "Microsoft Software Installer",
    Type.ZIP: "ZIP Compressed Archive",
    Type.RAR: "RAR Compressed Archive",
    Type.GZ: "Gunzip Compressed",
    Type.UDF: "Universal Disk Format",
    Type.ISO: "Optical Disk Image",
    Type.JAR: "Java Archive",
    Type.SEVENZIP: "7Zip Archive",
    Type.ACE: "Ace Compressed Archive",
    Type.CAB: "Cabinet Archive",
    Type.ARJ: "Robert Jung Archive",
    Type.AR: "Unix Archive",
    Type.XZ: "XZ Compressed",
    Type.TAR: "Tape Archive",
    Type.DMG: "Apple Disk Image",
    Type.Z: "Z Compressed",
    Type.LZH: "Lempel-Ziv-Huffman Compressed",
    Type.VHD: "Microsoft Virtual Hard Disk",
    Type.VHDX: "Microsoft Virtual Hard Disk V2",
    Type.BZ2: "BZIP2 Compressed",
    Type.ONE: "Microsoft One Note",
    Type.CLASS: "Java Class",
    Type.JSER: "Java Serialized Object",
    Type.DEB: "Debian Package",
    Type.RPM: "RPM Package",
    Type.DSSTORE: "Desktop Service Storage",
    Type.DEX: "Android Dalvik Executable",
    Type.UUE: "UU Encoded",
    Type.ZLIB: "ZLIB Compressed",
    Type.XAR: "Apple XAR Package",
    Type.CHM: "Microsoft Compiled HTML Help",
    Type.CRX: "Chrome Extension",
    Type.MSES: "Microsoft Encoded Script",
    Type.SZDD: "Microsoft Compress/Extract",
    Type.HLP: "Microsoft Help",
    Type.WIM: "Microsoft Windows Image",
    Type.ZST: "Zstandard Compressed",
    Type.WASM: "WebAssembly Binary",
    Type.ARSC: "Android Resource",
    Type.BXML: "Binary XML",
    Type.ASN1: "ASN.1 Sequence",
    Type.TTF: "TrueType Font",
    Type.GIF: "GIF Image",
    Type.ID3: "ID3 Tag",
    Type.JKS: "Java KeyStore",
    Type.PYC: "Python Bytecode",
    Type.JPEG: "JPEG Image",
    Type.PRI: "Windows PRI Resource",
    Type.CMS: "CMS/PKCS#7",
    Type.OGG: "Ogg Container",
    Type.MP4: "MP4 Video",
    Type.PNG: "PNG Image",
    Type.MP3: "MP3 Audio",
    Type.WMF: "Windows Metafile",
    Type.TORR: "BitTorrent Seed",
    Type.WOF2: "WOFF2 Font",
    Type.HTML: "HTML Document",
    Type.APPD: "AppleDouble Metadata",
    Type.APPS: "AppleSingle Metadata",
    Type.BOM: "Apple Bill of Materials",
    Type.U8BOM: "UTF-8 BOM Text",
    Type.U16LEBOM: "UTF-16 LE BOM Text",
    Type.U16BEBOM: "UTF-16 BE BOM Text",
    Type.U32LEBOM: "UTF-32 LE BOM Text",
    Type.U32BEBOM: "UTF-32 BE BOM Text",
    Type.SQLITE: "SQLite Database",
    Type.PHP: "PHP Script",
    Type.ASP: "ASP Script",
    Type.JSP: "JSP Script",
    Type.SAVW: "Saved Webpage",
    Type.PEMC: "PEM Certificate",
    Type.XML: "XML Document",
    Type.SVG: "Scalable Vector Graphics",
    Type.PICKLE: "Python Pickle",
    Type.TNEF: "Transport Neutral Encapsulation Format",
    Type.LZMA: "LZMA Compressed",
    Type.LZ4: "LZ4 Compressed",
    Type.EML: "Email Message",
    Type.IQY: "Microsoft Internet Query",
    Type.LIBRARYMS: "Windows Library Description",
    Type.A3X: "AutoIt Compiled Script",
    Type.NSIS: "Nullsoft Scriptable Install System Installer",
    Type.WASM32: "WebAssembly 32-bit Memory",
    Type.WASM64: "WebAssembly 64-bit Memory",
    Type.XLSB: "xlsb",
    Type.ODT: "odt",
    Type.ODS: "ods",
    Type.ODC: "odc",
    Type.ODF: "odf",
    Type.ODG: "odg",
    Type.ODI: "odi",
    Type.ODP: "odp",
    Type.HWP: "hwp",
    Type.PUB: "pub",
    Type.DOC95: "doc95",
    Type.DOT95: "dot95",
    Type.XLS95: "xls95",
    Type.PPT95: "ppt95",
    Type.ACTUAL_INSTALLER: "actual-installer",
    Type.ADVANCED_INSTALLER: "advanced-installer",
    Type.INNO_SETUP: "inno-setup",
    Type.INSTALLANYWHERE: "installanywhere",
    Type.INSTALLSHIELD: "installshield",
    Type.WISE_INSTALLER: "wise-installer",
    Type.WIX: "wix",
    Type.CSV: "csv",
    Type.ICS: "ics",
    Type.MBOX: "mbox",
    Type.RDP: "rdp",
    Type.NODEJS_PKG: "nodejs-pkg",
    Type.SFX_PEEXE: "sfx-peexe",
    Type.MSU: "msu",
    Type.VSIX: "vsix",
    Type.WHL: "whl",
    Type.XPI: "xpi",
    Type.H5: "h5",
    Type.MHTML: "mhtml",
    Type.MSC: "msc",
    Type.MSO: "mso",
    Type.SCT: "sct",
    Type.TENSORFLOW_PB: "tensorflow-pb",
    Type.PYTORCH_MODEL: "pytorch-model",
    Type.DWG: "dwg",
    Type.ASF: "asf",
    Type.WMV: "wmv",
    Type.MSIX: "msix",
    Type.ZIPX: "zipx",
    Type.UPX: "upx",
    Type.EVB: "enigma-virtual-box",
    Type.ASPACK: "aspack",
    Type.FSG: "fsg",
    Type.THEMIDA: "themida",
    Type.VMPROTECT: "vmprotect",
    Type.WINUPACK: "winupack",
    Type.PETITE: "petite",
    Type.PESPIN: "pespin",
    Type.ARMADILLO: "armadillo",
    Type.PECOMPACT: "pecompact",
    Type.NSPACK: "nspack",
    Type.MPRESS: "mpress",
    Type.BPLS: "Binary Property List",
    Type.IURL: "Internet Shortcut",
    Type.DAA: "PowerISO DAA Disk Image",
    Type.LZIP: "LZIP Compressed",
    Type.ROBJ: "RTF Object Markers",
    Type.RDDE: "RTF DDE Field",
    Type.RINC: "RTF INCLUDE Field",
    Type.RHYP: "RTF HYPERLINK Field",
    Type.RBIN: "RTF Binary Data",
    Type.TIF: "TIFF Image",
    Type.BMP: "Bitmap Image",
    Type.DIB: "Device Independent Bitmap",
    Type.MSXML: "MSXML SAXXMLReader",
    Type.FHTML: "Forms HTML Image",
    Type.AU: "Sun AU Audio",
    Type.AIF: "AIFF Audio",
    Type.AIFC: "AIFC Audio",
    Type.ICO: "Icon/Cursor",
    Type.SH: "Shell Script",
    Type.MFAT: "Macho Fat Binary",
    Type.DOC: "Microsoft Word Document (DOC)",
    Type.XLS: "Microsoft Excel Workbook (XLS)",
    Type.PPT: "Microsoft PowerPoint Presentation (PPT)",
    Type.VSD: "Microsoft Visio Document (VSD)",
    Type.MSG: "Microsoft Outlook Message (MSG)",
    Type.PWZ: "Microsoft PowerPoint Wizard/Add-in (PWZ)",
    Type.XLCH: "Microsoft Excel Chart (OLE)",
    Type.OLEL: "OLE Link Object",
    Type.FRMF: "Forms Frame",
    Type.APKX: "Android APK Bundle",
    Type.SPARC: "SPARC",
    Type.SPARC64: "SPARC64",
    Type.MIPS: "MIPS",
    Type.MIPS64: "MIPS64",
    Type.PPC: "PowerPC",
    Type.PPC64: "PowerPC64",
    Type.S390: "S390",
    Type.SUPH: "SuperH",
    Type.IA64: "IA-64",
    Type.ALPHA: "Alpha",
    Type.M68K: "Motorola 68k",
    Type.VAX: "VAX",
    Type.HPPA: "HP PA-RISC",
    Type.M32R: "M32R",
    Type.ARC: "ARC",
    Type.TILEGX: "TILE-Gx",
    Type.TILEPRO: "TILEPro",
    Type.LOONG: "LoongArch",
    Type.RISCV: "RISC-V",
    Type.OPENR: "OpenRISC",
    Type.ARCC: "ARC Compact",
    Type.XTEN: "Xtensa",
    Type.CSKY: "C-SKY",
    Type.DOCX: "Microsoft Word Document (DOCX)",
    Type.DOCM: "Microsoft Word Macro-Enabled Document (DOCM)",
    Type.DOTX: "Microsoft Word Template (DOTX)",
    Type.DOTM: "Microsoft Word Macro-Enabled Template (DOTM)",
    Type.XLSX: "Microsoft Excel Workbook (XLSX)",
    Type.XLSM: "Microsoft Excel Macro-Enabled Workbook (XLSM)",
    Type.XLTX: "Microsoft Excel Template (XLTX)",
    Type.XLTM: "Microsoft Excel Macro-Enabled Template (XLTM)",
    Type.XLAM: "Microsoft Excel Add-in (XLAM)",
    Type.PPTX: "Microsoft PowerPoint Presentation (PPTX)",
    Type.PPTM: "Microsoft PowerPoint Macro-Enabled Presentation (PPTM)",
    Type.PPSX: "Microsoft PowerPoint Slideshow (PPSX)",
    Type.PPSM: "Microsoft PowerPoint Macro-Enabled Slideshow (PPSM)",
    Type.POTX: "Microsoft PowerPoint Template (POTX)",
    Type.POTM: "Microsoft PowerPoint Macro-Enabled Template (POTM)",
    Type.PPAM: "Microsoft PowerPoint Add-in (PPAM)",
    Type.MSP: "Microsoft Project",
    Type.CPIO: "CPIO Archive",
    Type.WAR: "Java Web Archive (WAR)",
    Type.AU300: "AutoIt v3.00 - v3.25 Script",
    Type.AU326: "AutoIt v3.26+ Script"
}

FORMAT_IDS = {
    Type.XLSB: "xlsb",
    Type.ODT: "odt",
    Type.ODS: "ods",
    Type.ODC: "odc",
    Type.ODF: "odf",
    Type.ODG: "odg",
    Type.ODI: "odi",
    Type.ODP: "odp",
    Type.HWP: "hwp",
    Type.PUB: "pub",
    Type.DOC95: "doc95",
    Type.DOT95: "dot95",
    Type.XLS95: "xls95",
    Type.PPT95: "ppt95",
    Type.ACTUAL_INSTALLER: "actual-installer",
    Type.ADVANCED_INSTALLER: "advanced-installer",
    Type.INNO_SETUP: "inno-setup",
    Type.INSTALLANYWHERE: "installanywhere",
    Type.INSTALLSHIELD: "installshield",
    Type.WISE_INSTALLER: "wise-installer",
    Type.WIX: "wix",
    Type.CSV: "csv",
    Type.ICS: "ics",
    Type.MBOX: "mbox",
    Type.RDP: "rdp",
    Type.NODEJS_PKG: "nodejs-pkg",
    Type.SFX_PEEXE: "sfx-peexe",
    Type.MSU: "msu",
    Type.VSIX: "vsix",
    Type.WHL: "whl",
    Type.XPI: "xpi",
    Type.H5: "h5",
    Type.MHTML: "mhtml",
    Type.MSC: "msc",
    Type.MSO: "mso",
    Type.SCT: "sct",
    Type.TENSORFLOW_PB: "tensorflow-pb",
    Type.PYTORCH_MODEL: "pytorch-model",
    Type.DWG: "dwg",
    Type.ASF: "asf",
    Type.WMV: "wmv",
    Type.MSIX: "msix",
    Type.ZIPX: "zipx",
    Type.UPX: "upx",
    Type.EVB: "enigma-virtual-box",
    Type.ASPACK: "aspack",
    Type.FSG: "fsg",
    Type.THEMIDA: "themida",
    Type.VMPROTECT: "vmprotect",
    Type.WINUPACK: "winupack",
    Type.PETITE: "petite",
    Type.PESPIN: "pespin",
    Type.ARMADILLO: "armadillo",
    Type.PECOMPACT: "pecompact",
    Type.NSPACK: "nspack",
    Type.MPRESS: "mpress",
}

FORMAT_ALIASES = {
    value: value for value in FORMAT_IDS.values()
}
FORMAT_ALIASES.update({
    "asprotect": "aspack",
    "enigma-vb": "enigma-virtual-box",
    "evb": "enigma-virtual-box",
    "mht": "mhtml",
    "mht/mhtml": "mhtml",
    "pec": "pecompact",
    "sfx/peexe": "sfx-peexe",
    "peexe-sfx": "sfx-peexe",
    "self-extracting-pe": "sfx-peexe",
    "vmp": "vmprotect",
    "vmprotect64": "vmprotect",
    "winlicense": "themida",
    "winlice": "themida",
    "winupack0": "winupack",
})

ODF_MIME_MAP = {
    "application/vnd.oasis.opendocument.text": Type.ODT,
    "application/vnd.oasis.opendocument.spreadsheet": Type.ODS,
    "application/vnd.oasis.opendocument.chart": Type.ODC,
    "application/vnd.oasis.opendocument.formula": Type.ODF,
    "application/vnd.oasis.opendocument.graphics": Type.ODG,
    "application/vnd.oasis.opendocument.image": Type.ODI,
    "application/vnd.oasis.opendocument.presentation": Type.ODP,
}

ZIPX_METHODS = {12, 14, 18, 19, 98}
HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
ASF_HEADER_GUID = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"

INSTALLER_MARKERS = [
    (Type.ACTUAL_INSTALLER, [b"actual installer"]),
    (Type.ADVANCED_INSTALLER, [b"advanced installer"]),
    (Type.INNO_SETUP, [b"inno setup", b"inno setup setup data", b"jrsoftware"]),
    (Type.INSTALLANYWHERE, [b"installanywhere", b"zero g registry", b"zerog"]),
    (Type.INSTALLSHIELD, [b"installshield", b"issetup", b"setup.inx", b"data1.cab"]),
    (Type.WISE_INSTALLER, [b"wise installation system", b"wise installer"]),
    (Type.WIX, [b"wixbundle", b"wix toolset", b"burn bootstrapper", b"burnmanifest"]),
]

INSTALLER_TYPES = (
    Type.ACTUAL_INSTALLER
    | Type.ADVANCED_INSTALLER
    | Type.INNO_SETUP
    | Type.INSTALLANYWHERE
    | Type.INSTALLSHIELD
    | Type.WISE_INSTALLER
    | Type.WIX
    | Type.NSIS
)

PE_OVERLAY_ARCHIVE_MARKERS = (
    b"PK\x03\x04",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!",
    b"MSCF",
    b"\x1f\x8b",
)

NODEJS_PKG_MARKERS = (
    b"pkg/prelude/bootstrap.js",
    b"snapshot_blob.bin",
    b"pkg_snapshot",
    b"nodejs.pkg",
)

PE_PACKER_RULES = (
    (
        Type.ASPACK,
        (b".aspack",),
        (),
        (b"aspack", b"asprotect"),
    ),
    (
        Type.FSG,
        (b".fsg", b"fsg!", b"fsg"),
        (),
        (b"fsg!",),
    ),
    (
        Type.THEMIDA,
        (b".winlice",),
        (),
        (b"themida", b"winlicense", b"winlice"),
    ),
    (
        Type.VMPROTECT,
        (),
        (b".vmp", b"vmp"),
        (b"vmprotect", b"vmprotect64"),
    ),
    (
        Type.WINUPACK,
        (b".wup", b".wpack"),
        (),
        (b"winupack",),
    ),
    (
        Type.PETITE,
        (b".petite", b"petite"),
        (),
        (),
    ),
    (
        Type.PESPIN,
        (b".pespin", b"pespin"),
        (),
        (b"pespin",),
    ),
    (
        Type.ARMADILLO,
        (),
        (),
        (b"armadillo",),
    ),
    (
        Type.PECOMPACT,
        (b".pec", b"pec1", b"pec2"),
        (),
        (b"pecompact",),
    ),
    (
        Type.NSPACK,
        (b".nsp", b"nsp0", b"nsp1"),
        (),
        (b"nspack",),
    ),
    (
        Type.MPRESS,
        (b".mpress", b"mpress1", b"mpress2"),
        (),
        (b"mpress",),
    ),
)


OOXML_CONTENT_TYPES = {
    "application/vnd.ms-appx.blockmap+xml",
    "application/vnd.ms-appx.manifest+xml",
    "application/vnd.ms-appx.signature",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-excel.binIndexMs",
    "application/vnd.ms-excel.binIndexWs",
    "application/vnd.ms-excel.calcChain",
    "application/vnd.ms-excel.controlproperties+xml",
    "application/vnd.ms-excel.intlmacrosheet",
    "application/vnd.ms-excel.macrosheet",
    "application/vnd.ms-excel.sharedStrings",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.main",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-excel.styles",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.ms-excel.threadedcomments+xml",
    "application/vnd.ms-excel.worksheet",
    "application/vnd.ms-office.DrsConnector+xml",
    "application/vnd.ms-office.DrsDownRev+xml",
    "application/vnd.ms-office.DrsE2oDoc+xml",
    "application/vnd.ms-office.DrsPicture+xml",
    "application/vnd.ms-office.DrsShape+xml",
    "application/vnd.ms-office.activeX",
    "application/vnd.ms-office.activeX+xml",
    "application/vnd.ms-office.chartcolorstyle+xml",
    "application/vnd.ms-office.chartstyle+xml",
    "application/vnd.ms-office.drawingml.diagramDrawing+xml",
    "application/vnd.ms-office.vbaProject",
    "application/vnd.ms-office.vbaProjectSignature",
    "application/vnd.ms-office.vbaProjectSignatureAgile",
    "application/vnd.ms-pkiseccat",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.ms-powerpoint.revisioninfo+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-word.keyMapCustomizations+xml",
    "application/vnd.ms-word.stylesWithEffects+xml",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.ms-word.vbaData+xml",
    "application/vnd.openxmlformats-officedocument.custom-properties+xml",
    "application/vnd.openxmlformats-officedocument.customXmlProperties+xml",
    "application/vnd.openxmlformats-officedocument.drawing+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.chart+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.diagramColors+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.diagramLayout+xml",
    "application/vnd.openxmlformats-officedocument.drawingml.diagramStyle+xml",
    "application/vnd.openxmlformats-officedocument.extended-properties+xml",
    "application/vnd.openxmlformats-officedocument.oleObject",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.presProps+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slide",
    "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideLayout",
    "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideMaster",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "application/vnd.openxmlformats-officedocument.theme+xml",
    "application/vnd.openxmlformats-officedocument.themeManager+xml",
    "application/vnd.openxmlformats-officedocument.themeOverride+xml",
    "application/vnd.openxmlformats-officedocument.vmlDrawing",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.people+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
    "application/vnd.openxmlformats-package.core-properties+xml",
    "application/vnd.openxmlformats-package.relationships+xml",
}

ASP_THIRD_BYTES = {0x3D, 0x20, 0x09, 0x0D, 0x0A}

PE_ARCH_MAP = {
    0x014C: Type.X86,
    0x8664: Type.AMD64,
    0x01C0: Type.ARM32,
    0xAA64: Type.AARCH64,
}

ELF_ARCH_MAP = {
    0x02: Type.SPARC,
    0x03: Type.X86,
    0x04: Type.M68K,
    0x08: Type.MIPS,
    0x0A: Type.MIPS64,
    0x0F: Type.HPPA,
    0x14: Type.PPC,
    0x15: Type.PPC64,
    0x16: Type.S390,
    0x18: Type.SPARC,
    0x28: Type.ARM32,
    0x29: Type.ALPHA,
    0x2A: Type.SUPH,
    0x2B: Type.SPARC64,
    0x2D: Type.ARC,
    0x32: Type.IA64,
    0x3E: Type.AMD64,
    0x4B: Type.VAX,
    0x58: Type.M32R,
    0x5C: Type.OPENR,
    0x5D: Type.ARCC,
    0x5E: Type.XTEN,
    0xB7: Type.AARCH64,
    0xBC: Type.TILEPRO,
    0xBF: Type.TILEGX,
    0xF3: Type.RISCV,
    0xFC: Type.CSKY,
    0x102: Type.LOONG,
}

MACHO_ARCH_MAP = {
    0x7: Type.X86,
    0x1000007: Type.AMD64,
    0xC: Type.ARM32,
    0x100000C: Type.AARCH64,
}

OOXML_CONTENT_MAP = {
    "application/vnd.ms-word.document.macroEnabled.12": Type.DOCM,
    "application/vnd.ms-word.keyMapCustomizations+xml": Type.DOCX,
    "application/vnd.ms-word.stylesWithEffects+xml": Type.DOCX,
    "application/vnd.ms-word.template.macroEnabled.12": Type.DOTM,
    "application/vnd.ms-word.vbaData+xml": Type.DOCM,
    "application/vnd.ms-excel.sheet.macroEnabled.12": Type.XLSM,
    "application/vnd.ms-excel.sheet.binary.macroEnabled.main": Type.XLSB,
    "application/vnd.ms-excel.template.macroEnabled.12": Type.XLTM,
    "application/vnd.ms-excel.intlmacrosheet": Type.XLSM,
    "application/vnd.ms-excel.macrosheet": Type.XLSM,
    "application/vnd.ms-excel.addin.macroEnabled.12": Type.XLAM,
    "application/vnd.ms-powerpoint.addin.macroEnabled.12": Type.PPAM,
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12": Type.PPTM,
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12": Type.PPSM,
    "application/vnd.ms-powerpoint.template.macroEnabled.12": Type.POTM,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": Type.DOCX,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": Type.DOTX,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": Type.XLSX,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": Type.XLTX,
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": Type.PPTX,
    "application/vnd.openxmlformats-officedocument.presentationml.template": Type.POTX,
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": Type.PPSX,
    "application/vnd.openxmlformats-officedocument.presentationml.slide": Type.PPTX,
    "application/vnd.openxmlformats-officedocument.presentationml.slideLayout": Type.PPTX,
    "application/vnd.openxmlformats-officedocument.presentationml.slideMaster": Type.PPTX,
}

OLE_CLSID_MAP = {
    "00000300-0000-0000-c000-000000000046": Type.OLEL,
    "00020820-0000-0000-c000-000000000046": Type.XLCH,
    "00020906-0000-0000-c000-000000000046": Type.DOC,
    "00020907-0000-0000-c000-000000000046": Type.DOC,
    "00020900-0000-0000-c000-000000000046": Type.DOC,
    "00020810-0000-0000-c000-000000000046": Type.XLS,
    "00020830-0000-0000-c000-000000000046": Type.XLS,
    "00020905-0000-0000-c000-000000000046": Type.PPT,
    "00020901-0000-0000-c000-000000000046": Type.MSG,
    "00021a14-0000-0000-c000-000000000046": Type.VSD,
    "817246f0-720a-11cf-8718-00aa0060263b": Type.PWZ,
    "0002ce02-0000-0000-c000-000000000046": Type.OLEL,
    "0002e510-0000-0000-c000-000000000046": Type.PPT,
    "0002e50a-0000-0000-c000-000000000046": Type.PPT,
    "0002e509-0000-0000-c000-000000000046": Type.PPT,
    "0002e50e-0000-0000-c000-000000000046": Type.PPT,
    "f4754c9b-64f5-4b40-8af4-679732ac0607": Type.DOCX,
    "8bd21d10-ec42-11ce-9e0d-00aa006002f3": Type.FRMF,
    "00021201-0000-0000-00c0-000000000046": Type.MSP,
    "88d96a0c-f192-11d4-a65f-0040963251e5": Type.MSXML,
    "5512d112-5cc6-11cf-8d67-00aa00bdce1d": Type.FHTML
}

MAGIC_NUM = [
    ((0, 2), {
        b'MZ': (0, "_pe"),
        b'ZM': (0, "_pe"),
        b'\x78\x01': (Type.ZLIB, None),
        b'\x78\x9c': (Type.ZLIB, None),
        b'\x78\xda': (Type.ZLIB, None),
        b'\x78\x5e': (Type.ZLIB, None),
        b'\x78\x20': (Type.ZLIB, None),
        b'\x78\x7d': (Type.ZLIB, None),
        b'\x78\xbb': (Type.ZLIB, None),
        b'\x78\xf9': (Type.ZLIB, None),
        b'\x1f\x9d': (Type.Z, None),
        b'\x60\xea': (Type.ARJ, None),
        b'\x1f\x8b': (Type.GZ, None),
        b'\x30\x82': (Type.ASN1, None),
        b'\xff\xd8': (Type.JPEG, None),
        b'\xff\xfb': (Type.MP3, None),
        b'\xff\xf3': (Type.MP3, None),
        b'\xff\xf2': (Type.MP3, None),
        b'\xff\xfe': (0, "_bom"),
        b'\xfe\xff': (0, "_bom"),
        b'\xef\xbb': (0, "_bom"),
        b'd1': (0, "_torrent"),
        b'd2': (0, "_torrent"),
        b'd3': (0, "_torrent"),
        b'd4': (0, "_torrent"),
        b'd5': (0, "_torrent"),
        b'd6': (0, "_torrent"),
        b'd7': (0, "_torrent"),
        b'd8': (0, "_torrent"),
        b'd9': (0, "_torrent"),
        b'BM': (Type.BMP, None),
        b'II': (0, "_tiff"),
        b'MM': (0, "_tiff"),
        b'#!': (Type.SH, None),
        b'BZ': (0, "_bzh_or_id3"),
        b'ID': (0, "_bzh_or_id3"),
        b'<%': (0, "_jsp_or_asp"),
        b'\x80\x02': (0, "_pickle"),
        b'\x80\x03': (0, "_pickle"),
        b'\x80\x04': (0, "_pickle"),
        b'\x80\x05': (0, "_pickle"),
    }),
    ((0, 4), {
        b'\x00\x00\x01\x00': (0, "_ico"),
        b'\x00\x00\x02\x00': (0, "_ico"),
        b'%PDF': (Type.PDF, None),
        b'\x00\x00\xfe\xff': (0, "_bom"),
        b'\xed\xab\xee\xdb': (Type.RPM, None),
        b'\xd7\xcd\xc6\x9a': (Type.WMF, None),
        b'\x0c\x00\x00\x00': (0, "_dib"),
        b'\x28\x00\x00\x00': (0, "_dib"),
        b'\x6c\x00\x00\x00': (0, "_dib"),
        b'\x7c\x00\x00\x00': (0, "_dib"),
        b'\x01\x05\x00\x00': (0, "_ole1_embedded"),
        b'{\\rt': (Type.RTF, "_rtf_markers"),
        b'\x3f\x5f\x03\x00': (Type.HLP, None),
        b'\x78\x9f\x3e\x22': (Type.TNEF, None),
        b'\x04\x22\x4d\x18': (0, "_lz4"),
        b'\x02\x21\x4c\x18': (0, "_lz4"),
        b'\x5d\x00\x00\x80': (0, "_lzma"),
        b'PK\x03\x04': (Type.ZIP, "_zip"),
        b'Rar!': (Type.RAR, None),
        b'\x7fELF': (Type.ELF, "_elf"),
        b'dex\x0a': (Type.DEX, None),
        b'xar!': (Type.XAR, None),
        b'ITSF': (Type.CHM, None),
        b'Cr24': (Type.CRX, None),
        b'\xce\xfa\xed\xfe': (Type.MACHO, "_macho"),
        b'\xcf\xfa\xed\xfe': (Type.MACHO, "_macho"),
        b'\xca\xfe\xba\xbe': (0, "_cafebabe"),
        b'MSCF': (Type.CAB, "_cab"),
        b'#@~^': (Type.MSES, None),
        b'\x00asm': (0, "_wasm"),
        b'\x28\xb5\x2f\xfd': (Type.ZST, None),
        b'\x03\x00\x08\x00': (Type.BXML, None),
        b'\x02\x00\x0c\x00': (Type.ARSC, None),
        b'RIFF': (Type.RIFF, None),
        b'\xfe\xed\xfe\xed': (Type.JKS, None),
        b'\xac\xed\x00\x05': (Type.JSER, None),
        b'\xcb\x0d\x0d\x0a': (0, "_pyc"),
        b'\x00\x01\x00\x00': (Type.TTF, None),
        b'OTTO': (Type.TTF, None),
        b'ttcf': (Type.TTF, None),
        b'PKCX': (Type.CMS, None),
        b'OggS': (Type.OGG, None),
        b'wOF2': (Type.WOF2, None),
        b'.snd': (Type.AU, None),
        b'FORM': (0, "_aiff"),
        b'\x00\x05\x16\x07': (Type.APPD, None),
        b'\x00\x05\x16\x00': (Type.APPS, None),
        b'<htm': (Type.HTML, None),
        b'<HTM': (Type.HTML, None),
        b'LZIP': (Type.LZIP, None),
        b'DAA\x00': (Type.DAA, None),
        b'<%--': (Type.JSP, None),
        b'<?ph': (0, "_php_or_xml"),
        b'<?xm': (0, "_php_or_xml"),
        b'<svg': (Type.SVG, None),
        b'<SVG': (Type.SVG, None),
        b'7z\xbc\xaf': (0, "_sevenzip"),
        b'\xfd7zX': (0, "_xz"),
        b'begi': (0, "_uue"),
        b'GIF8': (0, "_gif"),
        b'0707': (0, "_cpio"),
    }),
    ((0, 8), {
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': (0, "_olecf"),
        b'\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e': (0, "_olecf"),
        b'!<arch>\x0a': (Type.AR, "_ar"),
        b'!<thin>\x0a': (Type.AR, "_ar"),
        b'conectix': (Type.VHD, None),
        b'vhdxfile': (Type.VHDX, None),
        b'\x00\x00\x00\x01Bud1': (Type.DSSTORE, None),
        b'\x53\x5a\x44\x44\x88\xf0\x27\x33': (Type.SZDD, None),
        b'\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d': (Type.ONE, None),
        b'L\x00\x00\x00\x01\x14\x02\x00': (Type.LNK, None),
        b'MSWIM\x00\x00\x00': (Type.WIM, None),
        b'ActiveMi': (0, "_active_mime"),
        HDF5_SIGNATURE: (Type.H5, None),
        b'mrm_pri2': (Type.PRI, None),
        b'\x89PNG\x0d\x0a\x1a\x0a': (Type.PNG, None),
        b'bplist00': (Type.BPLS, None),
        b'<!DOCTYP': (Type.HTML, None),
        b'<!doctyp': (Type.HTML, None),
        b'BOMStore': (Type.BOM, None),
    }),
    ((0, 16), {
        b'SQLite format 3\x00': (Type.SQLITE, None),
        ASF_HEADER_GUID: (Type.ASF, "_asf"),
        b'<!-- saved from ': (0, "_saved_web"),
        b'<!-- Saved From ': (0, "_saved_web"),
        b'-----BEGIN CERTI': (0, "_pemc"),
        b'[InternetShortcu': (0, "_internet_shortcut"),
        b'\xa3\x48\x4b\xbe\x98\x6c\x4a\xa9\x99\x4c\x53\x0a\x86\xd6\x48\x7d': (0, "_au3")
    }),
    ((0x8001, 0x8006), {
        b'CD001': (Type.ISO, None),
        b'NSR02': (Type.UDF, None),
        b'NSR03': (Type.UDF, None),
    }),
    ((0x8801, 0x8806), {
        b'CD001': (Type.ISO, None),
        b'NSR02': (Type.UDF, None),
        b'NSR03': (Type.UDF, None),
    }),
    ((0x9001, 0x9006), {
        b'CD001': (Type.ISO, None),
        b'NSR02': (Type.UDF, None),
        b'NSR03': (Type.UDF, None),
    }),
    ((2, 5), {
        b'-lh': (0, "_lzh"),
    }),
    ((257, 262), {
        b'ustar': (Type.TAR, None),
    }),
    ((-512, -508), {
        b'koly': (0, "_dmg"),
    }),
    ((7, 13), {
        b'**ACE*': (Type.ACE, None),
    }),
    ((4, 8), {
        b'ftyp': (Type.MP4, None),
    }),
]


class QuickID:
    """
    Quick file identification logic extracted from MalObj.
    Operates on a MalObj-like instance.
    """

    def __init__(self, obj: Any):
        self._obj = obj

    def identify(self, data: Any) -> None:
        obj = self._obj

        def _data_size() -> int:
            return data.size() if hasattr(data, "size") else len(data)

        def _unpack_from(fmt: str, offset: int):
            size = struct.calcsize(fmt)
            if offset < 0:
                offset = _data_size() + offset
            return struct.unpack(fmt, data[offset:offset + size])

        def _find_first(buff: bytes, within: int, buffs: List[bytes], start: int = 0, last: int = 0) -> int:
            _offset = start
            total = _data_size()
            last = total if last <= 0 or last > total else last
            while _offset < last:
                _offset = data.find(buff, _offset, last)
                if _offset == -1:
                    break
                _offset += len(buff)
                for buffb in buffs:
                    inner_hit = data.find(buffb, _offset, _offset + within)
                    if inner_hit != -1 and inner_hit < last:
                        return buffs.index(buffb)
            return -1

        def _path_lower() -> str:
            return str(getattr(obj, "_path", "") or "").lower()

        def _bounded_bytes(limit: int = 262144, start: int = 0) -> bytes:
            total = _data_size()
            if start < 0:
                start = max(total + start, 0)
            end = min(total, start + limit)
            if start >= end:
                return b""
            return bytes(data[start:end])

        def _bounded_lower(limit: int = 262144, start: int = 0) -> bytes:
            return _bounded_bytes(limit=limit, start=start).lower()

        def _read_uint(offset: int, size: int, endian: str) -> int | None:
            if offset < 0 or offset + size > _data_size():
                return None
            return int.from_bytes(data[offset:offset + size], endian)

        def _pattern_length(pattern: tuple[bytes | int, ...]) -> int:
            return sum(part if isinstance(part, int) else len(part) for part in pattern)

        def _pattern_fixed_segment(pattern: tuple[bytes | int, ...]) -> tuple[int, bytes] | None:
            offset = 0
            for part in pattern:
                if isinstance(part, int):
                    offset += part
                    continue
                if part:
                    return offset, part
            return None

        def _pattern_matches_at(pattern: tuple[bytes | int, ...], offset: int) -> bool:
            if offset < 0:
                return False
            total = _data_size()
            pos = offset
            for part in pattern:
                if isinstance(part, int):
                    pos += part
                    if pos > total:
                        return False
                    continue
                end = pos + len(part)
                if end > total or data[pos:end] != part:
                    return False
                pos = end
            return True

        def _find_pattern(
            pattern: tuple[bytes | int, ...],
            start: int,
            end: int,
        ) -> int:
            total_size = _data_size()
            start = max(start, 0)
            end = min(end, total_size)
            pattern_len = _pattern_length(pattern)
            if pattern_len <= 0 or pattern_len > end - start:
                return -1
            segment = _pattern_fixed_segment(pattern)
            last_start = end - pattern_len
            if segment is None:
                for offset in range(start, last_start + 1):
                    if _pattern_matches_at(pattern, offset):
                        return offset
                return -1

            segment_offset, fixed_segment = segment
            search_pos = start + segment_offset
            search_end = last_start + segment_offset + len(fixed_segment)
            while search_pos < search_end:
                hit = data.find(fixed_segment, search_pos, search_end)
                if hit == -1:
                    return -1
                candidate = hit - segment_offset
                if candidate >= 0 and _pattern_matches_at(pattern, candidate):
                    return candidate
                search_pos = hit + 1
            return -1

        def _zip_read_small(zf: Any, name: str, limit: int = 65536) -> bytes:
            try:
                info = zf.getinfo(name)
                if info.file_size > limit:
                    return b""
                return zf.read(name)[:limit]
            except Exception:
                return b""

        def _zip_read_text(zf: Any, name: str, limit: int = 65536) -> str:
            return _zip_read_small(zf, name, limit).decode("utf-8", errors="ignore")

        def _normalized_zip_names(names: list[str]) -> set[str]:
            return {name.replace("\\", "/") for name in names}

        def _pe_section_raw_end(pe_offset: int) -> int:
            section_count = _unpack_from("<H", pe_offset + 6)[0]
            optional_header_size = _unpack_from("<H", pe_offset + 20)[0]
            section_table = pe_offset + 24 + optional_header_size
            raw_end = 0
            total = _data_size()
            for index in range(section_count):
                section_offset = section_table + (index * 40)
                if section_offset + 40 > total:
                    return 0
                raw_size = _unpack_from("<I", section_offset + 16)[0]
                raw_offset = _unpack_from("<I", section_offset + 20)[0]
                if raw_offset == 0 or raw_size == 0:
                    continue
                raw_end = max(raw_end, raw_offset + raw_size)
            return raw_end if 0 < raw_end <= total else 0

        def _pe_section_names(pe_offset: int) -> set[bytes]:
            section_count = _unpack_from("<H", pe_offset + 6)[0]
            optional_header_size = _unpack_from("<H", pe_offset + 20)[0]
            section_table = pe_offset + 24 + optional_header_size
            total = _data_size()
            names = set()
            for index in range(section_count):
                section_offset = section_table + (index * 40)
                if section_offset + 40 > total:
                    return names
                name = bytes(data[section_offset:section_offset + 8]).split(b"\0", 1)[0].lower()
                if name:
                    names.add(name)
            return names

        def _upx_marker_scan(scan: bytes) -> bool:
            return UPX_INFO_MARKER in scan or (
                UPX_MAGIC in scan and b"upx0" in scan and b"upx1" in scan
            )

        def _elf_layout() -> tuple[str, int, int, int, int, int, int, int, int, int, int, int] | None:
            total = _data_size()
            if total < 0x34:
                return None

            elf_class = data[4]
            endian_flag = data[5]
            if endian_flag == 1:
                endian = "little"
            elif endian_flag == 2:
                endian = "big"
            else:
                return None

            if elf_class == 1:
                entry = _read_uint(0x18, 4, endian)
                phoff = _read_uint(0x1C, 4, endian)
                phentsize = _read_uint(0x2A, 2, endian)
                phnum = _read_uint(0x2C, 2, endian)
                ph_type_offset = 0
                ph_flags_offset = 24
                ph_offset_offset = 4
                ph_vaddr_offset = 8
                ph_filesz_offset = 16
                ph_min_size = 32
                word_size = 4
            elif elf_class == 2:
                if total < 0x40:
                    return None
                entry = _read_uint(0x18, 8, endian)
                phoff = _read_uint(0x20, 8, endian)
                phentsize = _read_uint(0x36, 2, endian)
                phnum = _read_uint(0x38, 2, endian)
                ph_type_offset = 0
                ph_flags_offset = 4
                ph_offset_offset = 8
                ph_vaddr_offset = 16
                ph_filesz_offset = 32
                ph_min_size = 56
                word_size = 8
            else:
                return None

            if entry is None or phoff is None or phentsize is None or phnum is None:
                return None
            return (
                endian,
                entry,
                phoff,
                phentsize,
                phnum,
                ph_type_offset,
                ph_flags_offset,
                ph_offset_offset,
                ph_vaddr_offset,
                ph_filesz_offset,
                ph_min_size,
                word_size,
            )

        def _elf_entry_file_offset() -> int | None:
            total = _data_size()
            layout = _elf_layout()
            if layout is None:
                return None
            (
                endian,
                entry,
                phoff,
                phentsize,
                phnum,
                ph_type_offset,
                _ph_flags_offset,
                ph_offset_offset,
                ph_vaddr_offset,
                ph_filesz_offset,
                ph_min_size,
                word_size,
            ) = layout

            if phoff <= 0 or phentsize < ph_min_size:
                return entry if 0 <= entry < total else None

            for index in range(min(phnum, 256)):
                ph = phoff + (index * phentsize)
                if ph < 0 or ph + ph_min_size > total:
                    break
                ph_type = _read_uint(ph + ph_type_offset, 4, endian)
                if ph_type != 1:
                    continue
                file_offset = _read_uint(ph + ph_offset_offset, word_size, endian)
                vaddr = _read_uint(ph + ph_vaddr_offset, word_size, endian)
                filesz = _read_uint(ph + ph_filesz_offset, word_size, endian)
                if file_offset is None or vaddr is None or filesz is None:
                    continue
                if filesz == 0 or not (vaddr <= entry < vaddr + filesz):
                    continue
                mapped = file_offset + (entry - vaddr)
                if 0 <= mapped < total:
                    return mapped

            return entry if 0 <= entry < total else None

        def _elf_executable_file_ranges() -> list[tuple[int, int]]:
            total = _data_size()
            layout = _elf_layout()
            if layout is None:
                return []
            (
                endian,
                _entry,
                phoff,
                phentsize,
                phnum,
                ph_type_offset,
                ph_flags_offset,
                ph_offset_offset,
                _ph_vaddr_offset,
                ph_filesz_offset,
                ph_min_size,
                word_size,
            ) = layout
            if phoff <= 0 or phentsize < ph_min_size:
                return []

            ranges = []
            for index in range(min(phnum, 256)):
                ph = phoff + (index * phentsize)
                if ph < 0 or ph + ph_min_size > total:
                    break
                ph_type = _read_uint(ph + ph_type_offset, 4, endian)
                flags = _read_uint(ph + ph_flags_offset, 4, endian)
                if ph_type != 1 or flags is None or not (flags & 0x1):
                    continue
                file_offset = _read_uint(ph + ph_offset_offset, word_size, endian)
                filesz = _read_uint(ph + ph_filesz_offset, word_size, endian)
                if file_offset is None or filesz is None or filesz == 0:
                    continue
                start = file_offset
                end = min(file_offset + filesz, start + UPX_ELF_EXEC_SEGMENT_SCAN_LIMIT, total)
                if start < end:
                    ranges.append((start, end))
            return ranges

        def _elf_upx_stub() -> bool:
            entry_offset = _elf_entry_file_offset()
            if entry_offset is not None:
                for pattern in UPX_ELF_STUB_PATTERNS:
                    if _pattern_matches_at(pattern, entry_offset):
                        return True

            for start, end in _elf_executable_file_ranges():
                for pattern in UPX_ELF_STUB_PATTERNS:
                    hit = _find_pattern(pattern, start, end)
                    if hit != -1 and hit != entry_offset:
                        return True
            return False

        def _pe_upx(pe_offset: int, scan: bytes) -> None:
            section_names = _pe_section_names(pe_offset)
            upx_section_names = section_names & UPX_SECTION_NAMES
            if UPX_INFO_MARKER in scan:
                obj._filetype |= Type.UPX
                return
            if UPX_MAGIC in scan and upx_section_names:
                obj._filetype |= Type.UPX
                return

        def _pe_packer_markers(pe_offset: int, scan: bytes) -> None:
            section_names = _pe_section_names(pe_offset)
            for packer_type, exact_sections, section_prefixes, markers in PE_PACKER_RULES:
                if any(section in section_names for section in exact_sections):
                    obj._filetype |= packer_type
                    continue
                if any(
                    section_name.startswith(prefix)
                    for prefix in section_prefixes
                    for section_name in section_names
                ):
                    obj._filetype |= packer_type
                    continue
                if any(marker in scan for marker in markers):
                    obj._filetype |= packer_type

        def _pe_enigma_virtual_box(pe_offset: int, scan: bytes) -> None:
            section_names = _pe_section_names(pe_offset)
            if {b".enigma1", b".enigma2"} <= section_names and b"evb\x00" in scan:
                obj._filetype |= Type.EVB

        def _nsis_candidate(firstheader_offset: int) -> bool:
            total = _data_size()
            if firstheader_offset + NSIS_FIRSTHEADER_SIZE > total:
                return False
            flags, siginfo, nsinst0, nsinst1, nsinst2, header_len, archive_size = _unpack_from(
                "<7I",
                firstheader_offset,
            )
            if flags & ~NSIS_FLAGS_MASK:
                return False
            if siginfo != 0xDEADBEEF:
                return False
            if (nsinst0, nsinst1, nsinst2) != (0x6C6C754E, 0x74666F73, 0x74736E49):
                return False
            if header_len == 0:
                return False
            if archive_size <= NSIS_FIRSTHEADER_SIZE:
                return False
            return firstheader_offset + archive_size <= total

        def _nsis(pe_offset: int) -> None:
            raw_end = _pe_section_raw_end(pe_offset)
            if raw_end == 0:
                return
            total = _data_size()
            search_start = ((raw_end + NSIS_SCAN_ALIGNMENT - 1) // NSIS_SCAN_ALIGNMENT) * NSIS_SCAN_ALIGNMENT
            for firstheader_offset in range(search_start, total - NSIS_FIRSTHEADER_SIZE + 1, NSIS_SCAN_ALIGNMENT):
                if _nsis_candidate(firstheader_offset):
                    obj._filetype |= Type.NSIS
                    return

        def _mark_installer_strings(scan: bytes) -> None:
            for installer_type, markers in INSTALLER_MARKERS:
                if any(marker in scan for marker in markers):
                    obj._filetype |= installer_type

        def _nodejs_pkg(scan: bytes) -> bool:
            has_pkg_marker = any(marker in scan for marker in NODEJS_PKG_MARKERS)
            has_runtime_context = b"package.json" in scan or b"node.js" in scan or b"node::" in scan
            if has_pkg_marker and has_runtime_context:
                obj._filetype |= Type.NODEJS_PKG
                return True
            return False

        def _pe_subtypes(pe_offset: int) -> None:
            scan = _bounded_lower(524288)
            _pe_upx(pe_offset, scan)
            _pe_enigma_virtual_box(pe_offset, scan)
            _pe_packer_markers(pe_offset, scan)
            _mark_installer_strings(scan)
            _nodejs_pkg(scan)

            raw_end = _pe_section_raw_end(pe_offset)
            if raw_end == 0:
                return
            overlay = _bounded_bytes(limit=65536, start=raw_end)
            if not overlay:
                return
            overlay_scan = overlay.lower()
            _mark_installer_strings(overlay_scan)
            if _nodejs_pkg(overlay_scan):
                return
            if int(obj._filetype) & int(INSTALLER_TYPES):
                return
            if any(marker in overlay for marker in PE_OVERLAY_ARCHIVE_MARKERS):
                obj._filetype |= Type.SFX_PEEXE

        def _pe():
            pe_offset = _unpack_from("<I", 0x3C)[0]
            if data[pe_offset: pe_offset + 4] == b"PE\0\0":
                optional_header_magic = _unpack_from("<H", pe_offset + 0x18)[0]
                if optional_header_magic == 0x10b or optional_header_magic == 0x20b:
                    obj._filetype |= Type.PE32
                    obj._filetype |= PE_ARCH_MAP.get(_unpack_from("<H", pe_offset + 4)[0], 0)
                    clr_rt_hdr_offset = (208 if optional_header_magic == 0x10b else 224) + pe_offset + 24
                    clr_rva, clr_size = _unpack_from("<II", clr_rt_hdr_offset)
                    if not (clr_rva == 0 or clr_size == 0):
                        obj._filetype |= Type.DOTNET
                    _nsis(pe_offset)
                    _pe_subtypes(pe_offset)

        def _elf():
            endian_flag = data[5]
            endian = "little" if endian_flag == 1 else "big"
            e_machine = int.from_bytes(data[18:20], endian)
            obj._filetype |= ELF_ARCH_MAP.get(e_machine, 0)
            scan = _bounded_lower(ELF_MARKER_SCAN_LIMIT)
            if _upx_marker_scan(scan) or _elf_upx_stub():
                obj._filetype |= Type.UPX
            _mark_installer_strings(scan)
            _nodejs_pkg(scan)

        def _macho():
            obj._filetype |= MACHO_ARCH_MAP.get(_unpack_from("<I", 4)[0], 0)
            scan = _bounded_lower(524288)
            _mark_installer_strings(scan)
            _nodejs_pkg(scan)

        def _cafebabe():
            nfat_arch = int.from_bytes(data[4:8], "big")
            if 1 <= nfat_arch <= 10:
                obj._filetype |= Type.MACHO
                obj._filetype |= Type.MFAT
                return
            major = int.from_bytes(data[6:8], "big")
            if 45 <= major <= 70:
                obj._filetype |= Type.CLASS

        def _ole1_embedded():
            if _data_size() < 24:
                return
            try:
                ole_ver = _unpack_from("<I", 0)[0]
                fmt_id = _unpack_from("<I", 4)[0]
                name_len = _unpack_from("<I", 8)[0]
            except Exception:
                return
            if ole_ver != 0x00000501:
                return
            if fmt_id not in (1, 2):
                return
            if name_len == 0 or name_len > 256 or (name_len % 2) != 0:
                return
            name_end = 12 + name_len
            if _data_size() < name_end:
                return
            # name bytes are not needed for identification beyond length checks
            obj._filetype |= Type.OLE

        def _ole1_embedded_loose():
            if _data_size() < 24:
                return
            try:
                fmt_id = _unpack_from("<I", 4)[0]
                name_len = _unpack_from("<I", 8)[0]
            except Exception:
                return
            if fmt_id not in (1, 2):
                return
            if name_len < 2 or name_len > 64:
                return
            name_end = 12 + name_len
            if _data_size() < name_end:
                return
            name_bytes = data[12:name_end]
            if b"\x00" not in name_bytes:
                return
            obj._filetype |= Type.OLE

        def _zip():
            hit = _find_first(b"PK\x01\x02", 66,
                              [b"[Content_Types].xml", b"AndroidManifest.xml",
                               b"META-INF/MANIFEST.MF", b"WEB-INF/web.xml"])
            result = (0, Type.OXML, Type.APK, -1, Type.WAR)[hit + 1]
            if result == -1:
                obj._filetype |= (Type.JAR, Type.WAR)[_find_first(b"PK\x01\x02", 66, [b"WEB-INF/web.xml"]) + 1]
            else:
                obj._filetype |= result
            path = getattr(obj, "_path", None)
            path_lower = _path_lower()
            if path_lower.endswith((".apkx", ".apks", ".apkm")):
                obj._filetype |= Type.APKX
            if not path:
                return
            try:
                import zipfile
                with zipfile.ZipFile(path, "r") as zf:
                    names = zf.namelist()
                    normalized_names = _normalized_zip_names(names)
                    lower_names = {name.lower() for name in normalized_names}
                    infos = zf.infolist()

                    if path_lower.endswith(".zipx") or any(
                        info.compress_type in ZIPX_METHODS or info.flag_bits & 0x40
                        for info in infos
                    ):
                        obj._filetype |= Type.ZIPX

                    mimetype = _zip_read_text(zf, "mimetype", limit=256).strip()
                    odf_type = ODF_MIME_MAP.get(mimetype)
                    if odf_type is not None:
                        obj._filetype |= odf_type

                    if "[Content_Types].xml" in normalized_names:
                        obj._filetype |= Type.OXML
                        content_text = _zip_read_text(zf, "[Content_Types].xml")
                        content_lower = content_text.lower()
                        has_rels = "_rels/.rels" in lower_names
                        if (
                            has_rels
                            and "xl/workbook.bin" in lower_names
                            and "application/vnd.ms-excel.sheet.binary.macroenabled.main" in content_lower
                        ):
                            obj._filetype |= Type.XLSB
                        for key, val in OOXML_CONTENT_MAP.items():
                            if key.lower() in content_lower:
                                obj._filetype |= val
                        if "appxmanifest.xml" in lower_names:
                            obj._filetype |= Type.MSIX
                        if "extension.vsixmanifest" in lower_names:
                            obj._filetype |= Type.VSIX

                    dist_info_wheels = [
                        name for name in lower_names
                        if name.endswith(".dist-info/wheel") and name.count("/") == 1
                    ]
                    if len(dist_info_wheels) == 1:
                        dist_info_prefix = dist_info_wheels[0].rsplit("/", 1)[0] + "/"
                        if (
                            any(name == dist_info_prefix + "record" for name in lower_names)
                            or path_lower.endswith(".whl")
                        ):
                            obj._filetype |= Type.WHL

                    if (
                        "install.rdf" in lower_names
                        or "chrome.manifest" in lower_names
                        or "meta-inf/mozilla.rsa" in lower_names
                        or (path_lower.endswith(".xpi") and "manifest.json" in lower_names)
                    ):
                        obj._filetype |= Type.XPI

                    pytorch_markers = {
                        "data.pkl",
                        "constants.pkl",
                        "version",
                        "model.json",
                    }
                    if any(name.rsplit("/", 1)[-1] in pytorch_markers for name in lower_names) and any(
                        name.endswith("data.pkl") for name in lower_names
                    ):
                        obj._filetype |= Type.PYTORCH_MODEL
            except Exception:
                return
            return

        def _ole_scan_subtypes(raw: bytes) -> None:
            scan = raw.lower()
            if b"fileheader" in scan and b"hwp document file" in scan:
                obj._filetype |= Type.HWP
            if b"microsoft publisher" in scan or b"publisher document" in scan:
                obj._filetype |= Type.PUB
            if b"word.template.6" in scan or b"word.template.7" in scan or b"dot95" in scan:
                obj._filetype |= Type.DOC | Type.DOT95
            if b"word.document.6" in scan or b"word.document.7" in scan or b"word 6.0" in scan:
                obj._filetype |= Type.DOC | Type.DOC95
            if b"powerpoint document" in scan and (b"powerpoint 95" in scan or b"ppt95" in scan):
                obj._filetype |= Type.PPT | Type.PPT95
            if b"mmc_consolefile" in scan or b"microsoft management console" in scan:
                obj._filetype |= Type.MSC
            if b"activemime" in scan:
                obj._filetype |= Type.MSO
            if b"workbook" in scan and b"\x09\x08" in raw and (b"\x05\x00" in raw or b"biff5" in scan):
                obj._filetype |= Type.XLS | Type.XLS95

        def _ole_stream_names(ole: Any) -> list[str]:
            names: list[str] = []
            try:
                for path_parts in ole.listdir(streams=True, storages=True):
                    if isinstance(path_parts, (list, tuple)):
                        names.append("/".join(str(part) for part in path_parts))
                    else:
                        names.append(str(path_parts))
            except Exception:
                pass
            return names

        def _ole_read_stream(ole: Any, name: str, limit: int = 65536) -> bytes:
            try:
                stream = ole.openstream(name.split("/"))
            except Exception:
                try:
                    stream = ole.openstream(name)
                except Exception:
                    return b""
            try:
                return stream.read(limit)
            except Exception:
                return b""

        def _olefile_subtypes(ole: Any) -> None:
            names = _ole_stream_names(ole)
            names_lower = [name.lower() for name in names]
            joined = "\n".join(names_lower).encode()
            _ole_scan_subtypes(joined)

            if "fileheader" in names_lower:
                header = _ole_read_stream(ole, names[names_lower.index("fileheader")], limit=512)
                if b"HWP Document File" in header:
                    obj._filetype |= Type.HWP
            for index, _name in enumerate(names_lower):
                raw = _ole_read_stream(ole, names[index], limit=4096)
                if raw:
                    _ole_scan_subtypes(names[index].encode(errors="ignore") + b"\n" + raw)

        def _olecf():
            msi = _find_first(b'\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00',
                              100, [b'\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'])
            obj._filetype |= Type.MSI if msi != -1 else Type.OLE
            _ole_scan_subtypes(_bounded_bytes(262144))
            path = getattr(obj, "_path", None)
            if msi != -1 or not path:
                return
            try:
                import olefile
                ole = olefile.OleFileIO(path)
            except Exception:
                return
            try:
                entries = getattr(ole, "direntries", [])
                for entry in entries:
                    try:
                        clsid_val = getattr(entry, "clsid", None)
                        if not clsid_val:
                            continue
                        val = OLE_CLSID_MAP.get(str(clsid_val).lower())
                        if val:
                            obj._filetype |= val
                    except Exception:
                        continue
                _olefile_subtypes(ole)
            finally:
                try:
                    ole.close()
                except Exception:
                    pass

        def _tiff():
            if data[0:2] == b'II' and data[2:4] == b'\x2a\x00':
                obj._filetype |= Type.TIF
            elif data[0:2] == b'MM' and data[2:4] == b'\x00\x2a':
                obj._filetype |= Type.TIF

        def _dib():
            if _data_size() < 12:
                return
            try:
                header_size = _unpack_from("<I", 0)[0]
            except Exception:
                return
            if header_size == 12:
                try:
                    width, height, planes, bitcount = _unpack_from("<HHHH", 4)
                except Exception:
                    return
                if width <= 0 or height <= 0:
                    return
                if planes != 1 or bitcount not in (1, 4, 8, 16, 24, 32):
                    return
                palette_entries = (1 << bitcount) if bitcount <= 8 else 0
                palette_size = palette_entries * 3
                row_bytes = ((width * bitcount + 15) // 16) * 2
                min_size = header_size + palette_size + (row_bytes * height)
                if _data_size() < min_size:
                    return
                obj._filetype |= Type.DIB
                return
            if header_size not in (40, 108, 124):
                return
            if _data_size() < header_size:
                return
            try:
                width, height, planes, bitcount, compression, size_image, _, _, clr_used, _ = _unpack_from(
                    "<iiHHIIiiII", 4
                )
            except Exception:
                return
            if width <= 0 or height == 0:
                return
            if planes != 1 or bitcount not in (1, 4, 8, 16, 24, 32):
                return
            if compression not in (0, 1, 2, 3, 4, 5, 6):
                return
            palette_entries = 0
            if bitcount <= 8:
                palette_entries = clr_used if clr_used else (1 << bitcount)
            palette_size = palette_entries * 4
            masks_size = 0
            if compression in (3, 6) and header_size == 40:
                masks_size = 12 if compression == 3 else 16
            if size_image == 0 and compression in (0, 3, 6):
                row_bytes = ((width * bitcount + 31) // 32) * 4
                size_image = row_bytes * abs(height)
            min_size = header_size + masks_size + palette_size
            if size_image:
                min_size += size_image
            if _data_size() < min_size:
                return
            obj._filetype |= Type.DIB

        def _aiff():
            if _data_size() < 12:
                return
            ftype = data[8:12]
            if ftype == b'AIFF':
                obj._filetype |= Type.AIF
            elif ftype == b'AIFC':
                obj._filetype |= Type.AIFC

        def _cab():
            scan = _bounded_lower(262144)
            if (
                b".cab" in scan
                and (b".xml" in scan or b"update.mum" in scan or b"wsusscan" in scan)
                and (b"package" in scan or b"update" in scan or b"microsoft" in scan)
            ):
                obj._filetype |= Type.MSU

        def _active_mime():
            if _data_size() >= 10 and data[:10] == b"ActiveMime":
                obj._filetype |= Type.MSO

        def _asf():
            scan = _bounded_lower(65536)
            obj._filetype |= Type.ASF
            if b"wmv" in scan or b"windows media video" in scan or b"wm/video" in scan:
                obj._filetype |= Type.WMV

        def _hdf5():
            for offset in (0, 512, 1024, 2048, 4096, 8192, 16384):
                if _data_size() >= offset + len(HDF5_SIGNATURE) and data[offset:offset + 8] == HDF5_SIGNATURE:
                    obj._filetype |= Type.H5
                    return

        def _dwg():
            if _data_size() >= 6 and data[:4] == b"AC10" and bytes(data[4:6]).isdigit():
                obj._filetype |= Type.DWG

        def _tensorflow_pb():
            scan = _bounded_lower(262144)
            path = _path_lower()
            strong_markers = (
                b"savedmodel",
                b"saved_model",
                b"tensorflow",
                b"signaturedef",
                b"graphdef",
            )
            weak_markers = (b"serving_default", b"node_def", b"tensor", b"op")
            if path.endswith("saved_model.pb") and any(marker in scan for marker in weak_markers + strong_markers):
                obj._filetype |= Type.TENSORFLOW_PB
                return
            marker_count = sum(1 for marker in strong_markers if marker in scan)
            if marker_count >= 1 and any(marker in scan for marker in weak_markers):
                obj._filetype |= Type.TENSORFLOW_PB

        def _pytorch_pickle():
            path = _path_lower()
            if not (int(obj._filetype) & int(Type.PICKLE) or path.endswith((".pt", ".pth", ".pkl", ".pickle"))):
                return
            scan = _bounded_lower(262144)
            if b"torch" not in scan:
                return
            if (
                b"torch._utils" in scan
                or b"torch.storage" in scan
                or b"torch.nn.modules" in scan
                or b"pytorch" in scan
            ):
                obj._filetype |= Type.PYTORCH_MODEL

        def _ico():
            if _data_size() < 22:
                return
            if data[0:2] != b'\x00\x00':
                return
            icon_type = data[2:4]
            if icon_type not in (b'\x01\x00', b'\x02\x00'):
                return
            count = int.from_bytes(data[4:6], "little")
            if count <= 0:
                return
            entry = data[6:22]
            bytes_in_res = int.from_bytes(entry[8:12], "little")
            image_offset = int.from_bytes(entry[12:16], "little")
            if bytes_in_res <= 0 or image_offset <= 0:
                return
            if image_offset + bytes_in_res > _data_size():
                return
            obj._filetype |= Type.ICO

        def _torrent():
            head = data[:4096]
            if head.find(b'4:info') != -1 and (head.find(b'8:announce') != -1
                                               or head.find(b'13:announce-list') != -1):
                obj._filetype |= Type.TORR

        def _rtf_markers():
            scan = bytes(data).lower()
            if b'\\object' in scan or b'\\objdata' in scan or b'\\objclass' in scan or b'\\objupdate' in scan \
                    or b'\\objautlink' in scan:
                obj._filetype |= Type.ROBJ
            if b'ddeauto' in scan or b'dde' in scan:
                obj._filetype |= Type.RDDE
            if b'includetext' in scan or b'includepicture' in scan:
                obj._filetype |= Type.RINC
            if b'hyperlink' in scan:
                obj._filetype |= Type.RHYP
            if b'\\bin' in scan:
                obj._filetype |= Type.RBIN
            if b'\\field' in scan or b'\\fldinst' in scan:
                obj._filetype |= Type.RINC

        def _bzh_or_id3():
            if _data_size() < 3:
                return
            third = data[2]
            if third == 0x68 and 0x31 <= data[3] <= 0x39:
                obj._filetype |= Type.BZ2
            elif third == 0x33:
                obj._filetype |= Type.ID3

        def _bom():
            if _data_size() < 2:
                return
            if _data_size() >= 4:
                head4 = data[0:4]
                if head4 == b'\xff\xfe\x00\x00':
                    obj._filetype |= Type.U32LEBOM
                    return
                if head4 == b'\x00\x00\xfe\xff':
                    obj._filetype |= Type.U32BEBOM
                    return
            if _data_size() >= 3 and data[0:3] == b'\xef\xbb\xbf':
                obj._filetype |= Type.U8BOM
                return
            head2 = data[0:2]
            if head2 == b'\xff\xfe':
                obj._filetype |= Type.U16LEBOM
            elif head2 == b'\xfe\xff':
                obj._filetype |= Type.U16BEBOM

        def _php_or_xml():
            if _data_size() < 5:
                return
            fifth = data[4]
            if 0x41 <= fifth <= 0x5A:
                fifth |= 0x20
            if fifth == 0x70:
                obj._filetype |= Type.PHP
            elif fifth == 0x6C:
                if _looks_like_svg_markup():
                    obj._filetype |= Type.SVG
                elif _looks_like_libraryms_markup():
                    obj._filetype |= Type.XML | Type.LIBRARYMS
                else:
                    obj._filetype |= Type.XML

        def _decoded_text_prefix(limit: int = 8192) -> str:
            raw = bytes(data[:min(limit, _data_size())])
            if raw.startswith(b'\xff\xfe\x00\x00'):
                return raw[4:].decode("utf-32le", errors="ignore")
            if raw.startswith(b'\x00\x00\xfe\xff'):
                return raw[4:].decode("utf-32be", errors="ignore")
            if raw.startswith(b'\xff\xfe'):
                return raw[2:].decode("utf-16le", errors="ignore")
            if raw.startswith(b'\xfe\xff'):
                return raw[2:].decode("utf-16be", errors="ignore")
            if raw.startswith(b'\xef\xbb\xbf'):
                raw = raw[3:]
            sample = raw[:256]
            if b'\x00' in sample:
                even_nulls = sample[0::2].count(0)
                odd_nulls = sample[1::2].count(0)
                if odd_nulls > 4 and odd_nulls > even_nulls * 3:
                    return raw.decode("utf-16le", errors="ignore")
                if even_nulls > 4 and even_nulls > odd_nulls * 3:
                    return raw.decode("utf-16be", errors="ignore")
                return ""
            return raw.decode("utf-8", errors="ignore")

        def _strip_xml_prefix(text: str) -> str:
            prefix = text.lstrip()
            if prefix.lower().startswith("<?xml"):
                end = prefix.find("?>")
                if end == -1:
                    return ""
                prefix = prefix[end + 2:].lstrip()
            while prefix.lower().startswith("<!--"):
                end = prefix.find("-->")
                if end == -1:
                    return ""
                prefix = prefix[end + 3:].lstrip()
            return prefix

        def _looks_like_svg_markup():
            prefix = bytes(data[:4096]).lstrip()
            if prefix.startswith(b'\xef\xbb\xbf'):
                prefix = prefix[3:].lstrip()
            lowered = prefix.lower()
            if lowered.startswith(b'<?xml'):
                end = lowered.find(b'?>')
                if end == -1:
                    return False
                prefix = prefix[end + 2:].lstrip()
                lowered = prefix.lower()
            while lowered.startswith(b'<!--'):
                end = lowered.find(b'-->')
                if end == -1:
                    return False
                prefix = prefix[end + 3:].lstrip()
                lowered = prefix.lower()
            if lowered.startswith(b'<!doctype'):
                end = lowered.find(b'>')
                if end == -1:
                    return False
                prefix = prefix[end + 1:].lstrip()
                lowered = prefix.lower()
            if not lowered.startswith(b'<svg'):
                return False
            return len(lowered) == 4 or lowered[4] in b' \t\r\n>/'

        def _looks_like_libraryms_markup():
            prefix = _strip_xml_prefix(_decoded_text_prefix(4096))
            lowered = prefix.lower()
            if not lowered.startswith("<librarydescription"):
                return False
            return len(lowered) == 19 or lowered[19] in " \t\r\n>/"

        def _jsp_or_asp():
            if _data_size() < 3:
                return
            third = data[2]
            if third == 0x40:
                obj._filetype |= Type.JSP
            elif third in ASP_THIRD_BYTES:
                obj._filetype |= Type.ASP

        def _saved_web():
            if _data_size() >= 20 and data[:20] == b'<!-- saved from url=' or data[:20] == b'<!-- Saved From Url=':
                obj._filetype |= Type.SAVW

        def _pemc():
            if _data_size() >= 27 and data[:27] == b'-----BEGIN CERTIFICATE-----':
                obj._filetype |= Type.PEMC

        def _internet_shortcut():
            if _data_size() >= 18 and data[:18] == b'[InternetShortcut]':
                obj._filetype |= Type.IURL

        def _lzh():
            if _data_size() >= 5 and data[2:5] == b'-lh':
                obj._filetype |= Type.LZH

        def _sevenzip():
            if _data_size() >= 6 and data[:6] == b'7z\xbc\xaf\x27\x1c':
                obj._filetype |= Type.SEVENZIP

        def _xz():
            if _data_size() >= 4 and data[:6] == b'\xfd7zXZ\x00':
                obj._filetype |= Type.XZ

        def _lzma():
            if _data_size() < 13:
                return
            props = data[0]
            value = props
            lc = value % 9
            value //= 9
            lp = value % 5
            pb = value // 5
            if lc > 8 or lp > 4 or pb > 4:
                return
            dict_size = int.from_bytes(data[1:5], "little")
            if dict_size == 0:
                return
            path = str(getattr(obj, "_path", "") or "").lower()
            if data[:5] == b'\x5d\x00\x00\x80\x00' or path.endswith(".lzma"):
                obj._filetype |= Type.LZMA

        def _lz4():
            if _data_size() < 4:
                return
            if data[:4] == b'\x02\x21\x4c\x18':
                obj._filetype |= Type.LZ4
                return
            if _data_size() < 7 or data[:4] != b'\x04\x22\x4d\x18':
                return
            flags = data[4]
            version = flags >> 6
            if version != 1:
                return
            obj._filetype |= Type.LZ4

        def _wasm():
            if _data_size() >= 8 and data[:8] == b'\x00asm\x01\x00\x00\x00':
                obj._filetype |= Type.WASM
                try:
                    wasm32, wasm64 = _wasm_memory_address_types()
                except ValueError:
                    return
                if wasm32:
                    obj._filetype |= Type.WASM32
                if wasm64:
                    obj._filetype |= Type.WASM64

        def _read_uleb(offset: int, end: int) -> tuple[int, int]:
            value = 0
            shift = 0
            while offset < end and shift <= 63:
                byte = data[offset]
                offset += 1
                value |= (byte & 0x7f) << shift
                if byte & 0x80 == 0:
                    return value, offset
                shift += 7
            raise ValueError("Invalid WebAssembly LEB128 integer")

        def _skip_wasm_name(offset: int, end: int) -> int:
            size, offset = _read_uleb(offset, end)
            next_offset = offset + size
            if next_offset > end:
                raise ValueError("Invalid WebAssembly name")
            return next_offset

        def _skip_wasm_reftype(offset: int, end: int) -> int:
            if offset >= end:
                raise ValueError("Invalid WebAssembly reference type")
            prefix = data[offset]
            offset += 1
            if prefix in (0x63, 0x64):
                _, offset = _read_uleb(offset, end)
            return offset

        def _read_wasm_limits(offset: int, end: int) -> tuple[bool, int]:
            if offset >= end:
                raise ValueError("Invalid WebAssembly limits")
            flags = data[offset]
            offset += 1
            if flags & ~0x07:
                raise ValueError("Unsupported WebAssembly limits flags")
            is_64_bit = bool(flags & 0x04)
            _, offset = _read_uleb(offset, end)
            if flags & 0x01:
                _, offset = _read_uleb(offset, end)
            return is_64_bit, offset

        def _skip_wasm_table_type(offset: int, end: int) -> int:
            offset = _skip_wasm_reftype(offset, end)
            _, offset = _read_wasm_limits(offset, end)
            return offset

        def _skip_wasm_global_type(offset: int, end: int) -> int:
            offset = _skip_wasm_reftype(offset, end)
            if offset >= end:
                raise ValueError("Invalid WebAssembly global type")
            return offset + 1

        def _read_wasm_imports(offset: int, end: int) -> tuple[bool, bool]:
            wasm32 = False
            wasm64 = False
            count, offset = _read_uleb(offset, end)
            for _ in range(count):
                offset = _skip_wasm_name(offset, end)
                offset = _skip_wasm_name(offset, end)
                if offset >= end:
                    raise ValueError("Invalid WebAssembly import descriptor")
                kind = data[offset]
                offset += 1
                if kind == 0x00:
                    _, offset = _read_uleb(offset, end)
                elif kind == 0x01:
                    offset = _skip_wasm_table_type(offset, end)
                elif kind == 0x02:
                    is_64_bit, offset = _read_wasm_limits(offset, end)
                    wasm64 = wasm64 or is_64_bit
                    wasm32 = wasm32 or not is_64_bit
                elif kind == 0x03:
                    offset = _skip_wasm_global_type(offset, end)
                elif kind == 0x04:
                    if offset >= end:
                        raise ValueError("Invalid WebAssembly tag type")
                    offset += 1
                    _, offset = _read_uleb(offset, end)
                else:
                    raise ValueError("Invalid WebAssembly import kind")
            return wasm32, wasm64

        def _read_wasm_memories(offset: int, end: int) -> tuple[bool, bool]:
            wasm32 = False
            wasm64 = False
            count, offset = _read_uleb(offset, end)
            for _ in range(count):
                is_64_bit, offset = _read_wasm_limits(offset, end)
                wasm64 = wasm64 or is_64_bit
                wasm32 = wasm32 or not is_64_bit
            return wasm32, wasm64

        def _wasm_memory_address_types() -> tuple[bool, bool]:
            offset = 8
            end = _data_size()
            wasm32 = False
            wasm64 = False
            while offset < end:
                section_id = data[offset]
                offset += 1
                section_size, offset = _read_uleb(offset, end)
                section_end = offset + section_size
                if section_end > end:
                    raise ValueError("Invalid WebAssembly section size")
                if section_id == 2:
                    section_wasm32, section_wasm64 = _read_wasm_imports(offset, section_end)
                    wasm32 = wasm32 or section_wasm32
                    wasm64 = wasm64 or section_wasm64
                elif section_id == 5:
                    section_wasm32, section_wasm64 = _read_wasm_memories(offset, section_end)
                    wasm32 = wasm32 or section_wasm32
                    wasm64 = wasm64 or section_wasm64
                offset = section_end
            return wasm32, wasm64

        def _pyc():
            if _data_size() < 9 or data[2:4] != b'\x0d\x0a':
                return
            for offset in (16, 12, 8):
                if _data_size() <= offset:
                    continue
                if offset == 16:
                    flags = int.from_bytes(data[4:8], "little")
                    if flags & ~0x03:
                        continue
                if data[offset] & 0x7f == ord("c"):
                    obj._filetype |= Type.PYC
                    return

        def _uue():
            if _data_size() >= 6 and data[:6] == b'begin ':
                obj._filetype |= Type.UUE

        def _gif():
            if _data_size() >= 6 and data[:6] in (b'GIF87a', b'GIF89a'):
                obj._filetype |= Type.GIF

        def _cpio():
            if _data_size() >= 6 and data[:6] in (b'070701', b'070702', b'070707'):
                obj._filetype |= Type.CPIO

        # TODO: Need to check this to verify
        def _ar():
            if _data_size() < 68:
                return
            if data[:8] not in (b'!<arch>\x0a', b'!<thin>\x0a'):
                return
            header = data[8:68]
            if header[58:60] != b'`\n':
                return
            name = header[:16].decode("ascii", errors="ignore").strip()
            name = name.rstrip("/")
            if name == "debian-binary":
                obj._filetype |= Type.DEB

        def _dmg():
            if _data_size() < 512:
                return
            if data[-512:-508] == b'koly':
                obj._filetype |= Type.DMG

        def _au3():
            val = {b'EA05': Type.AU300, b'EA06': Type.AU326}.get(data[20:24], None)
            if val is not None:
                obj._filetype |= Type.A3X | val

        def _pickle():
            if _data_size() >= 3 and data[0] == 0x80 and 2 <= data[1] <= 5:
                obj._filetype |= Type.PICKLE

        def _eml():
            text = _decoded_text_prefix(8192)
            if not text:
                return
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            if "\n\n" not in normalized:
                return
            header_block = normalized.split("\n\n", 1)[0]
            lines = header_block.split("\n")
            if not lines or ":" not in lines[0]:
                return
            common_headers = {
                "from", "to", "cc", "bcc", "subject", "date", "message-id",
                "mime-version", "content-type", "received", "return-path",
            }
            seen = set()
            for line in lines[:50]:
                if not line:
                    break
                if line[0] in " \t":
                    continue
                if ":" not in line:
                    return
                name = line.split(":", 1)[0].strip().lower()
                if name in common_headers:
                    seen.add(name)
            path = str(getattr(obj, "_path", "") or "").lower()
            required = 2 if path.endswith(".eml") else 3
            anchors = {"from", "received", "message-id", "mime-version", "content-type"}
            if len(seen) >= required and seen & anchors:
                obj._filetype |= Type.EML

        def _iqy():
            text = _decoded_text_prefix(4096)
            if not text:
                return
            lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
            lines = [line for line in lines if line]
            if len(lines) < 3 or lines[0].upper() != "WEB":
                return
            url_prefixes = ("http://", "https://", "ftp://")
            if any(line.lower().startswith(url_prefixes) for line in lines[1:12]):
                obj._filetype |= Type.IQY

        def _csv_text(text: str) -> bool:
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            lines = [line.strip() for line in normalized.split("\n") if line.strip()]
            if len(lines) < 3:
                return False
            sample = lines[:10]
            if any(line.startswith(("<", "{", "[", "BEGIN:")) for line in sample):
                return False
            for delimiter in (",", ";", "\t", "|"):
                counts = [line.count(delimiter) for line in sample]
                if min(counts) <= 0:
                    continue
                if len(set(counts)) == 1 and counts[0] >= 1:
                    return True
            return False

        def _mbox_text(text: str) -> bool:
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            lines = normalized.split("\n")
            for index, line in enumerate(lines[:200]):
                if not line.startswith("From "):
                    continue
                header_lines = lines[index + 1:index + 12]
                header_count = 0
                for header in header_lines:
                    if not header:
                        break
                    name = header.split(":", 1)[0].lower()
                    if name in {"from", "to", "subject", "date", "message-id", "content-type"}:
                        header_count += 1
                if header_count >= 2:
                    return True
            return False

        def _rdp_text(text: str) -> bool:
            lines = [line.strip().lower() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
            known = {
                "screen mode id:i:",
                "desktopwidth:i:",
                "desktopheight:i:",
                "session bpp:i:",
                "full address:s:",
                "username:s:",
                "authentication level:i:",
            }
            return sum(1 for line in lines if any(line.startswith(prefix) for prefix in known)) >= 2

        def _mhtml_text(text: str) -> bool:
            lower = text[:16384].lower()
            if "content-type: multipart/related" in lower and (
                "content-location:" in lower or "text/html" in lower
            ):
                return True
            if "mime-version:" in lower and "content-location:" in lower and (
                "text/html" in lower or "<html" in lower
            ):
                return True
            return False

        def _sct_text(text: str) -> bool:
            lower = text[:16384].lower()
            if "<scriptlet" not in lower:
                return False
            return (
                "<registration" in lower
                or "<script language=" in lower
                or "progid=" in lower
                or "classid=" in lower
            )

        def _flat_odf_text(text: str) -> None:
            lower = text[:16384].lower()
            if "office:mimetype" not in lower:
                return
            for mimetype, odf_type in ODF_MIME_MAP.items():
                if mimetype in lower:
                    obj._filetype |= Type.XML | odf_type
                    return

        def _structured_text_formats() -> None:
            text = _decoded_text_prefix(16384)
            if not text:
                return
            upper = text[:16384].upper()
            lower = text[:16384].lower()
            if "BEGIN:VCALENDAR" in upper and "VERSION:" in upper and "END:VCALENDAR" in upper:
                obj._filetype |= Type.ICS
            if _mbox_text(text):
                obj._filetype |= Type.MBOX
            if _rdp_text(text):
                obj._filetype |= Type.RDP
            if _mhtml_text(text):
                obj._filetype |= Type.MHTML
            if _sct_text(text):
                obj._filetype |= Type.XML | Type.SCT
            if "<office:document" in lower or "<office:document-content" in lower:
                _flat_odf_text(text)
            text_marker_types = int(Type.U8BOM | Type.U16LEBOM | Type.U16BEBOM | Type.U32LEBOM | Type.U32BEBOM)
            if int(obj._filetype) == 0 or (int(obj._filetype) & ~text_marker_types) == 0:
                if _csv_text(text):
                    obj._filetype |= Type.CSV

        obj._filetype = 0

        func_map = {
            "_pe": _pe,
            "_torrent": _torrent,
            "_tiff": _tiff,
            "_dib": _dib,
            "_ico": _ico,
            "_zip": _zip,
            "_elf": _elf,
            "_macho": _macho,
            "_cafebabe": _cafebabe,
            "_ole1_embedded": _ole1_embedded,
            "_olecf": _olecf,
            "_aiff": _aiff,
            "_cab": _cab,
            "_active_mime": _active_mime,
            "_asf": _asf,
            "_bzh_or_id3": _bzh_or_id3,
            "_bom": _bom,
            "_php_or_xml": _php_or_xml,
            "_jsp_or_asp": _jsp_or_asp,
            "_rtf_markers": _rtf_markers,
            "_saved_web": _saved_web,
            "_pemc": _pemc,
            "_internet_shortcut": _internet_shortcut,
            "_lzh": _lzh,
            "_sevenzip": _sevenzip,
            "_xz": _xz,
            "_lzma": _lzma,
            "_lz4": _lz4,
            "_wasm": _wasm,
            "_pyc": _pyc,
            "_uue": _uue,
            "_gif": _gif,
            "_cpio": _cpio,
            "_ar": _ar,
            "_dmg": _dmg,
            "_au3": _au3,
            "_pickle": _pickle,
        }

        for offset, dict_maches in MAGIC_NUM:
            sig, func_key = dict_maches.get(data[offset[0]:offset[1]], (None, None))
            if sig is None:
                continue
            obj._filetype |= sig
            if func_key is not None:
                func_map[func_key]()
                break

        if obj._filetype == 0:
            _ole1_embedded_loose()
        if obj._filetype == 0:
            _pyc()
        if obj._filetype == 0:
            _lzma()
        if obj._filetype == 0:
            _hdf5()
        if obj._filetype == 0:
            _dwg()
        if int(obj._filetype) & int(Type.SH | Type.CLASS):
            _mark_installer_strings(_bounded_lower(262144))
        _tensorflow_pb()
        _pytorch_pickle()
        text_marker_types = int(Type.U8BOM | Type.U16LEBOM | Type.U16BEBOM | Type.U32LEBOM | Type.U32BEBOM)
        if obj._filetype == 0 or (int(obj._filetype) & ~text_marker_types) == 0:
            _eml()
            _iqy()
        _structured_text_formats()
        if _looks_like_libraryms_markup():
            obj._filetype |= Type.XML | Type.LIBRARYMS
        if obj._filetype == 0 and _looks_like_svg_markup():
            obj._filetype |= Type.SVG
        if obj._filetype == 0:
            obj._filetype = Type.UNK


class _IdentificationTarget:
    def __init__(self, path: str | Path | None = None):
        self._filetype = Type.UNK
        self._path = str(path) if path is not None else None


def identify(data: Any, path: str | Path | None = None) -> Type:
    """Identify file content from a bytes-like object.

    Args:
        data: Bytes-like content supporting ``len()``, slicing, and ``find()``.
        path: Optional source path used for deeper ZIP/OLE inspection.

    Returns:
        A ``Type`` bitmask describing the detected file type.
    """
    target = _IdentificationTarget(path=path)
    QuickID(target).identify(data)
    return Type(target._filetype)


def identify_path(path: str | Path) -> Type:
    """Identify a file from disk using memory-mapped reads."""
    file_path = Path(path)
    if file_path.stat().st_size == 0:
        return Type.UNK
    with file_path.open("rb") as file_handle:
        data = mmap(file_handle.fileno(), 0, access=ACCESS_READ)
        try:
            return identify(data, path=file_path)
        finally:
            data.close()


def type_names(file_type: Type | int) -> list[str]:
    """Return human-readable names for a ``Type`` bitmask."""
    value = Type(file_type)
    names = [name for flag, name in COMMONTYPE.items() if value & flag]
    return names or [COMMONTYPE[Type.UNK]]


def format_ids(file_type: Type | int) -> list[str]:
    """Return canonical lowercase format IDs for a ``Type`` bitmask."""
    value = Type(file_type)
    return [format_id for flag, format_id in FORMAT_IDS.items() if value & flag]


def resolve_format_id(format_id: str) -> str:
    """Resolve a format ID or alias to its canonical lowercase format ID."""
    key = format_id.strip().lower()
    if key not in FORMAT_ALIASES:
        raise KeyError(format_id)
    return FORMAT_ALIASES[key]
