import struct
from enum import IntFlag, auto, unique
from mmap import ACCESS_READ, mmap
from pathlib import Path
from typing import Any, List

__all__ = [
    "COMMONTYPE",
    "OOXML_CONTENT_TYPES",
    "QuickID",
    "Type",
    "identify",
    "identify_path",
    "type_names",
]


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


OOXML_CONTENT_TYPES = {
    "application/vnd.ms-appx.blockmap+xml",
    "application/vnd.ms-appx.manifest+xml",
    "application/vnd.ms-appx.signature",
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
    "application/vnd.ms-powerpoint.revisioninfo+xml",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-word.keyMapCustomizations+xml",
    "application/vnd.ms-word.stylesWithEffects+xml",
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
    "application/vnd.openxmlformats-officedocument.presentationml.presProps+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "application/vnd.openxmlformats-officedocument.theme+xml",
    "application/vnd.openxmlformats-officedocument.themeManager+xml",
    "application/vnd.openxmlformats-officedocument.themeOverride+xml",
    "application/vnd.openxmlformats-officedocument.vmlDrawing",
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
    "application/vnd.ms-word.vbaData+xml": Type.DOCM,
    "application/vnd.ms-excel.sheet.macroEnabled.12": Type.XLSM,
    "application/vnd.ms-excel.sheet.binary.macroEnabled.main": Type.XLSM,
    "application/vnd.ms-excel.intlmacrosheet": Type.XLSM,
    "application/vnd.ms-excel.macrosheet": Type.XLSM,
    "application/vnd.ms-excel.addin.macroEnabled.12": Type.XLAM,
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
        b'<%': (0, "_jsp_or_asp")
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
        b'MSCF': (Type.CAB, None),
        b'#@~^': (Type.MSES, None),
        b'\x00asm': (Type.WASM, None),
        b'\x28\xb5\x2f\xfd': (Type.ZST, None),
        b'\x03\x00\x08\x00': (Type.BXML, None),
        b'\x02\x00\x0c\x00': (Type.ARSC, None),
        b'RIFF': (Type.RIFF, None),
        b'\xfe\xed\xfe\xed': (Type.JKS, None),
        b'\xac\xed\x00\x05': (Type.JSER, None),
        b'\xcb\x0d\x0d\x0a': (Type.PYC, None),
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
        b'mrm_pri2': (Type.PRI, None),
        b'\x89PNG\x0d\x0a\x1a\x0a': (Type.PNG, None),
        b'bplist00': (Type.BPLS, None),
        b'<!DOCTYP': (Type.HTML, None),
        b'<!doctyp': (Type.HTML, None),
        b'BOMStore': (Type.BOM, None),
    }),
    ((0, 16), {
        b'SQLite format 3\x00': (Type.SQLITE, None),
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

        def _elf():
            endian_flag = data[5]
            endian = "little" if endian_flag == 1 else "big"
            e_machine = int.from_bytes(data[18:20], endian)
            obj._filetype |= ELF_ARCH_MAP.get(e_machine, 0)

        def _macho():
            obj._filetype |= MACHO_ARCH_MAP.get(_unpack_from("<I", 4)[0], 0)

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
            p = data[0:]
            hit = _find_first(b"PK\x01\x02", 66,
                              [b"[Content_Types].xml", b"AndroidManifest.xml",
                               b"META-INF/MANIFEST.MF", b"WEB-INF/web.xml"])
            result = (0, Type.OXML, Type.APK, -1, Type.WAR)[hit + 1]
            if result == -1:
                obj._filetype |= (Type.JAR, Type.WAR)[_find_first(b"PK\x01\x02", 66, [b"WEB-INF/web.xml"]) + 1]
            else:
                obj._filetype |= result
            if result != Type.OXML:
                return
            path = getattr(obj, "_path", None)
            if not path:
                return
            try:
                import zipfile
                with zipfile.ZipFile(path, "r") as zf:
                    has_content_types = "[Content_Types].xml" in zf.namelist()
                    if not has_content_types:
                        return
                    content = zf.read("[Content_Types].xml")
                    text = content.decode("utf-8", errors="ignore")
                    for key, val in OOXML_CONTENT_MAP.items():
                        if key in text:
                            obj._filetype |= val
            except Exception:
                return
            return

        def _olecf():
            msi = _find_first(b'\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00',
                              100, [b'\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'])
            obj._filetype |= Type.MSI if msi != -1 else Type.OLE
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
                obj._filetype |= Type.XML

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
                obj._filetype |= val

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
            "_uue": _uue,
            "_gif": _gif,
            "_cpio": _cpio,
            "_ar": _ar,
            "_dmg": _dmg,
            "_au3": _au3
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
