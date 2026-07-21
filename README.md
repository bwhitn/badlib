# badlib

`badlib` is a Python library for malware sample storage workflows.
It is intended to support reading and writing compressed malware files,
identifying common archive and sample container formats, and preserving useful
metadata for controlled analysis environments.

This project is for defensive research, malware handling, and archival use. It
does not execute samples.

## Planned Capabilities

- Read and write compressed malware sample containers
- Identify archive and compression formats from file signatures
- Preserve original filenames, hashes, and storage metadata
- Provide safe defaults for common malware archive conventions
- Expose a small Python API and command-line interface

## Install

From a local checkout:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

The initial API exposes BADD compressed malware container support and quick file
type identification.

```python
import badlib

print(badlib.__version__)
```

Public imports:

```python
from badlib import (
    COMMONTYPE,
    CompressObj,
    CompressReader,
    CompressWriter,
    FORMAT_ALIASES,
    FORMAT_IDS,
    OOXML_CONTENT_TYPES,
    QuickID,
    Type,
    format_ids,
    identify,
    identify_path,
    is_badd_obj,
    is_trans_obj,
    resolve_format_id,
    type_names,
)
```

## BADD Containers

`CompressWriter` writes BADD compressed sample containers and `CompressReader`
reads them back. BADD containers are identified by a footer marker and preserve
the original SHA-256 in the container footer.

```python
from pathlib import Path

from badlib import CompressReader, CompressWriter, is_badd_obj

path = Path("sample.badd")
data = b"MZ" + (b"example" * 100)

with CompressWriter(path) as writer:
    writer.write(data)

assert is_badd_obj(path)

with CompressReader(path, verify=True) as reader:
    original = reader.read()
    sha256_hex = reader.sha256_hex
```

Readers reject unsafe declared resources before allocating full output. The
defaults allow at most 256 MiB of output, 128 compressed blocks, and a declared
output-to-container-payload ratio of 100,000:1. Applications can set tighter
limits for their worker budget:

```python
with CompressReader(
    path,
    verify=True,
    max_output_size=64 * 1024 * 1024,
    max_blocks=32,
    max_compression_ratio=10_000,
) as reader:
    original = reader.read()
```

Passing `None` disables an individual limit and should be reserved for callers
that enforce equivalent bounds in an independently contained worker. Layout
validation always completes before a full-output allocation. `verify=True`
additionally compares the decompressed bytes with the footer SHA-256.

`CompressObj` is also available as a compatibility wrapper for `rb` and `wb`
modes.

## File Identification

`identify` accepts bytes-like data and returns a `Type` bitmask. `identify_path`
does the same for files on disk using memory-mapped reads.

```python
from badlib import Type, identify, identify_path, type_names

file_type = identify(b"PK\x03\x04" + (b"\x00" * 32))

if file_type & Type.ZIP:
    print(type_names(file_type))

disk_type = identify_path("sample.zip")
```

`QuickID` remains available for lower-level integrations that need to identify
against an object with `_filetype` and optional `_path` attributes.

### Format IDs and Aliases

`format_ids()` returns canonical lowercase IDs for first-class format flags,
and `resolve_format_id()` maps aliases to canonical IDs.

Alias mappings:

- `mht` and `mht/mhtml` resolve to `mhtml`.
- `sfx/peexe`, `peexe-sfx`, and `self-extracting-pe` resolve to `sfx-peexe`.

New high-confidence IDs are based on signatures, package metadata, stream
names, or stable container markers:

- ZIP/OPC/package subtypes: `xlsb`, `odt`, `ods`, `odc`, `odf`, `odg`, `odi`,
  `odp`, `msix`, `vsix`, `whl`, `xpi`, `zipx`.
- CFB/OLE subtypes: `hwp`, `pub`, `doc95`, `dot95`, `xls95`, `ppt95`, `msc`,
  `mso`.
- Binary/media/data formats: `h5`, `dwg`, `asf`, `wmv`, `msu`.
- Structured text formats: `csv`, `ics`, `mbox`, `rdp`, `mhtml`, `sct`.

Heuristic IDs require stronger marker combinations and may depend on bounded
string windows or path hints:

- Installer and executable subtypes: `actual-installer`, `advanced-installer`,
  `inno-setup`, `installanywhere`, `installshield`, `wise-installer`, `wix`,
  `nodejs-pkg`, `sfx-peexe`.
- Model formats: `tensorflow-pb`, `pytorch-model`.

Parent/container flags remain visible where applicable, such as `zip` + `whl`,
`zip` + `odt`, `ole` + `hwp`, `cab` + `msu`, `asf` + `wmv`, and `pe32` +
`inno-setup`. Extension-only detection is avoided except for weak hints such as
`.zipx`, `.xpi`, `.whl`, and `saved_model.pb`, which still require supporting
content evidence.

## Imported Code

The initial compression and identification implementation was copied from the
local `malarchive` checkout:

- `malanalysis/base/badd_obj.py` -> `src/badlib/badd_obj.py`
- `malanalysis/base/quickid.py` -> `src/badlib/quickid.py`

The copied code provides the current BADD read/write format and signature-based
file type detection. Before publishing this repo as MIT, confirm that the
copied files can be redistributed under MIT; the local `malarchive` checkout
currently has a proprietary license file.

## Safety Notes

- Treat all stored files as hostile.
- RTF marker identification scans only the first 256 KiB instead of
  materializing the complete input.
- Do not extract samples onto shared or production systems.
- Keep sample storage directories isolated from normal user files.
- Use dedicated analysis infrastructure when handling live malware.

## License

MIT
