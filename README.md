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
    OOXML_CONTENT_TYPES,
    QuickID,
    Type,
    identify,
    identify_path,
    is_badd_obj,
    is_trans_obj,
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
- Do not extract samples onto shared or production systems.
- Keep sample storage directories isolated from normal user files.
- Use dedicated analysis infrastructure when handling live malware.

## License

MIT
