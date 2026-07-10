"""Malware sample storage helpers."""

from badlib.badd_obj import (
    CompressObj,
    CompressReader,
    CompressWriter,
    is_badd_obj,
    is_trans_obj,
)
from badlib.quickid import (
    COMMONTYPE,
    FORMAT_ALIASES,
    FORMAT_IDS,
    OOXML_CONTENT_TYPES,
    QuickID,
    Type,
    format_ids,
    identify,
    identify_path,
    resolve_format_id,
    type_names,
)

__version__ = "0.1.0"

__all__ = [
    "COMMONTYPE",
    "CompressObj",
    "CompressReader",
    "CompressWriter",
    "FORMAT_ALIASES",
    "FORMAT_IDS",
    "OOXML_CONTENT_TYPES",
    "QuickID",
    "Type",
    "__version__",
    "format_ids",
    "identify",
    "identify_path",
    "is_badd_obj",
    "is_trans_obj",
    "resolve_format_id",
    "type_names",
]
