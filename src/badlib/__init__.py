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
    OOXML_CONTENT_TYPES,
    QuickID,
    Type,
    identify,
    identify_path,
    type_names,
)

__version__ = "0.1.0"

__all__ = [
    "COMMONTYPE",
    "CompressObj",
    "CompressReader",
    "CompressWriter",
    "OOXML_CONTENT_TYPES",
    "QuickID",
    "Type",
    "__version__",
    "identify",
    "identify_path",
    "is_badd_obj",
    "is_trans_obj",
    "type_names",
]
