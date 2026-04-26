from __future__ import annotations

import badlib


def test_version_is_defined() -> None:
    assert badlib.__version__


def test_copied_api_is_exported() -> None:
    assert callable(badlib.CompressReader)
    assert callable(badlib.CompressWriter)
    assert callable(badlib.QuickID)
    assert badlib.Type.ZIP
    assert callable(badlib.identify)
    assert callable(badlib.identify_path)
    assert callable(badlib.is_trans_obj)
    assert callable(badlib.type_names)
