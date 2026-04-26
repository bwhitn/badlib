from __future__ import annotations

import malstore


def test_version_is_defined() -> None:
    assert malstore.__version__


def test_copied_api_is_exported() -> None:
    assert malstore.CompressReader
    assert malstore.CompressWriter
    assert malstore.QuickID
    assert malstore.Type.ZIP
    assert malstore.identify
    assert malstore.identify_path
    assert malstore.is_trans_obj
    assert malstore.type_names
