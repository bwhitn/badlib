from __future__ import annotations

import pickle
from pathlib import Path

from badlib import Type, identify, identify_path, type_names


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
