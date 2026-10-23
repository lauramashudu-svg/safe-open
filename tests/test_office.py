from zipfile import ZipFile

import pytest

from src.analysers.office import analyze_office


def create_word_document(file_path, extra_files=None):
    """Create a small test Word document without using real documents."""

    with ZipFile(file_path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            "<Types></Types>",
        )
        archive.writestr(
            "word/document.xml",
            "<document>Safe-Open test</document>",
        )

        if extra_files:
            for name, content in extra_files.items():
                archive.writestr(name, content)


def test_clean_word_document_has_no_known_indicators(tmp_path):
    file_path = tmp_path / "clean.docx"
    create_word_document(file_path)

    result = analyze_office(file_path)

    assert result["file_type"] == "Word document"
    assert result["findings"] == []
    assert result["indicators_found"] == 0
    assert result["status"] == "no_known_indicators_found"


def test_detects_vba_macro_project(tmp_path):
    file_path = tmp_path / "macro.docm"
    create_word_document(
        file_path,
        {"word/vbaProject.bin": b"test macro data"},
    )

    result = analyze_office(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "VBA macro project"
    assert result["findings"][0]["severity"] == "high"


def test_detects_external_relationship(tmp_path):
    file_path = tmp_path / "external.docx"
    create_word_document(
        file_path,
        {
            "word/_rels/document.xml.rels": (
                '<Relationships><Relationship '
                'TargetMode="External" Target="https://example.com" '
                '/></Relationships>'
            )
        },
    )

    result = analyze_office(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "External relationship"


def test_detects_embedded_object(tmp_path):
    file_path = tmp_path / "embedded.docx"
    create_word_document(
        file_path,
        {"word/embeddings/embedded1.bin": b"test embedded data"},
    )

    result = analyze_office(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "Embedded object"


def test_rejects_invalid_office_container(tmp_path):
    file_path = tmp_path / "invalid.docx"
    file_path.write_bytes(b"This is not a ZIP container.")

    with pytest.raises(ValueError, match="ZIP-based Office container"):
        analyze_office(file_path)


def test_rejects_container_missing_document(tmp_path):
    file_path = tmp_path / "incomplete.docx"

    with ZipFile(file_path, "w") as archive:
        archive.writestr("some_file.txt", "Not a Word document")

    with pytest.raises(ValueError, match="expected Office document"):
        analyze_office(file_path)


def test_rejects_unsupported_extension(tmp_path):
    file_path = tmp_path / "notes.txt"
    file_path.write_text("Not an Office document")

    with pytest.raises(ValueError, match="Unsupported Office file extension"):
        analyze_office(file_path)


def test_rejects_legacy_file_with_invalid_signature(tmp_path):
    file_path = tmp_path / "old.doc"
    file_path.write_bytes(b"Not a legacy Office document")

    with pytest.raises(ValueError, match="legacy Office signature"):
        analyze_office(file_path)
