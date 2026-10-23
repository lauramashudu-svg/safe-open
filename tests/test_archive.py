from zipfile import ZipFile

import pytest

from src.analysers.archive import (
    analyze_archive,
    is_suspicious_path,
)


def create_zip(file_path, files):
    """Create a small ZIP archive for testing."""

    with ZipFile(file_path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def test_clean_archive_has_no_known_indicators(tmp_path):
    file_path = tmp_path / "clean.zip"
    create_zip(file_path, {"readme.txt": "Safe-Open test"})

    result = analyze_archive(file_path)

    assert result["file_type"] == "ZIP archive"
    assert result["total_entries"] == 1
    assert result["findings"] == []
    assert result["indicators_found"] == 0
    assert result["status"] == "no_known_indicators_found"


def test_detects_executable_file(tmp_path):
    file_path = tmp_path / "executable.zip"
    create_zip(file_path, {"program.exe": "test content"})

    result = analyze_archive(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "Executable or script file"


def test_detects_nested_archive(tmp_path):
    file_path = tmp_path / "nested.zip"
    create_zip(file_path, {"backup.zip": "placeholder"})

    result = analyze_archive(file_path)

    assert result["findings"][0]["indicator"] == "Nested archive"


def test_detects_suspicious_parent_path(tmp_path):
    file_path = tmp_path / "path.zip"
    create_zip(file_path, {"../outside.txt": "test content"})

    result = analyze_archive(file_path)

    assert result["findings"][0]["indicator"] == "Suspicious archive path"


def test_detects_suspicious_windows_path():
    assert is_suspicious_path(r"..\outside.txt")
    assert is_suspicious_path(r"C:\temp\outside.txt")
    assert is_suspicious_path("/outside.txt")
    assert not is_suspicious_path("documents/readme.txt")


def test_rejects_invalid_zip(tmp_path):
    file_path = tmp_path / "invalid.zip"
    file_path.write_bytes(b"This is not a ZIP archive.")

    with pytest.raises(ValueError, match="valid ZIP archive"):
        analyze_archive(file_path)


def test_rejects_archive_with_too_many_entries(tmp_path, monkeypatch):
    file_path = tmp_path / "many.zip"
    create_zip(file_path, {"one.txt": "one", "two.txt": "two"})

    monkeypatch.setattr(
        "src.analysers.archive.MAX_ARCHIVE_ENTRIES", 1
    )

    with pytest.raises(ValueError, match="too many entries"):
        analyze_archive(file_path)


def test_rejects_entry_over_size_limit(tmp_path, monkeypatch):
    file_path = tmp_path / "large.zip"
    create_zip(file_path, {"large.txt": "A" * 20})

    monkeypatch.setattr(
        "src.analysers.archive.MAX_SINGLE_FILE_SIZE", 10
    )

    with pytest.raises(ValueError, match="entry exceeds"):
        analyze_archive(file_path)
