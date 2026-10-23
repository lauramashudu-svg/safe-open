import hashlib

import pytest

from src import intake


def test_accepts_valid_pdf_file(tmp_path):
    #Create a temporary PDF file.
    file_path = tmp_path / "sample.pdf"
    file_content = b"%PDF-1.7 Safe-Open test"
    file_path.write_bytes(file_content)

    #Inspect the file.
    result = intake.inspect_file(file_path)

    #Check the returned file information.
    assert result["file_name"] == "sample.pdf"
    assert result["file_size"] == len(file_content)
    assert result["extension"] == ".pdf"
    assert result["sha256"] == hashlib.sha256(file_content).hexdigest()


def test_rejects_missing_file(tmp_path):
    #Create a path for a file that does not exist.
    file_path = tmp_path / "missing.pdf"

    #Confirm that the correct error is raised.
    with pytest.raises(FileNotFoundError):
        intake.inspect_file(file_path)


def test_rejects_unsupported_extension(tmp_path):
    #Create a file with an unsupported extension.
    file_path = tmp_path / "notes.txt"
    file_path.write_text("Safe-Open test")

    #Confirm that the file is rejected.
    with pytest.raises(ValueError, match="extension is not supported"):
        intake.inspect_file(file_path)


def test_rejects_empty_file(tmp_path):
    #Create an empty PDF file.
    file_path = tmp_path / "empty.pdf"
    file_path.write_bytes(b"")

    #Confirm that the file is rejected.
    with pytest.raises(ValueError, match="file is empty"):
        intake.inspect_file(file_path)


def test_rejects_file_over_size_limit(tmp_path, monkeypatch):
    #Use a small limit so we don't need to create a 50 MB test file.
    monkeypatch.setattr(intake, "MAX_FILE_SIZE", 10)

    #Create a file larger than the temporary limit.
    file_path = tmp_path / "large.pdf"
    file_path.write_bytes(b"A" * 11)

    #Confirm that the file is rejected.
    with pytest.raises(ValueError, match="50 MB size limit"):
        intake.inspect_file(file_path)
