import pytest

from src.analysers.pdf import analyze_pdf


def test_clean_pdf_has_no_known_indicators(tmp_path):
    #Create a small test file with a PDF header and ordinary content.
    file_path = tmp_path / "clean.pdf"
    file_path.write_bytes(b"%PDF-1.7\nThis is a test PDF.")

    result = analyze_pdf(file_path)

    assert result["file_name"] == "clean.pdf"
    assert result["file_type"] == "PDF"
    assert result["findings"] == []
    assert result["indicators_found"] == 0
    assert result["status"] == "no_known_indicators_found"


def test_detects_javascript_indicator(tmp_path):
    #Create a PDF containing a JavaScript indicator.
    file_path = tmp_path / "javascript.pdf"
    file_path.write_bytes(
        b"%PDF-1.7\n/JavaScript"
    )

    result = analyze_pdf(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "JavaScript"
    assert result["findings"][0]["severity"] == "high"


def test_detects_multiple_indicators(tmp_path):
    #Create a PDF containing multiple suspicious indicators.
    file_path = tmp_path / "suspicious.pdf"
    file_path.write_bytes(
        b"%PDF-1.7\n/JavaScript /OpenAction /EmbeddedFile"
    )

    result = analyze_pdf(file_path)

    assert result["indicators_found"] == 3
    assert result["status"] == "suspicious_indicators_found"


def test_indicator_search_is_case_insensitive(tmp_path):
    #Check that uppercase and lowercase letters are both detected.
    file_path = tmp_path / "uppercase.pdf"
    file_path.write_bytes(b"%PDF-1.7\n/JAVASCRIPT")

    result = analyze_pdf(file_path)

    assert result["indicators_found"] == 1
    assert result["findings"][0]["indicator"] == "JavaScript"


def test_rejects_file_without_pdf_header(tmp_path):
    #Create a file that does not start with a PDF header.
    file_path = tmp_path / "not_pdf.pdf"
    file_path.write_bytes(b"This is not a PDF.")

    with pytest.raises(ValueError, match="PDF header"):
        analyze_pdf(file_path)


def test_rejects_missing_file(tmp_path):
    #Check that a missing file raises the normal file error.
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(FileNotFoundError):
        analyze_pdf(file_path)
