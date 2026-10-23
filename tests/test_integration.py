#Tests the complete Safe-Open scanning workflow.

from src.main import scan_file


def test_scan_file_returns_complete_report(tmp_path):
    """A valid PDF should pass through the full scanning workflow."""

    #Create a harmless test PDF containing only a basic PDF header.
    pdf_path = tmp_path / "clean_test.pdf"
    pdf_path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF"
    )

    #Run the complete scanner.
    report = scan_file(pdf_path)

    #Check the combined report.
    assert report["scanner"] == "Safe-Open"
    assert report["file"]["name"] == "clean_test.pdf"
    assert report["analysis"]["file_type"] == "PDF"
    assert report["analysis"]["indicators_found"] == 0
    assert report["risk"]["score"] == 0
    assert report["risk"]["level"] == "low"


def test_scan_file_detects_pdf_indicators(tmp_path):
    """The complete workflow should include detected PDF indicators."""

    pdf_path = tmp_path / "test_with_javascript.pdf"
    pdf_path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /JavaScript true >>\n"
        b"endobj\n"
        b"%%EOF"
    )

    report = scan_file(pdf_path)

    assert report["analysis"]["indicators_found"] > 0
    assert report["risk"]["score"] > 0
    assert report["analysis"]["status"] == "suspicious_indicators_found"


def test_scan_file_rejects_invalid_pdf_signature(tmp_path):
    """A PDF extension must not hide an unrecognised file signature."""

    pdf_path = tmp_path / "fake.pdf"
    pdf_path.write_bytes(b"This is not a PDF file.")

    try:
        scan_file(pdf_path)
    except ValueError as error:
        assert "signature" in str(error).lower()
    else:
        raise AssertionError("Expected the scanner to reject the file.")
