from src.analysers.generic import check_file_signature


def test_pdf_signature_matches_pdf_extension(tmp_path):
    #Create a temporary PDF test file.
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(b"%PDF-1.7 Safe-Open test")

    #Check the file signature.
    result = check_file_signature(file_path)

    #Confirm that the PDF signature is recognised.
    assert result["detected_type"] == ".pdf"
    assert result["status"] == "match"


def test_zip_signature_mismatch_for_pdf_extension(tmp_path):
    #Create a ZIP file disguised with a PDF extension.
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(b"PK\x03\x04Safe-Open test")

    #Check the file signature.
    result = check_file_signature(file_path)

    #Confirm that the mismatch is detected.
    assert result["detected_type"] == ".zip"
    assert result["status"] == "mismatch"
