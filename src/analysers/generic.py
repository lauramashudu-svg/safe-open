#Checks file signatures, extensions, sizes and suspicious characteristics.


#Detects common file signatures and checks whether they match the extension.

from pathlib import Path


#Common file signatures.
#A signature is a sequence of bytes that identifies a file format.
FILE_SIGNATURES = {
    ".pdf": [b"%PDF-"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
    ".docm": [b"PK\x03\x04"],
    ".xlsm": [b"PK\x03\x04"],
    ".pptm": [b"PK\x03\x04"],
    ".doc": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    ".xls": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    ".ppt": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
}


def detect_file_type(file_path):
    """Identify a file type using its initial bytes."""

    path = Path(file_path)

    with path.open("rb") as file:
        header = file.read(16)

    for extension, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if header.startswith(signature):
                #ZIP-based Office formats need separate identification.
                if extension in {".docx", ".xlsx", ".pptx",
                                 ".docm", ".xlsm", ".pptm"}:
                    continue

                return extension

    #ZIP-based Office files share the ZIP signature.
    #Their internal contents must be inspected to distinguish them.
    if header.startswith(b"PK\x03\x04"):
        return ".zip"

    return "unknown"


def check_file_signature(file_path):
    #Compare a file's detected signature with its extension.

    path = Path(file_path)
    extension = path.suffix.lower()
    detected_type = detect_file_type(path)

    if detected_type == "unknown":
        return {
            "file_name": path.name,
            "extension": extension,
            "detected_type": detected_type,
            "status": "unknown",
            "message": "The file signature was not recognised.",
        }

    if extension in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
        #These formats are ZIP-based. A ZIP signature alone cannot
        #confirm which specific Office format the file contains.
        if detected_type == ".zip":
            return {
                "file_name": path.name,
                "extension": extension,
                "detected_type": detected_type,
                "status": "needs_container_check",
                "message": (
                    "The file has a ZIP signature. "
                    "Inspect its contents to verify the Office format."
                ),
            }

    if extension != detected_type:
        return {
            "file_name": path.name,
            "extension": extension,
            "detected_type": detected_type,
            "status": "mismatch",
            "message": (
                "The detected file signature does not match "
                "the filename extension."
            ),
        }

    return {
        "file_name": path.name,
        "extension": extension,
        "detected_type": detected_type,
        "status": "match",
        "message": "The file signature matches the extension.",
    }
