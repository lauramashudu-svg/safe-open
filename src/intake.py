#Accepts file paths and performs initial validation.

from pathlib import Path
import hashlib


# Maximum file size for the first version: 50 MB.
MAX_FILE_SIZE = 50 * 1024 * 1024

# File extensions that Safe-Open currently plans to support.
SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".zip",
}


def calculate_sha256(file_path):
    """Calculate a file's SHA-256 hash without loading it all into memory."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(8192)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def inspect_file(file_path):
    """Validate a file and return its basic information."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError("The selected file does not exist.")

    if not path.is_file():
        raise ValueError("The selected path is not a file.")

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError("This file extension is not supported.")

    file_size = path.stat().st_size

    if file_size == 0:
        raise ValueError("The selected file is empty.")

    if file_size > MAX_FILE_SIZE:
        raise ValueError("The file exceeds the 50 MB size limit.")

    file_hash = calculate_sha256(path)

    return {
        "file_name": path.name,
        "file_size": file_size,
        "sha256": file_hash,
        "extension": path.suffix.lower(),
    }

