#Examines Office documents for macros, embedded objects and other risk indicators.

#Performs basic static analysis of Microsoft Office files.
#Does not extract files to disk or execute document content.

from pathlib import Path
from zipfile import BadZipFile, ZipFile, is_zipfile


MODERN_OFFICE_TYPES = {
    ".docx": "Word document",
    ".xlsx": "Excel workbook",
    ".pptx": "PowerPoint presentation",
    ".docm": "Word macro-enabled document",
    ".xlsm": "Excel macro-enabled workbook",
    ".pptm": "PowerPoint macro-enabled presentation",
}

LEGACY_OFFICE_TYPES = {
    ".doc": "Legacy Word document",
    ".xls": "Legacy Excel workbook",
    ".ppt": "Legacy PowerPoint presentation",
}

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

MAX_ARCHIVE_ENTRIES = 5000
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024


def analyze_office(file_path):
    """Inspect an Office document for basic suspicious indicators."""

    path = Path(file_path)
    extension = path.suffix.lower()

    if extension not in MODERN_OFFICE_TYPES and extension not in LEGACY_OFFICE_TYPES:
        raise ValueError("Unsupported Office file extension.")

    with path.open("rb") as file:
        header = file.read(8)

    # Legacy Office files use the OLE Compound File signature.
    if extension in LEGACY_OFFICE_TYPES:
        if not header.startswith(OLE_SIGNATURE):
            raise ValueError("The file does not have a recognised legacy Office signature.")

        return {
            "file_name": path.name,
            "file_type": LEGACY_OFFICE_TYPES[extension],
            "findings": [{
                "indicator": "Legacy Office format",
                "severity": "info",
                "description": (
                    "This legacy binary format needs specialised analysis "
                    "to inspect macros and embedded content."
                ),
                "count": 1,
            }],
            "indicators_found": 1,
            "status": "limited_analysis",
            "message": (
                "Only the file signature was checked. "
                "The document has not been fully analysed."
            ),
        }

    #Modern Office documents are ZIP containers.
    if not is_zipfile(path):
        raise ValueError("The file is not a valid ZIP-based Office container.")

    findings = []

    with ZipFile(path, "r") as archive:
        entries = archive.infolist()

        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("Office container has too many entries.")

        total_size = sum(entry.file_size for entry in entries)

        if total_size > MAX_UNCOMPRESSED_SIZE:
            raise ValueError("Office container exceeds the analysis size limit.")

        names = {entry.filename for entry in entries}
        lower_names = {name.lower() for name in names}

        #Confirm that the container has the expected main document.
        expected_parts = {
            ".docx": "word/document.xml",
            ".docm": "word/document.xml",
            ".xlsx": "xl/workbook.xml",
            ".xlsm": "xl/workbook.xml",
            ".pptx": "ppt/presentation.xml",
            ".pptm": "ppt/presentation.xml",
        }

        if expected_parts[extension] not in lower_names:
            raise ValueError("The container is missing its expected Office document.")

        #Macro projects may contain executable VBA code.
        macro_parts = [
            name for name in names
            if name.lower().endswith("vbaproject.bin")
        ]

        if macro_parts:
            findings.append({
                "indicator": "VBA macro project",
                "severity": "high",
                "description": "The Office container contains a VBA macro project.",
                "count": len(macro_parts),
            })

        #Embedded objects may contain other files.
        embedded_parts = [
            name for name in names
            if name.lower().startswith("word/embeddings/")
            or name.lower().startswith("xl/embeddings/")
            or name.lower().startswith("ppt/embeddings/")
        ]

        if embedded_parts:
            findings.append({
                "indicator": "Embedded object",
                "severity": "medium",
                "description": "The Office container contains embedded objects.",
                "count": len(embedded_parts),
            })

        #Inspect relationship files for links to external targets.
        external_links = 0

        for name in names:
            if not name.lower().endswith(".rels"):
                continue

            #Relationship files are normally small. Skip unusually large ones.
            info = archive.getinfo(name)
            if info.file_size > 2 * 1024 * 1024:
                continue

            relationship_data = archive.read(name).lower()
            external_links += relationship_data.count(b'targetmode="external"')

        if external_links:
            findings.append({
                "indicator": "External relationship",
                "severity": "medium",
                "description": "The Office container references external targets.",
                "count": external_links,
            })

    return {
        "file_name": path.name,
        "file_type": MODERN_OFFICE_TYPES[extension],
        "findings": findings,
        "indicators_found": len(findings),
        "status": (
            "suspicious_indicators_found"
            if findings
            else "no_known_indicators_found"
        ),
        "message": (
            "Static analysis only. This result does not prove "
            "whether the file is safe or malicious."
        ),
    }
