#Performs static analysis of ZIP archives.
#Archive contents are inspected without extracting or executing files.

from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile, is_zipfile


#Limits help reduce the risk of processing oversized archives.
MAX_ARCHIVE_ENTRIES = 5000
MAX_TOTAL_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000

#File types that may require extra caution inside an archive.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".bat", ".cmd", ".com",
    ".scr", ".ps1", ".vbs", ".js", ".jar", ".sh",
}

#Common nested archive formats.
NESTED_ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz",
}


def is_suspicious_path(file_name):
    """Check whether an archive entry has a potentially unsafe path."""

    #ZIP paths normally use forward slashes. Check both slash styles.
    normalised_name = file_name.replace("\\", "/")
    path = PurePosixPath(normalised_name)

    if path.is_absolute():
        return True

    if ".." in path.parts:
        return True

    #Check for Windows drive-style paths, such as C:/folder/file.txt.
    if len(normalised_name) >= 2 and normalised_name[1] == ":":
        return True

    return False


def analyze_archive(file_path):
    """Inspect a ZIP archive's entries and metadata."""

    path = Path(file_path)

    if not is_zipfile(path):
        raise ValueError("The file is not a valid ZIP archive.")

    findings = []

    try:
        with ZipFile(path, "r") as archive:
            entries = archive.infolist()

            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise ValueError("Archive contains too many entries.")

            total_uncompressed_size = sum(
                entry.file_size for entry in entries
            )

            if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
                raise ValueError(
                    "Archive exceeds the total uncompressed size limit."
                )

            suspicious_paths = []
            executable_files = []
            nested_archives = []
            encrypted_files = []
            high_compression_entries = []

            for entry in entries:
                #Directories are not files to classify.
                if entry.is_dir():
                    continue

                entry_path = PurePosixPath(
                    entry.filename.replace("\\", "/")
                )
                extension = entry_path.suffix.lower()

                if is_suspicious_path(entry.filename):
                    suspicious_paths.append(entry.filename)

                if extension in EXECUTABLE_EXTENSIONS:
                    executable_files.append(entry.filename)

                if extension in NESTED_ARCHIVE_EXTENSIONS:
                    nested_archives.append(entry.filename)

                #Bit 0 indicates traditional ZIP encryption.
                if entry.flag_bits & 0x1:
                    encrypted_files.append(entry.filename)

                if entry.file_size > MAX_SINGLE_FILE_SIZE:
                    raise ValueError(
                        "An archive entry exceeds the 50 MB file size limit."
                    )

                #Avoid division by zero for empty entries.
                if entry.compress_size == 0:
                    if entry.file_size > 0:
                        high_compression_entries.append(entry.filename)
                else:
                    ratio = entry.file_size / entry.compress_size

                    if (
                        entry.file_size > 1024 * 1024
                        and ratio > MAX_COMPRESSION_RATIO
                    ):
                        high_compression_entries.append(entry.filename)

            if suspicious_paths:
                findings.append({
                    "indicator": "Suspicious archive path",
                    "severity": "high",
                    "description": (
                        "Archive entries contain absolute or "
                        "parent-directory paths."
                    ),
                    "count": len(suspicious_paths),
                    "files": suspicious_paths,
                })

            if executable_files:
                findings.append({
                    "indicator": "Executable or script file",
                    "severity": "medium",
                    "description": (
                        "The archive contains executable or script file types."
                    ),
                    "count": len(executable_files),
                    "files": executable_files,
                })

            if nested_archives:
                findings.append({
                    "indicator": "Nested archive",
                    "severity": "low",
                    "description": (
                        "The archive contains files that may be archives themselves."
                    ),
                    "count": len(nested_archives),
                    "files": nested_archives,
                })

            if encrypted_files:
                findings.append({
                    "indicator": "Encrypted archive entry",
                    "severity": "medium",
                    "description": (
                        "Some entries are encrypted and cannot be fully inspected."
                    ),
                    "count": len(encrypted_files),
                    "files": encrypted_files,
                })

            if high_compression_entries:
                findings.append({
                    "indicator": "High compression ratio",
                    "severity": "high",
                    "description": (
                        "Some entries have an unusually high compression ratio."
                    ),
                    "count": len(high_compression_entries),
                    "files": high_compression_entries,
                })

            #Test every entry's compressed data for CRC or decompression errors.
            #This reads entries but does not write them to disk.
            for entry in entries:
                if entry.is_dir() or entry.flag_bits & 0x1:
                    continue

                if entry.file_size > MAX_SINGLE_FILE_SIZE:
                    continue

                with archive.open(entry, "r") as item:
                    while item.read(8192):
                        pass

    except BadZipFile as error:
        raise ValueError("The ZIP archive is corrupt or invalid.") from error
    except RuntimeError as error:
        raise ValueError(
            "The ZIP archive could not be fully inspected."
        ) from error

    return {
        "file_name": path.name,
        "file_type": "ZIP archive",
        "total_entries": len(entries),
        "total_uncompressed_size": total_uncompressed_size,
        "findings": findings,
        "indicators_found": len(findings),
        "status": (
            "suspicious_indicators_found"
            if findings
            else "no_known_indicators_found"
        ),
        "message": (
            "Static analysis only. This result does not prove "
            "whether the archive is safe or malicious."
        ),
    }
