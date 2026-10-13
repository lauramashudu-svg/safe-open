# Safe-Open Development Plan

## 1. Project Overview

Safe-Open is a Python-based static-analysis tool that examines PDFs, Microsoft Office documents and ZIP archives for potentially suspicious characteristics before users open them.

The application will analyse files without executing them and generate reports explaining its findings.

## 2. Project Objectives

- Validate input files before analysis.
- Identify file types using file signatures and format information.
- Calculate SHA-256 file hashes.
- Detect suspicious characteristics in supported file formats.
- Identify potentially dangerous archive contents and unsafe paths.
- Calculate a transparent risk score.
- Generate readable scan reports.
- Handle invalid, malformed and unsupported files safely.
- Include automated tests and documentation.

## 3. Supported File Types

- PDF documents
- Microsoft Office documents, including DOCX, XLSX, PPTX and macro-enabled formats
- ZIP archives

Legacy Office formats will be supported where practical.

## 4. Architecture

- intake.py: file validation and intake
- analysers/generic.py: general file analysis
- analysers/pdf.py: PDF analysis
- analysers/office.py: Office document analysis
- analysers/archive.py: ZIP archive analysis
- analysers/reputation.py: optional hash reputation checks
- scoring.py: risk scoring and classification
- report.py: report generation
- main.py: application entry point

## 5. Security Requirements

- Never execute scanned files.
- Avoid extracting untrusted archives during routine analysis.
- Apply file-size, archive-entry and processing limits.
- Treat filenames and document metadata as untrusted input.
- Do not upload files to external services without explicit consent.
- Clearly distinguish suspicious findings from confirmed malware.
- Report analysis failures instead of incorrectly declaring a file safe.

## 6. Development Milestones

1. Project setup and input validation.
2. General file identification and hashing.
3. PDF analysis.
4. Office document analysis.
5. ZIP archive analysis.
6. Risk scoring.
7. Report generation.
8. Automated testing and documentation.
9. Final demonstration.

## 7. Limitations

Safe-Open performs static analysis. It does not guarantee that files without detected indicators are safe, and it is not a replacement for antivirus software or dynamic malware analysis.