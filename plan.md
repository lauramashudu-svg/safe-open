# Safe-Open Development Plan

## 1. Project Overview

Safe-Open is a Python-based static-analysis tool that examines PDFs, Microsoft Office documents, and ZIP archives for potentially suspicious characteristics before users open them.

It validates files, calculates SHA-256 hashes, applies format-specific analysis rules, calculates a risk score, and produces readable and machine-readable reports.

The project is intended for educational and defensive security purposes. It does not guarantee file safety or provide definitive malware detection.

## 2. Project Objectives

The main objectives of Safe-Open are to:

- Validate input files before analysis.
- Check file signatures against expected formats.
- Calculate SHA-256 hashes.
- Analyse supported PDF files for suspicious indicators.
- Analyse supported Office documents and containers.
- Inspect ZIP archives for potentially dangerous contents and paths.
- Calculate transparent risk scores.
- Generate readable terminal reports and JSON reports.
- Handle invalid, malformed, and unsupported files through validation and error handling.
- Provide automated tests for individual components and the integrated workflow.
- Complete project documentation and prepare a final demonstration.

## 3. Supported File Types

| Category | Extensions |
|---|---|
| PDF documents | `.pdf` |
| Word documents | `.doc`, `.docx`, `.docm` |
| Excel spreadsheets | `.xls`, `.xlsx`, `.xlsm` |
| PowerPoint presentations | `.ppt`, `.pptx`, `.pptm` |
| ZIP archives | `.zip` |

The maximum supported file size is 50 MB.

Legacy Office formats receive limited analysis because their structure differs from modern Office ZIP containers.

## 4. Architecture

- `src/main.py` — coordinates the scan workflow and command-line interface.
- `src/intake.py` — validates input files, checks size and extension, and calculates SHA-256 hashes.
- `src/analysers/generic.py` — checks file signatures and format consistency.
- `src/analysers/pdf.py` — searches PDF content for known suspicious indicators.
- `src/analysers/office.py` — inspects supported Office containers for macros, embedded objects, and external relationships.
- `src/analysers/archive.py` — checks ZIP archives for suspicious paths, file types, nested archives, encryption, and unusual compression ratios.
- `src/analysers/reputation.py` — reserved for reputation-related functionality; implementation and integration must be verified before this is considered a completed feature.
- `src/scoring.py` — calculates risk scores and assigns risk levels.
- `src/report.py` — builds, formats, and saves scan reports.
- `tests/` — contains automated tests for individual components and integration.

## 5. Security Requirements

Safe-Open follows these security requirements:

- Scanned files must not be intentionally executed.
- Untrusted archives should not be extracted during routine analysis.
- File-size and archive-processing limits must be enforced.
- Filenames and archive paths must be treated as untrusted input.
- Scanned files must not be uploaded to external services without explicit consent.
- Suspicious findings must be distinguished from confirmed malware.
- Validation and analysis failures must be reported instead of incorrectly declaring a file safe.
- The limitations of static analysis must be explained in reports and documentation.

## 6. Development Milestones

### Milestone 1: Project Setup and Input Validation
**Status: Complete**

Set up the Python project structure and implement input validation, including file existence, supported extensions, empty-file checks, and file-size limits.

### Milestone 2: File Identification and Hashing
**Status: Complete**

Implement file signature checks and SHA-256 hashing to help identify files and detect mismatches between file extensions and file content.

### Milestone 3: PDF Analysis
**Status: Complete**

Develop a PDF analyser that searches for potentially suspicious indicators, including JavaScript, automatic actions, embedded files, and launch actions.

### Milestone 4: Office Document Analysis
**Status: Complete**

Implement analysis of supported Microsoft Office documents and containers, including checks for macro projects, embedded objects, and external relationships.

### Milestone 5: ZIP Archive Analysis
**Status: Complete**

Develop archive analysis to identify potentially suspicious paths, executable or script files, nested archives, encrypted entries, and unusual compression ratios.

### Milestone 6: Risk Scoring
**Status: Complete**

Implement a transparent risk-scoring system that assigns points according to finding severity and classifies the overall risk level.

### Milestone 7: Report Generation
**Status: Complete**

Generate readable terminal reports and JSON reports containing file details, SHA-256 hashes, analysis findings, risk scores, and a safety disclaimer.

### Milestone 8: Automated Testing
**Status: Complete — 46 tests passing**

Implement unit and integration tests covering input validation, file analysis, risk scoring, report generation, and the complete scanning workflow.

### Milestone 9: Documentation and Repository Review
**Status: In Progress**

Review and finalise the README and development plan, verify the GitHub repository and commit history, and complete any required architecture documentation, Wiki pages, and project board updates.

### Milestone 10: Final Demonstration
**Status: Pending**

Prepare and record a demonstration showing the scanner processing sample files, identifying suspicious indicators, calculating risk scores, and generating JSON reports. Explain the limitations of static analysis and clarify that the scanner does not provide a definitive malware verdict.

## 7. Testing Strategy

The project uses pytest to verify individual modules and the complete scanning workflow.

The current test suite contains 46 tests covering:

- Input validation and file-size limits.
- File signature matching and rejection.
- PDF indicator detection.
- Office container validation and indicator detection.
- ZIP archive safety checks.
- Risk scoring and invalid input handling.
- Terminal and JSON report generation.
- End-to-end scan behaviour.

The test suite must be run after the final changes:

```bash
python -m pytest -v
```

All tests should pass before final delivery.

## 8. Final Delivery Requirements

The remaining delivery work includes:

- Reviewing the README instructions against the actual application.
- Confirming generated reports and temporary files are excluded from Git.
- Reviewing the GitHub remote configuration and commit history.
- Updating GitHub issues and the development plan to reflect actual progress.
- Completing architecture documentation and any required Wiki pages.
- Demonstrating a clean sample and a sample containing known indicators.
- Showing the calculated risk score and generated JSON report.
- Explaining the limitations of static analysis.
- Running the complete test suite and confirming all tests pass.
- Verifying that all required files are committed and available in the repository.

## 9. Limitations

Safe-Open performs static analysis based on implemented rules. It does not guarantee that files without detected indicators are safe, and it cannot confirm malware solely from a suspicious indicator.

The scanner is not a replacement for antivirus software, sandboxed dynamic analysis, or specialist malware analysis. Some legitimate files may trigger findings, and some malicious files may evade detection.

## 10. Project Completion Criteria

The project is ready for delivery when the implemented scanning workflow passes its automated tests, the documentation accurately describes the available functionality, the repository is up to date, and the final demonstration clearly explains the tool's capabilities and limitations.
