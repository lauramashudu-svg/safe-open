# Safe-Open

**A Python-based static file security scanner for PDFs, Microsoft Office documents, and ZIP archives.**

Safe-Open analyses files for potentially suspicious characteristics before users open them. It checks file signatures, identifies known indicators, calculates a transparent risk score, and generates readable terminal reports and JSON reports.

**Important:** Safe-Open performs static analysis only. It does not guarantee that a file is safe or confirm that a file contains malware.

## Project Demonstration

Watch the Safe-Open demonstration video:

[Watch the Safe-Open Demo on YouTube](https://youtu.be/2zFQTtttvx8)

## Features

- **File validation:** Checks file existence, supported extensions, empty files, and file-size limits.
- **SHA-256 hashing:** Calculates a unique hash to help identify scanned files.
- **File signature validation:** Checks whether a file's content matches its expected format.
- **PDF analysis:** Searches for indicators such as JavaScript, automatic actions, embedded files, and launch actions.
- **Office document analysis:** Checks supported Office containers for VBA macro projects, embedded objects, and external relationships.
- **ZIP archive analysis:** Identifies potentially suspicious paths, executable or script files, nested archives, encrypted entries, and unusual compression ratios.
- **Risk scoring:** Assigns a score from 0 to 100 based on detected findings.
- **Reporting:** Displays a readable report and saves a JSON report for later review.
- **Automated testing:** Uses pytest to test individual components and the integrated scanning workflow.

## Supported File Types

| Category | Extensions |
|---|---|
| PDF | `.pdf` |
| Word | `.doc`, `.docx`, `.docm` |
| Excel | `.xls`, `.xlsx`, `.xlsm` |
| PowerPoint | `.ppt`, `.pptx`, `.pptm` |
| ZIP archives | `.zip` |

The maximum permitted file size is **50 MB**. Legacy Office formats receive more limited analysis because they use a different file structure.

## Project Structure

```text
safe-open/
├── src/
│   ├── main.py
│   ├── intake.py
│   ├── scoring.py
│   ├── report.py
│   └── analysers/
│       ├── generic.py
│       ├── pdf.py
│       ├── office.py
│       ├── archive.py
│       └── reputation.py
├── tests/
├── reports/
├── README.md
├── plan.md
├── requirements.txt
└── LICENSE
```

The `reports/` directory is created when a scan runs. Generated reports should not be committed to version control.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/lauramashudu-svg/safe-open.git
cd safe-open
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

Use Python 3.13 or another Python version compatible with the project's dependencies.

## Usage

Run the application from the project root:

```bash
python -m src.main
```

When prompted, enter the path to the file you want to scan. For example:

```text
Enter the path of the file to scan:
C:\Users\User\Downloads\sample.pdf
```

Safe-Open validates the file, checks its format, selects the appropriate analyser, calculates a risk score, and displays a report.

A JSON report is saved in the `reports/` directory. The filename includes the scanned file's name and a shortened portion of its SHA-256 hash.

Only scan files you are authorised to inspect. Safe-Open does not execute scanned files as part of its intended analysis workflow.

## Risk Scoring

Risk scores range from 0 to 100. Findings contribute points according to their assigned severity, and the final score is capped at 100.

| Severity | Points per finding |
|---|---:|
| Informational | 0 |
| Low | 10 |
| Medium | 20 |
| High | 35 |
| Critical | 50 |

The scanner classifies the resulting score into a risk level. A low score does not mean that a file is safe, and the score should be interpreted alongside the individual findings.

## Running the Tests

Run the automated test suite from the project root:

```bash
python -m pytest -v
```

The current development test suite contains **46 passing tests**, covering file validation, signatures, PDF analysis, Office analysis, ZIP archive analysis, risk scoring, report generation, and integration.

Run the tests again after making code changes to check for regressions.

## Security and Limitations

- Safe-Open is a static-analysis tool, not a full antivirus engine.
- It does not execute scanned files as part of its intended workflow.
- Detection is based on known indicators and implemented analysis rules.
- Some legitimate documents may contain suspicious characteristics.
- Malicious files may evade detection.
- Legacy Office formats receive limited analysis.
- A low risk score or absence of known indicators does not prove that a file is safe.
- The tool does not replace professional malware analysis or a reputable antivirus solution.

## Project Status

The core scanning workflow and automated tests are implemented. Documentation, final validation, and demonstration preparation remain part of the development and delivery process.

## Disclaimer

Safe-Open is provided for educational and defensive security purposes. Its findings are indicators for further investigation, not definitive malware verdicts.
