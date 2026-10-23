#Entry point that coordinates the scan.

from pathlib import Path

from src.intake import inspect_file
from src.analysers.generic import check_file_signature
from src.analysers.pdf import analyze_pdf
from src.analysers.office import analyze_office
from src.analysers.archive import analyze_archive
from src.scoring import calculate_risk
from src.report import create_report, format_report, save_json_report

 #Extensions handled by the Office analyser.
OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
}


def scan_file(file_path):
    """Validate, analyse, score, and report on a supported file."""

    #Step 1: Validate the file and calculate its SHA-256 hash.
    file_info = inspect_file(file_path)
    extension = file_info["extension"]

    #Step 2: Check the file signature.
    #Legacy Office files share the same signature, so we let
    #the Office analyser validate those files instead.
    if extension not in {".doc", ".xls", ".ppt"}:
        signature_result = check_file_signature(file_path)

        if signature_result["status"] in {"unknown", "mismatch"}:
            raise ValueError(signature_result["message"])

    #Step 3: Choose the correct analyser.
    if extension == ".pdf":
        analysis_result = analyze_pdf(file_path)
    elif extension == ".zip":
        analysis_result = analyze_archive(file_path)
    elif extension in OFFICE_EXTENSIONS:
        analysis_result = analyze_office(file_path)
    else:
        raise ValueError("No analyser is available for this file type.")

    #Step 4: Calculate the risk score using detected findings.
    risk_result = calculate_risk(analysis_result["findings"])

    #Step 5: Combine the results into one report.
    report = create_report(file_info, analysis_result, risk_result)

    return report

def main():
    """Run Safe-Open from the terminal."""

    print("=" * 40)
    print("             SAFE-OPEN")
    print("      Static File Security Scanner")
    print("=" * 40)

    file_path = input("Enter the path of the file to scan: ").strip()
    file_path = file_path.strip('"')

    try:
        # Run the complete scan.
        report = scan_file(file_path)

        # Display the readable report.
        print()
        print(format_report(report))

        # Save a JSON report in the reports folder.
        reports_folder = Path("reports")
        reports_folder.mkdir(exist_ok=True)

        file_name = Path(file_path).stem
        file_hash = report["file"]["sha256"]

        output_path = reports_folder / f"{file_name}_{file_hash[:12]}_report.json"

        save_json_report(report, output_path)

        print(f"\nJSON report saved to: {output_path}")
        print("\nScan completed. This is not a guarantee that the file is safe.")

    except (OSError, ValueError) as error:
        print(f"\nScan could not be completed: {error}")


if __name__ == "__main__":
    main()
