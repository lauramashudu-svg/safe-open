#Produces a readable report containing findings, severity and recommended actions.

#Creates readable and JSON reports for Safe-Open scans.

import json
from pathlib import Path


def create_report(file_info, analysis_result, risk_result):
    """Combine intake, analysis, and risk results into one report."""

    return {
        "scanner": "Safe-Open",
        "file": {
            "name": file_info["file_name"],
            "size_bytes": file_info["file_size"],
            "extension": file_info["extension"],
            "sha256": file_info["sha256"],
        },
        "analysis": {
            "file_type": analysis_result["file_type"],
            "status": analysis_result["status"],
            "findings": analysis_result["findings"],
            "indicators_found": analysis_result["indicators_found"],
        },
        "risk": {
            "score": risk_result["risk_score"],
            "level": risk_result["risk_level"],
            "findings_count": risk_result["findings_count"],
        },
        "disclaimer": (
            "Static analysis only. A low risk score or absence of "
            "known indicators does not prove that a file is safe."
        ),
    }


def format_report(report):
    """Format a scan report as readable terminal text."""

    file_info = report["file"]
    analysis = report["analysis"]
    risk = report["risk"]

    lines = [
        "=" * 48,
        "                 SAFE-OPEN",
        "          STATIC FILE SCAN REPORT",
        "=" * 48,
        "",
        f"File name: {file_info['name']}",
        f"File size: {file_info['size_bytes']} bytes",
        f"Extension: {file_info['extension']}",
        f"SHA-256:   {file_info['sha256']}",
        "",
        f"File type: {analysis['file_type']}",
        f"Analysis status: {analysis['status']}",
        f"Indicators found: {analysis['indicators_found']}",
        "",
        f"Risk score: {risk['score']}/100",
        f"Risk level: {risk['level'].upper()}",
        "",
        "FINDINGS",
        "-" * 48,
    ]

    if not analysis["findings"]:
        lines.append("No known indicators were found.")
    else:
        for number, finding in enumerate(analysis["findings"], start=1):
            lines.append(f"{number}. {finding['indicator']}")
            lines.append(f"   Severity: {finding['severity']}")
            lines.append(f"   Details: {finding['description']}")

            if "count" in finding:
                lines.append(f"   Occurrences: {finding['count']}")

            if "files" in finding:
                for name in finding["files"]:
                    lines.append(f"   Entry: {name}")

            lines.append("")

    lines.extend([
        "-" * 48,
        "IMPORTANT",
        report["disclaimer"],
        "=" * 48,
    ])

    return "\n".join(lines)


def save_json_report(report, output_path):
    """Save a scan report as JSON."""

    path = Path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)
        file.write("\n")

    return path
