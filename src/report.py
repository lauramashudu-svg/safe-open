#Produces a readable report containing findings, severity and recommended actions.

#Creates readable, colourful and JSON reports for Safe-Open scans.

import json
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console() 


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
    """Return a plain text report for tests and other consumers."""

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


def display_banner():
    """Display the Safe-Open title with pink styling."""

    title = Text()
    title.append("SAFE", style="bold white")
    title.append("-", style="bold hot_pink")
    title.append("OPEN", style="bold white")

    subtitle = Text(
        "STATIC FILE SECURITY SCANNER",
        style="bold magenta",
        justify="center",
    )

    content = Text()
    content.append_text(title)
    content.append("\n")
    content.append_text(subtitle)

    console.print(
        Panel(
            content,
            border_style="hot_pink",
            box=box.DOUBLE,
            padding=(1, 4),
        )
    )


def display_report(report):
    """Display scan results using colourful terminal components."""

    file_info = report["file"]
    analysis = report["analysis"]
    risk = report["risk"]

    # Show file information in a table.
    file_table = Table(
        title="FILE INFORMATION",
        title_style="bold hot_pink",
        box=box.ROUNDED,
        border_style="magenta",
        show_header=False,
    )
    file_table.add_column("Property", style="bold cyan")
    file_table.add_column("Value", style="white")

    file_table.add_row("Name", str(file_info["name"]))
    file_table.add_row("Size", f"{file_info['size_bytes']:,} bytes")
    file_table.add_row("Extension", str(file_info["extension"]))
    file_table.add_row("File type", str(analysis["file_type"]))
    file_table.add_row("SHA-256", str(file_info["sha256"]))

    console.print(file_table)

    # Display the analysis status.
    status = analysis["status"]
    if status == "no_known_indicators_found":
        status_style = "bold green"
    else:
        status_style = "bold yellow"

    console.print()
    console.print(
        Panel(
            Text(status.replace("_", " ").upper(), style=status_style),
            title="[bold hot_pink]ANALYSIS STATUS[/bold hot_pink]",
            border_style="magenta",
        )
    )

    # Choose a colour based on the calculated risk level.
    risk_colours = {
        "low": "green",
        "medium": "yellow",
        "high": "orange3",
        "critical": "bold red",
    }
    risk_level = str(risk["level"]).lower()
    risk_colour = risk_colours.get(risk_level, "white")

    score = risk["score"]
    score_line = Text()
    score_line.append("RISK SCORE  ", style="bold white")
    score_line.append(f"{score}/100", style=f"bold {risk_colour}")
    score_line.append("   ")
    score_line.append(
        risk_level.upper(),
        style=f"bold {risk_colour}",
    )

    # The bar is a visual representation of the existing score.
    safe_score = max(0, min(100, int(score)))
    filled = safe_score // 5
    bar = Text()
    bar.append("━" * filled, style=risk_colour)
    bar.append("━" * (20 - filled), style="grey30")

    score_content = Text()
    score_content.append_text(score_line)
    score_content.append("\n")
    score_content.append_text(bar)

    console.print(
        Panel(
            score_content,
            title="[bold hot_pink]RISK ASSESSMENT[/bold hot_pink]",
            border_style="hot_pink",
            padding=(1, 2),
        )
    )

    # Display the findings.
    console.print()
    console.rule("[bold hot_pink]SCAN FINDINGS[/bold hot_pink]")

    findings = analysis["findings"]

    if not findings:
        console.print(
            Panel(
                "[bold green]✓[/bold green] "
                "No known indicators were found.",
                border_style="green",
            )
        )
    else:
        for number, finding in enumerate(findings, start=1):
            severity = str(finding["severity"]).lower()

            severity_colours = {
                "info": "cyan",
                "low": "green",
                "medium": "yellow",
                "high": "orange3",
                "critical": "bold red",
            }
            colour = severity_colours.get(severity, "white")

            details = Text()
            details.append(f"{number}. ", style="bold hot_pink")
            details.append(
                str(finding["indicator"]),
                style="bold white",
            )
            details.append("\nSeverity: ")
            details.append(severity.upper(), style=colour)
            details.append("\nDetails: ")
            details.append(str(finding["description"]))

            if "count" in finding:
                details.append(
                    f"\nOccurrences: {finding['count']}"
                )

            if "files" in finding:
                for name in finding["files"]:
                    details.append(f"\nEntry: {name}")

            console.print(
                Panel(details, border_style=colour, padding=(0, 1))
            )

    # Display the static-analysis disclaimer.
    console.print()
    console.print(
        Panel(
            report["disclaimer"],
            title="[bold yellow]IMPORTANT[/bold yellow]",
            border_style="yellow",
        )
    )



def save_json_report(report, output_path):
    """Save a scan report as JSON without terminal styling."""

    path = Path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)
        file.write("\n")

    return path
