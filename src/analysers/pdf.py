#Inspects PDF metadata, JavaScript indicators and suspicious actions.


#Performs basic static analysis of PDF files.
#This module never opens the file in a PDF viewer or executes its contents.

from pathlib import Path


#PDF indicators that may deserve further investigation.
PDF_INDICATORS = {
    b"/javascript": {
        "name": "JavaScript",
        "severity": "high",
        "description": "The PDF contains a JavaScript indicator.",
    },
    b"/js": {
        "name": "JavaScript action",
        "severity": "high",
        "description": "The PDF contains a JavaScript action indicator.",
    },
    b"/openaction": {
        "name": "OpenAction",
        "severity": "medium",
        "description": "The PDF contains an automatic open-action indicator.",
    },
    b"/aa": {
        "name": "Additional Actions",
        "severity": "medium",
        "description": "The PDF contains an additional-actions indicator.",
    },
    b"/embeddedfile": {
        "name": "Embedded File",
        "severity": "medium",
        "description": "The PDF contains an embedded-file indicator.",
    },
    b"/launch": {
        "name": "Launch Action",
        "severity": "high",
        "description": "The PDF contains a launch-action indicator.",
    },
    b"/richmedia": {
        "name": "Rich Media",
        "severity": "medium",
        "description": "The PDF contains a rich-media indicator.",
    },
}


def analyze_pdf(file_path):
    """Inspect a PDF for basic suspicious indicators."""

    path = Path(file_path)

    #Read the file as bytes. Do not execute or render its contents.
    with path.open("rb") as file:
        content = file.read()

    #A valid PDF normally begins with this header.
    if not content.startswith(b"%PDF-"):
        raise ValueError("The file does not have a recognised PDF header.")

    content = content.lower()
    findings = []

    #Search for each indicator and record how often it appears.
    for indicator, details in PDF_INDICATORS.items():
        count = content.count(indicator)

        if count > 0:
            findings.append({
                "indicator": details["name"],
                "severity": details["severity"],
                "description": details["description"],
                "count": count,
            })

    return {
        "file_name": path.name,
        "file_type": "PDF",
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
