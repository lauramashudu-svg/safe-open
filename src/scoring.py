#Combines findings into a transparent risk score and classification.


#Calculates a risk score from static-analysis findings.
#The score is a prioritisation aid, not a malware verdict.


SEVERITY_POINTS = {
    "info": 0,
    "low": 10,
    "medium": 20,
    "high": 35,
    "critical": 50,
}

MAX_RISK_SCORE = 100


def calculate_risk(findings):
    """Calculate a risk score and level from a list of findings."""

    if not isinstance(findings, list):
        raise TypeError("Findings must be provided as a list.")

    score = 0

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

        severity = finding.get("severity")

        if severity not in SEVERITY_POINTS:
            raise ValueError(
                f"Unknown finding severity: {severity!r}"
            )

        score += SEVERITY_POINTS[severity]

    # Keep the score within the range of 0 to 100.
    score = min(score, MAX_RISK_SCORE)

    if score == 0:
        risk_level = "low"
    elif score <= 29:
        risk_level = "low"
    elif score <= 59:
        risk_level = "medium"
    elif score <= 84:
        risk_level = "high"
    else:
        risk_level = "critical"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings_count": len(findings),
        "message": (
            "This score is based on detected static indicators. "
            "It does not prove whether a file is safe or malicious."
        ),
    }
