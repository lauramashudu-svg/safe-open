import json

from src.report import create_report, format_report, save_json_report


def sample_report_inputs():
    file_info = {
        "file_name": "sample.pdf",
        "file_size": 120,
        "extension": ".pdf",
        "sha256": "abc123",
    }

    analysis_result = {
        "file_type": "PDF",
        "status": "suspicious_indicators_found",
        "findings": [
            {
                "indicator": "JavaScript",
                "severity": "high",
                "description": "The PDF contains a JavaScript indicator.",
                "count": 1,
            }
        ],
        "indicators_found": 1,
    }

    risk_result = {
        "risk_score": 35,
        "risk_level": "high",
        "findings_count": 1,
    }

    return file_info, analysis_result, risk_result


def test_create_report_combines_results():
    file_info, analysis, risk = sample_report_inputs()

    report = create_report(file_info, analysis, risk)

    assert report["scanner"] == "Safe-Open"
    assert report["file"]["name"] == "sample.pdf"
    assert report["analysis"]["file_type"] == "PDF"
    assert report["risk"]["score"] == 35
    assert report["risk"]["level"] == "high"
    assert "does not prove" in report["disclaimer"]


def test_format_report_includes_key_information():
    file_info, analysis, risk = sample_report_inputs()
    report = create_report(file_info, analysis, risk)

    text_report = format_report(report)

    assert "SAFE-OPEN" in text_report
    assert "sample.pdf" in text_report
    assert "SHA-256" in text_report
    assert "JavaScript" in text_report
    assert "HIGH" in text_report
    assert "does not prove" in text_report


def test_format_report_handles_no_findings():
    file_info, analysis, risk = sample_report_inputs()
    analysis["findings"] = []
    analysis["indicators_found"] = 0
    analysis["status"] = "no_known_indicators_found"
    risk["risk_score"] = 0
    risk["risk_level"] = "low"
    risk["findings_count"] = 0

    report = create_report(file_info, analysis, risk)
    text_report = format_report(report)

    assert "No known indicators were found." in text_report


def test_save_json_report(tmp_path):
    file_info, analysis, risk = sample_report_inputs()
    report = create_report(file_info, analysis, risk)
    output_path = tmp_path / "report.json"

    saved_path = save_json_report(report, output_path)

    assert saved_path == output_path
    assert output_path.exists()

    saved_data = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved_data["file"]["name"] == "sample.pdf"
    assert saved_data["risk"]["score"] == 35


def test_json_report_preserves_findings(tmp_path):
    file_info, analysis, risk = sample_report_inputs()
    report = create_report(file_info, analysis, risk)
    output_path = tmp_path / "report.json"

    save_json_report(report, output_path)

    saved_data = json.loads(output_path.read_text(encoding="utf-8"))

    assert saved_data["analysis"]["findings"][0]["indicator"] == "JavaScript"
    assert saved_data["analysis"]["findings"][0]["severity"] == "high"
