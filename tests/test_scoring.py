import pytest

from src.scoring import calculate_risk


def test_empty_findings_return_zero_score():
    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["findings_count"] == 0


def test_low_severity_finding():
    result = calculate_risk([
        {"severity": "low"}
    ])

    assert result["risk_score"] == 10
    assert result["risk_level"] == "low"


def test_medium_severity_finding():
    result = calculate_risk([
        {"severity": "medium"}
    ])

    assert result["risk_score"] == 20
    assert result["risk_level"] == "low"


def test_high_and_medium_findings():
    result = calculate_risk([
        {"severity": "high"},
        {"severity": "medium"},
    ])

    assert result["risk_score"] == 55
    assert result["risk_level"] == "medium"
    assert result["findings_count"] == 2


def test_critical_risk_level():
    result = calculate_risk([
        {"severity": "critical"},
        {"severity": "critical"},
    ])

    assert result["risk_score"] == 100
    assert result["risk_level"] == "critical"


def test_score_never_exceeds_100():
    result = calculate_risk([
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "high"},
    ])

    assert result["risk_score"] == 100


def test_rejects_non_list_findings():
    with pytest.raises(TypeError, match="list"):
        calculate_risk("high")


def test_rejects_unknown_severity():
    with pytest.raises(ValueError, match="Unknown finding severity"):
        calculate_risk([
            {"severity": "extreme"}
        ])


def test_rejects_non_dictionary_finding():
    with pytest.raises(ValueError, match="dictionary"):
        calculate_risk(["high"])
