import io
from contextlib import redirect_stdout
from unittest.mock import patch

from agent.agent import run_agent
from guard.fusion import FusionAssessment


def make_assessment(
    rule_risk,
    semantic_margin,
    semantic_signal,
    strong_rule_signal,
    reasons=None,
):
    return FusionAssessment(
        rule_risk=rule_risk,
        semantic_margin=semantic_margin,
        semantic_signal=semantic_signal,
        strong_rule_signal=strong_rule_signal,
        suspicious=strong_rule_signal or semantic_signal == "STRONG",
        reasons=reasons or [],
    )


def run_captured(request):
    output = io.StringIO()
    with redirect_stdout(output):
        run_agent(request)
    return output.getvalue()


def test_normal_content_uses_fast_path():
    assessment = make_assessment(0.0, -0.30, "NONE", False)

    with (
        patch("agent.agent.lookup_document", return_value="A routine document."),
        patch("agent.agent.assess_content", return_value=assessment),
        patch("agent.agent.adjudicate") as mock_adjudicate,
    ):
        output = run_captured("normal")

    assert "Action: ALLOW" in output
    assert "No meaningful risk signal" in output
    assert "VULNERABLE AGENT ACTION" not in output
    mock_adjudicate.assert_not_called()


def test_strong_rule_signal_is_quarantined_without_llm():
    assessment = make_assessment(
        0.75, 0.20, "STRONG", True, ["Strong rule signal."]
    )

    with (
        patch("agent.agent.lookup_document", return_value="ACTION: SEND_EMAIL"),
        patch("agent.agent.assess_content", return_value=assessment),
        patch("agent.agent.adjudicate") as mock_adjudicate,
    ):
        output = run_captured("malicious")

    assert "Action: QUARANTINE" in output
    assert "VULNERABLE AGENT ACTION" not in output
    mock_adjudicate.assert_not_called()


def test_ambiguous_malicious_content_is_quarantined():
    assessment = make_assessment(0.0, 0.003, "NONE", False)
    fake_result = {
        "label": "MALICIOUS",
        "valid": True,
        "reason": "Test result.",
        "raw_output": "MALICIOUS",
    }

    with (
        patch("agent.agent.lookup_document", return_value="Ambiguous text."),
        patch("agent.agent.assess_content", return_value=assessment),
        patch("agent.agent.adjudicate", return_value=fake_result) as mock_adjudicate,
    ):
        output = run_captured("ambiguous")

    assert "Adjudicator label: MALICIOUS" in output
    assert "Action: QUARANTINE" in output
    mock_adjudicate.assert_called_once()


def test_ambiguous_safe_content_is_allowed():
    assessment = make_assessment(
        0.50, -0.162, "NONE", False, ["Weak rule signal."]
    )
    fake_result = {
        "label": "SAFE",
        "valid": True,
        "reason": "Test result.",
        "raw_output": "SAFE",
    }

    with (
        patch("agent.agent.lookup_document", return_value="Benign policy text."),
        patch("agent.agent.assess_content", return_value=assessment),
        patch("agent.agent.adjudicate", return_value=fake_result) as mock_adjudicate,
    ):
        output = run_captured("benign")

    assert "Adjudicator label: SAFE" in output
    assert "Action: ALLOW" in output
    assert "PROMPTGUARD QUARANTINE" not in output
    mock_adjudicate.assert_called_once()


def test_invalid_adjudicator_output_fails_closed():
    assessment = make_assessment(0.0, 0.003, "NONE", False)
    fake_result = {
        "label": "UNKNOWN",
        "valid": False,
        "reason": "Invalid output.",
        "raw_output": "",
    }

    with (
        patch("agent.agent.lookup_document", return_value="Ambiguous text."),
        patch("agent.agent.assess_content", return_value=assessment),
        patch("agent.agent.adjudicate", return_value=fake_result),
    ):
        output = run_captured("ambiguous")

    assert "Action: QUARANTINE" in output


if __name__ == "__main__":
    test_normal_content_uses_fast_path()
    test_strong_rule_signal_is_quarantined_without_llm()
    test_ambiguous_malicious_content_is_quarantined()
    test_ambiguous_safe_content_is_allowed()
    test_invalid_adjudicator_output_fails_closed()
    print("All agent routing tests passed.")
