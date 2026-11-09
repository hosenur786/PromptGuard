import pytest

from guard.fusion import FusionAssessment
from guard.policy import PolicyAction
from guard.service import analyze_untrusted_content


def make_assessment(
    rule_risk=0.0,
    semantic_margin=-0.30,
    semantic_signal="NONE",
    strong_rule_signal=False,
    reasons=None,
):
    return FusionAssessment(
        rule_risk=rule_risk,
        semantic_margin=semantic_margin,
        semantic_signal=semantic_signal,
        strong_rule_signal=strong_rule_signal,
        suspicious=(
            strong_rule_signal or semantic_signal == "STRONG"
        ),
        reasons=reasons or [],
    )


def test_normal_content_uses_fast_path():
    result = analyze_untrusted_content(
        "Routine document.",
        assessor=lambda _: make_assessment(),
        adjudicator=lambda _: pytest.fail(
            "Adjudicator should not run on the fast path."
        ),
    )

    assert result.policy.action == PolicyAction.ALLOW
    assert result.decision_path == "fast_path_no_signal"
    assert result.adjudication_performed is False
    assert result.quarantine_record is None


def test_strong_rule_signal_skips_adjudication():
    result = analyze_untrusted_content(
        "ACTION: SEND_EMAIL",
        assessor=lambda _: make_assessment(
            rule_risk=0.75,
            semantic_margin=0.20,
            semantic_signal="STRONG",
            strong_rule_signal=True,
            reasons=["Strong rule signal."],
        ),
        adjudicator=lambda _: pytest.fail(
            "Strong rule evidence should bypass adjudication."
        ),
    )

    assert result.policy.action == PolicyAction.QUARANTINE
    assert result.decision_path == "strong_rule_short_circuit"
    assert result.adjudication_performed is False
    assert result.quarantine_record is not None


def test_high_rule_risk_is_blocked():
    result = analyze_untrusted_content(
        "High-risk content",
        assessor=lambda _: make_assessment(
            rule_risk=0.95,
            strong_rule_signal=True,
            reasons=["Multiple attack indicators."],
        ),
        adjudicator=lambda _: pytest.fail(
            "Strong rule evidence should bypass adjudication."
        ),
    )

    assert result.policy.action == PolicyAction.BLOCK
    assert result.quarantine_record is not None


def test_malicious_adjudication_causes_quarantine():
    result = analyze_untrusted_content(
        "Suspicious document.",
        assessor=lambda _: make_assessment(
            semantic_margin=0.01,
        ),
        adjudicator=lambda _: {
            "label": "MALICIOUS",
            "valid": True,
            "raw_output": "MALICIOUS_DIRECTIVE",
        },
    )

    assert result.adjudication_performed is True
    assert result.final_risk == 0.75
    assert result.policy.action == PolicyAction.QUARANTINE
    assert result.quarantine_record is not None


def test_safe_adjudication_allows_content():
    result = analyze_untrusted_content(
        "Benign policy text.",
        assessor=lambda _: make_assessment(
            rule_risk=0.50,
            semantic_margin=-0.162,
        ),
        adjudicator=lambda _: {
            "label": "SAFE",
            "valid": True,
            "raw_output": "SAFE_POLICY",
        },
    )

    assert result.adjudication_performed is True
    assert result.final_risk == 0.0
    assert result.policy.action == PolicyAction.ALLOW
    assert result.quarantine_record is None


def test_invalid_adjudicator_result_fails_closed():
    result = analyze_untrusted_content(
        "Ambiguous document.",
        assessor=lambda _: make_assessment(
            semantic_margin=0.01,
        ),
        adjudicator=lambda _: {
            "label": "UNKNOWN",
            "valid": False,
            "raw_output": "",
        },
    )

    assert result.final_risk == 0.75
    assert result.policy.action == PolicyAction.QUARANTINE
    assert result.quarantine_record is not None
    assert any(
        "Invalid adjudicator output" in reason
        for reason in result.reasons
    )


def test_non_dictionary_adjudicator_result_fails_closed():
    result = analyze_untrusted_content(
        "Ambiguous document.",
        assessor=lambda _: make_assessment(semantic_margin=0.01),
        adjudicator=lambda _: None,
    )

    assert result.final_risk == 0.75
    assert result.policy.action == PolicyAction.QUARANTINE
    assert result.quarantine_record is not None
    assert result.adjudicator_result["valid"] is False
    assert "non-dictionary" in result.adjudicator_result["reason"]


def test_adjudicator_exception_fails_closed():
    def failing_adjudicator(_):
        raise RuntimeError("synthetic model failure")

    result = analyze_untrusted_content(
        "Ambiguous document.",
        assessor=lambda _: make_assessment(semantic_margin=0.01),
        adjudicator=failing_adjudicator,
    )

    assert result.final_risk == 0.75
    assert result.policy.action == PolicyAction.QUARANTINE
    assert result.quarantine_record is not None
    assert result.adjudicator_result["valid"] is False
    assert result.adjudicator_result["reason"] == (
        "Adjudicator exception: RuntimeError"
    )
    assert any(
        "Invalid adjudicator output" in reason for reason in result.reasons
    )


def test_empty_content_is_rejected():
    with pytest.raises(ValueError, match="non-empty string"):
        analyze_untrusted_content("   ")


def test_empty_source_is_rejected():
    with pytest.raises(ValueError, match="Source must"):
        analyze_untrusted_content(
            "Some content",
            source=" ",
        )


def test_security_decision_records_source_and_hash():
    content = "Routine document."
    result = analyze_untrusted_content(
        content,
        source="test_document",
        assessor=lambda _: make_assessment(),
        adjudicator=lambda _: pytest.fail(
            "Adjudicator should not run."
        ),
    )

    assert result.security_decision.source == "test_document"
    assert len(result.security_decision.content_hash) == 64
    assert result.security_decision.content_length == len(content)
    assert result.security_decision.action == "ALLOW"
