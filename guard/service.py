"""Reusable PromptGuard analysis service for untrusted content."""

from dataclasses import dataclass
from typing import Optional, Callable

from guard.adjudicator import adjudicate
from guard.decision import SecurityDecision, create_security_decision
from guard.fusion import FusionAssessment, assess_content
from guard.policy import PolicyAction, PolicyDecision, evaluate_policy
from guard.quarantine import QuarantineRecord, quarantine_content


AMBIGUOUS_MARGIN_FLOOR = -0.02
MIN_ADJUDICATOR_RISK = 0.50
QUARANTINE_RISK = 0.75


@dataclass
class ContentAnalysis:
    """Structured result of analyzing untrusted content."""

    source: str
    assessment: FusionAssessment
    adjudication_performed: bool
    adjudicator_result: Optional[dict]
    final_risk: float
    reasons: list[str]
    policy: PolicyDecision
    security_decision: SecurityDecision
    quarantine_record: Optional[QuarantineRecord]
    decision_path: str


def analyze_untrusted_content(
    content: str,
    source: str = "manual_input",
    *,
    assessor: Optional[Callable] = None,
    adjudicator: Optional[Callable] = None,
) -> ContentAnalysis:
    """Analyze content using PromptGuard's current security pipeline.

    The content is treated as untrusted data. This function never executes
    instructions or performs actions requested by that content.

    Optional assessor/adjudicator callables allow deterministic unit tests.
    """

    if not isinstance(content, str) or not content.strip():
        raise ValueError("Content must be a non-empty string.")

    if not isinstance(source, str) or not source.strip():
        raise ValueError("Source must be a non-empty string.")

    assess_fn = assessor or assess_content
    adjudicate_fn = adjudicator or adjudicate

    assessment = assess_fn(content)
    reasons = list(assessment.reasons)

    adjudication_performed = False
    adjudicator_result = None

    # Strong rule evidence cannot be overridden by the LLM.
    if assessment.strong_rule_signal:
        final_risk = assessment.rule_risk
        decision_path = "strong_rule_short_circuit"

    elif (
        assessment.semantic_signal == "STRONG"
        or assessment.rule_risk >= MIN_ADJUDICATOR_RISK
        or assessment.semantic_margin >= AMBIGUOUS_MARGIN_FLOOR
    ):
        adjudication_performed = True
        decision_path = "adjudicator_review"
        try:
            candidate = adjudicate_fn(content)
            if isinstance(candidate, dict):
                adjudicator_result = candidate
            else:
                adjudicator_result = {
                    "label": "UNKNOWN",
                    "valid": False,
                    "reason": "Adjudicator returned a non-dictionary result.",
                }
        except Exception as exc:
            adjudicator_result = {
                "label": "UNKNOWN",
                "valid": False,
                "reason": f"Adjudicator exception: {type(exc).__name__}",
            }

        if (
            not adjudicator_result.get("valid", False)
            or adjudicator_result.get("label") not in ("SAFE", "MALICIOUS")
        ):
            final_risk = QUARANTINE_RISK
            reasons.append(
                "Invalid adjudicator output; quarantined by default."
            )

        elif adjudicator_result["label"] == "MALICIOUS":
            final_risk = max(assessment.rule_risk, QUARANTINE_RISK)
            reasons.append(
                "Qwen adjudicator classified content as malicious."
            )

        else:
            # Preserve the current agent's behavior after SAFE adjudication.
            final_risk = 0.0
            reasons.append(
                "Qwen classified reviewed content as safe."
            )

    else:
        final_risk = 0.0
        decision_path = "fast_path_no_signal"

    policy = evaluate_policy(final_risk)

    security_decision = create_security_decision(
        content=content,
        source=source,
        safe=(policy.action == PolicyAction.ALLOW),
        risk_score=final_risk,
        detection_reasons=reasons,
        policy=policy,
    )

    quarantine_record = None
    if policy.action in (PolicyAction.QUARANTINE, PolicyAction.BLOCK):
        quarantine_record = quarantine_content(
            content=content,
            risk_score=final_risk,
            reasons=reasons,
        )

    return ContentAnalysis(
        source=source,
        assessment=assessment,
        adjudication_performed=adjudication_performed,
        adjudicator_result=adjudicator_result,
        final_risk=final_risk,
        reasons=reasons,
        policy=policy,
        security_decision=security_decision,
        quarantine_record=quarantine_record,
        decision_path=decision_path,
    )
