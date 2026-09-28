from dataclasses import dataclass
from typing import List

from guard.detector import detect_prompt_injection
from guard.semantic import analyze_semantics


SEMANTIC_WEAK_THRESHOLD = 0.05
SEMANTIC_STRONG_THRESHOLD = 0.10


@dataclass
class FusionAssessment:
    rule_risk: float
    semantic_margin: float
    semantic_signal: str
    strong_rule_signal: bool
    suspicious: bool
    reasons: List[str]
    


def assess_content(text: str) -> FusionAssessment:
    """
    Combine rule-based and semantic evidence.

    The fusion layer is intentionally diagnostic at this stage.
    It does not directly enforce ALLOW/QUARANTINE/BLOCK.
    """

    rule_result = detect_prompt_injection(text)
    semantic_result = analyze_semantics(text)

    margin = semantic_result["margin"]

    if margin >= SEMANTIC_STRONG_THRESHOLD:
        semantic_signal = "STRONG"
    elif margin >= SEMANTIC_WEAK_THRESHOLD:
        semantic_signal = "WEAK"
    else:
        semantic_signal = "NONE"

    reasons = list(rule_result["reasons"])

    if semantic_signal == "STRONG":
        reasons.append(
            "Semantic analysis found strong similarity to attack intent."
        )
    elif semantic_signal == "WEAK":
        reasons.append(
            "Semantic analysis found weak similarity to attack intent."
        )

    strong_rule_signal = rule_result["risk_score"] >= 0.75

    suspicious = (
        strong_rule_signal
        or semantic_signal == "STRONG"
    )
    
    if strong_rule_signal:
        reasons.append(
            "Rule detector found multiple correlated attack indicators."
        )

    return FusionAssessment(
        rule_risk=rule_result["risk_score"],
        semantic_margin=margin,
        semantic_signal=semantic_signal,
        strong_rule_signal=strong_rule_signal,
        suspicious=suspicious,
        reasons=reasons,
    )
