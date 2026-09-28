from dataclasses import dataclass
from enum import Enum


class PolicyAction(Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


@dataclass
class PolicyDecision:
    action: PolicyAction
    risk_score: float
    reason: str


def evaluate_policy(risk_score: float) -> PolicyDecision:
    """
    Convert a detector risk score into an enforcement decision.

    Policy:
        < 0.50  -> ALLOW
        < 0.90  -> QUARANTINE
        >= 0.90 -> BLOCK
    """

    if risk_score < 0.50:
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            risk_score=risk_score,
            reason="Risk is below the quarantine threshold.",
        )

    if risk_score < 0.90:
        return PolicyDecision(
            action=PolicyAction.QUARANTINE,
            risk_score=risk_score,
            reason="Risk is elevated and requires quarantine.",
        )

    return PolicyDecision(
        action=PolicyAction.BLOCK,
        risk_score=risk_score,
        reason="Risk is high and the content must be blocked.",
    )
