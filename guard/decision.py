from dataclasses import dataclass
from hashlib import sha256
from typing import List

from guard.policy import PolicyDecision


@dataclass
class SecurityDecision:
    """
    Structured record of one PromptGuard security decision.
    """

    source: str
    content_hash: str
    content_length: int
    risk_score: float
    safe: bool
    action: str
    detection_reasons: List[str]
    policy_reason: str

    def summary(self) -> str:
        return (
            f"SecurityDecision | "
            f"source={self.source} | "
            f"risk_score={self.risk_score:.2f} | "
            f"safe={self.safe} | "
            f"action={self.action}"
        )


def create_security_decision(
    content: str,
    source: str,
    safe: bool,
    risk_score: float,
    detection_reasons: List[str],
    policy: PolicyDecision,
) -> SecurityDecision:
    """
    Create a structured security decision without storing the
    original content in the decision record.

    A SHA-256 hash is used to identify the content deterministically.
    """

    content_hash = sha256(content.encode("utf-8")).hexdigest()

    return SecurityDecision(
        source=source,
        content_hash=content_hash,
        content_length=len(content),
        risk_score=risk_score,
        safe=safe,
        action=policy.action.value,
        detection_reasons=detection_reasons,
        policy_reason=policy.reason,
    )
