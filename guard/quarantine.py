from dataclasses import dataclass, field
from typing import List


@dataclass
class QuarantineRecord:
    """
    Represents untrusted content that PromptGuard has blocked.
    """

    content: str
    risk_score: float
    reasons: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Quarantined content | "
            f"risk_score={self.risk_score:.2f} | "
            f"reasons={len(self.reasons)}"
        )


def quarantine_content(
    content: str,
    risk_score: float,
    reasons: List[str],
) -> QuarantineRecord:
    """
    Create a structured quarantine record.

    No external action is performed.
    """
    return QuarantineRecord(
        content=content,
        risk_score=risk_score,
        reasons=reasons,
    )
