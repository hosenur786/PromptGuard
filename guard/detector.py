import re


# Patterns that may indicate prompt injection or unauthorized actions.
SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"\bignore\s+(the\s+)?previous\s+instructions\b",
        r"\bignore\s+(the\s+)?original(\s+user)?\s+request\b",
        r"\bignore\s+all\s+previous\s+instructions\b",
    ],
    "instruction_hijacking": [
        r"\bfollow\s+these\s+instructions\b",
        r"\bthe\s+following\s+instructions\s+override\b",
        r"\bsystem\s+instruction\b",
        r"\bnew\s+instructions\b",
    ],
    "action_directive": [
        r"^\s*ACTION\s*:",
        r"\bSEND_EMAIL\b",
    ],
}


def detect_prompt_injection(text: str) -> dict:
    """
    Analyze untrusted text for suspicious prompt-injection patterns.

    Returns:
        {
            "safe": bool,
            "risk_score": float,
            "reasons": list[str]
        }
    """

    reasons = []
    matched_categories = set()

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                matched_categories.add(category)
                break

    if "instruction_override" in matched_categories:
        reasons.append("Detected instruction override attempt.")

    if "instruction_hijacking" in matched_categories:
        reasons.append("Detected instruction hijacking language.")

    if "action_directive" in matched_categories:
        reasons.append("Detected an explicit action directive.")

    # Simple baseline risk scoring.
    if len(matched_categories) == 0:
        risk_score = 0.0
    elif len(matched_categories) == 1:
        risk_score = 0.5
    elif len(matched_categories) == 2:
        risk_score = 0.75
    else:
        risk_score = 0.95

    return {
        "safe": risk_score < 0.5,
        "risk_score": risk_score,
        "reasons": reasons,
    }
