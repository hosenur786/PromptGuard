import re
import unicodedata


SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"\bignore\s+(the\s+)?previous\s+instructions\b",
        r"\bignore\s+(the\s+)?original(\s+user)?\s+request\b",
        r"\bignore\s+all\s+previous\s+instructions\b",
        r"\bdisregard\s+(everything|all|the)\b.*\b(previous|earlier|preceding|current)\b",
        r"\bdiscard\s+(the\s+)?previous\s+instructions\b",
        r"\breplace\s+(the\s+)?current\s+task\b",
        r"\buse\s+.*\b(instead|as\s+the\s+new\s+task)\b",
    ],
    "instruction_hijacking": [
        r"\bfollow\s+these\s+instructions\b",
        r"\bthe\s+following\s+instructions\s+override\b",
        r"\bsystem\s+instruction\b",
        r"\bnew\s+instructions\b",
        r"\bhigher\s+priority\s+than\s+the\s+user",
        r"\btreat\s+.*\s+as\s+authoritative\b",
        r"\bthe\s+assistant\s+is\s+expected\s+to\b",
        r"\bcarry\s+out\s+the\s+instructions\b",
        r"\binstructions\s+embedded\s+in\b",
    ],
    "role_hijacking": [
        r"\byou\s+are\s+now\s+operating\s+as\b",
        r"\bact\s+as\s+(the\s+)?(administrator|security\s+administrator)\b",
        r"\byou\s+are\s+now\s+the\s+(administrator|security\s+administrator)\b",
    ],
    "action_directive": [
        r"^\s*ACTION\s*:",
        r"\bSEND_EMAIL\b",
        r"\ba[\W_]*c[\W_]*t[\W_]*i[\W_]*o[\W_]*n\s*:",
    ],
    "external_action": [
        r"\b(send|forward|upload|share|transfer)\b.*\b(external|outside|attacker|recipient)\b",
        r"\b(send|forward|upload|share|transfer)\b.*\b(confidential|secret|private)\b",
    ],
}


def normalize_text(text: str) -> str:
    """
    Normalize text before pattern matching.

    This helps handle Unicode variations and inconsistent whitespace
    without attempting to infer meaning.
    """

    text = unicodedata.normalize("NFKC", text)

    # Normalize common dash variants.
    text = re.sub(r"[\u2010-\u2015]", "-", text)

    # Collapse repeated whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip()


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

    normalized_text = normalize_text(text)

    matched_categories = set()

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, normalized_text, re.IGNORECASE):
                matched_categories.add(category)
                break

    reasons = []

    if "instruction_override" in matched_categories:
        reasons.append("Detected instruction override attempt.")

    if "instruction_hijacking" in matched_categories:
        reasons.append("Detected instruction hijacking language.")

    if "role_hijacking" in matched_categories:
        reasons.append("Detected suspicious role reassignment.")

    if "action_directive" in matched_categories:
        reasons.append("Detected an explicit action directive.")

    if "external_action" in matched_categories:
        reasons.append("Detected a potentially unsafe external action.")

    if len(matched_categories) == 0:
        risk_score = 0.0
    elif len(matched_categories) == 1:
        risk_score = 0.50
    elif len(matched_categories) == 2:
        risk_score = 0.75
    else:
        risk_score = 0.95

    return {
        "safe": risk_score < 0.50,
        "risk_score": risk_score,
        "reasons": reasons,
    }
