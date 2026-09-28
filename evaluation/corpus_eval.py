from attacks.corpus import ATTACK_CASES
from guard.detector import detect_prompt_injection


def evaluate_corpus() -> dict:
    """
    Evaluate PromptGuard against the local attack corpus.
    """

    attacks = [
        case for case in ATTACK_CASES
        if case["category"] != "benign"
    ]

    benign_cases = [
        case for case in ATTACK_CASES
        if case["category"] == "benign"
    ]

    detected_attacks = 0

    for case in attacks:
        result = detect_prompt_injection(case["text"])

        if not result["safe"]:
            detected_attacks += 1

        print(
            f"{case['id']:<28} "
            f"risk={result['risk_score']:.2f} "
            f"detected={not result['safe']}"
        )

    false_positives = 0

    for case in benign_cases:
        result = detect_prompt_injection(case["text"])

        if not result["safe"]:
            false_positives += 1

        print(
            f"{case['id']:<28} "
            f"risk={result['risk_score']:.2f} "
            f"detected={not result['safe']}"
        )

    detection_rate = (
        detected_attacks / len(attacks)
        if attacks
        else 0.0
    )

    false_positive_rate = (
        false_positives / len(benign_cases)
        if benign_cases
        else 0.0
    )

    return {
        "total_attacks": len(attacks),
        "detected_attacks": detected_attacks,
        "detection_rate": detection_rate,
        "benign_cases": len(benign_cases),
        "false_positives": false_positives,
        "false_positive_rate": false_positive_rate,
    }


if __name__ == "__main__":
    print("\nPROMPTGUARD CORPUS EVALUATION")
    print("=" * 70)

    metrics = evaluate_corpus()

    print("\nMETRICS")
    print("=" * 70)
    print(f"Total attacks:       {metrics['total_attacks']}")
    print(f"Detected attacks:    {metrics['detected_attacks']}")
    print(f"Detection rate:      {metrics['detection_rate']:.2%}")
    print(f"Benign cases:        {metrics['benign_cases']}")
    print(f"False positives:     {metrics['false_positives']}")
    print(f"False positive rate: {metrics['false_positive_rate']:.2%}")
