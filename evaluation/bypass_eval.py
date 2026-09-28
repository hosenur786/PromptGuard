from attacks.bypass_corpus import BYPASS_CASES
from guard.detector import detect_prompt_injection


def evaluate_bypasses() -> dict:
    total = len(BYPASS_CASES)
    detected = 0
    bypassed = 0

    for case in BYPASS_CASES:
        result = detect_prompt_injection(case["text"])
        was_detected = not result["safe"]

        if was_detected:
            detected += 1
        else:
            bypassed += 1

        print(
            f"{case['id']:<28} "
            f"risk={result['risk_score']:.2f} "
            f"detected={was_detected} "
            f"bypassed={not was_detected}"
        )

    bypass_rate = bypassed / total if total else 0.0
    detection_rate = detected / total if total else 0.0

    return {
        "total_cases": total,
        "detected": detected,
        "bypassed": bypassed,
        "detection_rate": detection_rate,
        "bypass_rate": bypass_rate,
    }


if __name__ == "__main__":
    print("\nPROMPTGUARD BYPASS EVALUATION")
    print("=" * 70)

    metrics = evaluate_bypasses()

    print("\nMETRICS")
    print("=" * 70)
    print(f"Total bypass attempts: {metrics['total_cases']}")
    print(f"Detected:              {metrics['detected']}")
    print(f"Bypassed:              {metrics['bypassed']}")
    print(f"Detection rate:        {metrics['detection_rate']:.2%}")
    print(f"Bypass rate:           {metrics['bypass_rate']:.2%}")
