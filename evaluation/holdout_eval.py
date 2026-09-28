from attacks.holdout_corpus import HOLDOUT_CASES
from guard.detector import detect_prompt_injection


def evaluate_holdout() -> dict:
    true_positive = 0
    false_negative = 0
    false_positive = 0
    true_negative = 0

    for case in HOLDOUT_CASES:
        result = detect_prompt_injection(case["text"])
        detected = not result["safe"]

        if case["label"] == "malicious":
            if detected:
                true_positive += 1
            else:
                false_negative += 1
        else:
            if detected:
                false_positive += 1
            else:
                true_negative += 1

        print(
            f"{case['id']:<30} "
            f"label={case['label']:<9} "
            f"risk={result['risk_score']:.2f} "
            f"detected={detected}"
        )

    malicious_total = true_positive + false_negative
    benign_total = false_positive + true_negative

    detection_rate = (
        true_positive / malicious_total
        if malicious_total
        else 0.0
    )

    bypass_rate = (
        false_negative / malicious_total
        if malicious_total
        else 0.0
    )

    false_positive_rate = (
        false_positive / benign_total
        if benign_total
        else 0.0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    return {
        "true_positive": true_positive,
        "false_negative": false_negative,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "detection_rate": detection_rate,
        "bypass_rate": bypass_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
    }


if __name__ == "__main__":
    print("\nPROMPTGUARD HOLDOUT EVALUATION")
    print("=" * 75)

    metrics = evaluate_holdout()

    print("\nMETRICS")
    print("=" * 75)

    print(f"True positives:      {metrics['true_positive']}")
    print(f"False negatives:     {metrics['false_negative']}")
    print(f"False positives:     {metrics['false_positive']}")
    print(f"True negatives:      {metrics['true_negative']}")
    print(f"Detection rate:      {metrics['detection_rate']:.2%}")
    print(f"Bypass rate:         {metrics['bypass_rate']:.2%}")
    print(f"False positive rate: {metrics['false_positive_rate']:.2%}")
    print(f"Precision:           {metrics['precision']:.2%}")
