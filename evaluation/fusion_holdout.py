from attacks.holdout_corpus import HOLDOUT_CASES
from guard.fusion import assess_content


def evaluate_fusion():
    true_positive = 0
    false_negative = 0
    false_positive = 0
    true_negative = 0

    print("\nPROMPTGUARD FUSION HOLDOUT")
    print("=" * 100)

    for case in HOLDOUT_CASES:
        result = assess_content(case["text"])

        detected = result.suspicious

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
            f"rule={result.rule_risk:.2f} "
            f"semantic={result.semantic_margin:+.3f} "
            f"signal={result.semantic_signal:<6} "
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

    print("\nMETRICS")
    print("=" * 100)
    print(f"True positives:      {true_positive}")
    print(f"False negatives:     {false_negative}")
    print(f"False positives:     {false_positive}")
    print(f"True negatives:      {true_negative}")
    print(f"Detection rate:      {detection_rate:.2%}")
    print(f"Bypass rate:         {bypass_rate:.2%}")
    print(f"False positive rate: {false_positive_rate:.2%}")


if __name__ == "__main__":
    evaluate_fusion()
