from attacks.calibration_corpus import CALIBRATION_CASES
from guard.semantic import analyze_semantics


def collect_scores():
    results = []

    print("\nPROMPTGUARD SEMANTIC CALIBRATION")
    print("=" * 85)

    for case in CALIBRATION_CASES:
        result = analyze_semantics(case["text"])

        margin = result["margin"]

        results.append(
            {
                "id": case["id"],
                "label": case["label"],
                "margin": margin,
            }
        )

        print(
            f"{case['id']:<10} "
            f"label={case['label']:<9} "
            f"margin={margin:+.3f}"
        )

    return results


def evaluate_threshold(results, threshold):
    malicious = [
        item for item in results
        if item["label"] == "malicious"
    ]

    benign = [
        item for item in results
        if item["label"] == "benign"
    ]

    true_positive = sum(
        item["margin"] >= threshold
        for item in malicious
    )

    false_negative = len(malicious) - true_positive

    false_positive = sum(
        item["margin"] >= threshold
        for item in benign
    )

    true_negative = len(benign) - false_positive

    detection_rate = (
        true_positive / len(malicious)
        if malicious
        else 0.0
    )

    false_positive_rate = (
        false_positive / len(benign)
        if benign
        else 0.0
    )

    accuracy = (
        (true_positive + true_negative)
        / len(results)
        if results
        else 0.0
    )

    return {
        "threshold": threshold,
        "true_positive": true_positive,
        "false_negative": false_negative,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "accuracy": accuracy,
    }


def main():
    results = collect_scores()

    print("\nTHRESHOLD COMPARISON")
    print("=" * 85)

    thresholds = [
        0.00,
        0.05,
        0.10,
        0.15,
        0.20,
        0.25,
        0.30,
    ]

    for threshold in thresholds:
        metrics = evaluate_threshold(results, threshold)

        print(
            f"threshold={threshold:.2f} | "
            f"detection={metrics['detection_rate']:.2%} | "
            f"false_positive={metrics['false_positive_rate']:.2%} | "
            f"accuracy={metrics['accuracy']:.2%}"
        )


if __name__ == "__main__":
    main()
