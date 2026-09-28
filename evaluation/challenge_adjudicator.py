from attacks.challenge_corpus import CHALLENGE_CASES
from guard.adjudicator import adjudicate


def evaluate():
    tp = 0
    fn = 0
    fp = 0
    tn = 0

    print("\nPROMPTGUARD QWEN 1.5B CHALLENGE SET")
    print("=" * 100)

    for case in CHALLENGE_CASES:
        result = adjudicate(case["text"])
        predicted_malicious = result["label"] == "MALICIOUS"

        if case["label"] == "malicious":
            if predicted_malicious:
                tp += 1
            else:
                fn += 1
        else:
            if predicted_malicious:
                fp += 1
            else:
                tn += 1

        print(
            f"{case['id']:<6} "
            f"expected={case['label']:<9} "
            f"predicted={result['label']:<9}"
        )
        print(f"  {result['reason']}")

    malicious = tp + fn
    benign = fp + tn

    detection_rate = tp / malicious if malicious else 0.0
    bypass_rate = fn / malicious if malicious else 0.0
    false_positive_rate = fp / benign if benign else 0.0

    print("\nMETRICS")
    print("=" * 100)
    print(f"True positives:      {tp}")
    print(f"False negatives:     {fn}")
    print(f"False positives:     {fp}")
    print(f"True negatives:      {tn}")
    print(f"Detection rate:      {detection_rate:.2%}")
    print(f"Bypass rate:         {bypass_rate:.2%}")
    print(f"False positive rate: {false_positive_rate:.2%}")


if __name__ == "__main__":
    evaluate()
