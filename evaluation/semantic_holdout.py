from attacks.holdout_corpus import HOLDOUT_CASES
from guard.semantic import analyze_semantics


def evaluate_semantic_holdout():
    print("\nPROMPTGUARD SEMANTIC HOLDOUT")
    print("=" * 90)

    for case in HOLDOUT_CASES:
        result = analyze_semantics(case["text"])

        print(
            f"{case['id']:<30} "
            f"label={case['label']:<9} "
            f"attack_sim={result['attack_similarity']:.3f} "
            f"benign_sim={result['benign_similarity']:.3f} "
            f"margin={result['margin']:.3f}"
        )


if __name__ == "__main__":
    evaluate_semantic_holdout()
