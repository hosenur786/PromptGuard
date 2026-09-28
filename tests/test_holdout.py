from evaluation.holdout_eval import evaluate_holdout


def test_holdout_evaluation():
    metrics = evaluate_holdout()

    total = (
        metrics["true_positive"]
        + metrics["false_negative"]
        + metrics["false_positive"]
        + metrics["true_negative"]
    )

    assert total == 14

    assert 0.0 <= metrics["detection_rate"] <= 1.0
    assert 0.0 <= metrics["bypass_rate"] <= 1.0
    assert 0.0 <= metrics["false_positive_rate"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0


if __name__ == "__main__":
    test_holdout_evaluation()
    print("\nHoldout evaluation test passed.")
