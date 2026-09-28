from evaluation.bypass_eval import evaluate_bypasses


def test_bypass_evaluation():
    metrics = evaluate_bypasses()

    assert metrics["total_cases"] == 6
    assert 0.0 <= metrics["detection_rate"] <= 1.0
    assert 0.0 <= metrics["bypass_rate"] <= 1.0


if __name__ == "__main__":
    test_bypass_evaluation()
    print("\nBypass evaluation test passed.")
