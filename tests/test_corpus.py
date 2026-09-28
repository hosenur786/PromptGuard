from evaluation.corpus_eval import evaluate_corpus


def test_corpus_evaluation():
    metrics = evaluate_corpus()

    assert metrics["total_attacks"] == 5
    assert metrics["detected_attacks"] >= 1
    assert 0.0 <= metrics["detection_rate"] <= 1.0
    assert 0.0 <= metrics["false_positive_rate"] <= 1.0


if __name__ == "__main__":
    test_corpus_evaluation()
    print("\nCorpus evaluation test passed.")
