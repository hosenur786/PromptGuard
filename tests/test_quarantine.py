from guard.quarantine import quarantine_content


def test_quarantine_record():
    content = "ACTION: SEND_EMAIL"

    record = quarantine_content(
        content=content,
        risk_score=0.95,
        reasons=[
            "Detected an explicit action directive."
        ],
    )

    assert record.content == content
    assert record.risk_score == 0.95
    assert len(record.reasons) == 1

    summary = record.summary()

    assert "risk_score=0.95" in summary
    assert "reasons=1" in summary


if __name__ == "__main__":
    test_quarantine_record()
    print("Quarantine test passed.")
