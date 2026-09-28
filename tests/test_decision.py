from guard.decision import create_security_decision
from guard.policy import evaluate_policy, PolicyAction


def test_security_decision_record():
    content = "ACTION: SEND_EMAIL"

    policy = evaluate_policy(0.95)

    decision = create_security_decision(
        content=content,
        source="tool_output",
        safe=False,
        risk_score=0.95,
        detection_reasons=[
            "Detected an explicit action directive."
        ],
        policy=policy,
    )

    print("\nSECURITY DECISION")
    print(decision)
    print(decision.summary())

    assert decision.source == "tool_output"
    assert decision.content_length == len(content)
    assert len(decision.content_hash) == 64
    assert decision.risk_score == 0.95
    assert decision.safe is False
    assert decision.action == PolicyAction.BLOCK.value
    assert len(decision.detection_reasons) == 1


if __name__ == "__main__":
    test_security_decision_record()
    print("\nSecurity decision test passed.")
