from guard.policy import PolicyAction, evaluate_policy


def test_low_risk_is_allowed():
    decision = evaluate_policy(0.0)

    print("\nLOW RISK")
    print(decision)

    assert decision.action == PolicyAction.ALLOW


def test_medium_risk_is_quarantined():
    decision = evaluate_policy(0.75)

    print("\nMEDIUM RISK")
    print(decision)

    assert decision.action == PolicyAction.QUARANTINE


def test_high_risk_is_blocked():
    decision = evaluate_policy(0.95)

    print("\nHIGH RISK")
    print(decision)

    assert decision.action == PolicyAction.BLOCK


if __name__ == "__main__":
    test_low_risk_is_allowed()
    test_medium_risk_is_quarantined()
    test_high_risk_is_blocked()

    print("\nAll policy tests passed.")
