from agent.tools import lookup_document
from guard.adjudicator import adjudicate
from guard.fusion import assess_content
from guard.policy import evaluate_policy, PolicyAction
from guard.quarantine import quarantine_content
from guard.decision import create_security_decision


AMBIGUOUS_MARGIN_FLOOR = -0.02
MIN_ADJUDICATOR_RISK = 0.50
QUARANTINE_RISK = 0.75


def run_agent(user_request: str) -> None:
    print("\n" + "=" * 60)
    print("PROMPTGUARD - PROTECTED AGENT")
    print("=" * 60)

    print("\n[1] User request:")
    print(user_request)

    print("\n[2] Agent calls document tool...")
    tool_output = lookup_document(user_request)

    print("\n[3] Retrieved tool output:")
    print(tool_output.strip())

    print("\n[4] Rule and semantic analysis...")
    assessment = assess_content(tool_output)

    print(f"Rule risk: {assessment.rule_risk:.2f}")
    print(f"Semantic margin: {assessment.semantic_margin:+.3f}")
    print(f"Semantic signal: {assessment.semantic_signal}")

    reasons = list(assessment.reasons)

    # Strong rule evidence cannot be overridden by the LLM.
    if assessment.strong_rule_signal:
        final_risk = assessment.rule_risk
        print("Strong rule evidence; Qwen adjudication skipped.")

    # Strong semantic evidence is reviewed by the adjudicator.
    # Only strong rule evidence bypasses LLM review immediately.
    elif (
        assessment.semantic_signal == "STRONG"
        or assessment.rule_risk >= MIN_ADJUDICATOR_RISK
        or assessment.semantic_margin >= AMBIGUOUS_MARGIN_FLOOR
    ):
        if assessment.semantic_signal == "STRONG":
            print("\n[5] Strong semantic signal; invoking Qwen for review...")
        else:
            print("\n[5] Ambiguous content; invoking Qwen adjudicator...")
        result = adjudicate(tool_output)

        print(f"Adjudicator label: {result['label']}")
        print(f"Adjudicator valid: {result['valid']}")

        if (
            not result["valid"]
            or result["label"] not in ("SAFE", "MALICIOUS")
        ):
            final_risk = QUARANTINE_RISK
            reasons.append(
                "Invalid adjudicator output; quarantined by default."
            )

        elif result["label"] == "MALICIOUS":
            final_risk = max(assessment.rule_risk, QUARANTINE_RISK)
            reasons.append(
                "Qwen adjudicator classified content as malicious."
            )

        else:
            # Strong rule evidence bypasses this branch. Semantic
            # signals have now been reviewed by the adjudicator.
            final_risk = 0.0
            reasons.append(
                "Qwen classified reviewed content as safe."
            )

    else:
        # Fast path: no meaningful suspicious signal.
        final_risk = 0.0
        print("No meaningful risk signal; Qwen adjudication skipped.")

    policy = evaluate_policy(final_risk)

    security_decision = create_security_decision(
        content=tool_output,
        source="tool_output",
        safe=(policy.action == PolicyAction.ALLOW),
        risk_score=final_risk,
        detection_reasons=reasons,
        policy=policy,
    )

    print("\nSecurity decision record:")
    print(security_decision.summary())

    print("\n[6] Policy decision:")
    print(f"Action: {policy.action.value}")
    print(f"Reason: {policy.reason}")

    if policy.action in (PolicyAction.QUARANTINE, PolicyAction.BLOCK):
        record = quarantine_content(
            content=tool_output,
            risk_score=final_risk,
            reasons=reasons,
        )

        print("\n" + "=" * 60)
        print(f"PROMPTGUARD {policy.action.value}")
        print("=" * 60)
        print(
            "Retrieved content will not be treated as trusted instructions."
        )
        print(record.summary())
        print("=" * 60)
        return

    print("\n[7] Content allowed as data.")
    print("Instructions inside retrieved content are never executed.")
    print("Agent finished processing.")


if __name__ == "__main__":
    print("\nChoose a scenario:")
    print("1. Normal document")
    print("2. Malicious document")

    choice = input("\nEnter choice (1/2): ").strip()

    if choice == "1":
        run_agent("normal")
    elif choice == "2":
        run_agent("malicious")
    else:
        print("Invalid choice.")
