from agent.tools import lookup_document
from guard.adjudicator import adjudicate
from guard.fusion import assess_content
from guard.policy import PolicyAction
from guard.service import analyze_untrusted_content


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

    # Use the shared service while retaining patchable dependencies
    # for deterministic agent tests.
    result = analyze_untrusted_content(
        tool_output,
        source="tool_output",
        assessor=assess_content,
        adjudicator=adjudicate,
    )

    assessment = result.assessment
    policy = result.policy

    print(f"Rule risk: {assessment.rule_risk:.2f}")
    print(f"Semantic margin: {assessment.semantic_margin:+.3f}")
    print(f"Semantic signal: {assessment.semantic_signal}")

    if result.decision_path == "strong_rule_short_circuit":
        print("Strong rule evidence; Qwen adjudication skipped.")

    elif result.decision_path == "adjudicator_review":
        if assessment.semantic_signal == "STRONG":
            print(
                "\n[5] Strong semantic signal; "
                "invoking Qwen for review..."
            )
        else:
            print(
                "\n[5] Ambiguous content; "
                "invoking Qwen adjudicator..."
            )

        adjudicator_result = result.adjudicator_result or {}
        print(f"Adjudicator label: {adjudicator_result.get('label', 'UNKNOWN')}")
        print(f"Adjudicator valid: {adjudicator_result.get('valid', False)}")

    else:
        print("No meaningful risk signal; Qwen adjudication skipped.")

    print("\nSecurity decision record:")
    print(result.security_decision.summary())

    print("\n[6] Policy decision:")
    print(f"Action: {policy.action.value}")
    print(f"Reason: {policy.reason}")

    if result.quarantine_record is not None:
        print("\n" + "=" * 60)
        print(f"PROMPTGUARD {policy.action.value}")
        print("=" * 60)
        print(
            "Retrieved content will not be treated as trusted instructions."
        )
        print(result.quarantine_record.summary())
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
