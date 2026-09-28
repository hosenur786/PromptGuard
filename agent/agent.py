from agent.tools import lookup_document, execute_action
from guard.detector import detect_prompt_injection
from guard.quarantine import quarantine_content
from guard.decision import create_security_decision
from guard.policy import evaluate_policy, PolicyAction

def run_agent(user_request: str) -> None:
    print("\n" + "=" * 60)
    print("PROMPTGUARD - PROTECTED AGENT")
    print("=" * 60)

    print("\n[1] User request:")
    print(user_request)

    print("\n[2] Agent calls document tool...")
    tool_output = lookup_document(user_request)

    print("\n[3] Tool output:")
    print(tool_output.strip())

    print("\n[4] PromptGuard analyzes tool output...")

    detection = detect_prompt_injection(tool_output)

    print(f"\nRisk score: {detection['risk_score']:.2f}")
    print(f"Safe: {detection['safe']}")

    if detection["reasons"]:
        print("Detection reasons:")
        for reason in detection["reasons"]:
            print(f" - {reason}")

    policy = evaluate_policy(detection["risk_score"])

    security_decision = create_security_decision(
        content=tool_output,
        source="tool_output",
        safe=detection["safe"],
        risk_score=detection["risk_score"],
        detection_reasons=detection["reasons"],
        policy=policy,
    )

    print("\nSecurity decision record:")
    print(security_decision.summary())

    print("\n[5] PromptGuard policy decision:")
    print(f"Action: {policy.action.value}")
    print(f"Reason: {policy.reason}")

    if policy.action in (PolicyAction.QUARANTINE, PolicyAction.BLOCK):
        quarantine_record = quarantine_content(
            content=tool_output,
            risk_score=detection["risk_score"],
            reasons=detection["reasons"],
        )

        print("\n" + "=" * 60)

        if policy.action == PolicyAction.BLOCK:
            print("🛑 PROMPTGUARD BLOCK")
        else:
            print("🛑 PROMPTGUARD QUARANTINE")

        print("=" * 60)
        print("The agent will NOT execute instructions from this output.")
        print()
        print(quarantine_record.summary())
        print("=" * 60)

        return

    print("\n[6] Tool output allowed.")
    print("Agent continues normal processing.")

    
    for line in tool_output.splitlines():
        line = line.strip()

        if line.startswith("ACTION:"):
            action = line[len("ACTION:"):].strip()
            execute_action(action)

    print("\n[7] Agent finished processing.")


if __name__ == "__main__":
    print("\nChoose a scenario:")
    print("1. Normal document")
    print("2. Malicious document")

    choice = input("\nEnter choice (1/2): ").strip()

    if choice == "2":
        run_agent("malicious")
    elif choice == "1":
        run_agent("normal")
    else:
        print("Invalid choice.")
