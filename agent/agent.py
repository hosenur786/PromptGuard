from agent.tools import lookup_document, execute_action


def run_agent(user_request: str) -> None:
    print("\n" + "=" * 60)
    print("PROMPTGUARD - VULNERABLE AGENT BASELINE")
    print("=" * 60)

    print("\n[1] User request:")
    print(user_request)

    print("\n[2] Agent calls document tool...")
    tool_output = lookup_document(user_request)

    print("\n[3] Tool output:")
    print(tool_output.strip())

    print("\n[4] Agent processes tool output...")

    # INTENTIONALLY VULNERABLE:
    # The agent treats untrusted tool output as instructions.
    for line in tool_output.splitlines():
        line = line.strip()

        if line.startswith("ACTION:"):
            action = line[len("ACTION:"):].strip()
            execute_action(action)

    print("\n[5] Agent finished processing.")


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
