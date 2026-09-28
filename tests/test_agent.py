import io
from contextlib import redirect_stdout

from agent.agent import run_agent


def test_normal_document_is_allowed():
    output = io.StringIO()

    with redirect_stdout(output):
        run_agent("normal")

    result = output.getvalue()

    assert "Safe: True" in result
    assert "Action: ALLOW" in result
    assert "PROMPTGUARD QUARANTINE" not in result
    assert "PROMPTGUARD BLOCK" not in result
    assert "VULNERABLE AGENT ACTION" not in result


def test_malicious_document_is_quarantined():
    output = io.StringIO()

    with redirect_stdout(output):
        run_agent("malicious")

    result = output.getvalue()

    assert "Safe: False" in result
    assert "Action: QUARANTINE" in result
    assert "The agent will NOT execute instructions from this output." in result
    assert "VULNERABLE AGENT ACTION" not in result


if __name__ == "__main__":
    test_normal_document_is_allowed()
    test_malicious_document_is_quarantined()
    print("All agent protection tests passed.")
