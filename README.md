# PromptGuard

**PromptGuard** is a local AI-agent security prototype that inspects untrusted
content for potential prompt injection before an agent trusts that content.

Version: 0.1 development release.

## Features

- Rule-based prompt-injection detection.
- Semantic similarity analysis using Sentence Transformers.
- Optional local GGUF model adjudication using llama-cpp-python.
- Risk-based ALLOW, QUARANTINE, and BLOCK policy decisions.
- Structured security decision records with SHA-256 content hashes.
- Streamlit dashboard for interactive content inspection.
- CLI demonstration of a protected agent workflow.
- Automated tests for security decisions and policy behavior.

PromptGuard is a defense-in-depth component, not a guarantee that attacks
will always be detected.

## Architecture

Untrusted content -> Rule detection and semantic analysis -> Fusion and
risk assessment -> Local model review when needed -> Policy engine ->
ALLOW, QUARANTINE, or BLOCK -> Security decision record.

The shared analysis service is guard/service.py. The dashboard is app.py.
The CLI demonstration is agent/agent.py. Experimental task-conflict
classifiers are retained for research and are not connected to production
routing.

## Requirements

- Linux or WSL2 Ubuntu.
- Python 3.10 or a compatible Python version.
- A compatible local instruction-tuned GGUF model.
- Internet access during setup if dependencies or embedding weights must
  be downloaded.

Model weights are not included. Download a compatible model separately
and follow its licence and usage terms.

## Installation

From the repository root, create and prepare the virtual environment:

1. Run: python3 -m venv .venv
2. Run: .venv/bin/python -m pip install --upgrade pip
3. Run: .venv/bin/python -m pip install -r requirements.txt

## Configure the model

Set PROMPTGUARD_GGUF_PATH to the full path of your GGUF model file before
starting the application. For example:

export PROMPTGUARD_GGUF_PATH="$HOME/models/qwen2.5-7b-instruct-q4_k_m.gguf"

Change the example path to the actual location of your model. The file
must exist. The semantic embedding model may download its weights on
first use and currently runs on the CPU.

## Run the dashboard

From the repository root, run:

PYTHONPATH=. .venv/bin/python -m streamlit run app.py

Open the local URL printed by Streamlit, normally http://localhost:8501.
Use the dashboard to submit untrusted text and inspect its policy result,
risk score, detection reasons, and security decision record.

The dashboard is for local development. It does not include authentication
or multi-user access controls. Do not expose it to the public internet.

## Run the CLI demonstration

Run:

PYTHONPATH=. .venv/bin/python -m agent.agent

Choose the normal or malicious simulated document scenario. Document
retrieval is hardcoded for demonstration purposes. No real email is sent.

## Run tests

Install pytest if needed:

.venv/bin/python -m pip install pytest

Then run:

PYTHONPATH=. .venv/bin/python -m pytest -q

The development baseline reached 34 passing tests. Rerun tests after
changes; a previous passing run does not guarantee future correctness.

## Current policy

- Risk below 0.50: ALLOW.
- Risk from 0.50 to below 0.90: QUARANTINE.
- Risk at or above 0.90: BLOCK.

Risk scores are heuristic values, not calibrated probabilities.

## Limitations

- Rule and semantic detectors can produce false positives and miss attacks.
- The local model may misclassify quoted attacks and task diversions.
- Task-conflict experiments rely heavily on synthetic, provisionally
  labeled data and do not establish real-world detection rates.
- Retrieval and external tool execution are simulated; production agent
  integrations are not included.
- Quarantine records are in-memory objects, not durable storage.
- The application does not include authentication or role-based access.
- ALLOW does not guarantee safety. PromptGuard should not be the sole
  security boundary for sensitive operations.

Use least-privilege tool permissions, validate actions independently, keep
secrets out of untrusted contexts, and require approval for sensitive actions.

## Development status

Version 0.1 focuses on a working local demonstration, reproducible setup,
basic policy enforcement, and transparent limitations. Future versions can
improve attribution accuracy, evaluations, persistent audit storage,
agent integrations, and deployment hardening.

## Licence

No project licence has been declared yet. Do not assume unrestricted
redistribution or reuse until a licence is added.
