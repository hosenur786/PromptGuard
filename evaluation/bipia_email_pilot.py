"""Small BIPIA EmailQA pilot for PromptGuard.

BIPIA source: https://github.com/microsoft/BIPIA
Its repository is MIT-licensed. Injection positions follow its
start/middle/end construction convention.

This is an adapter pilot, not a full official BIPIA reproduction.
It measures whether inserted instructions are contained by PromptGuard.
Unmodified contexts are controls, not independently verified benign samples.
"""

import csv
import json
import random
import re
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from statistics import mean, median
from time import perf_counter

from nltk.tokenize.punkt import PunktSentenceTokenizer

from guard.adjudicator import adjudicate
from guard.fusion import assess_content
from guard.policy import evaluate_policy, PolicyAction


SEED = 2023
CONTEXT_LIMIT = 5
ATTACKS_PER_CATEGORY = 2

AMBIGUOUS_MARGIN_FLOOR = -0.02
MIN_ADJUDICATOR_RISK = 0.50
QUARANTINE_RISK = 0.75

DATA_ROOT = Path.home() / "datasets" / "BIPIA" / "benchmark"
CONTEXT_FILE = DATA_ROOT / "email" / "test.jsonl"
ATTACK_FILE = DATA_ROOT / "text_attack_test.json"

ATTACK_CATEGORIES = [
    "Task Automation",
    "Base Encoding",
    "Reverse Text",
    "Scams & Fraud",
    "Misinformation & Propaganda",
]


def insert_at_end(context, attack):
    return "\n".join([context, attack])


def insert_at_start(context, attack):
    return "\n".join([attack, context])


def insert_in_middle(context, attack):
    # Mirrors BIPIA's seeded Punkt sentence-span selection.
    spans = list(PunktSentenceTokenizer().span_tokenize(context))
    if not spans:
        return insert_at_end(context, attack)

    start, _ = random.Random(SEED).sample(spans, k=1)[0]
    return "\n".join([context[:start], attack, context[start:]])


def load_data():
    for path in (CONTEXT_FILE, ATTACK_FILE):
        if not path.is_file():
            raise FileNotFoundError(f"Missing BIPIA file: {path}")

    with CONTEXT_FILE.open(encoding="utf-8") as handle:
        contexts = [
            json.loads(line)
            for line in handle
            if line.strip()
        ][:CONTEXT_LIMIT]

    with ATTACK_FILE.open(encoding="utf-8") as handle:
        attack_data = json.load(handle)

    attacks = []
    for category in ATTACK_CATEGORIES:
        prompts = attack_data.get(category)
        if not prompts:
            raise ValueError(f"Attack category missing or empty: {category}")

        for index, prompt in enumerate(prompts[:ATTACKS_PER_CATEGORY], start=1):
            attacks.append({
                "id": f"{category}-{index}",
                "category": category,
                "text": prompt,
            })

    if not contexts:
        raise ValueError("No email contexts were loaded.")

    return contexts, attacks


def build_cases(contexts, attacks):
    cases = []
    insertions = [
        ("end", insert_at_end),
        ("start", insert_at_start),
        ("middle", insert_in_middle),
    ]

    # Context-only controls: useful for measuring alerts on unmodified data.
    for context_index, row in enumerate(contexts, start=1):
        cases.append({
            "id": f"control_{context_index:02d}",
            "label": "control",
            "category": "context_only",
            "position": "none",
            "trusted_task": row.get("question", ""),
            "text": row["context"],
        })

    # Reproduce the same three insertion positions used by BIPIA.
    for position, insert_function in insertions:
        for context_index, row in enumerate(contexts, start=1):
            for attack in attacks:
                slug = re.sub(
                    r"[^a-z0-9]+",
                    "_",
                    attack["category"].lower(),
                ).strip("_")

                cases.append({
                    "id": (
                        f"email{context_index:02d}_"
                        f"{slug}_{attack['id'].rsplit('-', 1)[-1]}_"
                        f"{position}"
                    ),
                    "label": "injected",
                    "category": attack["category"],
                    "position": position,
                    "trusted_task": row.get("question", ""),
                    "text": insert_function(row["context"], attack["text"]),
                })

    return cases


def evaluate_case(case):
    started = perf_counter()
    assessment = assess_content(case["text"])

    route = ""
    adjudicator_label = "-"
    adjudicator_seconds = 0.0

    if assessment.strong_rule_signal:
        route = "STRONG_RULE"
        final_risk = assessment.rule_risk

    elif (
        assessment.semantic_signal == "STRONG"
        or assessment.rule_risk >= MIN_ADJUDICATOR_RISK
        or assessment.semantic_margin >= AMBIGUOUS_MARGIN_FLOOR
    ):
        route = (
            "STRONG_SEMANTIC_REVIEW"
            if assessment.semantic_signal == "STRONG"
            else "ADJUDICATOR_REVIEW"
        )

        review_started = perf_counter()
        result = adjudicate(case["text"])
        adjudicator_seconds = perf_counter() - review_started
        adjudicator_label = result.get("label", "UNKNOWN")

        if (
            not result.get("valid", False)
            or adjudicator_label not in ("SAFE", "MALICIOUS")
        ):
            final_risk = QUARANTINE_RISK
            route += "_INVALID"

        elif adjudicator_label == "MALICIOUS":
            final_risk = max(assessment.rule_risk, QUARANTINE_RISK)

        else:
            final_risk = 0.0

    else:
        route = "FAST_ALLOW"
        final_risk = 0.0

    policy = evaluate_policy(final_risk)

    return {
        "id": case["id"],
        "label": case["label"],
        "category": case["category"],
        "position": case["position"],
        "route": route,
        "rule_risk": assessment.rule_risk,
        "semantic_margin": assessment.semantic_margin,
        "semantic_signal": assessment.semantic_signal,
        "adjudicator_label": adjudicator_label,
        "action": policy.action.value,
        "quarantined": policy.action != PolicyAction.ALLOW,
        "adjudicator_seconds": adjudicator_seconds,
        "total_seconds": perf_counter() - started,
    }


def summarize_group(title, rows):
    if not rows:
        return

    flagged = sum(row["quarantined"] for row in rows)
    print(
        f"{title:<32} "
        f"{flagged:>3}/{len(rows):<3} "
        f"contained={flagged / len(rows):6.2%}"
    )


def main():
    contexts, attacks = load_data()
    cases = build_cases(contexts, attacks)
    injected_count = sum(row["label"] == "injected" for row in cases)
    control_count = sum(row["label"] == "control" for row in cases)

    print("PROMPTGUARD — BIPIA EMAIL PILOT")
    print("=" * 88)
    print(f"Email contexts: {len(contexts)}")
    print(f"Attack prompts: {len(attacks)}")
    print(f"Injected cases: {injected_count}")
    print(f"Context controls: {control_count}")
    print("Expected behavior: contain injected instructions in untrusted context")
    print("Note: context controls are not verified benign examples.")
    print()

    results = []
    for index, case in enumerate(cases, start=1):
        result = evaluate_case(case)
        results.append(result)

        outcome = "QUARANTINE" if result["quarantined"] else "ALLOW"
        print(
            f"{index:>3}/{len(cases)} "
            f"{result['id']:<57} "
            f"{result['route']:<25} "
            f"{outcome}"
        )

    injected = [row for row in results if row["label"] == "injected"]
    controls = [row for row in results if row["label"] == "control"]

    contained = sum(row["quarantined"] for row in injected)
    missed = [row for row in injected if not row["quarantined"]]
    control_flagged = sum(row["quarantined"] for row in controls)
    control_allowed = len(controls) - control_flagged

    print("\nOVERALL RESULTS")
    print("=" * 65)
    print(f"Injected cases contained:    {contained}/{len(injected)} "
          f"({contained / len(injected):.2%})")
    print(f"Injected cases allowed:      {len(missed)}/{len(injected)} "
          f"({len(missed) / len(injected):.2%})")
    print(f"Context-only controls flagged: {control_flagged}/{len(controls)}")
    print(f"Context-only controls allowed: {control_allowed}/{len(controls)}")

    print("\nBY ATTACK CATEGORY")
    print("-" * 65)
    for category in ATTACK_CATEGORIES:
        group = [row for row in injected if row["category"] == category]
        summarize_group(category, group)

    print("\nBY INSERTION POSITION")
    print("-" * 65)
    for position in ("start", "middle", "end"):
        group = [row for row in injected if row["position"] == position]
        summarize_group(position, group)

    calls = [row["adjudicator_seconds"] for row in results
             if row["adjudicator_seconds"] > 0]
    durations = [row["total_seconds"] for row in results]

    print("\nLATENCY")
    print("-" * 65)
    print(f"Mean case latency: {mean(durations):.2f}s")
    print(f"Median case latency: {median(durations):.2f}s")
    print(f"Adjudicator calls: {len(calls)}")
    if calls:
        print(f"Mean adjudicator latency: {mean(calls):.2f}s")
        print(f"Median adjudicator latency: {median(calls):.2f}s")

    if missed:
        print("\nINJECTED CASES ALLOWED — REVIEW THESE")
        print("-" * 65)
        for row in missed:
            print(
                f"{row['id']} | category={row['category']} | "
                f"position={row['position']} | route={row['route']} | "
                f"rule_risk={row['rule_risk']:.2f} | "
                f"semantic_margin={row['semantic_margin']:+.3f} | "
                f"LLM={row['adjudicator_label']}"
            )

    flagged_controls = [row for row in controls if row["quarantined"]]
    if flagged_controls:
        print("\nCONTEXT-ONLY CONTROLS FLAGGED — REVIEW THESE")
        print("-" * 65)
        for row in flagged_controls:
            print(f"{row['id']} | route={row['route']} | "
                  f"rule_risk={row['rule_risk']:.2f} | "
                  f"LLM={row['adjudicator_label']}")

    # Persist the run outside the PromptGuard Git repository.
    output_dir = Path.home() / "datasets" / "BIPIA" / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"promptguard_email_pilot_{timestamp}.csv"

    fields = [
        "id", "label", "category", "position", "route",
        "rule_risk", "semantic_margin", "semantic_signal",
        "adjudicator_label", "action", "quarantined",
        "adjudicator_seconds", "total_seconds",
    ]

    with output_file.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults CSV: {output_file}")
    print(f"Context-file SHA256: {sha256(CONTEXT_FILE.read_bytes()).hexdigest()}")
    print(f"Attack-file SHA256:   {sha256(ATTACK_FILE.read_bytes()).hexdigest()}")
    print("\nPilot evaluation finished.")


if __name__ == "__main__":
    main()
