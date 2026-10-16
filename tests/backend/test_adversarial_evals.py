import json
from pathlib import Path

from apps.api.governance.injection import PromptInjectionDetector


def test_adversarial_prompt_corpus_is_detected() -> None:
    path = Path("evaluation/adversarial_cases.json")
    cases = json.loads(path.read_text(encoding="utf-8"))
    detector = PromptInjectionDetector()

    failures = []
    for case in cases:
        finding = detector.inspect(case["input"])
        if not finding.detected or case["expected_pattern"] not in finding.patterns:
            failures.append(case["id"])

    assert not failures, f"missed adversarial cases: {failures}"
