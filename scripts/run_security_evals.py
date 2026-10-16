#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict

from governance.injection import PromptInjectionDetector


class AdversarialCase(TypedDict):
    id: str
    category: str
    input: str
    expected_pattern: str


def load_cases(path: Path) -> list[AdversarialCase]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(cases: list[AdversarialCase]) -> list[dict[str, object]]:
    detector = PromptInjectionDetector()
    results = []
    for case in cases:
        finding = detector.inspect(case["input"])
        passed = finding.detected and case["expected_pattern"] in finding.patterns
        results.append(
            {
                "id": case["id"],
                "category": case["category"],
                "passed": passed,
                "detected_patterns": finding.patterns,
            }
        )
    return results


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    results = evaluate(load_cases(root / "evaluation" / "adversarial_cases.json"))
    passed = sum(bool(result["passed"]) for result in results)
    report = {"passed": passed, "total": len(results), "results": results}
    print(json.dumps(report, indent=2))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
