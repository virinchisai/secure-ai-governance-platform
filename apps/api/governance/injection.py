from __future__ import annotations

import re

from pydantic import BaseModel


class InjectionFinding(BaseModel):
    detected: bool
    patterns: list[str]
    reason: str


class PromptInjectionDetector:
    PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "instruction_override",
            re.compile(r"(?i)ignore (?:all |any )?(?:previous|prior|system) instructions"),
        ),
        (
            "privilege_escalation",
            re.compile(r"(?i)(?:you are now|act as) (?:an? )?(?:administrator|admin|root)"),
        ),
        (
            "exfiltration",
            re.compile(
                r"(?i)(?:upload|send|email|exfiltrate).{0,50}"
                r"(?:all files|database|contents|attacker@)"
            ),
        ),
        (
            "secret_request",
            re.compile(r"(?i)(?:reveal|show|print|return).{0,30}(?:api keys?|secrets?|passwords?)"),
        ),
        (
            "tool_override",
            re.compile(r"(?i)(?:call|use|execute).{0,20}(?:send_email|shell|admin tool)"),
        ),
    )

    def inspect(self, text: str) -> InjectionFinding:
        matches = [name for name, pattern in self.PATTERNS if pattern.search(text)]
        return InjectionFinding(
            detected=bool(matches),
            patterns=matches,
            reason=(
                "Untrusted content contains instruction-like text; "
                "it is excluded from model instructions."
                if matches
                else "No known prompt-injection pattern detected."
            ),
        )

    def isolate_untrusted_content(self, text: str) -> str:
        finding = self.inspect(text)
        if not finding.detected:
            return text
        sanitized = text
        for _, pattern in self.PATTERNS:
            sanitized = pattern.sub("[UNTRUSTED_INSTRUCTION_REMOVED]", sanitized)
        return sanitized
