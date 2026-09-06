"""
LLM Sentinel security scanner.

This module performs defensive pattern-based analysis of text
associated with LLM applications.

It does NOT execute discovered instructions.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    recommendation: str
    patterns: tuple[str, ...]


RULES: tuple[Rule, ...] = (

    Rule(
        rule_id="PI001",
        category="prompt-injection",
        severity="HIGH",
        title="Instruction-hierarchy override attempt",
        description=(
            "The input appears to contain instructions attempting to "
            "override system, developer, or security instructions."
        ),
        recommendation=(
            "Separate trusted instructions from untrusted content, "
            "apply instruction hierarchy enforcement, and validate "
            "model outputs before sensitive actions."
        ),
        patterns=(
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"ignore\s+(the\s+)?system\s+prompt",
            r"disregard\s+(all\s+)?previous\s+instructions",
            r"override\s+(the\s+)?system\s+message",
            r"forget\s+(all\s+)?previous\s+instructions",
        ),
    ),

    Rule(
        rule_id="PI002",
        category="prompt-extraction",
        severity="HIGH",
        title="System prompt extraction attempt",
        description=(
            "The input appears to request hidden system or developer "
            "instructions."
        ),
        recommendation=(
            "Treat system and developer prompts as confidential "
            "application configuration and avoid exposing them in "
            "model responses."
        ),
        patterns=(
            r"show\s+(me\s+)?(the\s+)?system\s+prompt",
            r"reveal\s+(the\s+)?system\s+prompt",
            r"print\s+(the\s+)?system\s+prompt",
            r"what\s+is\s+your\s+system\s+prompt",
            r"repeat\s+(your\s+)?hidden\s+instructions",
            r"developer\s+instructions",
        ),
    ),

    Rule(
        rule_id="PI003",
        category="guardrail-bypass",
        severity="HIGH",
        title="Guardrail bypass attempt",
        description=(
            "The input contains language commonly associated with "
            "attempts to bypass safety restrictions."
        ),
        recommendation=(
            "Use layered controls including input filtering, policy "
            "enforcement, output validation, tool authorization, "
            "and monitoring."
        ),
        patterns=(
            r"bypass\s+(the\s+)?(safety|security|content)\s+filter",
            r"disable\s+(the\s+)?guardrail",
            r"remove\s+(the\s+)?restrictions",
            r"jailbreak",
            r"developer\s+mode",
            r"do\s+anything\s+now",
        ),
    ),

    Rule(
        rule_id="SECRET001",
        category="secret-exposure",
        severity="CRITICAL",
        title="Potential secret or credential exposure",
        description=(
            "The scanned content contains a pattern resembling a "
            "credential, token, or private key."
        ),
        recommendation=(
            "Immediately revoke exposed credentials, rotate secrets, "
            "remove them from logs/prompts, and use a dedicated secret "
            "manager."
        ),
        patterns=(
            r"AKIA[0-9A-Z]{16}",
            r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
            r"(?i)secret[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
            r"(?i)password\s*[:=]\s*\S+",
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        ),
    ),

    Rule(
        rule_id="RAG001",
        category="rag-poisoning",
        severity="HIGH",
        title="Potential RAG instruction poisoning",
        description=(
            "Retrieved content appears to contain instructions aimed "
            "at manipulating downstream LLM behavior."
        ),
        recommendation=(
            "Treat retrieved documents as untrusted data. Isolate "
            "instructions from retrieved content, validate provenance, "
            "scan documents before indexing, and constrain model actions."
        ),
        patterns=(
            r"(?i)ignore\s+(the\s+)?user",
            r"(?i)ignore\s+(all\s+)?instructions",
            r"(?i)system\s+instruction\s*:",
            r"(?i)assistant\s+must\s+now",
            r"(?i)do\s+not\s+tell\s+the\s+user",
            r"(?i)hidden\s+instruction",
        ),
    ),

    Rule(
        rule_id="TOOL001",
        category="tool-security",
        severity="CRITICAL",
        title="Potential unauthorized tool action",
        description=(
            "The content appears to instruct an AI agent to perform "
            "a sensitive external action."
        ),
        recommendation=(
            "Require explicit authorization and policy checks before "
            "executing external side effects. Use least privilege and "
            "human approval for high-impact actions."
        ),
        patterns=(
            r"(?i)send\s+an?\s+email",
            r"(?i)delete\s+(the\s+)?file",
            r"(?i)execute\s+(the\s+)?command",
            r"(?i)transfer\s+(the\s+)?money",
            r"(?i)upload\s+(the\s+)?data",
            r"(?i)make\s+(the\s+)?purchase",
        ),
    ),
)


def _extract_evidence(text: str, pattern: str) -> str:
    """
    Return a short piece of matching evidence.

    Evidence is truncated so reports don't unnecessarily expose
    large amounts of user content.
    """

    match = re.search(pattern, text, flags=re.IGNORECASE)

    if not match:
        return ""

    start = max(0, match.start() - 60)
    end = min(len(text), match.end() + 60)

    evidence = text[start:end].replace("\n", " ")

    return evidence[:200]


def scan_text(text: str) -> list[Finding]:
    """
    Scan text against all Sentinel security rules.

    The scanner is intentionally non-executing:
    it only analyzes text.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if not text.strip():
        return []

    findings: list[Finding] = []

    for rule in RULES:

        for pattern in rule.patterns:

            if re.search(pattern, text, flags=re.IGNORECASE):

                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=_extract_evidence(text, pattern),
                        recommendation=rule.recommendation,
                    )
                )

                break

    return findings


def scan_many(texts: Iterable[str]) -> list[Finding]:
    """
    Scan multiple text inputs and combine findings.
    """

    findings: list[Finding] = []

    for text in texts:
        findings.extend(scan_text(text))

    return findings


def risk_score(findings: list[Finding]) -> int:
    """
    Calculate a simple deterministic risk score.

    Critical = 10
    High     = 7
    Medium   = 4
    Low      = 1
    """

    weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }

    score = sum(
        weights.get(finding.severity.upper(), 0)
        for finding in findings
    )

    return min(score, 100)


def risk_level(score: int) -> str:
    """
    Convert numeric score into a human-readable risk level.
    """

    if score >= 20:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "INFO"