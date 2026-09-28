"""AgentCore Platform v1.0"""

# Node contract: extend FunctionNode; execute(state) -> dict (changed keys only);
# AgentStatus enum. Composite main slot running the four middle steps of the original
# pipeline: PromptGovernanceScanner (5 checks) → FindingsAggregate → SeverityGrade →
# RewriteSuggest.
#
# Governance-check toggles are read from the injected graph config (default all-enabled).
# Injection patterns are the inline baseline (the CI-safe set; production may extend).

from __future__ import annotations

import json
import re

from framework.nodes.function_node import FunctionNode
from typing import Any, ClassVar
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus

from shared.utils.audit_logger import emit_trace_event

_MAX_EXCERPT_LEN = 80  # S-3: never reproduce full malicious content
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_DEFAULT_FAIL_THRESHOLD = "HIGH"

# ── Injection patterns (inline baseline) ───────────────────────────────────
_INJECTION_PATTERNS = [
    (
        "INJ-001",
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
        "CRITICAL",
        "Ignore-previous-instructions injection pattern",
    ),
    (
        "INJ-002",
        re.compile(r"disregard\s+(all\s+)?previous", re.I),
        "CRITICAL",
        "Disregard previous instructions variant",
    ),
    ("INJ-003", re.compile(r"you\s+are\s+now\s+a", re.I), "HIGH", "Persona override injection"),
    (
        "INJ-004",
        re.compile(r"act\s+as\s+(?:a\s+)?(?:different|new|unrestricted|jailbroken)", re.I),
        "HIGH",
        "Role-play override injection",
    ),
    ("INJ-005", re.compile(r"DAN\s*(mode|prompt|jailbreak)?", re.I), "CRITICAL", "DAN (Do Anything Now) jailbreak"),
    (
        "INJ-006",
        re.compile(
            r"pretend\s+(you\s+)?(?:are|have no|don.t have)\s+(a\s+)?(?:restrictions?|limits?|guidelines?)", re.I
        ),
        "HIGH",
        "Restriction bypass via pretend framing",
    ),
    ("INJ-007", re.compile(r"<\s*/?\s*(?:system|user|assistant)\s*>", re.I), "HIGH", "Fake role tag injection"),
    (
        "INJ-008",
        re.compile(r"###\s*(?:instruction|system|prompt|override)", re.I),
        "HIGH",
        "Markdown heading override injection",
    ),
]
_PII_PATTERNS = [
    (
        "PII-001",
        re.compile(r"(?i)send\s+(the\s+)?(?:user.?s?|customer|their)\s+(?:name|email|address|phone|data|info)"),
        "HIGH",
        "Instruction to exfiltrate user PII",
    ),
    (
        "PII-002",
        re.compile(r"(?i)include\s+(?:the\s+)?(?:personal|private|confidential)\s+(?:data|information|details)"),
        "HIGH",
        "Instruction to include personal data in output",
    ),
    (
        "PII-003",
        re.compile(r"(?i)(?:log|store|save|record)\s+(?:user\s+)?(?:passwords?|credentials?|tokens?)"),
        "CRITICAL",
        "Instruction to log/store credentials",
    ),
    (
        "PII-004",
        re.compile(r"(?i)(?:マイナンバー|個人番号|住所|氏名).{0,20}(?:送|出力|含)"),
        "HIGH",
        "Japanese PII exfiltration pattern",
    ),
]
_METI_PATTERNS = [
    (
        "METI-001",
        re.compile(r"(?i)never\s+(?:refuse|reject|deny)\s+(?:a\s+)?(?:user|request)"),
        "HIGH",
        "Disables refusal capability — violates METI AI Guidelines safety principle",
    ),
    (
        "METI-002",
        re.compile(r"(?i)always\s+(?:comply|agree|say\s+yes)"),
        "HIGH",
        "Unconditional compliance instruction — violates METI accountability principle",
    ),
    (
        "METI-003",
        re.compile(
            r"(?i)do\s+not\s+(?:mention|disclose|reveal)\s+(?:that\s+)?(?:you\s+are\s+an?\s+)?(?:AI|assistant|bot|language model)"
        ),
        "HIGH",
        "Transparency violation — METI requires AI identity disclosure",
    ),
]
_FSA_PATTERNS = [
    (
        "FSA-001",
        re.compile(r"(?i)guarantee\s+(?:accuracy|correctness|profit|return)"),
        "HIGH",
        "Guarantee of accuracy/return — violates FSA AI Model Risk Guidelines",
    ),
    (
        "FSA-002",
        re.compile(r"(?i)(?:financial|investment|trading)\s+advice"),
        "MEDIUM",
        "Financial advice framing — requires FSA disclaimer",
    ),
    (
        "FSA-003",
        re.compile(r"(?i)(?:always|never)\s+(?:approve|reject|accept)\s+(?:loans?|applications?|claims?)"),
        "HIGH",
        "Hardcoded loan/claim decision — model risk violation",
    ),
]
_HALLUCINATION_PATTERNS = [
    (
        "HAL-001",
        re.compile(
            r"(?i)(?:always|must)\s+(?:provide|give|include)\s+(?:a\s+)?(?:specific|exact|precise)\s+(?:number|figure|statistic|date)"
        ),
        "HIGH",
        "Forces fabrication of specific figures — hallucination risk",
    ),
    (
        "HAL-002",
        re.compile(r"(?i)if\s+you\s+don.t\s+know.*(?:make|create|invent|fabricate)"),
        "CRITICAL",
        "Explicit instruction to fabricate when uncertain",
    ),
    (
        "HAL-003",
        re.compile(r"(?i)(?:never|do not)\s+(?:say|mention|use|write)\s+.?i don.?t know.?"),
        "HIGH",
        "Suppresses uncertainty expression — hallucination risk",
    ),
    (
        "HAL-004",
        re.compile(r"(?i)(?:always|must)\s+(?:sound|appear|seem)\s+(?:confident|certain|sure)"),
        "MEDIUM",
        "Forces false confidence — hallucination-inducing pattern",
    ),
    (
        "HAL-005",
        re.compile(r"(?i)(?:make up|invent|fabricate|create)\s+(?:examples?|data|facts?|statistics?)"),
        "CRITICAL",
        "Explicit fabrication instruction",
    ),
]

_CHECKS = [
    ("injection_check", _INJECTION_PATTERNS, "InjectionVulnerabilityCheck"),
    ("pii_leakage_check", _PII_PATTERNS, "PIILeakageCheck"),
    ("meti_ai_guidelines_check", _METI_PATTERNS, "METIAIGuidelinesCheck"),
    ("fsa_model_risk_check", _FSA_PATTERNS, "FSAModelRiskCheck"),
    ("hallucination_pattern_check", _HALLUCINATION_PATTERNS, "HallucinationPatternCheck"),
]

_REWRITE_TEMPLATES = {
    "InjectionVulnerabilityCheck": "Remove the instruction override pattern. Replace with an explicit scope statement: 'This agent responds only to [describe valid use case].'",
    "PIILeakageCheck": "Remove the PII handling instruction. If user data processing is required, reference a privacy policy or data handling procedure instead of embedding instructions.",
    "METIAIGuidelinesCheck": "Add an AI identity disclosure statement and ensure refusal capability is preserved. Example: 'This is an AI assistant. It may decline requests that conflict with its guidelines.'",
    "FSAModelRiskCheck": "Add a required disclaimer: 'This agent provides informational assistance only and does not constitute financial advice. All outputs require human review before use.'",
    "HallucinationPatternCheck": "Replace certainty-forcing instructions with uncertainty-acknowledging language. Example: 'Provide your best answer and clearly state any uncertainty or limitations.'",
}
_AI_DISCLAIMER = "(AI-generated suggestion — human review required before use)"
_MAX_REWRITE_EXCERPT = 80


def _safe_excerpt(text: str) -> str:
    return text if len(text) <= _MAX_EXCERPT_LEN else text[:_MAX_EXCERPT_LEN] + "…[truncated]"


def _run_check(
    segments: list[dict[str, Any]], patterns: list[tuple[str, re.Pattern[str], str, str]], check_name: str
) -> list[dict[str, Any]]:
    findings = []
    for seg in segments:
        line_no = seg.get("line_no", 0)
        text = seg.get("text", "")
        for pat_id, regex, severity, recommendation in patterns:
            if regex.search(text):
                findings.append(
                    {
                        "check": check_name,
                        "pattern_id": pat_id,
                        "severity": severity,
                        "line_no": line_no,
                        "excerpt": _safe_excerpt(text.strip()),
                        "recommendation": recommendation,
                    }
                )
    return findings


class MainNode(FunctionNode):
    """Composite main: 5-check governance scan → aggregate → grade → rewrite suggest."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._checks = (config or {}).get("governance_checks", {})

    def _enabled(self, key: str) -> bool:
        return bool(self._checks.get(key, True))  # safe-on: default enabled

    def execute(self, state: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            segments = json.loads(state.get("line_segments") or "[]")
        except (json.JSONDecodeError, TypeError):
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", []) + ["MainNode: line_segments parse error"],
            }

        # ── Scan (per-check, toggle-aware) ────────────────────────────────────
        per_check: dict[str, list[dict[str, Any]]] = {}
        for key, patterns, name in _CHECKS:
            per_check[name] = _run_check(segments, patterns, name) if self._enabled(key) else []

        # ── Aggregate (dedupe by check, line_no, pattern_id; sort by severity) ─
        all_findings: list[dict[str, Any]] = []
        seen = set()
        for findings in per_check.values():
            for f in findings:
                k = (f.get("check"), f.get("line_no"), f.get("pattern_id"))
                if k not in seen:
                    seen.add(k)
                    all_findings.append(f)
        all_findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.get("severity", "INFO"), 4), f.get("line_no", 0)))

        # ── Severity grade + verdict ──────────────────────────────────────────
        if all_findings:
            highest = min((f.get("severity", "INFO") for f in all_findings), key=lambda s: _SEVERITY_ORDER.get(s, 4))
            threshold_rank = _SEVERITY_ORDER.get(_DEFAULT_FAIL_THRESHOLD, 1)
            verdict = "FAIL" if _SEVERITY_ORDER.get(highest, 4) <= threshold_rank else "PASS"
        else:
            highest, verdict = "INFO", "PASS"

        # ── Rewrite suggestions (HIGH/CRITICAL, one per line) ─────────────────
        suggestions = []
        seen_lines = set()
        for f in all_findings:
            if f.get("severity") not in ("CRITICAL", "HIGH"):
                continue
            line_no = f.get("line_no", 0)
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            template = _REWRITE_TEMPLATES.get(
                f.get("check", ""), "Review and rewrite this line to remove the identified risk."
            )
            suggestions.append(
                {
                    "line_no": line_no,
                    "original_excerpt": f.get("excerpt", "")[:_MAX_REWRITE_EXCERPT],
                    "suggestion": f"{template} {_AI_DISCLAIMER}",
                    "reason": f.get("recommendation", ""),
                    "severity": f.get("severity"),
                }
            )

        emit_trace_event(
            "scan_complete",
            {"findings_count": len(all_findings), "severity_grade": highest, "verdict": verdict},
            state,
        )

        return {
            "injection_findings": json.dumps(per_check["InjectionVulnerabilityCheck"], ensure_ascii=False),
            "pii_findings": json.dumps(per_check["PIILeakageCheck"], ensure_ascii=False),
            "meti_findings": json.dumps(per_check["METIAIGuidelinesCheck"], ensure_ascii=False),
            "fsa_risk_findings": json.dumps(per_check["FSAModelRiskCheck"], ensure_ascii=False),
            "hallucination_findings": json.dumps(per_check["HallucinationPatternCheck"], ensure_ascii=False),
            "all_findings": json.dumps(all_findings, ensure_ascii=False),
            "severity_grade": highest,
            "overall_verdict": verdict,
            "rewrite_suggestions": json.dumps(suggestions, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
