"""AgentCore Platform v1.0"""

# Node contract: extend FunctionNode; execute(state) -> dict (changed keys only);
# AgentStatus enum. Ports GovernanceReportGenerate + OutputGate (S-3).
#
# S-3: the report never reproduces the full prompt — finding excerpts are already
# capped (≤80 in main); this node hard-caps any excerpt at 100 chars and the output
# gate blocks credential patterns. `_extra_security_gate_output` is the non-suppressible
# backstop (raises on any credential leak).

from __future__ import annotations

import json
import re

from framework.nodes.function_node import FunctionNode
from typing import Any, ClassVar
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus

from shared.utils.audit_logger import emit_trace_event

_CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"eyJ[a-zA-Z0-9._\-]{10,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
]
_S3_BLOCKED = "OUTPUT BLOCKED: Security gate prevented output. Contact administrator."

_DISCLAIMER = (
    "\n\n---\n> **DISCLAIMER:** This report is AI-generated. "
    "All findings and suggestions require human review before acting on them. "
    "This tool is advisory only and does not constitute a security audit."
)
_SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
_MAX_EXCERPT = 100  # S-3 hard cap in report
_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _safe_excerpt(text: str) -> str:
    return text if len(text) <= _MAX_EXCERPT else text[:_MAX_EXCERPT] + "...[truncated]"


def _render_findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "_No findings._\n"
    lines = [
        "| Severity | Check | Line | Excerpt | Recommendation |",
        "|----------|-------|------|---------|----------------|",
    ]
    for f in findings:
        sev = f.get("severity", "INFO")
        lines.append(
            f"| {_SEVERITY_ICONS.get(sev, '')} {sev} "
            f"| {f.get('check', '').replace('Check', '')} "
            f"| {f.get('line_no', '')} "
            f"| `{_safe_excerpt(f.get('excerpt', ''))}` "
            f"| {f.get('recommendation', '')} |"
        )
    return "\n".join(lines) + "\n"


def _render_suggestions(suggestions: list[dict[str, Any]]) -> str:
    if not suggestions:
        return "_No rewrite suggestions (no HIGH/CRITICAL findings)._\n"
    out = []
    for s in suggestions:
        out.append(
            f"**Line {s.get('line_no', '')}** ({s.get('severity', '')})\n"
            f"- Original: `{_safe_excerpt(s.get('original_excerpt', ''))}`\n"
            f"- Suggestion: {s.get('suggestion', '')}\n"
            f"- Reason: {s.get('reason', '')}\n"
        )
    return "\n".join(out)


def _build_report(state: dict[str, Any]) -> str:
    try:
        all_findings = json.loads(state.get("all_findings") or "[]")
    except (json.JSONDecodeError, TypeError):
        all_findings = []
    try:
        suggestions = json.loads(state.get("rewrite_suggestions") or "[]")
    except (json.JSONDecodeError, TypeError):
        suggestions = []

    severity_grade = state.get("severity_grade", "INFO")
    verdict = state.get("overall_verdict", "PASS")
    counts: dict[str, int] = {}
    for f in all_findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    counts_str = (
        ", ".join(
            f"{_SEVERITY_ICONS.get(s, '')} {s}: {n}"
            for s, n in sorted(counts.items(), key=lambda x: _ORDER.index(x[0]) if x[0] in _ORDER else 9)
        )
        or "None"
    )
    verdict_icon = "✅" if verdict == "PASS" else "❌"

    return (
        "# Governance Review Report\n\n"
        f"## Overall Verdict: {verdict_icon} {verdict}\n\n"
        f"**Highest Severity:** {_SEVERITY_ICONS.get(severity_grade, '')} {severity_grade}\n"
        f"**Total Findings:** {len(all_findings)} ({counts_str})\n\n"
        "---\n\n## Findings\n\n"
        f"{_render_findings_table(all_findings)}\n"
        "---\n\n## Rewrite Suggestions\n\n"
        f"{_render_suggestions(suggestions)}"
        f"{_DISCLAIMER}\n"
    )


class PostProcessNode(FunctionNode):
    """Assemble governance report + S-3 output gate (ports GovernanceReportGenerate + OutputGate)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
        report = _build_report(state)

        # S-3 output gate: credential scan (non-bypassable).
        for pat in _CREDENTIAL_PATTERNS:
            if pat.search(report):
                emit_trace_event("s3_credential_blocked", {}, state)
                blocked = _S3_BLOCKED
                # Do NOT return the tainted report — replace every output field.
                return {
                    "report": blocked,
                    "final_output": blocked,
                    "result": blocked,
                    "formatted_output": blocked,
                    "status": AgentStatus.SUCCESS.value,
                }

        emit_trace_event(
            "output_approved",
            {"severity_grade": state.get("severity_grade"), "verdict": state.get("overall_verdict")},
            state,
        )

        return {
            "report": report,
            "final_output": report,
            "result": report,
            "formatted_output": report,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 backstop: raise on any residual credential leak in the output.

        Contract (FunctionNode 1.0.0): receive the execute() result dict, RETURN it;
        MAY raise to block output (RuntimeError → converted to status:error by __call__).
        """
        for key, value in result.items():
            if not isinstance(value, str):
                continue
            for pat in _CREDENTIAL_PATTERNS:
                if pat.search(value):
                    raise RuntimeError(f"PostProcessNode S-3: credential pattern in result['{key}'] — blocking output")
        return result
