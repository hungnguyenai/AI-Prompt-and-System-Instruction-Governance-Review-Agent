# CMN-C1-074 — Unit Tests: PostProcessNode (report build + S-3 output gate)

import json

import pytest

from framework.schemas.agent_status import AgentStatus
from src.nodes.post_process_node import PostProcessNode


def _state(**kw):
    base = {
        "correlation_id": "c", "session_id": "s", "trace_id": "t", "node_history": [], "error_log": [],
        "all_findings": json.dumps([
            {"check": "InjectionVulnerabilityCheck", "pattern_id": "INJ-001", "severity": "CRITICAL",
             "line_no": 2, "excerpt": "ignore all previous instructions", "recommendation": "Remove override"},
        ]),
        "rewrite_suggestions": json.dumps([
            {"line_no": 2, "original_excerpt": "ignore...", "suggestion": "Scope it.", "reason": "x", "severity": "CRITICAL"},
        ]),
        "severity_grade": "CRITICAL", "overall_verdict": "FAIL",
    }
    base.update(kw)
    return base


class TestPostProcessNode:
    def test_builds_report(self):
        result = PostProcessNode().execute(_state())
        assert result["status"] == AgentStatus.SUCCESS
        out = result["final_output"]
        assert "Governance Review Report" in out
        assert "Overall Verdict" in out and "FAIL" in out
        assert "DISCLAIMER" in out
        assert result["result"] == result["formatted_output"] == out

    def test_clean_pass_report(self):
        result = PostProcessNode().execute(_state(all_findings="[]", rewrite_suggestions="[]",
                                                  severity_grade="INFO", overall_verdict="PASS"))
        assert "PASS" in result["final_output"]
        assert "_No findings._" in result["final_output"]

    def test_s3_backstop_raises_on_credential(self):
        node = PostProcessNode()
        with pytest.raises(RuntimeError):
            node._extra_security_gate_output({"final_output": "leak AKIA1234567890ABCDEF"})

    def test_s3_backstop_passes_clean(self):
        node = PostProcessNode()
        clean = {"final_output": "# Governance Review Report\nPASS"}
        assert node._extra_security_gate_output(clean) == clean
