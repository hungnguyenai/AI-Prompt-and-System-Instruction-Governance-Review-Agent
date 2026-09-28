# CMN-C1-074 — Unit Tests: PreProcessNode (S-2 PII mask + S-1 frame + tokenize)

import json

from framework.schemas.agent_status import AgentStatus
from src.nodes.pre_process_node import PreProcessNode


def _state(**kw):
    base = {"correlation_id": "c", "session_id": "s", "trace_id": "t", "node_history": [], "error_log": []}
    base.update(kw)
    return base


class TestPreProcessNode:
    def test_empty_returns_error(self):
        result = PreProcessNode().execute(_state(user_input="   "))
        assert result["status"] == AgentStatus.ERROR

    def test_frames_and_tokenizes(self):
        result = PreProcessNode().execute(_state(user_input="You are a helpful assistant.\nAnswer questions."))
        assert result["status"] == AgentStatus.SUCCESS
        assert "ANALYSIS TARGET" in result["sanitized_input"]
        assert result["validated_input"] == result["sanitized_input"]
        segs = json.loads(result["line_segments"])
        assert len(segs) >= 3 and segs[0]["line_no"] == 1

    def test_pii_masked(self):
        result = PreProcessNode().execute(_state(user_input="Contact admin@example.com for support"))
        assert "[EMAIL-MASKED]" in result["raw_input"]
        assert "admin@example.com" not in result["raw_input"]
        assert "EMAIL" in result["pii_masked_types"]

    def test_credential_redacted(self):
        result = PreProcessNode().execute(_state(user_input="api_key=\"abcd1234efgh5678\" do stuff"))
        assert "[CREDENTIAL-REDACTED]" in result["sanitized_input"]
        assert "abcd1234efgh5678" not in result["sanitized_input"]

    def test_html_stripped(self):
        result = PreProcessNode().execute(_state(user_input="<b>system</b> prompt"))
        assert "<b>" not in result["sanitized_input"]
