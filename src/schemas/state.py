"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict extending AgentState — never Pydantic.
# All fields are msgpack-safe primitives / JSON-serialised strings. No credentials,
# no dataclasses, no InvocationContext.

from typing import Optional

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """State for CMN-C1-074 AI Prompt & System Instruction Governance Review Agent.

    Inherited from AgentState (do not re-declare): user_input, validated_input,
    status, session_id, node_history, error_log, trace_id, correlation_id,
    schema_version, response_metadata, trust_level, formatted_output, result.

    The system prompt under review arrives in AgentState.user_input.
    """

    # Pre-process (PromptIngest + PromptTokenize)
    raw_input: Optional[str]  # S-2 PII-masked raw prompt
    sanitized_input: Optional[str]  # S-1 sanitised + analysis-framed
    line_segments: Optional[str]  # JSON list of {line_no, text}
    pii_masked_types: Optional[str]  # comma-separated PII labels masked (or "")

    # Main (5-check scan → aggregate → grade → rewrite suggest)
    injection_findings: Optional[str]  # JSON list
    pii_findings: Optional[str]
    meti_findings: Optional[str]
    fsa_risk_findings: Optional[str]
    hallucination_findings: Optional[str]
    all_findings: Optional[str]  # JSON merged + deduped + sorted
    severity_grade: Optional[str]  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    overall_verdict: Optional[str]  # PASS | FAIL
    rewrite_suggestions: Optional[str]  # JSON list

    # Post-process (GovernanceReportGenerate + OutputGate)
    report: Optional[str]
    final_output: Optional[str]
