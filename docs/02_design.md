# CMN-C1-074 — Design Document

## Metadata
| Field | Value |
|-------|-------|
| Template ID | CMN-C1-074 |
| Agent Name | PromptGovernanceReviewAgent |
| **L1 Base** | AgentBaseGraph (L1 direct extension — new-gen scaffold, no L2 inheritance) |
| base_type (semantic) | ChatAgent |
| Category | Cat 1 (CMN — cross-industry generic component) |
| Trust level | INTERNAL |

---

## Overview

Reviews AI system prompts / agent instructions for security and compliance issues across
five governance dimensions (injection, PII leakage, METI AI Guidelines, FSA model risk,
hallucination-inducing patterns) and produces a severity-graded governance report with
line-level findings + rewrite suggestions. **Advisory only — human review required.**

This is a **Cat 1** generic component: the governance checks are config-toggleable and the
pattern library is cross-industry (no domain assumption in code).

---

## Architecture — AgentBaseGraph 5-node backbone

This template inherits **directly from `framework.graph.agent_base_graph.AgentBaseGraph`**
(L1 direct extension, per the 2026-05-18 layer-model policy — no L2 base class). The fixed
backbone is `initialize → pre_process → main → post_process → finalize`.

```
InitializeNode      (framework default)
    ↓
PreProcessNode      ← domain slot 1 : S-2 PII mask + S-1 sanitise/credential-redact/frame + tokenize
    ↓
MainNode            ← domain slot 2 : composite — 5-check scan → aggregate → severity grade → rewrite suggest
    ↓
PostProcessNode     ← domain slot 3 : governance report build + S-3 output gate
    ↓
FinalizeNode        (framework default)
```

The legacy 8-node free-form graph is consolidated into the 3 domain slots — no business
logic was dropped:

| Legacy node | New-gen home |
|-------------|--------------|
| PromptIngestNode | `PreProcessNode` — S-2 PII mask + S-1 framing |
| PromptTokenizeNode | `PreProcessNode` — line-numbered segments |
| PromptGovernanceScannerNode | `MainNode` — 5 governance checks (toggle-aware) |
| FindingsAggregateNode | `MainNode` — dedupe + severity sort |
| SeverityGradeNode | `MainNode` — highest severity + PASS/FAIL verdict |
| RewriteSuggestNode | `MainNode` — rewrite suggestions for HIGH/CRITICAL |
| GovernanceReportGenerateNode | `PostProcessNode` — report markdown |
| OutputGateNode | `PostProcessNode` — S-3 credential gate |

---

## State Schema (`src/schemas/state.py`)

```python
class State(AgentState):
    # inherited: user_input, validated_input, result, formatted_output,
    #   error_log, status, correlation_id, session_id, ...
    raw_input: Optional[str]             # S-2 PII-masked raw prompt
    sanitized_input: Optional[str]       # S-1 sanitised + analysis-framed
    line_segments: Optional[str]        # JSON list of {line_no, text}
    pii_masked_types: Optional[str]
    injection_findings: Optional[str]    # JSON (per check)
    pii_findings: Optional[str]
    meti_findings: Optional[str]
    fsa_risk_findings: Optional[str]
    hallucination_findings: Optional[str]
    all_findings: Optional[str]          # JSON merged + deduped + sorted
    severity_grade: Optional[str]
    overall_verdict: Optional[str]       # PASS | FAIL
    rewrite_suggestions: Optional[str]   # JSON
    report: Optional[str]
    final_output: Optional[str]
```

`State` extends the framework `AgentState` flat TypedDict — primitives + JSON-serialised
strings (msgpack-safe, no Pydantic, no credentials, no `InvocationContext`). The system
prompt under review arrives in `AgentState.user_input`.

---

## Node Responsibilities

| Slot | Port logic | Output fields |
|------|-----------|---------------|
| **PreProcessNode** | S-2 PII mask (email/phone/My Number/card/passport/MRN); S-1 HTML strip + credential redact + analysis framing; tokenize into line segments. Empty → `status=ERROR` | `raw_input`, `sanitized_input`, `pii_masked_types`, `line_segments` |
| **MainNode** | Run the 5 governance checks (toggle-aware via injected config); dedupe + sort findings; compute highest severity + PASS/FAIL (fail_threshold=HIGH); generate rewrite suggestions for HIGH/CRITICAL | 5 per-check finding fields + `all_findings`, `severity_grade`, `overall_verdict`, `rewrite_suggestions` |
| **PostProcessNode** | Assemble the governance report (capped excerpts, disclaimer); S-3 output gate (credential scan → BLOCKED) | `report`, `final_output`, `result`, `formatted_output` |

Scanning is **deterministic** (inline pattern baseline); governance-check toggles come from
`config/agent.yaml → agent.config.governance_checks`.

---

## Security Controls (5-layer, re-homed for new-gen)

| Layer | Implementation |
|-------|---------------|
| S-1 | `PreProcessNode.required_trust_level = TrustLevel.INTERNAL` (legacy VERIFIED_INTERNAL → canonical INTERNAL); input wrapped in analysis framing — never executed |
| S-2 | PII detection + masking in `PreProcessNode` before any processing |
| S-3 | Excerpts capped (≤80 in main, ≤100 in report); `PostProcessNode` output gate blocks credential patterns; `_extra_security_gate_output` non-suppressible backstop raises on residual credential leak |
| S-4 | `emit_trace_event` (defensive import) at node boundaries; PII content never logged (labels only) |
| S-5 | Framework `__init_subclass__` JWT/secret pattern detection at import — automatic |

---

## Downstream Integration

- **Self-review:** run the agent on its own system prompt before deployment
- Any Cat 2/3 template's governance gate

---

## L1 Base Note

Inherits directly from `AgentBaseGraph` (L1) per the 2026-05-18 layer-model policy.
No L2 intermediate class is used; `base_type: ChatAgent` in `config/agent.yaml` is a
**semantic** label (it documents the pattern, not a code superclass).


---

## Supported entry point — HTTP/gateway only (Marketplace out of scope)

Every node in this template declares `required_trust_level = INTERNAL`, which is the design
decision recorded for this agent: the data it reads is not material an arbitrary authenticated
caller should be able to query.

The one-shot Marketplace runner stamps the caller at `VERIFIED_EXTERNAL` and exposes no
configuration surface or elevation path to `INTERNAL`, so the S-1 gate refuses every Marketplace
invocation **before** `execute()` runs. Two consequences are worth stating, because both read as
a broken image: the Pod still reports success and the audit counters do not move, and the terminal
failure carries no reason, so the chat surface shows an opaque error.

Nesting does not change this. A subgraph is invoked with the caller's own context
(`subgraph.invoke(..., ctx=ctx)`), so the trust level propagates unchanged and an inner node
cannot be reached at a higher level than the outer call arrived with.

### The HTTP path is also closed, deliberately

The standalone adapter used to promote an anonymous caller straight to `INTERNAL` once it
presented the shared `INVOKE_AUTH_TOKEN`. That token authenticates a *deployment*, not a person,
so granting `INTERNAL` on it placed a back door behind the very gate this design depends on. The
adapter now grants `VERIFIED_EXTERNAL`, which is what its own documentation always described.
**The gate is unchanged** — every node still requires `INTERNAL`.

The consequence is stated rather than hidden: since the nodes require `INTERNAL` and nothing in
either entry point can now supply it, **this template currently has no reachable entry point at
all**. That is fail-closed and intended.

One legitimate route remains open: trust established by upstream middleware is passed through
unchanged, so a gateway that has verified the caller's identity can still reach these nodes.

### What is NOT being done

- The nodes' `required_trust_level` is **not** lowered. Doing so would widen who may query this
  data, which is a product decision and not an engineering one.
- No Marketplace image is published and the template is not registered as a Marketplace agent.
