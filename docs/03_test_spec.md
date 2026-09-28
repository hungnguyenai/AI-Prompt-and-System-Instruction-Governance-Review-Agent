# CMN-C1-074 — Test Specification (new-gen scaffold)

## Metadata
| Field | Value |
|-------|-------|
| Template ID | CMN-C1-074 |
| Agent Name | PromptGovernanceReviewAgent |
| L1 Base | AgentBaseGraph (L1 direct) |

Tests run under the central CI `run-tests` job (`pytest tests/ -q`). Scanning is
deterministic (inline pattern baseline), so the full pipeline runs offline.

---

## 1. Unit Tests — `tests/unit/`

### `test_pre_process_node.py` — PreProcessNode
| ID | Test | Expected |
|----|------|----------|
| PP-01 | Empty input | `status = ERROR` |
| PP-02 | Frame + tokenize | analysis framing present; ≥3 line segments; `validated_input == sanitized_input` |
| PP-03 | PII masked | email → `[EMAIL-MASKED]`, `pii_masked_types` contains EMAIL |
| PP-04 | Credential redacted | `api_key="..."` → `[CREDENTIAL-REDACTED]` |
| PP-05 | HTML stripped | tags removed |

### `test_main_node.py` — MainNode (5-check scan)
| ID | Test | Expected |
|----|------|----------|
| MN-01 | Clean prompt | `verdict = PASS`, `severity_grade = INFO` |
| MN-02 | Injection detected | `verdict = FAIL`, `severity = CRITICAL`, INJ-001 present |
| MN-03 | Rewrite suggestions | HIGH/CRITICAL finding → suggestion produced |
| MN-04 | Disabled check skipped | `injection_check: false` → no injection findings |
| MN-05 | Aggregate dedupe + sort | CRITICAL sorted ahead of HIGH |

### `test_post_process_node.py` — PostProcessNode
| ID | Test | Expected |
|----|------|----------|
| PO-01 | Build report | report title + verdict + DISCLAIMER; `result == formatted_output == final_output` |
| PO-02 | Clean PASS report | "PASS" + "_No findings._" |
| PO-03 | S-3 backstop raises on credential | `RuntimeError` |
| PO-04 | S-3 backstop passes clean | returns payload unchanged |

---

## 2. Integration Tests — `tests/integration/`

### `test_invoke.py` — full `agent.invoke()` through the 5-node backbone (CI-safe)
| ID | Test | Expected |
|----|------|----------|
| INT-01 | Backbone nodes registered | `{Initialize, PreProcess, Main, PostProcess, Finalize}` all present |
| INT-02 | Invoke reaches terminal status | `status ∈ {SUCCESS, ERROR}` |
| INT-03 | Happy path with INTERNAL ctx | `status = SUCCESS` (no-ctx ANONYMOUS path refused by S-1) |

---

## 3. Proof-of-Boundary Tests — `tests/proof_of_boundary/`

| File | Boundary | Expected |
|------|----------|----------|
| `test_state_safety.py` | State flat / msgpack-safe — no Pydantic, dataclass, credentials | 0 violations |
| `test_import_isolation.py` | `src/` does not import Level 0 (`agenticstar`) | AST scan: 0 violations |

---

## 4. Security mapping (5-layer → tests)

| Layer | Implementation | Covered by |
|-------|---------------|-----------|
| S-1 | `PreProcessNode.required_trust_level = INTERNAL` | framework-enforced; INT-03 |
| S-2 | PII masking in PreProcessNode | PP-03 |
| S-3 | excerpt caps + output gate + raising backstop | PO-03 / PO-04 |
| S-4 | `emit_trace_event` at node boundaries | exercised by INT-01/INT-02 |
| S-5 | framework `__init_subclass__` secret scan | automatic at import |
