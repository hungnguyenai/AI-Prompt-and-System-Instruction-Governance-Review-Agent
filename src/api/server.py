"""AgentCore Platform v1.0"""

# Standalone HTTP entry point. Adapter only — no business logic.
# Platform routing calls agent.invoke() directly.

import os
import secrets

from typing import Any, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from src.graph.graph import PromptGovernanceReviewAgent

app = FastAPI(title="CMN-C1-074 AI Prompt & System Instruction Governance Review Agent")

agent = PromptGovernanceReviewAgent()
agent.compile()


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""


@app.post("/invoke", response_model=None)
async def invoke(req: InvokeRequest, request: Request) -> dict[str, Any]:
    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Standalone caller auth: when
    # INVOKE_AUTH_TOKEN is set on the server environment, callers that no upstream
    # middleware vouched for (still ANONYMOUS) must present it as a Bearer token
    # and run at INTERNAL. Middleware-established trust is never demoted.
    # This adapter is the entry-point auth boundary (standalone equivalent of
    # platform AuthMiddleware) — a deployment-level caller credential, not an
    # agent secret, so ctx.secrets does not apply (no InvocationContext exists
    # before auth). This is the documented entry-point exception.
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        # VERIFIED_EXTERNAL, never INTERNAL: this token authenticates a deployment,
        # not a person. Handing out INTERNAL here would let anyone holding one shared
        # server secret read records the S-1 gate reserves for named internal staff.
        # Consequence, stated deliberately: the nodes require INTERNAL, so this path
        # now reaches no node either. That is fail-closed and intended -- see
        # docs/02_design.md. Do NOT 'fix' it by lowering the nodes' required level.
        trust = TrustLevel.VERIFIED_EXTERNAL
    ctx = InvocationContext(
        session_id=req.session_id or str(uuid4()),
        caller_trust_level=trust,
        caller_id=getattr(request.state, "caller_id", ""),
    )
    return cast(dict[str, Any], agent.invoke(req.input, ctx=ctx))


@app.get("/health", response_model=None)
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "cmn_c1_074"}
