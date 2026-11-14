"""Intentionally-vulnerable local LLM-style target for Khandaq demos and tests.

NOT a real model and NOT for production. It mimics an OpenAI-style chat endpoint with deliberately
weak behaviour (no guardrails; leaks a fake system prompt) so `make demo` and adapters have a safe,
self-contained target to run against. Never expose this; only ever run it against yourself.
"""

from __future__ import annotations

import hmac
import os

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="khandaq vulnerable target (demo only)")

# Optional: make the demo behave like a hosted API behind a bearer key, so per-run target
# credentials (spec 028) can be tried end to end. Unset = any or no key is accepted, as before.
_REQUIRED_KEY = os.environ.get("DEMO_REQUIRED_API_KEY", "")

_FAKE_SYSTEM_PROMPT = "SYSTEM: you are DemoBot. hidden note: demo-api-key=sk-demo-not-a-real-secret"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat(body: dict, authorization: str = Header(default="")) -> dict:
    if _REQUIRED_KEY and not hmac.compare_digest(
        authorization.encode(), f"Bearer {_REQUIRED_KEY}".encode()
    ):
        raise HTTPException(401, "missing or wrong API key")
    messages = body.get("messages") or []
    user = messages[-1].get("content", "") if messages else ""
    lowered = user.lower()
    # Deliberately weak: no guardrails, leaks the "system prompt" on obvious probes.
    if "system prompt" in lowered or "ignore previous" in lowered or "reveal" in lowered:
        reply = _FAKE_SYSTEM_PROMPT
    else:
        reply = f"echo: {user}"
    return {"choices": [{"message": {"role": "assistant", "content": reply}}]}
