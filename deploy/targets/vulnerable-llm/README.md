# Vulnerable demo target

A tiny, deliberately weak LLM-style endpoint used by `make demo` and tests so Khandaq has a safe,
self-contained target. **Not a real model. Never expose it. Authorised self-testing only.**

- `POST /v1/chat/completions` — OpenAI-style; leaks a fake system prompt on obvious probes.
- `GET /health`

Run: `docker build -t khandaq-vulnerable-target . && docker run -p 8900:8900 khandaq-vulnerable-target`
