# Khandaq — top-level developer entry points. Sub-builds live in core/ api/ adapters/ web/.
# Targets delegate to each part; parts land during R1 (see docs/roadmap/sprints.md), so some
# targets are placeholders until their directory exists.

.PHONY: help lint test demo dev-infra core api web adapters fmt

help:
	@echo "Khandaq make targets:"
	@echo "  make lint       - lint everything (cargo clippy/fmt, ruff, manifest validate, pnpm lint)"
	@echo "  make test       - test everything (cargo, pytest, adapter contract-tests, vitest)"
	@echo "  make demo       - run a suite against the bundled vulnerable target and show the report"
	@echo "  make dev-infra  - start Postgres + object store for local development"
	@echo "  make fmt        - format Rust and Python"

lint:
	@[ -d core ] && (cd core && cargo fmt --check && cargo clippy --all-targets -- -D warnings) || echo "core/ not present yet"
	@[ -d api ] && (cd api && uv run ruff check . && uv run ruff format --check . && uv run mypy) || echo "api/ not present yet"
	@[ -d adapters ] && python3 adapters/_tooling/validate_manifests.py || echo "adapters/ not present yet"
	@[ -d web ] && (cd web && pnpm lint) || echo "web/ not present yet"

test:
	@[ -d core ] && (cd core && cargo test) || echo "core/ not present yet"
	@[ -d api ] && (cd api && uv run pytest -q) || echo "api/ not present yet"
	@[ -d web ] && (cd web && pnpm test -- --run) || echo "web/ not present yet"

fmt:
	@[ -d core ] && (cd core && cargo fmt) || true
	@[ -d api ] && (cd api && uv run ruff format .) || true

demo:
	@echo "Runs a suite against the bundled intentionally-vulnerable local target (never a third party)."
	@echo "Available from R1 (spec 005-007). See deploy/README.md."

dev-infra:
	cd deploy && docker compose up -d postgres rustfs
