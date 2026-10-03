#!/usr/bin/env python3
"""Khandaq deployment smoke test (spec 019). Python 3.10+, standard library only.

Walks a deployment through the R1/R2 spine with an API token and prints one line per check:

    health → identity → worker alive (admin tokens) → engagement → scope lock (allowed and
    refused) → echo run → findings → ledger → report export + re-verify → evidence route →
    campaign create + pause → alerts → close → report still verifiable

It uses the built-in ``echo`` adapter only. That runs inside the API process and **never contacts
the target**: the target it registers is ``smoke.khandaq.invalid`` (a reserved name that cannot
resolve), and the rules of engagement are recorded as synthetic. The engagement it creates is
closed at the end, and its campaign is paused, so nothing keeps running.

Usage:
    KHANDAQ_TOKEN=khq_... python3 deploy/smoke.py --url https://khandaq-stg.example.org

Create the token in the console (API tokens page). The token is only ever sent over https (plain
http is allowed for localhost) and redirects are not followed. Exit code 0 means every check
passed, 1 that one failed, 2 a usage error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# UTC that also exists on Python 3.10 (datetime.UTC arrived in 3.11).
UTC = dt.timezone.utc  # noqa: UP017

TARGET_HOST = "smoke.khandaq.invalid"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
TARGET_MODEL = "smoke-model"
MIN_SCHEMA = "0011"


class SmokeFailure(Exception):
    """A check did not hold."""


class SmokeSkip(Exception):
    """A check that cannot run with this token; reported as skipped, never as passed."""


# (method, path, json body or None) -> (status, parsed body or raw bytes)
Transport = Callable[[str, str, Any], tuple[int, Any]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would carry the bearer token to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def http_transport(base_url: str, token: str, timeout: float = 30.0) -> Transport:
    """Real HTTP against ``base_url`` with ``Authorization: Bearer <token>``.

    The token is sent only over https (plain http is allowed for localhost), and redirects are
    answered, not followed, so it never reaches another host (PR #36 review)."""
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError(f"not an http(s) URL: {base_url!r}")
    if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
        raise ValueError("refusing to send the API token over plain http; use https://")
    opener = urllib.request.build_opener(_NoRedirect)

    def call(method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            base_url.rstrip("/") + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, _decode(resp.read(), resp.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as exc:
            return exc.code, _decode(exc.read(), exc.headers.get("Content-Type", ""))

    return call


def _decode(raw: bytes, content_type: str) -> Any:
    if "application/json" in content_type:
        return json.loads(raw or b"null")
    return raw


@dataclass
class Smoke:
    call: Transport
    out: Callable[[str], None] = print
    results: list[tuple[str, bool]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def expect(self, method: str, path: str, status: int, body: Any = None) -> Any:
        got, payload = self.call(method, path, body)
        if got != status:
            detail = payload.get("detail") if isinstance(payload, dict) else ""
            raise SmokeFailure(f"{method} {path}: expected {status}, got {got} {detail}".strip())
        return payload

    def check(self, name: str, fn: Callable[[], str | None]) -> Any:
        try:
            note = fn()
        except SmokeSkip as skip:
            self.skipped.append(name)
            self.out(f"– {name}: skipped ({skip})")
            return None
        except Exception as exc:  # a smoke test reports every failure, transport errors included
            self.results.append((name, False))
            self.out(f"✗ {name}: {type(exc).__name__}: {exc}")
            raise
        self.results.append((name, True))
        self.out(f"✓ {name}" + (f" — {note}" if note else ""))
        return note

    def run(self) -> bool:
        state: dict[str, Any] = {}
        stamp = dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        try:
            self._steps(state, stamp)
        except Exception:  # already reported by check(); now leave nothing runnable behind
            if "eng" in state:
                try:
                    self.call("POST", f"/api/engagements/{state['eng']}/close", None)
                except Exception as exc:  # report, but never hide the original failure
                    self.out(f"! cleanup failed: engagement {state['eng']} left open: {exc}")
            return False
        return True

    def _steps(self, s: dict[str, Any], stamp: str) -> None:
        def health() -> str:
            self.expect("GET", "/api/health", 200)
            version = self.expect("GET", "/api/version", 200)
            rev = str(version.get("schema_revision") or "")
            # Revisions are "NNNN_name"; anything else (None, "none") means the API cannot read it.
            assert rev[:4].isdigit() and rev[:4] >= MIN_SCHEMA, (
                f"schema revision {rev!r} is missing or older than {MIN_SCHEMA}"
            )
            return f"schema {rev}"

        self.check("API healthy and migrated", health)

        def identity() -> str:
            me = self.expect("GET", "/api/auth/me", 200)
            assert me["auth"] == "token", f"authenticated by {me['auth']!r}, not the token"
            return me["email"]

        self.check("token authenticates", identity)

        def worker_alive() -> str:
            got, status = self.call("GET", "/api/deployment", None)
            if got == 403:
                raise SmokeSkip("the token's user is not an organisation admin")
            if got != 200:
                raise SmokeFailure(f"GET /api/deployment: expected 200, got {got}")
            alive = [w for w in status["workers"] if w["alive"]]
            assert alive, "no worker has reported in the last 2 minutes: queued runs will wait"
            alerts = alive[0]["summary"]["alerts"]
            on = [name for name, enabled in alerts.items() if enabled] or ["none"]
            return f"{len(alive)} alive; worker alerts: {', '.join(on)}"

        self.check("a worker is alive (spec 023)", worker_alive)

        def engagement() -> str:
            eng = self.expect(
                "POST",
                "/api/engagements",
                201,
                {"name": f"khandaq-smoke {stamp}", "client": "smoke"},
            )
            s["eng"] = eng["id"]
            tgt = self.expect(
                "POST",
                f"/api/engagements/{s['eng']}/targets",
                201,
                {"type": "llm_endpoint", "spec": {"host": TARGET_HOST, "model": TARGET_MODEL}},
            )
            s["tgt"] = tgt["id"]
            self.expect(
                "PUT",
                f"/api/engagements/{s['eng']}/scope",
                200,
                {
                    "allow": {"llm_endpoint": [{"host": TARGET_HOST, "models": [TARGET_MODEL]}]},
                    "deny": [],
                    "roe": {},
                },
            )
            self.expect(
                "POST",
                f"/api/engagements/{s['eng']}/activate",
                200,
                {"authorisation_ref": "SMOKE (synthetic; echo adapter, no network)"},
            )
            return s["eng"]

        self.check("engagement created, scoped and activated", engagement)

        def scope_lock() -> str:
            ok = self.expect(
                "POST", f"/api/engagements/{s['eng']}/scope-check", 200, {"target_id": s["tgt"]}
            )
            assert ok["allowed"] is True, f"in-scope target refused: {ok['reason']}"
            run = self.expect(
                "POST",
                f"/api/engagements/{s['eng']}/runs",
                201,
                {"adapter": "echo", "target_id": s["tgt"], "params": {"model": "not-allowed"}},
            )
            assert run["state"] == "rejected", f"out-of-scope run was {run['state']}"
            return f"out-of-scope run rejected: {run['reject_reason']}"

        self.check("scope lock allows in scope and rejects out of scope", scope_lock)

        def echo_run() -> str:
            run = self.expect(
                "POST",
                f"/api/engagements/{s['eng']}/runs",
                201,
                {"adapter": "echo", "target_id": s["tgt"]},
            )
            assert run["state"] == "succeeded", f"echo run {run['state']}: {run['reject_reason']}"
            findings = self.expect("GET", f"/api/engagements/{s['eng']}/findings", 200)
            assert len(findings) == 2, f"expected 2 canonical findings, got {len(findings)}"
            s["evidence"] = findings[0]["evidence"][0]
            # Spec 020: the core table adds the frameworks the adapter does not name.
            frameworks = {m["framework"] for f in findings for m in f["mappings"]}
            assert "nist-ai-rmf" in frameworks, f"mapping table not applied: {sorted(frameworks)}"
            return "2 deduplicated findings, mapped by the core table"

        self.check("echo run succeeds with deduplicated findings", echo_run)

        def ledger() -> str:
            led = self.expect("GET", f"/api/engagements/{s['eng']}/ledger", 200)
            assert led["verify"]["ok"] is True, f"ledger broken: {led['verify']}"
            return f"{led['count']} entries, root {led['root'][:19]}…"

        self.check("evidence ledger verifies", ledger)

        def report() -> str:
            rep = self.expect("GET", f"/api/engagements/{s['eng']}/report", 200)
            s["pin"] = rep["evidence"]
            verdict = self.expect(
                "POST", f"/api/engagements/{s['eng']}/report/verify", 200, s["pin"]
            )
            assert verdict["ok"] is True and verdict["issued"] is True, f"verify: {verdict}"
            html = self.expect("GET", f"/api/engagements/{s['eng']}/report.html", 200)
            assert b"Khandaq engagement report" in html, "HTML report missing its heading"
            # Specs 020/021: the report names the mapping table each finding was mapped with.
            recorded = rep.get("mapping_tables", {}).get("recorded", [])
            assert recorded and recorded[0].get("versions"), "report names no mapping table"
            overlay = recorded[0].get("overlay")
            mapped = f"overlay {overlay['name']}" if overlay else "built-in mapping table"
            return f"pinned {s['pin']['count']} entries; re-verified, issued; {mapped}"

        self.check("report exports and re-verifies against its pin", report)

        def evidence_route() -> str:
            got, _ = self.call(
                "GET", f"/api/engagements/{s['eng']}/evidence/{s['evidence']}/content", None
            )
            assert got == 404, f"echo evidence (no stored bytes) should be 404, got {got}"
            return "route live (echo evidence has no stored bytes: 404)"

        self.check("evidence download route answers", evidence_route)

        def campaign() -> str:
            cmp = self.expect(
                "POST",
                f"/api/engagements/{s['eng']}/campaigns",
                201,
                {
                    "name": "smoke campaign",
                    "adapter": "echo",
                    "target_id": s["tgt"],
                    "interval_minutes": 1440,
                    "start_at": (dt.datetime.now(UTC) + dt.timedelta(days=1)).isoformat(),
                },
            )
            paused = self.expect(
                "PATCH",
                f"/api/engagements/{s['eng']}/campaigns/{cmp['id']}",
                200,
                {"enabled": False},
            )
            assert paused["enabled"] is False, "campaign did not pause"
            self.expect("GET", f"/api/engagements/{s['eng']}/campaigns/{cmp['id']}/diffs", 200)
            self.expect("GET", f"/api/engagements/{s['eng']}/alerts", 200)
            return f"{cmp['id']} created and paused"

        self.check("campaign created and paused; diffs and alerts readable", campaign)

        def close() -> str:
            eng = self.expect("POST", f"/api/engagements/{s['eng']}/close", 200)
            assert eng["state"] == "closed", f"engagement is {eng['state']}"
            verdict = self.expect(
                "POST", f"/api/engagements/{s['eng']}/report/verify", 200, s["pin"]
            )
            assert verdict["ok"] is True, f"closed engagement no longer verifies: {verdict}"
            return "closed; report still verifies"

        self.check("engagement closes and stays verifiable", close)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", required=True, help="the deployment's public URL")
    parser.add_argument(
        "--token", default=os.environ.get("KHANDAQ_TOKEN", ""), help="API token (or KHANDAQ_TOKEN)"
    )
    args = parser.parse_args(argv)
    if not args.token:
        print("an API token is required (--token or KHANDAQ_TOKEN)", file=sys.stderr)
        return 2
    try:
        transport = http_transport(args.url, args.token)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    smoke = Smoke(transport)
    ok = smoke.run()
    passed = sum(1 for _, good in smoke.results if good)
    skipped = f", {len(smoke.skipped)} skipped" if smoke.skipped else ""
    print(f"\n{passed}/{len(smoke.results)} checks passed{skipped}" + ("" if ok else " — FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
