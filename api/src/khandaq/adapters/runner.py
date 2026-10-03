"""Adapter runners (spec 005, ADR-0009).

A runner executes one adapter for one run and returns canonical findings + evidence. Two runners:

- ``EchoRunner`` — in-process, deterministic; used for the demo and tests. It proves the
  pipeline (execute → seal evidence → normalise/dedup → persist) without a container.
- ``DockerRunner`` (``docker.py``) — runs the pinned adapter image in a per-run sandbox on an
  internal network whose only exit is a forwarder to the one in-scope target (spec 012,
  ADR-0009).

The run request always carries exactly one resolved, already-scope-checked target, so an
adapter can never see another engagement's or another target's details.
"""

from __future__ import annotations

import hashlib
import json

from ..settings import Settings
from .docker import DockerRunner
from .manifest import AdapterManifest


def build_run_request(
    run_id: str, engagement_id: str, target_type: str, target_spec: dict, params: dict
) -> dict:
    """The JSON contract handed to an adapter: one target, the params, and the run identity."""
    return {
        "run_id": run_id,
        "engagement_id": engagement_id,
        "target": {"type": target_type, "spec": target_spec},
        "params": params,
    }


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class EchoRunner:
    """Deterministic in-process adapter: emits sealed-ready evidence and canonical findings.

    It produces three raw findings — two sightings of the same rule at the same location (to
    exercise dedup) and one distinct — each citing a piece of evidence, all against the single
    provided target.
    """

    def run(self, request: dict) -> dict:
        run_id = request["run_id"]
        eng_id = request["engagement_id"]
        tref = (
            "tgt"  # the finding's target_ref is a logical marker; the real target is in the request
        )

        evidence = []
        for i in range(1, 4):
            content = json.dumps(
                {"prompt": f"probe {i}", "response": f"response {i}", "run": run_id}
            )
            evidence.append(
                {
                    "local_id": f"e{i}",
                    "kind": "transcript",
                    "object_key": f"{eng_id}/{run_id}/e{i}.json",
                    "sha256": _sha256(content),
                    "bytes": len(content),
                    "redacted": False,
                }
            )

        loc1 = [{"logicalLocations": [{"fullyQualifiedName": "chat.completions"}]}]
        loc2 = [{"logicalLocations": [{"fullyQualifiedName": "system.prompt"}]}]

        def finding(rule, sev, mappings, locs, ev_local):
            return {
                "schema": "khandaq.finding/2",
                "engagement_id": eng_id,
                "run_id": run_id,
                "rule_id": rule,
                "title": f"echo: {rule}",
                "severity": sev,
                "source": {"tool": "echo", "version": "0.1.0", "native_severity": sev},
                "target_ref": tref,
                "locations": locs,
                "x-khandaq": {
                    "phase": "04-prompt-injection",
                    "mappings": [{"framework": f, "id": i} for f, i in mappings],
                    "evidence": [],
                },
                "_evidence_local": ev_local,
            }

        llm01 = [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")]
        findings = [
            finding("echo.inject", "medium", llm01, loc1, ["e1"]),
            finding("echo.inject", "high", llm01, loc1, ["e2"]),  # same identity → dup
            finding("echo.leak", "low", [("owasp-llm-2026", "LLM02")], loc2, ["e3"]),
        ]
        return {"evidence": evidence, "findings": findings}


def get_runner(manifest: AdapterManifest, settings: Settings):
    """Pick the runner for an adapter: in-process for builtins, Docker for real tools."""
    if manifest.builtin:
        return EchoRunner()
    return DockerRunner(manifest, settings)
