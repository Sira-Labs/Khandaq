"""Unit tests for the adapter layer (spec 005): no database, no containers."""

from __future__ import annotations

import pytest

from khandaq.adapters import build_run_request, get_manifest
from khandaq.adapters.manifest import AdapterManifest
from khandaq.adapters.runner import DockerRunner
from khandaq.settings import Settings


def test_manifest_problems_detects_bad_manifests():
    good = AdapterManifest(
        name="garak",
        version="0.17.0",
        phases=["03-scanning"],
        severity_table={"fail": "high"},
        image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    )
    assert good.problems() == []

    floating = AdapterManifest(
        name="x",
        version="",
        phases=[],
        severity_table={},
        image=None,
    )
    probs = floating.problems()
    assert any("version" in p for p in probs)
    assert any("phase" in p for p in probs)
    assert any("severity_table" in p for p in probs)
    assert any("image" in p for p in probs)

    bad_sev = AdapterManifest(
        name="x",
        version="1.0",
        phases=["p"],
        severity_table={"fail": "spicy"},
        builtin=True,
    )
    assert any("unknown severities" in p for p in bad_sev.problems())


def test_echo_manifest_is_registered_and_valid():
    echo = get_manifest("echo")
    assert echo is not None and echo.builtin
    assert echo.problems() == []


def test_run_request_carries_exactly_one_target():
    req = build_run_request(
        "run_1", "eng_1", "llm_endpoint", {"host": "gw.acme.test", "model": "m"}, {"p": 1}
    )
    # Exactly one target, and it is the one provided — an adapter can see no other.
    assert set(req.keys()) == {"run_id", "engagement_id", "target", "params"}
    assert req["target"] == {"type": "llm_endpoint", "spec": {"host": "gw.acme.test", "model": "m"}}


def test_docker_runner_command_is_locked_down():
    manifest = AdapterManifest(
        name="garak",
        version="0.17.0",
        phases=["03-scanning"],
        severity_table={"fail": "high"},
        image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    )
    cmd = DockerRunner(manifest, Settings()).build_command(
        "/tmp/req.json", "/tmp/evidence", "khandaq-run-abc"
    )
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "khandaq-run-abc" in cmd  # the egress-restricted per-run network
    assert cmd[-1] == "ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0"


def test_docker_runner_applies_resource_limits_and_drops_root():
    manifest = AdapterManifest(
        name="garak",
        version="0.17.0",
        phases=["03-scanning"],
        severity_table={"fail": "high"},
        image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
        resources={"cpu": "1", "memory": "2Gi"},
    )
    cmd = DockerRunner(manifest, Settings()).build_command(
        "/tmp/req.json", "/tmp/evidence", "khandaq-run-abc"
    )

    def value(flag: str) -> str:
        return cmd[cmd.index(flag) + 1]

    assert value("--memory") == "2g" and value("--cpus") == "1"
    assert value("--pids-limit") == "512"
    assert value("--user") == "65534:65534"
    assert value("--tmpfs").startswith("/tmp:") and "noexec" in value("--tmpfs")


def test_docker_runner_refuses_mount_paths_that_change_the_volume_spec():
    manifest = AdapterManifest(
        name="garak",
        version="0.17.0",
        phases=["03-scanning"],
        severity_table={"fail": "high"},
        image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    )
    with pytest.raises(ValueError, match="unsafe mount path"):
        DockerRunner(manifest, Settings()).build_command(
            "/tmp/req.json:/etc/passwd", "/tmp/evidence", "net"
        )
