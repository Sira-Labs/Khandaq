"""Egress containment against a real Docker daemon (spec 012 behaviour 4, ADR-0009).

A probe adapter runs through ``DockerRunner`` exactly as a tool would. It must reach the in-scope
target through the forwarder. It must NOT reach a decoy server on the same egress network (only the
containment stands between them), the decoy by name, or the internet.

Runs only when ``KHANDAQ_E2E_DOCKER=1`` (the CI ``e2e`` job); needs a daemon and pulls images.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from khandaq.adapters.docker import DockerRunner
from khandaq.adapters.manifest import AdapterManifest
from khandaq.settings import Settings

pytestmark = pytest.mark.skipif(
    os.environ.get("KHANDAQ_E2E_DOCKER") != "1", reason="set KHANDAQ_E2E_DOCKER=1 (needs Docker)"
)

ROOT = Path(__file__).resolve().parents[3]
FORWARDER_IMAGE = os.environ.get("KHANDAQ_E2E_FORWARDER_IMAGE", "python:3.12-slim")
TARGET_PORT = 8900


def docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def ip_on(container: str, network: str) -> str:
    return docker(
        "inspect",
        "-f",
        f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
        container,
    )


@pytest.fixture(scope="module")
def lab() -> Iterator[dict]:
    tag = uuid.uuid4().hex[:8]
    egress = f"khq-e2e-egress-{tag}"
    target, decoy = f"khq-e2e-target-{tag}", f"khq-e2e-decoy-{tag}"
    target_image, probe_image = f"khq-e2e-target:{tag}", f"khq-e2e-probe:{tag}"
    if prebuilt := os.environ.get("KHANDAQ_E2E_TARGET_IMAGE"):
        target_image = prebuilt  # e.g. built behind a TLS-intercepting proxy
    else:
        docker("build", "-q", "-t", target_image, str(ROOT / "deploy/targets/vulnerable-llm"))
    docker("build", "-q", "-t", probe_image, str(Path(__file__).parent / "egress_probe"))
    docker("pull", "-q", FORWARDER_IMAGE)
    docker("network", "create", egress)
    try:
        for name in (target, decoy):
            docker("run", "-d", "--name", name, "--network", egress, target_image)
        docker(
            "run",
            "--rm",
            "--network",
            egress,
            FORWARDER_IMAGE,
            "python",
            "-c",
            "import time,urllib.request\n"
            f"for h in ('{target}','{decoy}'):\n"
            "  for _ in range(60):\n"
            "    try: urllib.request.urlopen(f'http://{h}:"
            + str(TARGET_PORT)
            + "/health',timeout=2); break\n"
            "    except OSError: time.sleep(0.5)\n"
            "  else: raise SystemExit(f'{h} never came up')",
        )
        yield {
            "egress": egress,
            "probe_image": probe_image,
            "target_ip": ip_on(target, egress),
            "decoy_ip": ip_on(decoy, egress),
            "decoy_name": decoy,
        }
    finally:
        subprocess.run(["docker", "rm", "-f", target, decoy], capture_output=True)
        subprocess.run(["docker", "network", "rm", egress], capture_output=True)


def test_the_adapter_reaches_its_target_and_nothing_else(lab):
    manifest = AdapterManifest(
        name="egress-probe",
        version="0.0.0",
        phases=["03-scanning"],
        severity_table={"info": "info"},
        image=lab["probe_image"],
        resources={"cpu": "0.5", "memory": "128Mi"},
    )
    settings = Settings(
        forwarder_image=FORWARDER_IMAGE,
        adapter_egress_network=lab["egress"],
        adapter_timeout_seconds=120,
        adapter_output_limit_mb=8,
    )
    request = {
        "run_id": f"run_e2e{uuid.uuid4().hex[:8]}",
        "engagement_id": "eng_e2e",
        # The in-scope host only exists inside the run network, as the forwarder's alias.
        "target": {
            "type": "llm_endpoint",
            "spec": {
                "host": "target.e2e.test",
                "base_url": f"http://target.e2e.test:{TARGET_PORT}/v1",
            },
        },
        "params": {
            "must_not_reach": {
                "decoy_by_ip": f"http://{lab['decoy_ip']}:{TARGET_PORT}/health",
                "decoy_by_name": f"http://{lab['decoy_name']}:{TARGET_PORT}/health",
                "internet": "http://example.com/",
            }
        },
    }
    # The worker resolves the in-scope host; here that is the target container's address.
    runner = DockerRunner(manifest, settings, resolver=lambda host, port: [lab["target_ip"]])

    out = runner.run(request)

    evidence = {e["local_id"]: e for e in out["evidence"]}
    results = json.loads(evidence["results.json"]["content"])
    assert results["target"]["ok"] is True, results
    assert results["target"]["body"] == '{"status":"ok"}'
    for blocked in ("decoy_by_ip", "decoy_by_name", "internet"):
        assert results[blocked]["ok"] is False, (blocked, results)
    assert results["uid"] == 65534
    assert results["rootfs_writable"] is False
    assert out["findings"] == []

    # Nothing of the run is left behind.
    leftovers = docker("ps", "-a", "--filter", f"label=khandaq.run={request['run_id']}", "-q")
    networks = docker("network", "ls", "--filter", f"label=khandaq.run={request['run_id']}", "-q")
    assert leftovers == "" and networks == ""


def test_control_without_the_sandbox_the_decoy_is_reachable(lab):
    """Control for the test above: run uncontained on the egress network, the same probe reaches
    the decoy — so the block above comes from the containment, not from a dead decoy."""
    import io
    import tarfile

    request = {
        "target": {"spec": {"base_url": f"http://{lab['target_ip']}:{TARGET_PORT}/v1"}},
        "params": {
            "must_not_reach": {"decoy_by_ip": f"http://{lab['decoy_ip']}:{TARGET_PORT}/health"}
        },
    }
    out = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            lab["egress"],
            "--tmpfs",
            "/evidence",
            "--env",
            "KHANDAQ_RUN_REQUEST=" + json.dumps(request),
            lab["probe_image"],
        ],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(out)) as tar:
        member = tar.extractfile("results.json")
        assert member is not None
        results = json.loads(member.read())
    assert results["decoy_by_ip"]["ok"] is True, results
