"""Egress-contained container execution of an adapter (spec 012, ADR-0009).

One run, one sandbox:

1. ``docker network create --internal khq-net-<run>``: a network with no route out.
2. The egress forwarder (``khandaq.egress_forwarder``) starts on the deployment's egress network and
   joins the internal network under the **target's hostname** as an alias. It relays TCP to the one
   address the worker resolved and checked here, and to nothing else.
3. The adapter container is created on the internal network only — read-only rootfs, no
   capabilities, ``nobody``, resource limits, tmpfs ``/tmp`` and ``/evidence`` — with the run
   request in ``KHANDAQ_RUN_REQUEST``. It writes one tar of ``/evidence`` to stdout, nothing else.
4. ``docker start -a`` under a timeout and an output cap; then the containers and the network are
   removed whatever happened.

No host paths are mounted: with the Docker socket (shape A) ``-v`` paths are resolved on the *host*,
not in the worker container, so the request goes in through the environment and the evidence comes
out through stdout. Evidence hashes are computed here, never taken from the adapter.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Protocol

from .. import egress_forwarder
from ..scope import ScopeError, network_endpoint
from ..settings import Settings
from .manifest import AdapterManifest

log = logging.getLogger("khandaq.adapters.docker")

FINDINGS_FILE = "findings.jsonl"
MAX_FILES = 1000
_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")
_NOBODY = "65534:65534"
_STDERR_TAIL = 2000


class RunnerError(Exception):
    """The run could not be executed or its output is not trustworthy; the message is recorded."""


@dataclass(frozen=True)
class CliResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class DockerCli(Protocol):
    """Runs ``docker <args>``. ``timeout``/``stdout_limit`` raise RunnerError when exceeded."""

    def __call__(
        self, args: list[str], *, timeout: float | None = None, stdout_limit: int | None = None
    ) -> CliResult: ...


class SubprocessDockerCli:
    """The real Docker CLI. Output goes to temporary files whose size is watched while the process
    runs, so a misbehaving adapter can neither exhaust memory nor fill the disk past the cap."""

    def __init__(self, binary: str = "docker", poll_seconds: float = 0.2) -> None:
        self.binary = binary
        self.poll_seconds = poll_seconds

    def __call__(
        self, args: list[str], *, timeout: float | None = None, stdout_limit: int | None = None
    ) -> CliResult:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen([self.binary, *args], stdout=out, stderr=err)
            deadline = None if timeout is None else time.monotonic() + timeout
            try:
                while proc.poll() is None:
                    if stdout_limit is not None and os.fstat(out.fileno()).st_size > stdout_limit:
                        raise RunnerError(f"adapter output exceeded {stdout_limit} bytes")
                    if deadline is not None and time.monotonic() > deadline:
                        raise RunnerError(f"adapter did not finish within {timeout:.0f}s")
                    time.sleep(self.poll_seconds)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            if stdout_limit is not None and os.fstat(out.fileno()).st_size > stdout_limit:
                raise RunnerError(f"adapter output exceeded {stdout_limit} bytes")
            return CliResult(proc.returncode, _read(out), _read(err))


def _read(f: IO[bytes]) -> bytes:
    f.seek(0)
    return f.read()


Resolver = Callable[[str, int], list[str]]


def resolve(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to, the way a client connecting to it would."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RunnerError(f"cannot resolve target host {host!r}: {exc}") from exc
    return sorted({str(info[4][0]) for info in infos})


def check_address(raw: str) -> str:
    """Refuse addresses a run must never reach whatever the scope says: loopback (that would be the
    forwarder itself), link-local (cloud metadata services), multicast and unspecified."""
    ip = ipaddress.ip_address(raw)
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise RunnerError(f"target resolves to a forbidden address {raw}")
    return str(ip)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def read_output(data: bytes) -> dict[str, bytes]:
    """The files in an adapter's stdout tar. Only flat, regular files within the limits pass."""
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            for member in tar:
                name = member.name.removeprefix("./")
                if member.isdir() and name in ("", "."):
                    continue
                if not member.isfile():
                    raise RunnerError(f"adapter output entry {member.name!r} is not a regular file")
                if not _NAME.fullmatch(name):
                    raise RunnerError(f"adapter output entry {member.name!r} has an unsafe name")
                if name in files:
                    raise RunnerError(f"adapter output names {name!r} twice")
                if len(files) >= MAX_FILES:
                    raise RunnerError(f"adapter output has more than {MAX_FILES} files")
                extracted = tar.extractfile(member)
                files[name] = extracted.read() if extracted is not None else b""
    except tarfile.TarError as exc:
        raise RunnerError(f"adapter output is not a tar archive: {exc}") from exc
    return files


def _kind(name: str) -> str:
    if name.endswith((".jsonl", ".json")):
        return "report"
    if name.endswith((".log", ".txt")):
        return "log"
    return "artefact"


def artifacts_from_output(files: dict[str, bytes], request: dict) -> dict:
    """Turn the adapter's files into the runner result: findings, and every other file as evidence
    with a hash computed here."""
    if FINDINGS_FILE not in files:
        raise RunnerError(f"adapter output has no {FINDINGS_FILE}")
    findings = []
    for number, line in enumerate(files[FINDINGS_FILE].decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RunnerError(f"{FINDINGS_FILE} line {number} is not JSON: {exc}") from exc
        if not isinstance(finding, dict):
            raise RunnerError(f"{FINDINGS_FILE} line {number} is not an object")
        findings.append(finding)
    evidence = [
        {
            "local_id": name,
            "kind": _kind(name),
            "object_key": f"{request['engagement_id']}/{request['run_id']}/{name}",
            "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "redacted": False,
            "content": content,
        }
        for name, content in sorted(files.items())
        if name != FINDINGS_FILE
    ]
    return {"evidence": evidence, "findings": findings}


def _hardening(memory: str, cpus: str, pids: int) -> list[str]:
    return [
        "--read-only",
        "--user",
        _NOBODY,  # the tool never runs as root, even inside its container
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        memory,
        "--cpus",
        cpus,
        "--pids-limit",
        str(pids),
    ]


def docker_memory(value: str) -> str:
    """Manifest memory uses Kubernetes units (``2Gi``); Docker wants ``2g``."""
    units = {"Ki": "k", "Mi": "m", "Gi": "g"}
    for suffix, docker in units.items():
        if value.endswith(suffix) and value[: -len(suffix)].isdigit():
            return value[: -len(suffix)] + docker
    if value.isdigit() or (value[:-1].isdigit() and value[-1].lower() in "kmg"):
        return value
    raise ValueError(f"unsupported memory limit {value!r}")


class DockerRunner:
    """Run a pinned adapter image in a per-run sandbox whose only exit is the in-scope target."""

    def __init__(
        self,
        manifest: AdapterManifest,
        settings: Settings,
        cli: DockerCli | None = None,
        resolver: Resolver = resolve,
    ) -> None:
        self.manifest = manifest
        self.settings = settings
        self.cli = cli or SubprocessDockerCli()
        self.resolver = resolver

    # --- pieces, exposed for tests --------------------------------------------------------------

    def endpoint(self, request: dict) -> tuple[str, int, str]:
        """(host, port, address): the one endpoint this run may reach, resolved and checked."""
        target = request["target"]
        try:
            host, port = network_endpoint(target["type"], target["spec"])
        except ScopeError as exc:
            raise RunnerError(f"target has no usable network endpoint: {exc}") from exc
        if _is_ip_literal(host):
            raise RunnerError("IP-literal targets are not supported for container runs")
        addresses = self.resolver(host, port)
        if not addresses:
            raise RunnerError(f"target host {host!r} resolves to no address")
        checked = [check_address(a) for a in addresses]  # any forbidden address refuses the run
        return host, port, checked[0]

    def forwarder_args(self, name: str, port: int, address: str, labels: list[str]) -> list[str]:
        if not self.settings.forwarder_image:
            raise RunnerError("KHANDAQ_FORWARDER_IMAGE is not set; container runs are disabled")
        connect = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        return [
            "run",
            "--detach",
            "--name",
            name,
            *labels,
            "--network",
            self.settings.adapter_egress_network,
            *_hardening("64m", "0.5", 64),
            # Lets `nobody` bind the target's port (e.g. 443) inside its own network namespace.
            "--sysctl",
            "net.ipv4.ip_unprivileged_port_start=0",
            "--entrypoint",
            "python3",
            self.settings.forwarder_image,
            "-c",
            egress_forwarder.source(),
            "--listen-port",
            str(port),
            "--connect",
            connect,
        ]

    def adapter_args(self, name: str, network: str, env_file: str, labels: list[str]) -> list[str]:
        if not self.manifest.image:
            raise RunnerError(f"adapter {self.manifest.name} has no image")
        resources = self.manifest.resources or {}
        output_mb = self.settings.adapter_output_limit_mb
        return [
            "create",
            "--name",
            name,
            *labels,
            "--network",
            network,
            *_hardening(
                docker_memory(str(resources.get("memory", "1Gi"))),
                str(resources.get("cpu", "1")),
                512,
            ),
            # Writable, non-executable scratch space; $HOME points there for tools that need one.
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m,mode=1777",
            "--tmpfs",
            f"/evidence:rw,noexec,nosuid,size={output_mb}m,mode=1777",
            "--env",
            "HOME=/tmp",
            # The request (target details, later an ephemeral credential) goes through a 0600 file
            # the CLI reads itself, so it never appears on a command line visible in `ps`.
            "--env-file",
            env_file,
            self.manifest.image,
        ]

    # --- execution --------------------------------------------------------------------------------

    def run(self, request: dict) -> dict:
        run_id = request["run_id"]
        host, port, address = self.endpoint(request)
        network, forwarder, adapter = f"khq-net-{run_id}", f"khq-fwd-{run_id}", f"khq-run-{run_id}"
        labels = ["--label", f"khandaq.run={run_id}"]
        fd, env_file = tempfile.mkstemp(prefix="khq-env-", text=True)  # created 0600
        try:
            with os.fdopen(fd, "w") as f:
                # Compact JSON has no raw newline, so it is one env-file line.
                f.write("KHANDAQ_RUN_REQUEST=" + json.dumps(request, separators=(",", ":")) + "\n")
            self._ok(["network", "create", "--internal", *labels, network], "create the network")
            self._ok(self.forwarder_args(forwarder, port, address, labels), "start the forwarder")
            self._ok(
                ["network", "connect", "--alias", host, network, forwarder],
                "attach the forwarder",
            )
            self._ok(self.adapter_args(adapter, network, env_file, labels), "create the adapter")
            result = self.cli(
                ["start", "--attach", adapter],
                timeout=self.settings.adapter_timeout_seconds,
                stdout_limit=self.settings.adapter_output_limit_mb * 1024 * 1024,
            )
        finally:
            os.unlink(env_file)
            self._cleanup(network, forwarder, adapter)
        if result.returncode != 0:
            tail = result.stderr.decode("utf-8", "replace")[-_STDERR_TAIL:]
            raise RunnerError(f"adapter exited with {result.returncode}: {tail}")
        return artifacts_from_output(read_output(result.stdout), request)

    def _ok(self, args: list[str], what: str) -> CliResult:
        result = self.cli(args, timeout=120)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace")[-_STDERR_TAIL:]
            raise RunnerError(f"could not {what}: {detail}")
        return result

    def _cleanup(self, network: str, forwarder: str, adapter: str) -> None:
        """Remove everything the run created; each step runs even if an earlier one failed."""
        for args in (["rm", "--force", adapter, forwarder], ["network", "rm", network]):
            try:
                result = self.cli(args, timeout=60)
            except RunnerError as exc:
                log.error("cleanup %s failed: %s", args, exc)
                continue
            if result.returncode != 0:
                log.warning(
                    "cleanup %s: %s", args, result.stderr.decode("utf-8", "replace").strip()
                )
