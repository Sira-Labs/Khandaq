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
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Protocol

from .. import egress_forwarder
from ..credential_values import CREDENTIAL_ENV, redact, redact_bytes
from ..scope import ScopeError, network_endpoint
from ..settings import Settings
from .manifest import AdapterManifest

log = logging.getLogger("khandaq.adapters.docker")

FINDINGS_FILE = "findings.jsonl"
MAX_FILES = 1000
_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")
_NOBODY = "65534:65534"
_STDERR_TAIL = 2000
# Docker reads an env file line by line with a 64 KiB scanner; stay well below it.
MAX_REQUEST_BYTES = 60_000


# What a run can take outside its adapter's own timeout: resolving the target, four setup calls
# (network, forwarder, attach, create) and three removals (adapter, forwarder, network), each
# under its own limit. Stale-run recovery adds this to the adapter timeout, so it never takes a
# run whose worker is still inside one of these steps for a lost one.
RESOLVE_SECONDS = 30
SETUP_STEP_SECONDS = 120
REMOVE_STEP_SECONDS = 60
OVERHEAD_SECONDS = RESOLVE_SECONDS + 4 * SETUP_STEP_SECONDS + 3 * REMOVE_STEP_SECONDS


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


def redact_output(files: dict[str, bytes], credential: str | None) -> tuple[dict[str, bytes], set]:
    """The adapter's files with the run's credential replaced, and the names that changed.

    Runs before anything is parsed or hashed (spec 028 §7): the ledger seals the redacted bytes and
    the unredacted ones are never stored. A target that echoes its caller's key is a finding in
    itself; the finding survives, the key does not.
    """
    if not credential:
        return files, set()
    clean = {name: redact_bytes(content, credential) for name, content in files.items()}
    return clean, {name for name, content in clean.items() if content != files[name]}


def artifacts_from_output(
    files: dict[str, bytes], request: dict, redacted: frozenset[str] | set[str] = frozenset()
) -> dict:
    """Turn the adapter's files into the runner result: findings, and every other file as evidence
    with a hash computed here. ``redacted`` names the files a credential was removed from."""
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
            "redacted": name in redacted,
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


class LeftoversError(RunnerError):
    """The run is over but its containers or network could not be removed: its forwarder may
    still be relaying. The run must not be recorded as ended while that is so (spec 032)."""


def _names(run_id: str) -> tuple[str, str, str]:
    """(network, forwarder, adapter): the Docker objects of one run."""
    return f"khq-net-{run_id}", f"khq-fwd-{run_id}", f"khq-run-{run_id}"


# What the Docker daemon answers for an object that is not there, with the object's name filled
# in. Only such an answer proves absence: "not found" alone is also what the CLI says of a missing
# context, and then nothing was asked of any daemon.
_ABSENT = ("no such container: {name}", "no such network: {name}", "network {name} not found")
# Lookups that never returned (``_resolve``). Each keeps a thread until its resolver call comes
# back, so their number is bounded: beyond it a run fails instead of starting another.
RESOLVER_SLOTS = 4
_resolver_slots = threading.BoundedSemaphore(RESOLVER_SLOTS)
_LEFTOVERS = "the run's containers or network could not be removed"


def daemon_id(cli: DockerCli | None = None) -> str:
    """The id of the Docker daemon this process talks to (``docker info``). It is stable across
    restarts of the daemon, and it is what tells one Docker host from another (spec 032)."""
    docker = cli or SubprocessDockerCli()
    try:
        result = docker(["info", "--format", "{{.ID}}"], timeout=SETUP_STEP_SECONDS)
    except OSError as exc:
        raise RunnerError(f"could not ask the Docker daemon for its id: {exc}") from None
    found = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode != 0 or not found or len(found.split()) != 1:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RunnerError(f"could not ask the Docker daemon for its id: {detail[-_STDERR_TAIL:]}")
    return found


def remove_run_leftovers(run_id: str, cli: DockerCli | None = None) -> bool:
    """Remove the containers and the network a lost run may have left behind (spec 032).

    A worker that died mid-run never ran its own cleanup, so the run's forwarder can still be
    relaying. Returns ``True`` when nothing of the run is left: an object that is already gone
    counts as removed. ``False`` means something may still be running.
    """
    return _remove(cli or SubprocessDockerCli(), run_id, None)


def _says_absent(detail: str, name: str) -> bool:
    """Whether a failed removal's message is the daemon saying that ``name`` does not exist."""
    said = detail.lower()
    return any(text.format(name=name.lower()) in said for text in _ABSENT)


def _remove(docker: DockerCli, run_id: str, credential: str | None) -> bool:
    """Remove the run's adapter, forwarder and network; ``True`` when none of them is left.

    Every object is tried even if an earlier one failed. One object per call: in a combined call
    "no such container" for one of them would hide a failure to remove the other. A container
    that could not be removed still holds the run's environment, the credential included, in its
    configuration on the Docker host, so what is logged is redacted.
    """
    network, forwarder, adapter = _names(run_id)
    gone = True
    for args in (
        ["rm", "--force", adapter],
        ["rm", "--force", forwarder],
        ["network", "rm", network],
    ):
        try:
            result = docker(args, timeout=REMOVE_STEP_SECONDS)
        except (RunnerError, OSError) as exc:
            log.error("removing %s failed: %s", args[-1], redact(str(exc), credential))
            gone = False
            continue
        detail = redact(result.stderr.decode("utf-8", "replace").strip(), credential)
        if result.returncode != 0 and not _says_absent(detail, args[-1]):
            log.error("removing %s failed: %s", args[-1], detail)
            gone = False
    return gone


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
        self.resolve_seconds: float = RESOLVE_SECONDS

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
        addresses = self._resolve(host, port)
        if not addresses:
            raise RunnerError(f"target host {host!r} resolves to no address")
        checked = [check_address(a) for a in addresses]  # any forbidden address refuses the run
        return host, port, checked[0]

    def pace(self, request: dict) -> float | None:
        """The requests-per-minute rate the forwarder holds for this run, or ``None`` (spec 032).

        A ``forwarder_paced`` adapter with a declared ``rate_per_minute`` is paced. A rate the
        forwarder cannot hold refuses the run: nothing falls back to an unpaced forwarder.
        """
        rate = (request.get("params") or {}).get("rate_per_minute")
        if not self.manifest.forwarder_paced or rate is None:
            return None
        problem = RunnerError(f"the run cannot be paced at {str(rate)[:40]!r} requests per minute")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)):
            raise problem
        try:
            return egress_forwarder.parse_pace(repr(float(rate)))
        except (ValueError, OverflowError) as exc:
            raise problem from exc

    def _resolve(self, host: str, port: int) -> list[str]:
        """The resolver's answer within ``RESOLVE_SECONDS``. ``getaddrinfo`` has no deadline of
        its own, and a run that hung here would still be ``running`` when recovery came for it."""
        answer: list[list[str] | BaseException] = []
        if not _resolver_slots.acquire(blocking=False):
            raise RunnerError(
                f"{RESOLVER_SLOTS} earlier lookups of a target host have not returned; "
                "no further one is started"
            )

        def ask() -> None:
            try:
                answer.append(self.resolver(host, port))
            except BaseException as exc:  # handed to the caller's thread, re-raised there
                answer.append(exc)
            finally:
                # Only here: a lookup that timed out for its run still occupies its thread.
                _resolver_slots.release()

        # A daemon thread: one that never returns must not keep the worker from exiting.
        thread = threading.Thread(target=ask, name="khq-resolve", daemon=True)
        try:
            thread.start()
        except RuntimeError:  # no thread could be started: nothing will give the slot back
            _resolver_slots.release()
            raise RunnerError(f"could not start the lookup of target host {host!r}") from None
        thread.join(self.resolve_seconds)
        if not answer:
            raise RunnerError(
                f"resolving target host {host!r} took longer than {self.resolve_seconds:.0f}s"
            )
        if isinstance(answer[0], BaseException):
            raise answer[0]
        return answer[0]

    def forwarder_args(
        self, name: str, port: int, address: str, labels: list[str], pace: float | None = None
    ) -> list[str]:
        if not self.settings.forwarder_image:
            raise RunnerError("KHANDAQ_FORWARDER_IMAGE is not set; container runs are disabled")
        connect = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        pacing = [] if pace is None else ["--pace-per-minute", repr(pace)]
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
            *pacing,
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
            # The request and, for a keyed target, its credential (spec 028) go through a 0600 file
            # the CLI reads itself, so it never appears on a command line visible in `ps`.
            "--env-file",
            env_file,
            self.manifest.image,
        ]

    # --- execution --------------------------------------------------------------------------------

    def run(self, request: dict, credential: str | None = None) -> dict:
        """Execute the run. ``credential`` (spec 028) reaches the adapter through the env file only
        and is redacted from every file and error message that comes back."""
        try:
            return self._run(request, credential)
        except LeftoversError:
            raise  # carries no adapter text, and its type decides what happens to the run
        except RunnerError as exc:
            if not credential:
                raise
            # `from None`: the original message, which may hold the credential, must not travel
            # on as a chained exception into a traceback or a log line.
            raise RunnerError(redact(str(exc), credential)) from None

    def _run(self, request: dict, credential: str | None) -> dict:
        run_id = request["run_id"]
        host, port, address = self.endpoint(request)
        pace = self.pace(request)  # before anything starts: an unusable pace refuses the run
        network, forwarder, adapter = _names(run_id)
        labels = ["--label", f"khandaq.run={run_id}"]
        # Compact JSON has no raw newline, so it is one env-file line.
        line = "KHANDAQ_RUN_REQUEST=" + json.dumps(request, separators=(",", ":")) + "\n"
        if len(line.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise RunnerError(f"the run request exceeds {MAX_REQUEST_BYTES} bytes")
        if credential:
            if not self.manifest.accepts_credential:
                raise RunnerError(f"adapter {self.manifest.name} does not accept a credential")
            # A second line of the same 0600 file: never the request JSON, never a docker argument.
            line += f"{CREDENTIAL_ENV}={credential}\n"
        fd, env_file = tempfile.mkstemp(prefix="khq-env-", text=True)  # created 0600
        removed = True
        try:
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(line)
                self._ok(
                    ["network", "create", "--internal", *labels, network],
                    "create the network",
                    credential,
                )
                self._ok(
                    self.forwarder_args(forwarder, port, address, labels, pace),
                    "start the forwarder",
                    credential,
                )
                self._ok(
                    ["network", "connect", "--alias", host, network, forwarder],
                    "attach the forwarder",
                    credential,
                )
                self._ok(
                    self.adapter_args(adapter, network, env_file, labels),
                    "create the adapter",
                    credential,
                )
                result = self.cli(
                    ["start", "--attach", adapter],
                    timeout=self.settings.adapter_timeout_seconds,
                    stdout_limit=self.settings.adapter_output_limit_mb * 1024 * 1024,
                )
            finally:
                try:
                    os.unlink(env_file)
                finally:
                    # Even if the env file could not be deleted: whether the run's containers
                    # are gone decides what may be recorded about the run.
                    removed = _remove(self.cli, run_id, credential)
        except Exception:
            if not removed:
                # `from None`: the run's own error may hold the credential, and what matters now
                # is that something of the run is still there.
                raise LeftoversError(_LEFTOVERS) from None
            raise
        if not removed:
            raise LeftoversError(_LEFTOVERS)
        if result.returncode != 0:
            # Redact before cutting the tail: a cut through the credential would leave a part of it
            # that no longer matches.
            stderr = redact(result.stderr.decode("utf-8", "replace"), credential)
            raise RunnerError(f"adapter exited with {result.returncode}: {stderr[-_STDERR_TAIL:]}")
        files, redacted = redact_output(read_output(result.stdout), credential)
        return artifacts_from_output(files, request, redacted)

    def _ok(self, args: list[str], what: str, credential: str | None = None) -> CliResult:
        result = self.cli(args, timeout=SETUP_STEP_SECONDS)
        if result.returncode != 0:
            # Redacted before the cut, as for the adapter's own stderr.
            detail = redact(result.stderr.decode("utf-8", "replace"), credential)
            raise RunnerError(f"could not {what}: {detail[-_STDERR_TAIL:]}")
        return result
