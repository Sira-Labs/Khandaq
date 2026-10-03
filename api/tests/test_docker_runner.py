"""Unit tests for egress-contained container execution (spec 012, ADR-0009).

A fake Docker CLI records every call, so the sandbox's construction, its cleanup on every failure
path and the checks on the adapter's output are tested without a daemon. The real-daemon
containment test lives in ``tests/e2e``.
"""

from __future__ import annotations

import io
import json
import os
import tarfile

import pytest

from khandaq.adapters.docker import (
    CliResult,
    DockerRunner,
    RunnerError,
    check_address,
    read_output,
)
from khandaq.adapters.manifest import AdapterManifest
from khandaq.settings import Settings

MANIFEST = AdapterManifest(
    name="garak",
    version="0.17.0",
    phases=["03-scanning"],
    severity_table={"high": "high"},
    image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    resources={"cpu": "1", "memory": "2Gi"},
)
SETTINGS = Settings(
    forwarder_image="ghcr.io/sira-labs/khandaq-api:test",
    adapter_egress_network="khandaq_default",
    adapter_timeout_seconds=600,
    adapter_output_limit_mb=8,
)


def _request(spec: dict | None = None) -> dict:
    return {
        "run_id": "run_abc",
        "engagement_id": "eng_1",
        "target": {
            "type": "llm_endpoint",
            "spec": spec or {"host": "target.test", "base_url": "https://target.test/v1"},
        },
        "params": {},
    }


def _tar(files: dict[str, bytes], extra: list[tarfile.TarInfo] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        for info in extra or []:
            tar.addfile(info)
    return buf.getvalue()


FINDING = {"schema": "khandaq.finding/2", "rule_id": "garak.x", "_evidence_local": ["report.jsonl"]}
GOOD_OUTPUT = _tar(
    {"findings.jsonl": (json.dumps(FINDING) + "\n").encode(), "report.jsonl": b'{"entry":1}\n'}
)


class FakeCli:
    """Records calls; ``start`` returns the scripted adapter result (or raises)."""

    def __init__(self, start: CliResult | Exception, fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.start = start
        self.fail_on = fail_on
        self.start_kwargs: dict = {}

    def __call__(self, args, *, timeout=None, stdout_limit=None):
        self.calls.append(list(args))
        if "--env-file" in args:  # read it now: the runner deletes it once the run is over
            path = args[args.index("--env-file") + 1]
            self.env_file = (path, open(path).read(), os.stat(path).st_mode & 0o777)
        if self.fail_on and args[:2] == self.fail_on.split():
            return CliResult(1, b"", b"daemon said no")
        if args[0] == "start":
            self.start_kwargs = {"timeout": timeout, "stdout_limit": stdout_limit}
            if isinstance(self.start, Exception):
                raise self.start
            return self.start
        return CliResult(0, b"", b"")

    def find(self, *prefix: str) -> list[str]:
        return next(c for c in self.calls if c[: len(prefix)] == list(prefix))

    def cleaned_up(self) -> bool:
        return ["rm", "--force", "khq-run-run_abc", "khq-fwd-run_abc"] in self.calls and [
            "network",
            "rm",
            "khq-net-run_abc",
        ] in self.calls


def _runner(cli: FakeCli, addresses: list[str] | None = None) -> DockerRunner:
    return DockerRunner(
        MANIFEST, SETTINGS, cli=cli, resolver=lambda host, port: addresses or ["203.0.113.7"]
    )


def _value(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_sandbox_is_built_in_order_and_torn_down():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    out = _runner(cli).run(_request())

    order = [c[:2] for c in cli.calls]
    assert order == [
        ["network", "create"],
        ["run", "--detach"],
        ["network", "connect"],
        ["create", "--name"],
        ["start", "--attach"],
        ["rm", "--force"],
        ["network", "rm"],
    ]
    assert "--internal" in cli.find("network", "create")  # no route out of the run network
    assert cli.find("network", "connect") == [
        "network",
        "connect",
        "--alias",
        "target.test",  # the adapter's lookup of the target lands on the forwarder
        "khq-net-run_abc",
        "khq-fwd-run_abc",
    ]
    assert cli.start_kwargs == {"timeout": 600, "stdout_limit": 8 * 1024 * 1024}
    assert out["findings"] == [FINDING]
    [ev] = out["evidence"]
    assert ev["local_id"] == "report.jsonl" and ev["kind"] == "report"
    assert ev["object_key"] == "eng_1/run_abc/report.jsonl"
    assert ev["content"] == b'{"entry":1}\n' and ev["bytes"] == 12


def test_the_forwarder_relays_only_to_the_checked_address():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    _runner(cli).run(_request())
    fwd = cli.find("run", "--detach")
    assert _value(fwd, "--network") == "khandaq_default"
    assert fwd[fwd.index("--connect") + 1] == "203.0.113.7:443"
    assert _value(fwd, "--listen-port") == "443"
    assert _value(fwd, "--entrypoint") == "python3"
    assert _value(fwd, "--user") == "65534:65534" and "--read-only" in fwd
    assert _value(fwd, "--cap-drop") == "ALL"


def test_the_adapter_is_locked_down_and_gets_only_the_request():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    _runner(cli).run(_request())
    adapter = cli.find("create", "--name")
    assert _value(adapter, "--network") == "khq-net-run_abc"  # the internal network only
    assert adapter.count("--network") == 1
    assert "--read-only" in adapter and _value(adapter, "--cap-drop") == "ALL"
    assert _value(adapter, "--security-opt") == "no-new-privileges"
    assert _value(adapter, "--user") == "65534:65534"
    assert _value(adapter, "--memory") == "2g" and _value(adapter, "--cpus") == "1"
    assert _value(adapter, "--pids-limit") == "512"
    assert not any(a in ("-v", "--volume", "--mount", "--privileged") for a in adapter)
    # The request is not on any command line (visible in `ps`); it is in a private env file.
    assert not any("KHANDAQ_RUN_REQUEST" in a for c in cli.calls for a in c)
    path, content, mode = cli.env_file
    assert mode == 0o600 and not os.path.exists(path)
    key, value = content.rstrip("\n").split("=", 1)
    assert key == "KHANDAQ_RUN_REQUEST" and "\n" not in content.rstrip("\n")
    assert json.loads(value) == _request()
    assert adapter[-1] == MANIFEST.image


@pytest.mark.parametrize(
    "fail_on", ["network create", "run --detach", "network connect", "create --name"]
)
def test_a_failed_setup_step_still_tears_everything_down(fail_on):
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""), fail_on=fail_on)
    with pytest.raises(RunnerError, match="daemon said no"):
        _runner(cli).run(_request())
    assert cli.cleaned_up()
    assert not any(c[0] == "start" for c in cli.calls)


@pytest.mark.parametrize(
    "start",
    [
        RunnerError("adapter did not finish within 600s"),
        RunnerError("adapter output exceeded 8388608 bytes"),
        CliResult(3, b"", b"garak: connection refused"),
    ],
)
def test_a_failed_or_runaway_adapter_is_torn_down_and_reported(start):
    cli = FakeCli(start)
    with pytest.raises(RunnerError) as exc:
        _runner(cli).run(_request())
    assert cli.cleaned_up()
    if isinstance(start, CliResult):
        assert "exited with 3" in str(exc.value) and "connection refused" in str(exc.value)


@pytest.mark.parametrize(
    ("spec", "addresses", "reason"),
    [
        ({"base_url": "http://10.0.0.5:8000/v1"}, None, "IP-literal"),
        ({"host": "target.test"}, None, "needs the target's URL"),
        ({"base_url": "https://target.test/v1"}, ["127.0.0.1"], "forbidden address"),
        ({"base_url": "https://target.test/v1"}, ["169.254.169.254"], "forbidden address"),
        ({"base_url": "https://target.test/v1"}, ["203.0.113.7", "fe80::1"], "forbidden address"),
    ],
)
def test_unusable_or_forbidden_endpoints_launch_nothing(spec, addresses, reason):
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    with pytest.raises(RunnerError, match=reason):
        _runner(cli, addresses).run(_request(spec))
    assert cli.calls == []


def test_container_runs_are_refused_without_a_forwarder_image():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    runner = DockerRunner(MANIFEST, Settings(), cli=cli, resolver=lambda h, p: ["203.0.113.7"])
    with pytest.raises(RunnerError, match="KHANDAQ_FORWARDER_IMAGE"):
        runner.run(_request())
    assert cli.cleaned_up()


def _symlink(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    return info


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (_tar({"../escape": b"x", "findings.jsonl": b""}), "unsafe name"),
        (_tar({"sub/dir.txt": b"x", "findings.jsonl": b""}), "unsafe name"),
        (_tar({"findings.jsonl": b""}, [_symlink("link")]), "not a regular file"),
        (b"not a tar archive at all" * 40, "not a tar archive"),
    ],
)
def test_untrustworthy_output_is_refused(data, reason):
    with pytest.raises(RunnerError, match=reason):
        read_output(data)


def test_output_without_findings_or_with_bad_lines_is_refused():
    cli = FakeCli(CliResult(0, _tar({"report.jsonl": b"{}"}), b""))
    with pytest.raises(RunnerError, match="no findings.jsonl"):
        _runner(cli).run(_request())
    cli = FakeCli(CliResult(0, _tar({"findings.jsonl": b"[1, 2]\n"}), b""))
    with pytest.raises(RunnerError, match="not an object"):
        _runner(cli).run(_request())


def test_evidence_hashes_are_computed_not_trusted():
    content = b"transcript"
    cli = FakeCli(CliResult(0, _tar({"findings.jsonl": b"", "t.txt": content}), b""))
    [ev] = _runner(cli).run(_request())["evidence"]
    import hashlib

    assert ev["sha256"] == "sha256:" + hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("raw", ["127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0"])
def test_forbidden_addresses(raw):
    with pytest.raises(RunnerError):
        check_address(raw)


def test_private_addresses_are_allowed_for_self_hosted_targets():
    assert check_address("172.18.0.5") == "172.18.0.5"
