"""Unit tests for egress-contained container execution (spec 012, ADR-0009).

A fake Docker CLI records every call, so the sandbox's construction, its cleanup on every failure
path and the checks on the adapter's output are tested without a daemon. The real-daemon
containment test lives in ``tests/e2e``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import tarfile

import pytest

from khandaq.adapters.docker import (
    OVERHEAD_SECONDS,
    CliResult,
    DockerRunner,
    LeftoversError,
    RunnerError,
    check_address,
    read_output,
    remove_run_leftovers,
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
        return self.calls[-3:] == [
            ["rm", "--force", "khq-run-run_abc"],
            ["rm", "--force", "khq-fwd-run_abc"],
            ["network", "rm", "khq-net-run_abc"],
        ]


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
        ["rm", "--force"],  # the adapter
        ["rm", "--force"],  # the forwarder
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


def test_an_oversized_request_is_refused_before_anything_is_created():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    request = _request()
    request["params"] = {"notes": "x" * 70_000}
    with pytest.raises(RunnerError, match="exceeds"):
        _runner(cli).run(request)
    assert cli.calls == []


# --- target credentials (spec 028) ---------------------------------

KEY = "synthetic/runner+key=for:tests-0123456789"  # synthetic; every encodable character
ACCEPTING = AdapterManifest(
    name="garak",
    version="0.17.0",
    phases=["03-scanning"],
    severity_table={"high": "high"},
    image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    resources={"cpu": "1", "memory": "2Gi"},
    accepts_credential=True,
)


def _keyed_runner(cli: FakeCli) -> DockerRunner:
    return DockerRunner(ACCEPTING, SETTINGS, cli=cli, resolver=lambda host, port: ["203.0.113.7"])


def test_the_credential_is_only_in_the_env_file_never_in_any_docker_argument():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))

    _keyed_runner(cli).run(_request(), credential=KEY)

    path, content, mode = cli.env_file
    request_line, credential_line = content.splitlines()
    assert mode == 0o600
    assert credential_line == f"KHANDAQ_TARGET_CREDENTIAL={KEY}"
    assert request_line.startswith("KHANDAQ_RUN_REQUEST=") and KEY not in request_line
    assert all(KEY not in arg for call in cli.calls for arg in call)
    assert not os.path.exists(path)

    # Without a credential the file is exactly what it was before spec 028: one line.
    plain = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    _keyed_runner(plain).run(_request())
    assert (
        plain.env_file[1].count("\n") == 1 and "KHANDAQ_TARGET_CREDENTIAL" not in plain.env_file[1]
    )


@pytest.mark.parametrize(
    "start", [CliResult(2, b"", b"boom"), RunnerError("adapter did not finish within 600s")]
)
def test_the_env_file_is_removed_even_when_the_run_fails(start):
    cli = FakeCli(start)
    with pytest.raises(RunnerError):
        _keyed_runner(cli).run(_request(), credential=KEY)
    assert not os.path.exists(cli.env_file[0]) and cli.cleaned_up()


def test_a_credential_is_never_handed_to_an_adapter_that_does_not_accept_one():
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    with pytest.raises(RunnerError) as exc:
        _runner(cli).run(_request(), credential=KEY)  # MANIFEST declares no accepts_credential
    assert "does not accept a credential" in str(exc.value) and KEY not in str(exc.value)
    assert cli.calls == []  # nothing was created, and no env file was written


def test_echoed_credentials_are_redacted_from_findings_and_evidence_before_hashing():
    from urllib.parse import quote

    finding = {**FINDING, "title": f"the target replayed {KEY}"}
    report = f'{{"output":"key={KEY}"}}\n'.encode()
    hitlog = f'{{"url":"?k={quote(KEY, safe="")}"}}\n'.encode()
    output = _tar(
        {
            "findings.jsonl": (json.dumps(finding) + "\n").encode(),
            "report.jsonl": report,
            "hitlog.jsonl": hitlog,
            "clean.log": b"nothing to see\n",
        }
    )
    cli = FakeCli(CliResult(0, output, f"garak said {KEY}".encode()))

    result = _keyed_runner(cli).run(_request(), credential=KEY)

    marker = b"[REDACTED:target-credential]"
    by_name = {e["local_id"]: e for e in result["evidence"]}
    assert by_name["report.jsonl"]["content"] == b'{"output":"key=' + marker + b'"}\n'
    assert by_name["hitlog.jsonl"]["content"] == b'{"url":"?k=' + marker + b'"}\n'
    assert by_name["clean.log"]["content"] == b"nothing to see\n"
    assert {name: e["redacted"] for name, e in by_name.items()} == {
        "report.jsonl": True,
        "hitlog.jsonl": True,
        "clean.log": False,
    }
    for e in result["evidence"]:  # the hash and size are those of the bytes that will be stored
        assert e["sha256"] == "sha256:" + hashlib.sha256(e["content"]).hexdigest()
        assert e["bytes"] == len(e["content"])
    assert by_name["report.jsonl"]["sha256"] != "sha256:" + hashlib.sha256(report).hexdigest()
    [found] = result["findings"]
    assert found["title"] == "the target replayed [REDACTED:target-credential]"
    assert KEY not in json.dumps(result["findings"])

    # The same output without a credential is untouched and unmarked.
    untouched = _keyed_runner(FakeCli(CliResult(0, output, b""))).run(_request())
    assert all(e["redacted"] is False for e in untouched["evidence"])


def test_stderr_and_error_text_are_redacted_before_they_are_recorded():
    # The key sits across the point where the 2000-character tail is cut: cutting first would
    # leave half a key that no longer matches.
    stderr = ("x" * 100 + KEY + "y" * (2000 - len(KEY) // 2)).encode()
    with pytest.raises(RunnerError) as exc:
        _keyed_runner(FakeCli(CliResult(2, b"", stderr))).run(_request(), credential=KEY)
    message = str(exc.value)
    assert KEY not in message and KEY[len(KEY) // 2 :] not in message
    assert exc.value.__cause__ is None and exc.value.__suppress_context__  # no chained original

    # A setup step whose daemon error repeats the env file is redacted too.
    class Leaky(FakeCli):
        def __call__(self, args, *, timeout=None, stdout_limit=None):
            if args[0] == "create":
                return CliResult(1, b"", f"invalid env file line: {KEY}".encode())
            return super().__call__(args, timeout=timeout, stdout_limit=stdout_limit)

    with pytest.raises(RunnerError) as exc:
        _keyed_runner(Leaky(CliResult(0, GOOD_OUTPUT, b""))).run(_request(), credential=KEY)
    assert "[REDACTED:target-credential]" in str(exc.value) and KEY not in str(exc.value)


def _leaky(rm_fails: bool) -> FakeCli:
    # The key straddles the 2000-character cut of a daemon error.
    daemon = ("x" * 50 + KEY + "y" * (2000 - len(KEY) // 2)).encode()

    class Leaky(FakeCli):
        def __call__(self, args, *, timeout=None, stdout_limit=None):
            if args[0] == "create":
                return CliResult(1, b"", daemon)
            if args[0] == "rm" and rm_fails:
                return CliResult(1, b"", f"cannot remove: env {KEY}".encode())
            return super().__call__(args, timeout=timeout, stdout_limit=stdout_limit)

    return Leaky(CliResult(0, GOOD_OUTPUT, b""))


def test_a_setup_error_is_redacted_before_it_is_cut(caplog):
    with caplog.at_level("DEBUG"), pytest.raises(RunnerError) as exc:
        _keyed_runner(_leaky(rm_fails=False)).run(_request(), credential=KEY)
    message = str(exc.value)
    assert "could not create the adapter" in message
    assert KEY not in message and KEY[len(KEY) // 2 :] not in message
    assert KEY not in caplog.text


def test_a_failed_removal_is_reported_as_leftovers_and_its_logs_are_redacted(caplog):
    with caplog.at_level("DEBUG"), pytest.raises(LeftoversError) as exc:
        _keyed_runner(_leaky(rm_fails=True)).run(_request(), credential=KEY)
    # The setup error, which held the key, is not carried along.
    assert KEY not in str(exc.value) and exc.value.__cause__ is None
    assert KEY not in caplog.text and "[REDACTED:target-credential]" in caplog.text
    # A container that could not be removed still holds the key: that is an error, not a warning.
    assert any(r.levelname == "ERROR" and "removing" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "start",
    [
        RunnerError("adapter did not finish within 600s"),  # a timeout: the adapter may live on
        CliResult(3, b"", b"garak: connection refused"),
        CliResult(0, GOOD_OUTPUT, b""),  # even a run that went well
    ],
)
@pytest.mark.parametrize("stuck", ["khq-run-run_abc", "khq-fwd-run_abc", "khq-net-run_abc"])
def test_a_run_whose_containers_cannot_be_removed_ends_in_leftovers(start, stuck):
    """Whatever the run's own outcome: while something of it is left, its forwarder may still
    relay, and the caller must not record the run as ended (spec 032)."""

    removal = {
        "khq-run-run_abc": ["rm", "--force", "khq-run-run_abc"],
        "khq-fwd-run_abc": ["rm", "--force", "khq-fwd-run_abc"],
        "khq-net-run_abc": ["network", "rm", "khq-net-run_abc"],
    }[stuck]

    class Stuck(FakeCli):
        def __call__(self, args, *, timeout=None, stdout_limit=None):
            # Only the removal fails: `network create` and `network connect` end in the same
            # names, and failing those would end the run before the scripted outcome.
            if list(args) == removal:
                self.calls.append(list(args))
                return CliResult(1, b"", b"permission denied")
            return super().__call__(args, timeout=timeout, stdout_limit=stdout_limit)

    cli = Stuck(start)
    with pytest.raises(LeftoversError, match="could not be removed"):
        _runner(cli).run(_request())
    assert cli.cleaned_up()  # all three removals were still tried
    started = cli.calls.index(["start", "--attach", "khq-run-run_abc"])
    assert started == len(cli.calls) - 4  # the adapter ran, and only then the removals


def test_the_time_a_run_takes_outside_its_adapter_is_what_recovery_allows_for():
    """Stale-run recovery adds OVERHEAD_SECONDS to the adapter timeout. If a Docker call is added
    or its limit raised without that constant, recovery could take a live run for a lost one and
    remove its containers."""

    class Timed(FakeCli):
        def __init__(self) -> None:
            super().__init__(CliResult(0, GOOD_OUTPUT, b""))
            self.limits: list[tuple[str, float]] = []

        def __call__(self, args, *, timeout=None, stdout_limit=None):
            self.limits.append((args[0], timeout))
            return super().__call__(args, timeout=timeout, stdout_limit=stdout_limit)

    cli = Timed()
    runner = _runner(cli)
    runner.run(_request())
    assert all(limit is not None for _, limit in cli.limits)  # nothing may wait for ever
    around = sum(limit for what, limit in cli.limits if what != "start")
    assert around == OVERHEAD_SECONDS == 660
    assert dict(cli.limits)["start"] == runner.settings.adapter_timeout_seconds


@pytest.mark.parametrize("rm_fails", [True, False])
def test_the_containers_are_removed_even_if_the_env_file_cannot_be_deleted(monkeypatch, rm_fails):
    """After a timeout the adapter may live on. A failure to delete the env file must not skip
    the removal, nor hide that the removal failed."""
    from khandaq.adapters import docker

    class Cli(FakeCli):
        def __call__(self, args, *, timeout=None, stdout_limit=None):
            if args[0] == "rm" and rm_fails:
                self.calls.append(list(args))
                return CliResult(1, b"", b"permission denied")
            return super().__call__(args, timeout=timeout, stdout_limit=stdout_limit)

    real_unlink = os.unlink

    def unlink(path):
        real_unlink(path)  # the file does go; the call still reports an error
        raise OSError("read-only file system")

    monkeypatch.setattr(docker.os, "unlink", unlink)
    cli = Cli(RunnerError("adapter did not finish within 600s"))
    with pytest.raises(LeftoversError if rm_fails else OSError):
        _runner(cli).run(_request())
    assert cli.cleaned_up()  # all three removals were tried


# --- pacing (spec 032) ----------------------------------------------------------------------------

PACED = dataclasses.replace(MANIFEST, forwarder_paced=True)


def _paced_request(rate: object) -> dict:
    request = _request()
    request["params"] = {"rate_per_minute": rate}
    return request


def _forwarder(manifest: AdapterManifest, request: dict) -> list[str]:
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    DockerRunner(manifest, SETTINGS, cli=cli, resolver=lambda host, port: ["203.0.113.7"]).run(
        request
    )
    return cli.find("run", "--detach")


@pytest.mark.parametrize(("rate", "flag"), [(60, "60.0"), (0.5, "0.5")])
def test_forwarder_is_paced_for_a_paced_adapter(rate, flag):
    fwd = _forwarder(PACED, _paced_request(rate))
    assert _value(fwd, "--pace-per-minute") == flag
    assert fwd[fwd.index("--connect") + 1] == "203.0.113.7:443"  # still the one checked address


def test_forwarder_is_not_paced_without_a_rate_or_flag():
    assert "--pace-per-minute" not in _forwarder(PACED, _request())
    assert "--pace-per-minute" not in _forwarder(MANIFEST, _paced_request(60))


@pytest.mark.parametrize("rate", [0, -1, "60", True, float("inf"), 10**400])
def test_unusable_pace_refuses_the_run(rate):
    cli = FakeCli(CliResult(0, GOOD_OUTPUT, b""))
    runner = DockerRunner(PACED, SETTINGS, cli=cli, resolver=lambda host, port: ["203.0.113.7"])
    with pytest.raises(RunnerError, match="cannot be paced"):
        runner.run(_paced_request(rate))
    assert cli.calls == []  # nothing started, and nothing fell back to an unpaced forwarder


# --- leftovers of a lost run (spec 032) -----------------------------------------------------------


class ScriptedCli:
    """Answers each removal by the name of the object it removes."""

    def __init__(self, **answers: CliResult | Exception) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, args, *, timeout=None, stdout_limit=None):
        self.calls.append(list(args))
        answer = self.answers.get(args[-1].split("-")[1], OK)
        if isinstance(answer, Exception):
            raise answer
        return answer


OK = CliResult(0, b"", b"")
ABSENT_CONTAINER = CliResult(1, b"", b"Error response from daemon: No such container: khq-x")
ABSENT_NETWORK = CliResult(1, b"", b"Error response from daemon: network khq-net-x not found")
REMOVALS = [
    ["rm", "--force", "khq-run-run_abc"],
    ["rm", "--force", "khq-fwd-run_abc"],
    ["network", "rm", "khq-net-run_abc"],
]


def test_leftovers_of_a_lost_run_are_removed():
    cli = ScriptedCli()
    assert remove_run_leftovers("run_abc", cli) is True
    assert cli.calls == REMOVALS  # one object per call


def test_leftovers_that_are_already_gone_count_as_removed():
    cli = ScriptedCli(run=ABSENT_CONTAINER, fwd=ABSENT_CONTAINER, net=ABSENT_NETWORK)
    assert remove_run_leftovers("run_abc", cli) is True


@pytest.mark.parametrize(
    "answers",
    [
        {"run": CliResult(1, b"", b"permission denied")},
        {"fwd": CliResult(1, b"", b"permission denied")},
        {"net": CliResult(1, b"", b"network has active endpoints")},
        {"run": RunnerError("adapter did not finish within 60s")},
        {"run": FileNotFoundError("docker"), "fwd": FileNotFoundError("docker")},
        # The adapter is gone, the forwarder cannot be removed: the absence must not hide it.
        {"run": ABSENT_CONTAINER, "fwd": CliResult(1, b"", b"cannot remove: permission denied")},
        {"run": ABSENT_CONTAINER, "fwd": ABSENT_CONTAINER, "net": CliResult(1, b"", b"in use")},
    ],
)
def test_leftovers_that_cannot_be_removed_are_reported(answers):
    cli = ScriptedCli(**answers)
    assert remove_run_leftovers("run_abc", cli) is False
    assert cli.calls == REMOVALS  # every object is still tried after a failure
