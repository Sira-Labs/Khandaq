"""The ART adapter in the sandbox (spec 035): the wrapper runs the pinned ART on a model and a
dataset it is handed on standard input.

These tests need what the image holds (``adapters/art/requirements.txt``); CI installs it. Every
model and dataset here is synthetic: a seeded scikit-learn classifier on generated data.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pickle
import tarfile
from pathlib import Path

import jsonschema
import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("art")
skops_io = pytest.importorskip("skops.io")
from sklearn.datasets import make_classification  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.svm import LinearSVC  # noqa: E402

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent
REPO = HERE.parents[2]
SCHEMA = json.loads((REPO / "core/khandaq-core/schema/finding.schema.json").read_text())

_spec = importlib.util.spec_from_file_location("art_wrap_run", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _synthetic() -> tuple[bytes, bytes]:
    """A seeded two-class classifier as a skops file, and held-out rows as an .npz."""
    x, y = make_classification(
        n_samples=700, n_features=12, n_informative=8, n_classes=2, random_state=7
    )
    x = (x - x.min(0)) / (x.max(0) - x.min(0))
    model = LogisticRegression(max_iter=500).fit(x[:500], y[:500])
    data = io.BytesIO()
    np.savez(data, x=x[500:], y=y[500:])
    return skops_io.dumps(model), data.getvalue()


MODEL, DATASET = _synthetic()


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _request(model: bytes = MODEL, dataset: bytes = DATASET, **params: object) -> dict:
    return {
        "run_id": "run_1",
        "engagement_id": "eng_1",
        "target": {"type": "model_artifact", "spec": {"digest": _digest(model)}},
        "params": params,
        "inputs": {
            "model": {"sha256": _digest(model), "bytes": len(model)},
            "dataset": {"sha256": _digest(dataset), "bytes": len(dataset)},
        },
    }


def _tar(members: dict[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    buffer.seek(0)
    return buffer


def _main(tmp_path, monkeypatch, request, members) -> tuple[int, bytes, Path]:
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(request))
    out = io.BytesIO()
    evidence = tmp_path / "evidence"
    code = wrap.main(
        tmp_path / "none.json", evidence, tmp_path / "scratch", stdin=_tar(members), out=out
    )
    return code, out.getvalue(), evidence


def _files(tar_bytes: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}


def _evaluate(tmp_path, request: dict, model: bytes = MODEL, dataset: bytes = DATASET):
    (tmp_path / "model").write_bytes(model)
    (tmp_path / "dataset").write_bytes(dataset)
    return wrap.evaluate(request, tmp_path / "model", tmp_path / "dataset")


def test_main_reads_stdin_and_writes_the_evidence_tar(tmp_path, monkeypatch):
    request = _request(attacks=[{"name": "FastGradientMethod", "params": {"eps": 0.3}}])
    code, out, _ = _main(tmp_path, monkeypatch, request, {"model": MODEL, "dataset": DATASET})
    assert code == 0
    files = _files(out)
    assert set(files) == {"art-results.jsonl", "findings.jsonl"}
    results = [json.loads(line) for line in files["art-results.jsonl"].splitlines()]
    assert results[-1] == {"khandaq": "completion", "results": 1}
    assert results[0]["art_version"] == "1.20.1" and results[0]["samples"] == 200
    findings = [json.loads(line) for line in files["findings.jsonl"].splitlines()]
    assert len(findings) == 1
    jsonschema.validate(findings[0], SCHEMA)
    assert findings[0]["rule_id"] == "art.evasion.fastgradientmethod"
    assert findings[0]["target_ref"] == _digest(MODEL)


def test_a_synthetic_model_is_evaluated_and_translated(tmp_path):
    """What the wrapper writes is what the spec-033 parser reads, with ART's own numbers."""
    results = _evaluate(tmp_path, _request(samples=120))
    assert [r["attack"] for r in results] == ["FastGradientMethod"]  # the default
    result = results[0]
    assert result["attack_module"] == "art.attacks.evasion.fast_gradient"
    assert result["estimator"] == "ScikitlearnLogisticRegression"
    assert result["samples"] == 120 and result["params"]["eps"] == 0.3  # ART's default
    assert 0 < result["success_rate"] <= 1 and 0.5 < result["clean_accuracy"] <= 1
    lines = [json.dumps(r) for r in results] + ['{"khandaq":"completion","results":1}']
    findings = wrap.parse_report(lines, engagement_id="e", run_id="r", target_ref="t")
    assert len(findings) == 1


def test_the_chosen_attacks_and_parameters_reach_art(tmp_path):
    request = _request(
        samples=40,
        attacks=[
            {"name": "FastGradientMethod", "params": {"eps": 0.05, "norm": 2}},
            {
                "name": "ProjectedGradientDescent",
                "params": {"eps": 0.1, "eps_step": 0.02, "max_iter": 5, "norm": "inf"},
            },
            {"name": "HopSkipJump", "params": {"max_iter": 2, "max_eval": 50, "init_eval": 10}},
        ],
    )
    results = _evaluate(tmp_path, request)
    assert [r["attack"] for r in results] == [
        "FastGradientMethod",
        "ProjectedGradientDescent",
        "HopSkipJump",
    ]
    assert results[0]["params"]["eps"] == 0.05 and results[0]["params"]["norm"] == 2
    assert results[1]["params"]["max_iter"] == 5 and results[1]["params"]["norm"] == "inf"
    assert results[2]["params"]["max_eval"] == 50
    assert all(r["samples"] == 40 and r["params"]["targeted"] is False for r in results)


def test_a_model_without_probabilities_is_measured_as_scikit_learn_measures_it(tmp_path):
    """A LinearSVC on the labels 0 and 1: the clean accuracy ART reports is the model's own."""
    model = LinearSVC().fit(X, Y)
    results = _evaluate(tmp_path, _request(samples=len(X)), skops_io.dumps(model), DATASET)
    assert results[0]["clean_accuracy"] == pytest.approx(model.score(X, Y), abs=1e-6)


@pytest.mark.parametrize(
    "params",
    [
        {"attacks": []},
        {"attacks": [{"name": "FastGradientMethod"}] * 9},
        {"attacks": "FastGradientMethod"},
        {"attacks": [{"name": "CarliniL2Method"}]},  # an ART attack, but not in the table
        {"attacks": [{"name": "FastGradientMethod", "params": {"targeted": True}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"eps": 0}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"eps": float("inf")}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"eps": "0.3"}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"norm": 3}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"minimal": 1}}]},
        {"attacks": [{"name": "ProjectedGradientDescent", "params": {"max_iter": 10_001}}]},
        {"attacks": [{"name": "ProjectedGradientDescent", "params": {"max_iter": 2.5}}]},
        {"attacks": [{"name": "HopSkipJump", "params": {"eps": 0.1}}]},  # not HopSkipJump's
        {"attacks": [{"name": "FastGradientMethod", "extra": 1}]},
        {"attacks": [{"name": "FastGradientMethod", "params": [0.3]}]},
        # Values that are not even the right kind of thing: refused, not a crash.
        {"attacks": [{"name": "FastGradientMethod", "params": {"norm": [1]}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"norm": {"inf": 1}}}]},
        {"attacks": [{"name": "FastGradientMethod", "params": {"eps": 10**400}}]},
        {"attacks": [{"name": "HopSkipJump", "params": {"norm": 1}}]},  # ART takes 2 or inf
        {"samples": 0},
        {"samples": 5001},
        {"samples": True},
        {"samples": "200"},
    ],
)
def test_parameters_outside_the_table_are_refused(tmp_path, monkeypatch, params):
    with pytest.raises(wrap.RequestError):
        _evaluate(tmp_path, _request(**params))
    code, out, evidence = _main(
        tmp_path, monkeypatch, _request(**params), {"model": MODEL, "dataset": DATASET}
    )
    assert code == 2 and out == b"" and not (evidence / "findings.jsonl").exists()


class _Pwned:
    def __reduce__(self):
        return (print, ("code ran while a model was loaded",))


def _npz(**arrays) -> bytes:
    data = io.BytesIO()
    np.savez(data, **arrays)
    return data.getvalue()


def _pickled_npz() -> bytes:
    data = io.BytesIO()
    np.savez(data, x=np.array([[_Pwned()]], dtype=object), y=np.array([0]))
    return data.getvalue()


X = np.load(io.BytesIO(DATASET))["x"]
Y = np.load(io.BytesIO(DATASET))["y"]


def _needs_an_untrusted_type() -> bytes:
    """A well-formed skops file whose estimator carries a function skops does not trust."""
    import os

    from sklearn.preprocessing import FunctionTransformer

    return skops_io.dumps(FunctionTransformer(func=os.getcwd))


def _a_pipeline() -> bytes:
    """A fitted scikit-learn estimator of trusted types that ART has no wrapper for."""
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    pipeline = Pipeline([("scale", StandardScaler()), ("model", LogisticRegression())])
    return skops_io.dumps(pipeline.fit(X, Y))


def _other_labels(model_class, low: int, high: int) -> tuple[bytes, bytes]:
    """A classifier fitted on the labels ``low`` and ``high``, and data with the same labels."""
    labels = np.where(Y == 1, high, low)
    return skops_io.dumps(model_class().fit(X, labels)), _npz(x=X, y=labels)


def _npz_with_a_text_member() -> bytes:
    import zipfile

    data = io.BytesIO(_npz(y=Y))
    with zipfile.ZipFile(data, "a") as archive:
        archive.writestr("x", b"not an array")
    return data.getvalue()


@pytest.mark.parametrize(
    ("model", "dataset", "why"),
    [
        (pickle.dumps(_Pwned()), DATASET, "not a skops file"),
        (MODEL[: len(MODEL) // 2], DATASET, "not a skops file"),
        (b"", DATASET, "not a skops file"),
        (MODEL, _pickled_npz(), "not a plain .npz"),
        (MODEL, b"x,y\n1,0\n", "not a plain .npz"),
        (MODEL, _npz(x=X), "'x' and 'y'"),
        (MODEL, _npz(x=X, y=Y[:-1]), "same length"),
        (MODEL, _npz(x=X[:, 0], y=Y), "2-D 'x'"),
        (MODEL, _npz(x=np.full_like(X, np.nan), y=Y), "finite numbers"),
        (MODEL, _npz(x=X, y=Y + 5), "labels the model does not know"),
        # A real skops file that needs a type beyond skops's own list: this is the trust check.
        (_needs_an_untrusted_type(), DATASET, "types that are not trusted"),
        (_a_pipeline(), DATASET, "ART"),
        (MODEL, _npz(x=X[:, :5], y=Y), "cannot predict on this dataset"),
        (MODEL, _npz(x=X.astype(np.float64) * 1e300, y=Y), "fit 32-bit floats"),
        (MODEL, _npz(x=X.astype(np.complex64) + 1j, y=Y), "real numbers"),
        (MODEL, _npz_with_a_text_member(), "must be arrays"),
        # ART reads predictions of a model without probabilities as class indices: with these
        # labels it would report an accuracy of 0.5 for a model that is right nine times in ten.
        (*_other_labels(LinearSVC, -1, 1), "integers 0 to n-1"),
        (*_other_labels(LinearSVC, 1, 2), "integers 0 to n-1"),
        (*_other_labels(LogisticRegression, -1, 1), "integers 0 to n-1"),
    ],
)
def test_inputs_that_are_not_what_they_claim_are_refused(
    tmp_path, monkeypatch, capsys, model, dataset, why
):
    code, out, evidence = _main(
        tmp_path, monkeypatch, _request(model, dataset), {"model": model, "dataset": dataset}
    )
    captured = capsys.readouterr()
    assert code == 2 and out == b""
    assert why in captured.err
    assert "code ran" not in captured.out + captured.err  # nothing was unpickled
    assert "Traceback" not in captured.err and "getcwd" not in captured.err  # no text of the file
    assert not (evidence / "findings.jsonl").exists()


@pytest.mark.parametrize(
    ("members", "why"),
    [
        ({"model": MODEL}, "not both there"),
        ({"model": MODEL, "dataset": DATASET, "extra": b"x"}, "unexpected input 'extra'"),
        ({"model": MODEL, "../dataset": DATASET}, "unexpected input"),
        ({"model": MODEL + b"\x00", "dataset": DATASET}, "not the size the request declares"),
        ({"model": MODEL[:-1], "dataset": DATASET}, "not the size the request declares"),
        # The declared size, other bytes.
        (
            {"model": MODEL[:-1] + bytes([MODEL[-1] ^ 1]), "dataset": DATASET},
            "not the content the request declares",
        ),
    ],
)
def test_the_hand_over_takes_exactly_the_two_declared_inputs(
    tmp_path, monkeypatch, capsys, members, why
):
    code, out, _ = _main(tmp_path, monkeypatch, _request(), members)
    assert code == 2 and out == b"" and why in capsys.readouterr().err
    assert not (tmp_path / "scratch" / "extra").exists()
    assert not (tmp_path / "dataset").exists()  # nothing was written outside the scratch space


def test_a_request_without_declared_inputs_or_a_broken_tar_is_refused(tmp_path, monkeypatch):
    request = _request()
    del request["inputs"]
    assert _main(tmp_path, monkeypatch, request, {"model": MODEL, "dataset": DATASET})[0] == 2
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(_request()))
    out = io.BytesIO()
    code = wrap.main(
        tmp_path / "none.json",
        tmp_path / "evidence",
        tmp_path / "scratch2",
        stdin=io.BytesIO(b"this is not a tar archive" * 100),
        out=out,
    )
    assert code == 2 and out.getvalue() == b""


def test_the_table_names_only_art_classes_and_their_own_parameters():
    """Each allowed name is an ART evasion class, and each allowed parameter is one of that
    class's own ``attack_params``: the wrapper passes numbers, it defines nothing."""
    import art.attacks.evasion as evasion

    for name, params in wrap.ATTACKS.items():
        cls = getattr(evasion, name)
        assert cls.__module__.startswith("art.attacks.evasion.")
        assert set(params) <= set(cls.attack_params), name
        assert "targeted" not in params
