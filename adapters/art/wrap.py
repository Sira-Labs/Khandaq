#!/usr/bin/env python3
"""ART adapter wrapper (spec 033).

Khandaq orchestrates the Adversarial Robustness Toolbox (Linux Foundation AI & Data, MIT); it does
not reimplement it (ADR-0001). This wrapper translates the results of ART's published evasion
attacks, as ART itself measured them, into canonical Khandaq findings. It contains no attack, no
perturbation and no payload of its own, and it opens no network connection.

In the run sandbox (spec 035) it is handed a stored model and a stored dataset on standard input,
in a container without any network. It loads them from formats that cannot run code (skops with
no extra trusted types, ``.npz`` without pickles), calls the ART attack classes the operator chose
from a fixed table with the numbers the operator gave, and records what ART measured. The parser
is contract-tested against a fixture recorded from a real ART run on a synthetic model.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import sys
import tarfile
from pathlib import Path
from typing import IO

VERSION = "1.20.1"
PHASE = "05-adversarial-ml"
REPORT_NAME = "art-results.jsonl"

# ART attack family → framework ids (extends the core mapping table; ADR-0012). Only what is
# curated here is read: a family without an entry fails the run instead of being guessed at.
FAMILY_FRAMEWORKS = {
    "evasion": [
        ("atlas", "AML.T0015"),
        ("atlas", "AML.T0043"),
        ("nist-ai-rmf", "MEASURE-2.7"),
    ],
}
# The ART package each family's attack classes live in.
FAMILY_MODULE = {"evasion": "art.attacks.evasion"}

# Parameters worth a place in the title, in this order, when the attack has them.
_TITLE_PARAMS = ("eps", "norm", "max_iter", "targeted")


class ReportError(ValueError):
    """The ART results cannot be trusted as a complete account of the run. The wrapper exits
    non-zero rather than emit a partial or empty finding set that would read as "clean"."""


def _severity(success_rate: float) -> str | None:
    """Severity from ART's success rate, with the thresholds garak's failure rate uses."""
    if success_rate >= 0.5:
        return "high"
    if success_rate >= 0.2:
        return "medium"
    if success_rate > 0:
        return "low"
    return None  # the attack changed no prediction → not a finding


def _fraction(rec: dict, key: str, line: int) -> float:
    """A number between 0 and 1; anything else is a ReportError."""
    value = rec.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"line {line}: {key!r} is not a number: {value!r}")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ReportError(f"line {line}: {key!r} is not between 0 and 1: {value!r}")
    return float(value)


def _text(rec: dict, key: str, line: int) -> str:
    value = rec.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReportError(f"line {line}: {key!r} is missing")
    return value.strip()


def _title(attack: str, rec: dict, rate: float, clean: float, adversarial: float) -> str:
    params = rec.get("params") if isinstance(rec.get("params"), dict) else {}
    shown = ", ".join(f"{k}={params[k]}" for k in _TITLE_PARAMS if k in params)
    targeted = params.get("targeted") is True
    what = "reached the target class on" if targeted else "changed the prediction of"
    return (
        f"ART: {attack}{f' ({shown})' if shown else ''} {what} {rate:.1%} of "
        f"{rec['samples']} samples; accuracy {clean:.3f} → {adversarial:.3f}"
    )[:200]


def _finding(rec: dict, line: int, *, engagement_id: str, run_id: str, target_ref: str):
    """The canonical finding for one ART result, or ``None`` when the attack had no effect."""
    if rec.get("art_version") != VERSION:
        raise ReportError(
            f"line {line}: the result is from ART {rec.get('art_version')!r}, not {VERSION}"
        )
    family = _text(rec, "family", line).lower()
    if family not in FAMILY_FRAMEWORKS:
        raise ReportError(f"line {line}: ART family {family!r} is not one this adapter reads")
    attack = _text(rec, "attack", line)
    module = _text(rec, "attack_module", line)
    package = FAMILY_MODULE[family]
    if module != package and not module.startswith(package + "."):
        raise ReportError(f"line {line}: {module!r} is not an ART {family} attack")
    samples = rec.get("samples")
    if isinstance(samples, bool) or not isinstance(samples, int) or samples <= 0:
        raise ReportError(f"line {line}: 'samples' is not a positive integer: {samples!r}")
    rate = _fraction(rec, "success_rate", line)
    clean = _fraction(rec, "clean_accuracy", line)
    adversarial = _fraction(rec, "adversarial_accuracy", line)
    severity = _severity(rate)
    if severity is None:
        return None
    qualified = f"{package}.{attack}"
    return {
        "schema": "khandaq.finding/2",
        "engagement_id": engagement_id,
        "run_id": run_id,
        "rule_id": f"art.{family}.{attack.lower()}",
        "title": _title(attack, rec, rate, clean, adversarial),
        "severity": severity,
        "confidence": "confirmed",  # ART measured it on the model itself
        "source": {"tool": "art", "version": VERSION, "native_severity": severity},
        "target_ref": target_ref,
        "locations": [{"logicalLocations": [{"fullyQualifiedName": qualified}]}],
        "x-khandaq": {
            "phase": PHASE,
            "mappings": [{"framework": f, "id": i} for f, i in FAMILY_FRAMEWORKS[family]],
            "evidence": [],
        },
    }


def parse_report(
    report_lines: list[str], *, engagement_id: str, run_id: str, target_ref: str
) -> list[dict]:
    """Translate ART results into canonical findings, one per attack that changed a prediction.

    Each line is one evaluated attack (spec 033); the file is closed by ``{"khandaq":
    "completion", "results": N}``. Fails closed: a line that is not a JSON object, a result after
    the completion record, a missing or mismatched completion record (ART crashed or was killed
    mid-run), an empty run, or a result that is malformed or not from the pinned ART version
    raises ReportError.
    """
    findings: list[dict] = []
    results = 0
    declared: int | None = None
    for n, line in enumerate(report_lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReportError(f"line {n} is not valid JSON (truncated results?): {exc}") from exc
        if not isinstance(rec, dict):
            raise ReportError(f"line {n} is not a JSON object")
        if rec.get("khandaq") == "completion":
            if declared is not None:
                raise ReportError(f"line {n}: a second completion record")
            count = rec.get("results")
            if isinstance(count, bool) or not isinstance(count, int):
                raise ReportError(f"line {n}: completion record has no result count")
            declared = count
            continue
        if declared is not None:
            raise ReportError(f"line {n}: a result after the completion record")
        results += 1
        finding = _finding(
            rec, n, engagement_id=engagement_id, run_id=run_id, target_ref=target_ref
        )
        if finding is not None:
            findings.append(finding)
    if declared is None:
        raise ReportError("the results have no completion record: ART did not finish the run")
    if declared != results:
        raise ReportError(f"the completion record declares {declared} results, found {results}")
    if results == 0:
        raise ReportError("the results are empty: no attack was evaluated")
    return findings


def target_ref(request: dict) -> str:
    """The model artefact the results are about: its digest, or its location without one."""
    spec = (request.get("target") or {}).get("spec") or {}
    for key in ("digest", "location"):
        value = spec.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "target"


def translate(request: dict, evidence: Path) -> int:
    """Translate the ART results in ``evidence`` into ``findings.jsonl``.

    Returns non-zero, and leaves no findings file, when the results are missing, incomplete or
    unreadable: a run that produced no trustworthy results must surface as a failed run, never as
    a run with zero findings.
    """
    report = evidence / REPORT_NAME
    findings_file = evidence / "findings.jsonl"
    # Findings of an earlier call must not survive a call that fails: they would describe
    # results this call refused.
    findings_file.unlink(missing_ok=True)
    if not report.is_file():
        print(f"art adapter: {report} is missing; ART did not run", file=sys.stderr)
        return 2
    try:
        findings = parse_report(
            report.read_text().splitlines(),
            engagement_id=request["engagement_id"],
            run_id=request["run_id"],
            target_ref=target_ref(request),
        )
    except ReportError as exc:
        print(f"art adapter: refusing untrustworthy results: {exc}", file=sys.stderr)
        return 2
    findings_file.write_text("".join(json.dumps(f) + "\n" for f in findings))
    return 0


# --- running ART in the sandbox (spec 035) --------------------------------------------------------

INPUT_NAMES = ("model", "dataset")
MAX_ATTACKS = 8
DEFAULT_SAMPLES, MAX_SAMPLES = 200, 5000
MAX_COUNT = 10_000
_NORMS = {1: 1, 2: 2, "inf": math.inf}

# The attacks an operator may choose, and the parameters each takes: all of them ART's own
# published classes and ART's own parameter names. Nothing here describes how an attack works.
#   "number": a finite number above 0; "count": a positive integer up to MAX_COUNT;
#   "norm": 1, 2 or "inf" ("norm2": 2 or "inf", where ART takes no other); "flag": true or
#   false; "count0": a count that may be 0.
ATTACKS: dict[str, dict[str, str]] = {
    "FastGradientMethod": {
        "eps": "number",
        "eps_step": "number",
        "norm": "norm",
        "num_random_init": "count0",
        "minimal": "flag",
        "batch_size": "count",
    },
    "ProjectedGradientDescent": {
        "eps": "number",
        "eps_step": "number",
        "norm": "norm",
        "max_iter": "count",
        "num_random_init": "count0",
        "batch_size": "count",
    },
    "HopSkipJump": {
        "norm": "norm2",
        "max_iter": "count",
        "max_eval": "count",
        "init_eval": "count",
        "init_size": "count",
        "batch_size": "count",
    },
}


class RequestError(ValueError):
    """The request or its inputs cannot be turned into an ART evaluation; the run fails before
    ART is called."""


def load_request(environ: dict[str, str], fallback: Path) -> dict:
    """The run request from ``KHANDAQ_RUN_REQUEST`` (the sandbox contract), else from a file."""
    raw = environ.get("KHANDAQ_RUN_REQUEST")
    if raw is None:
        if not fallback.is_file():
            raise RequestError("no run request: KHANDAQ_RUN_REQUEST is not set")
        raw = fallback.read_text()
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RequestError(f"the run request is not JSON: {exc}") from exc
    if not isinstance(request, dict) or not isinstance(request.get("target"), dict):
        raise RequestError("the run request has no target")
    return request


def _value(kind: str, name: str, value: object) -> object:
    """``value`` as ART takes it, or a RequestError naming the parameter."""
    shown = (
        value if isinstance(value, (bool, float, str)) or value is None else type(value).__name__
    )
    problem = RequestError(f"parameter {name!r} is not a valid {kind.rstrip('02')}: {shown!r}")
    if kind == "flag":
        if not isinstance(value, bool):
            raise problem
        return value
    if kind in ("norm", "norm2"):
        allowed = _NORMS if kind == "norm" else {2: 2, "inf": math.inf}
        # The type first: an unhashable value cannot even be looked up.
        if isinstance(value, bool) or not isinstance(value, (int, str)) or value not in allowed:
            raise problem
        return allowed[value]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise problem
    if kind in ("count", "count0"):
        least = 0 if kind == "count0" else 1
        if not isinstance(value, int) or not least <= value <= MAX_COUNT:
            raise problem
        return value
    try:
        number = float(value)  # an integer too large for a float is no number ART can take
    except OverflowError:
        raise problem from None
    if not math.isfinite(number) or number <= 0:
        raise problem
    return number


def chosen_attacks(params: dict) -> list[tuple[str, dict]]:
    """The attacks the run asks for, each checked against ``ATTACKS``. Default: one
    ``FastGradientMethod`` with ART's own defaults."""
    wanted = params.get("attacks", [{"name": "FastGradientMethod"}])
    if not isinstance(wanted, list) or not 1 <= len(wanted) <= MAX_ATTACKS:
        raise RequestError(f"'attacks' must be a list of 1 to {MAX_ATTACKS} attacks")
    chosen: list[tuple[str, dict]] = []
    for entry in wanted:
        if not isinstance(entry, dict) or set(entry) - {"name", "params"}:
            raise RequestError("an attack is {'name': ..., 'params': {...}}")
        name = entry.get("name")
        if not isinstance(name, str) or name not in ATTACKS:
            raise RequestError(f"attack {name!r} is not one of {sorted(ATTACKS)}")
        given = entry.get("params", {})
        if not isinstance(given, dict):
            raise RequestError(f"the parameters of {name} must be an object")
        unknown = sorted(set(given) - set(ATTACKS[name]))
        if unknown:
            raise RequestError(f"{name} takes no parameter {unknown}")
        chosen.append((name, {k: _value(ATTACKS[name][k], k, v) for k, v in given.items()}))
    return chosen


def sample_count(params: dict) -> int:
    samples = params.get("samples", DEFAULT_SAMPLES)
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= MAX_SAMPLES:
        raise RequestError(f"'samples' must be an integer from 1 to {MAX_SAMPLES}")
    return samples


def read_inputs(stream: IO[bytes], request: dict, scratch: Path) -> dict[str, Path]:
    """Unpack the hand-over tar: exactly ``model`` and ``dataset``, regular files, each of the
    size the request declares. Anything else is refused before a byte of it is interpreted."""
    declared = request.get("inputs")
    if not isinstance(declared, dict) or set(declared) != set(INPUT_NAMES):
        raise RequestError("the run request does not declare the inputs 'model' and 'dataset'")
    scratch.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                name = member.name
                if name not in INPUT_NAMES or name in paths or not member.isfile():
                    raise RequestError(f"unexpected input {name!r}")
                size = (declared[name] or {}).get("bytes")
                if isinstance(size, bool) or not isinstance(size, int) or member.size != size:
                    raise RequestError(f"input {name!r} is not the size the request declares")
                source = tar.extractfile(member)
                if source is None:
                    raise RequestError(f"input {name!r} cannot be read")
                paths[name] = scratch / name
                seen = hashlib.sha256()
                with open(paths[name], "wb") as target:
                    while chunk := source.read(1024 * 1024):
                        seen.update(chunk)
                        target.write(chunk)
                if "sha256:" + seen.hexdigest() != declared[name].get("sha256"):
                    raise RequestError(f"input {name!r} is not the content the request declares")
    except tarfile.TarError as exc:
        raise RequestError(f"the inputs are not a tar archive: {exc}") from exc
    if set(paths) != set(INPUT_NAMES):
        raise RequestError("the inputs 'model' and 'dataset' are not both there")
    return paths


def load_model(path: Path):
    """The scikit-learn estimator in a skops file. ``trusted=[]``: a file that needs any type
    beyond skops's own default list is refused, and nothing in it is ever unpickled."""
    import skops.io
    from skops.io.exceptions import UntrustedTypesFoundException

    try:
        return skops.io.load(path, trusted=[])
    except UntrustedTypesFoundException:
        # Not their names: they are text from the file, and this message is recorded.
        raise RequestError("the model needs types that are not trusted; it is not loaded") from None
    except Exception as exc:  # skops raises many types for a file that is not a skops file
        raise RequestError(f"the model is not a skops file: {type(exc).__name__}") from exc


def load_dataset(path: Path, samples: int):
    """``x`` and ``y`` from an ``.npz``, the first ``samples`` rows. No pickles."""
    import numpy as np

    try:
        with np.load(path, allow_pickle=False) as data:
            if "x" not in data.files or "y" not in data.files:
                raise RequestError("the dataset needs the arrays 'x' and 'y'")
            x, y = data["x"], data["y"]
    except RequestError:
        raise
    except Exception as exc:  # not an .npz, or one that needs pickle
        raise RequestError(f"the dataset is not a plain .npz: {type(exc).__name__}") from exc
    if not isinstance(x, np.ndarray) or not isinstance(y, np.ndarray):
        raise RequestError("the dataset's 'x' and 'y' must be arrays")
    if x.ndim != 2 or y.ndim != 1 or len(x) != len(y) or len(x) == 0:
        raise RequestError("the dataset needs a 2-D 'x' and a 1-D 'y' of the same length")
    # Real numbers only: a complex 'x' would lose its imaginary part without a word.
    if x.dtype.kind not in "iuf":
        raise RequestError("the dataset's 'x' must be real numbers")
    with np.errstate(over="ignore"):
        rows = x[:samples].astype(np.float32)
    if not np.isfinite(rows).all():  # after the cast: 1e300 is finite as float64 only
        raise RequestError("the dataset's 'x' must be finite numbers that fit 32-bit floats")
    return rows, y[:samples]


def _plain(value: object) -> object:
    """A parameter value as it goes into the results (JSON)."""
    import numpy as np

    if isinstance(value, (np.floating, np.integer)):
        value = value.item()
    if isinstance(value, float) and math.isinf(value):
        return "inf"
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return str(value)


def evaluate(request: dict, model_path: Path, dataset_path: Path) -> list[dict]:
    """Run the chosen ART attacks on the model and return one result per attack, in the
    spec-033 format: what was run, with which parameters, and what ART measured."""
    params = request.get("params") or {}
    attacks = chosen_attacks(params)
    x, y = load_dataset(dataset_path, sample_count(params))
    model = load_model(model_path)

    import art
    import art.attacks.evasion as evasion
    import numpy as np
    from art.estimators.classification import SklearnClassifier
    from art.utils import compute_success

    if art.__version__ != VERSION:
        raise RequestError(f"this image holds ART {art.__version__}, not the pinned {VERSION}")
    classes = getattr(model, "classes_", None)
    if classes is None:
        raise RequestError("the model is not a fitted classifier")
    known = {label.item() if hasattr(label, "item") else label for label in classes}
    # ART's scikit-learn wrapper reads a prediction as a class index wherever the model has no
    # probabilities (a LinearSVC, for one). With other labels (-1 and 1, say) it would measure
    # a different model than the one uploaded, silently: such a model is refused.
    if any(isinstance(label, bool) or not isinstance(label, int) for label in known) or sorted(
        known
    ) != list(range(len(known))):
        raise RequestError("the model's classes must be the integers 0 to n-1")
    labels = [label.item() if hasattr(label, "item") else label for label in y]
    if not set(labels) <= known:
        raise RequestError("the dataset has labels the model does not know")
    try:
        estimator = SklearnClassifier(model=model, clip_values=(float(x.min()), float(x.max())))
    except Exception as exc:  # ART refuses estimators it has no wrapper for
        raise RequestError(f"ART does not accept this estimator: {type(exc).__name__}") from exc
    index = {label: position for position, label in enumerate(sorted(known))}
    positions = np.array([index[label] for label in labels])
    one_hot = np.eye(len(known))[positions]

    def accuracy(samples) -> float:
        return float((np.argmax(estimator.predict(samples), axis=1) == positions).mean())

    def refused(what: str, exc: Exception) -> RequestError:
        # The type only: the message of a library error can quote the data.
        return RequestError(f"{what}: {type(exc).__name__}")

    try:
        clean = accuracy(x)
    except Exception as exc:  # e.g. rows of another width than the model was fitted on
        raise refused("the model cannot predict on this dataset", exc) from None
    results: list[dict] = []
    for name, given in attacks:
        cls = getattr(evasion, name)
        quiet = {"verbose": False} if "verbose" in cls.attack_params else {}
        try:
            attack = cls(estimator, **given, **quiet)
            adversarial = attack.generate(x=x)
            adversarial_accuracy = accuracy(adversarial)
            success = float(compute_success(estimator, x, one_hot, adversarial))
        except Exception as exc:  # ART refuses a combination of estimator and parameters
            raise refused(
                f"ART could not run {name} on this model with these parameters", exc
            ) from None
        results.append(
            {
                "art_version": art.__version__,
                "family": "evasion",
                "attack": cls.__name__,
                "attack_module": cls.__module__,
                "params": {
                    key: _plain(getattr(attack, key))
                    for key in cls.attack_params
                    if key not in ("summary_writer", "verbose") and hasattr(attack, key)
                },
                "estimator": type(estimator).__name__,
                "samples": int(len(x)),
                "clean_accuracy": round(clean, 6),
                "adversarial_accuracy": round(adversarial_accuracy, 6),
                "success_rate": round(success, 6),
            }
        )
    return results


def write_results(results: list[dict], evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(result) for result in results]
    lines.append(json.dumps({"khandaq": "completion", "results": len(results)}))
    (evidence / REPORT_NAME).write_text("\n".join(lines) + "\n")


def write_tar(evidence: Path, out: IO[bytes]) -> None:
    """The sandbox output contract (spec 012): one uncompressed tar of ``evidence`` on stdout."""
    with tarfile.open(fileobj=out, mode="w|") as tar:
        for path in sorted(evidence.iterdir()):
            tar.add(path, arcname=path.name)


def main(
    request_path: Path = Path("/run-request.json"),
    evidence: Path = Path("/evidence"),
    scratch: Path = Path("/tmp/art"),
    stdin: IO[bytes] | None = None,
    out: IO[bytes] | None = None,
) -> int:
    """Sandbox entrypoint: read the request and the inputs, run ART, translate its results, and
    emit the evidence tar on standard output (only on success)."""
    # Standard output carries the evidence tar and nothing else. Whatever a library prints while
    # the model is loaded and evaluated (a model stored with `verbose` set reports its progress
    # there) goes to standard error instead; the tar is written to the real stream afterwards.
    archive = out or sys.stdout.buffer
    source = stdin or sys.stdin.buffer
    with contextlib.redirect_stdout(sys.stderr):
        try:
            request = load_request(dict(os.environ), request_path)
            inputs = read_inputs(source, request, scratch)
            results = evaluate(request, inputs["model"], inputs["dataset"])
        except RequestError as exc:
            print(f"art adapter: {exc}", file=sys.stderr)
            return 2
        write_results(results, evidence)
        code = translate(request, evidence)
    if code == 0:
        write_tar(evidence, archive)
    return code


if __name__ == "__main__":
    sys.exit(main())
