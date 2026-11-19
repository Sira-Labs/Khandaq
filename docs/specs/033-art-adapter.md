# Spec 033 — ART adapter (adversarial robustness)

Sprint 8, story S8-2. Depends on: 005 (adapter contract), 020 (mapping table), 025 (the pattern
this follows). Packages: `adapters/art/`, `core/khandaq-core/mappings/`, `api/tests/`,
`.github/workflows/`, `docs/`.

## Goal

Phase 05 (adversarial ML and privacy) gets its first adapter. When this spec is done:

- `adapters/art/` wraps the **Adversarial Robustness Toolbox** (ART, Linux Foundation AI & Data,
  MIT), pinned to **1.20.1**.
- Its wrapper translates the results of ART evasion-robustness evaluations into canonical
  findings: one per attack that changed the model's predictions.
- A contract test runs the wrapper against a fixture recorded from a real ART 1.20.1 run and
  checks every finding against the canonical schema.
- The release workflow publishes `ghcr.io/sira-labs/khandaq-adapter-art`.
- The core mapping table gains the ART evasion family, and the drift test covers the wrapper.

Khandaq adds no attack of its own. ART's published attack classes do the work; the wrapper reads
what ART measured.

As with PyRIT, promptfoo and mcp-scanner before their execution specs, this spec delivers the
parser, the image and the contract. Running ART against a `model_artifact` inside the run sandbox
needs a way to bring the artefact and its evaluation data into a sandbox that has no network
target, and is its own spec (see "Out of scope"). Until then the adapter is not registered, so no
run can be queued for it, and the wrapper fails closed when there are no results.

## User story

As an assessor of a classifier I am authorised to test, I get ART's robustness results in the
same inbox and report as my other findings, mapped to MITRE ATLAS and the NIST AI RMF, with ART's
own numbers as evidence.

## Interface

- **Manifest** `adapters/art/adapter.yaml`: `name: art`, `version: "1.20.1"`, image
  `ghcr.io/sira-labs/khandaq-adapter-art:1.20.1`, phase `05-adversarial-ml`, frameworks `atlas`
  and `nist-ai-rmf`, severity table `high`/`medium`/`low`. No `accepts_credential`, no
  `paces_requests`: it reaches no network target.
- **Image**: `python:3.12-slim` with `adversarial-robustness-toolbox==1.20.1`, `packaging` (ART
  1.20.1 imports it without declaring it) and the wrapper.
- **Results** `art-results.jsonl` in the evidence directory, one line per evaluated attack, closed
  by a completion record:

  ```json
  {"art_version": "1.20.1", "family": "evasion", "attack": "FastGradientMethod",
   "attack_module": "art.attacks.evasion.fast_gradient",
   "params": {"norm": "inf", "eps": 0.3, "targeted": false},
   "estimator": "ScikitlearnLogisticRegression", "samples": 200,
   "clean_accuracy": 0.845, "adversarial_accuracy": 0.155, "success_rate": 1.0}
  {"khandaq": "completion", "results": 1}
  ```

  - `attack` and `attack_module` are the ART class and its module; `params` are the values of
    the class's own `attack_params`.
  - `success_rate` is ART's own measure, `art.utils.compute_success`: for an untargeted attack
    the share of the samples whose prediction the attack changed, for a targeted one the share
    that reached the target class.
  - `clean_accuracy` and `adversarial_accuracy` are the estimator's accuracy on the same
    `samples` before and after `attack.generate`. They are context for the reader. They do not
    decide: on a two-class model an attack that flips every prediction also "corrects" the
    samples the model had wrong, so the accuracy drop understates what the attack did (seen on
    the recorded run: every prediction changed, accuracy fell from 0.845 to 0.155).
- **Wrapper** `adapters/art/wrap.py`: `parse_report(lines, *, engagement_id, run_id, target_ref)`
  and `main(request_path, evidence)`.
- **Mapping table** (`builtin.json`): `art.evasion` → ATLAS `AML.T0015` (evade the model) and
  `AML.T0043` (craft adversarial data), NIST AI RMF `MEASURE-2.7`. No bare `art` default: a family
  nobody curated stays unmapped, as for garak and mcp-scanner.

## Behaviour

1. **What is a finding.** ART's `success_rate` decides. Above 0 the attack changed at least one
   prediction and the result is a finding; at 0 it is not.
2. **Severity** from `success_rate`, with the thresholds the garak adapter uses for a failure
   rate: `≥ 0.5` high, `≥ 0.2` medium, above 0 low.
3. **Identity.** `rule_id` is `art.<family>.<attack class, lower case>`, for example
   `art.evasion.fastgradientmethod`; the location is the attack's qualified name. The same attack
   with other parameters is the same finding (spec 003 deduplicates; the highest severity wins).
   The title carries the numbers and the main parameters.
4. **Only what is curated.** `family` must be `evasion`, and `attack_module` must lie under
   `art.attacks.evasion`. Anything else fails the run: the wrapper does not guess what a privacy
   or poisoning result means.
5. **Fail closed** (exit 2, no `findings.jsonl`), as the other wrappers do:
   - no results file, a line that is not a JSON object, a result after the completion record;
   - no completion record, or one whose count differs from the results read;
   - no results at all;
   - a `success_rate` or an accuracy that is not a number between 0 and 1, `samples` that is not
     a positive integer, a missing attack name;
   - an `art_version` other than the pinned one.
6. **Target.** `target_ref` is the `model_artifact`'s digest from the run request (its location
   when it has no digest). The wrapper reads nothing else of the request.
7. **Invariants.** The adapter opens no network connection and adds no attack, perturbation or
   payload: the image holds ART as published and a parser. The scope lock, the audit log and the
   ledger are not touched.

## Acceptance criteria

- [x] `Dockerfile` pins ART to `1.20.1`; `make contract-test` passes against the recorded fixture.
- [x] Every finding validates against `finding.schema.json`, has phase `05-adversarial-ml` and
      carries the `art.evasion` mappings.
- [x] An attack with a `success_rate` above 0 is a finding with the severity that rate gives; one
      at 0 is skipped.
- [x] Every fail-closed case in Behaviour 5 raises `ReportError`, and `main` exits 2 without
      writing `findings.jsonl`.
- [x] The core table maps `art.evasion.*`; a family nobody curated is unmapped; the drift test
      covers the wrapper.
- [x] `adapters/art/adapter.yaml` passes the manifest validation; the release workflow builds the
      image; the adapter is **not** in the run registry.

## Test cases

Contract (`adapters/art/tests/test_contract.py`): `test_fixture_findings_are_schema_valid`,
`test_severity_follows_the_success_rate`, `test_an_attack_without_effect_is_skipped`,
`test_the_same_attack_is_one_rule_whatever_its_parameters`, `test_fail_closed` (the table of
Behaviour 5), `test_only_the_evasion_family_is_read`, `test_main_writes_findings_or_exits_2`,
`test_the_target_is_named_by_its_digest`.
Unit (`api/tests/test_mapping_drift.py`): the ART family joins the drift cases;
`test_an_uncurated_art_family_is_unmapped`.
Unit (`api/tests/test_adapter_registry.py`): `test_art_is_not_runnable_yet`.
Security: no test here needs a network or a model; the fixture is synthetic (see below).

## The fixture

`adapters/art/fixtures/art-results.jsonl` was recorded on 2026-11-18 with ART 1.20.1,
scikit-learn 1.9.1 and NumPy 2.5.5: a logistic-regression classifier trained on
`sklearn.datasets.make_classification` data (synthetic, seeded), wrapped in ART's scikit-learn
estimator, evaluated on 200 held-out samples with `FastGradientMethod` (twice, a large and a
negligible `eps`), `ProjectedGradientDescent` and the black-box `HopSkipJump`. No real model, no
real data and no third party were involved.

## Out of scope

- **Running ART in the sandbox** (next spec of sprint 8): how a `model_artifact` and a `dataset`
  reach a sandbox without a network target (fetch by the worker, digest check against the scope,
  hand-over into the container), which estimators are loaded, and registering the adapter.
- Privacy attacks (membership inference, attribute inference), extraction and poisoning results:
  each needs its own meaning of "finding" and its own mapping.
- TextAttack and ML Privacy Meter (phase 05, later).
