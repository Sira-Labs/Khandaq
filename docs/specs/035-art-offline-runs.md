# Spec 035 — ART runs on stored content, in a sandbox without network

Sprint 8, story S8-4. Depends on: 012 (sandbox, ADR-0009), 033 (the ART adapter's parser), 034
(stored content of `model_artifact` and `dataset` targets). Packages: `api/src/khandaq/`,
`adapters/art/`, `api/tests/`, `.github/workflows/`, `docs/`.

## Goal

Phase 05 becomes runnable. When this spec is done:

- An operator starts an `art` run on a `model_artifact` target and names a `dataset` target for
  the evaluation data. Both must be in scope and both must have their content stored (spec 034).
- The worker hands the two verified contents to the pinned ART image in a container that has
  **no network at all**, and gets back ART's results and the canonical findings.
- The wrapper drives ART's own published evasion attacks on the model, as the operator chose
  them from a fixed list, and records what ART measured. Khandaq adds no attack.
- `art` is in the run registry.

## User story

As an assessor of a classifier I am authorised to test, I run ART's robustness evaluation on the
exact model file and evaluation data the statement of work names, without either leaving the
Khandaq deployment, and I get the result in the same inbox as my other findings.

## Interface

- **Manifest flag** `offline` (`AdapterManifest.offline`, `adapter.yaml`): the adapter reaches no
  network and takes the stored content of its targets as input. `art`: `offline: true`,
  `paces_requests: true` (it sends nothing, so no rate can be exceeded). The scope lock is
  unchanged: under a rate cap it wants `rate_per_minute` from every run, this one included.
- **Run parameters** for `art`:
  - `dataset_target_id` (required): a `dataset` target of the same engagement.
  - `samples` (optional, default `200`, `1`–`5000`): how many rows of the dataset are used, from
    the start.
  - `attacks` (optional): a list of at most 8 entries `{"name": …, "params": {…}}`. Default:
    `[{"name": "FastGradientMethod"}]` with ART's own defaults. Allowed names and parameters:

    | name | parameters |
    |---|---|
    | `FastGradientMethod` | `eps`, `eps_step`, `norm`, `num_random_init`, `minimal`, `batch_size` |
    | `ProjectedGradientDescent` | `eps`, `eps_step`, `norm`, `max_iter`, `num_random_init`, `batch_size` |
    | `HopSkipJump` | `norm`, `max_iter`, `max_eval`, `init_eval`, `init_size`, `batch_size` |

    `norm` is `1`, `2` or `"inf"` (`HopSkipJump`: `2` or `"inf"`, the two ART takes). Every
    attack is untargeted. Numbers must be finite; counts are
    positive integers of at most 10 000.
- **Content formats** (what the wrapper loads; anything else fails the run):
  - model: a scikit-learn estimator saved with **skops** (`skops.io.dump`), loaded with
    `trusted=[]`, so a file that needs any type outside skops's default list is refused. Never
    `pickle`. It must be an estimator ART's `SklearnClassifier` accepts, and its classes must be
    the integers `0` to `n-1`: ART reads the predictions of a model without probabilities as
    class indices, so with other labels it would measure a different model.
  - dataset: a NumPy `.npz` (loaded with `allow_pickle=False`) holding `x` (2-D, finite real
    numbers that fit 32-bit floats) and `y` (1-D, class labels the model knows), of equal length.
- **Run request** (`KHANDAQ_RUN_REQUEST`) gains `inputs`:
  `{"model": {"sha256": …, "bytes": …}, "dataset": {"sha256": …, "bytes": …}}`.
- **Hand-over**: the worker writes one uncompressed tar with the members `model` and `dataset` to
  the container's standard input. No host path is mounted (as before, spec 012).
- **Image**: `adapters/art/requirements.txt` pins `adversarial-robustness-toolbox==1.20.1`,
  `scikit-learn==1.9.1`, `skops==0.16.0`, `numpy==2.5.5`, and `packaging`, `scipy`, `joblib` and
  `threadpoolctl` at the versions the tests ran with; the `Dockerfile` and the CI contract job
  install from it.
- **Audit**: `run.started` gains `inputs: {"model": <digest>, "dataset": <digest>}` for an offline
  run.

## Behaviour

1. **The scope lock decides both targets.** The run's own target is checked as always. The
   dataset target is checked by the same lock with the same parameters, at creation and again at
   the worker's claim. A refusal of either rejects the run and is audited as `run.rejected`; the
   reason for the dataset starts with `dataset:`. The lock itself is unchanged.
2. **The adapter must fit the target.** An `offline` adapter is refused for anything but a
   `model_artifact` target. An adapter that needs a network is refused for a `model_artifact` or
   `dataset` target (before, such a run was queued and failed in the runner).
3. **Content runs only by its digest.** The lock lets a `model_artifact` or `dataset` in when an
   allow rule names its digest **or** its `location`. A location is never fetched or checked by
   Khandaq, so for an offline run that is not enough: the digest of the model and of the dataset
   must each be named by an allow rule of its type. Otherwise a target with an allowed location
   and any digest at all would bring that digest's content into a run. This is an added refusal
   in `runs.py`; `scope.py` is unchanged.
   **Content must be stored.** A model or dataset target without stored content refuses the run,
   with a reason that says which one and what to upload. `dataset_target_id` must name a `dataset`
   target of the same engagement; anything else refuses the run.
4. **Verified again at the start.** The worker reads both contents through `read_artefact`, which
   returns them only if they still match the digests their targets declare. Any failure fails the
   run before a container exists.
5. **No network.** The adapter container is created with `--network none`. No forwarder and no
   per-run network are created for an offline run. Everything else is the spec-012 sandbox:
   read-only root, no capabilities, `nobody`, resource limits, tmpfs scratch, one tar of evidence
   on standard output, an output cap and the adapter timeout.
6. **The wrapper**:
   - reads the request and the tar from standard input, accepting exactly the two members, as
     regular files, of the sizes and SHA-256 digests the request declares;
   - loads the model and the data as described above; a file in another format, an estimator ART
     does not accept, labels the model does not know, or parameters outside the table end the run
     with exit 2 and a message on standard error. The message names what was wrong and, for an
     error raised by a library, only the error's type: text taken from the model or the data
     (the names of untrusted types, for instance) is never repeated, because the message is
     recorded with the run;
   - for each attack calls the ART class with the given parameters, `generate` on the samples,
     and `art.utils.compute_success`, and writes one result line per attack and the completion
     record (the spec-033 format);
   - translates the results with the spec-033 parser and writes the evidence tar only on success.
     Standard output carries the tar and nothing else: what a library prints while the model
     is loaded and evaluated goes to standard error.
7. **Evidence** is `art-results.jsonl`. The model and the data are not copied into the evidence:
   they are already stored, named by digest in the audit entry and the findings' `target_ref`.
8. **Invariants.** The wrapper contains no attack, perturbation or payload of its own: it names
   ART classes and passes numbers. The container cannot reach any host. `scope.py`, `audit.py`
   and the ledger are not modified; no run that the scope lock refuses is allowed by this spec.

## Acceptance criteria

- [x] `art` is registered; the registry matches `adapters/art/adapter.yaml`, including `offline`.
- [x] A run whose model or dataset is out of scope, missing, of the wrong type, of another
      engagement or without stored content is rejected and audited; none reaches the runner.
- [x] A network adapter on an artefact target and `art` on a network target are rejected.
- [x] The worker hands the runner exactly the two verified contents; tampered content fails the
      run before any container is created.
- [x] An offline run creates no network and no forwarder, uses `--network none`, and feeds the
      inputs through standard input; the container is removed whatever happened.
- [x] The wrapper evaluates a synthetic skops model on a synthetic `.npz` with ART 1.20.1 and
      emits schema-valid findings; unsafe or malformed inputs and parameters outside the table
      exit 2 without findings.
- [x] `run.started` records the two digests.
- [x] A model or dataset that the scope allows only by its `location` is not run.

## Test cases

Unit (`api/tests/test_adapter_registry.py`): `test_art_is_a_registered_offline_adapter`.
Integration (`api/tests/test_offline_runs.py`, Postgres):
`test_an_offline_run_is_queued_when_both_targets_are_in_scope_and_stored`,
`test_an_offline_run_needs_both_targets_in_scope_and_stored` (the refusal table),
`test_adapters_must_fit_their_target`,
`test_under_a_rate_cap_an_offline_run_declares_a_rate_like_any_other`,
`test_content_allowed_only_by_its_location_is_not_run`,
`test_the_builtin_adapter_still_runs_on_any_target_in_scope`,
`test_the_claim_checks_the_dataset_again`,
`test_the_worker_hands_over_the_verified_contents_and_audits_their_digests`,
`test_tampered_content_fails_the_run_before_the_runner`.
Unit (`api/tests/test_docker_runner.py`): `test_an_offline_run_has_no_network_and_takes_its_inputs_on_stdin`,
`test_an_offline_run_is_cleaned_up_whatever_happened`,
`test_an_offline_adapter_without_inputs_is_refused`,
`test_an_offline_container_that_cannot_be_created_or_removed`,
`test_the_real_cli_feeds_standard_input_without_a_file_on_disk`.
Adapter (`adapters/art/tests/test_run.py`, with the pinned ART installed):
`test_a_synthetic_model_is_evaluated_and_translated`, `test_the_chosen_attacks_and_parameters_reach_art`,
`test_parameters_outside_the_table_are_refused`, `test_inputs_that_are_not_what_they_claim_are_refused`
(a pickle, a truncated file, an `.npz` with objects, unknown labels, an extra tar member, an
oversized member), `test_main_reads_stdin_and_writes_the_evidence_tar`.
Security: the refusal table and the tamper tests above; every model and dataset is synthetic.

## Out of scope

- Estimators other than scikit-learn (PyTorch, TensorFlow, XGBoost) and other model formats.
- Targeted attacks, and ART's privacy, extraction and poisoning families (spec 033).
- A console form for the `art` parameters and the upload.
- Pacing forwarder interplay (spec 032, not merged): an offline run starts no forwarder.
