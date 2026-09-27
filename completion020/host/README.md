# Host tooling

Run commands from the project root after installing the root Python package
(`python -m pip install -e .`), or set `PYTHONPATH=host`. The root
`requirements-tested.txt` records the environment actually validated. This code
does not download datasets, communicate externally, or sign a device firmware
image: its packages contain only the inference model and its preprocessing.

## Local keys and controlled fixtures

```bash
python -m ids_update_lab keygen --output local_keys/experiment1
python -m ids_update_lab demo --private-key local_keys/experiment1/private.pem --output experiments/synthetic1
python -m ids_update_lab export-header --package experiments/synthetic1/release-A.sids --public-key experiments/synthetic1/public.pem --contract experiments/synthetic1/feature_contract.json --data-origin synthetic_plumbing
```

Never commit or distribute `private.pem`. Key generation and experiment generation
refuse existing output directories. The bundled `examples/synthetic_demo` contains
public material only; its corresponding private key is intentionally absent.
Generating new keys requires generating a new model header and rebuilding the
firmware before testing those packages. A package signed by a different key is
supposed to fail.

`export-header` intentionally updates the named build input and metadata directory.
It verifies the package, contract, provenance and package digest before doing so.
The generated header pins the schema, feature count, public key and factory model.
Use separate copied firmware source/build directories when preparing A and B
whole-firmware images. Do not replace a header while a build is running.

## Local TON_IoT training

```bash
python -m ids_update_lab train-ton --csv /path/to/Train_Test_Network.csv --features duration,src_bytes,dst_bytes --units seconds,bytes,bytes --private-key local_keys/experiment1/private.pem --output experiments/ton1
```

This is an example feature list, not an automatic endorsement of a dataset
variant. Confirm the actual column semantics and units first. Input `label` must
mean `0=normal, 1=attack`; the program does not infer label meanings. Features must
be numeric, explicit, finite, and no more than 16. No missing-data imputation or
silent row dropping occurs. Obvious label/attack/identifier columns are blocked,
but reviewing feature provenance remains necessary.

Exact feature vectors are grouped **after float32 conversion** before a seeded
70/15/15 train/validation/test group split. Contradictory labels within a feature
group stop preparation; investigate the data or revise the predeclared feature
set rather than removing difficult cases opportunistically. Exact grouping does
not establish temporal, device, endpoint, or scenario independence. StandardScaler
is fitted on training rows only; logistic hyperparameters are fixed; the threshold
is selected on validation balanced accuracy using a fixed grid. Test labels do
not select the classifier or threshold.

A is the trained float32 release. B represents the same real-arithmetic affine
classifier under deliberately changed normalization. It is a controlled update
fixture, not a newly trained or improved IDS. All three partitions must pass a
pre-export numerical gate: absolute A/B probability error at most `2e-6` and zero
label differences. Do not retune this transformation against test results to force
a desired outcome. If the gate fails, no eligible experiment directory is created.

The export includes signed packages, public key, canonical contract, row/group
split indices, source and artifact hashes, software versions, validation threshold
selection, and per-class host metrics. `golden.jsonl` is a seeded stratified sample
of distinct test groups (default at most 512) for board correctness and latency.
It is not a replacement for the full held-out host evaluation. The explicit
`--data-origin synthetic_plumbing` option is available only to label synthetic
training-pipeline checks honestly.

## One update trial and its inference observations

```bash
python -m ids_update_lab run --experiment examples/synthetic_demo --native build/native/ids_update_native --native-store local_runs/store01 --output local_runs/run01
python -m ids_update_lab run --experiment examples/synthetic_demo --native build/native/ids_update_native --native-store local_runs/store02 --output local_runs/run02 --model-only --checkpoint after_write
python -m ids_update_lab run --experiment experiments/ton1 --port COM10 --board-id esp32s3-board1 --output local_runs/board_run01
```

For physical serial transport, install `pyserial`. The runner checks the starting
factory version, payload digest, schema, chip, release and data provenance; it does
not erase an existing device to make an experiment pass. Select the compiled board
policy explicitly when flashing. The native `--model-only` option chooses the
intentionally incomplete policy `model_only_factory_preprocess`.

Each run performs initial inference, signature-corruption rejection, one B update
or software-restart fault trial, subsequent inference and current-version replay
rejection. `--checkpoint` accepts `none`, `after_erase`, `after_write`,
`after_verify`, or `after_commit`. Native restart exits and launches a new process
against the same backing files. A reset is **not** a physical power interruption.

The default uses the complete frozen golden list. `--limit N` explicitly creates
a first-N correctness smoke test and records truncation; such a prefix must not be
treated as a stratified accuracy estimate. `--repetitions N` repeats **inference
only**; the update/fault trial count is always one. Repeated update trials require
independent new run directories and the protocol's explicit restoration of the
starting state. No automatic hidden restoration or erase occurs.

Runs preserve `manifest.json`, raw `transcript.jsonl`, `events.jsonl`,
`observations.jsonl`, and `summary.json`, including failed partial runs. The
measurement origin is `native_simulation` or `actual_mcu`; the data origin is
separate. Firmware `latency_us` is distinct from `host_roundtrip_ns`. Update event
wire byte counts include the ASCII command and newline. The manifest records
native executable hash, optional `--firmware-bin` hash and optional board ID.
`summary.status=complete` means implementation checks passed against that policy's
own reference. For the model-only baseline, separately compare its output against
the intended complete B pipeline when reporting the update's scientific effect.
