# Revision 039 numerical experiments

Original software author: **Oleksandr Kuznetsov**.

These scripts extend the frozen030 experiment without replacing its outputs.
They address R1.5–8 and R2.1. No manuscript results are claimed before running.

## Required inputs

- The pinned repository snapshot, including `research030/` and `paper037/`.
- The original `runs/ids-completion-030/training/` evidence is preferred. If its
  model files are unavailable, the 24 byte-identical published models in
  `paper037/evidence_inputs/training/models/` are used, verified against the
  original software manifest.
- For `prepare`: saved NPZ inputs under `training/samples/`. If reconstructed
  separately, pass `--samples-root PATH` to the directory containing `samples/`.
  If samples are missing, `prepare --data-root PATH` reconstructs them with the
  unchanged030 sampler in its new `reconstructed_inputs/` directory and checks
  every included array against published content fingerprints. This may take
  substantially longer than preparing the panel from existing samples.
- For `future`: the original hash-verified `test_vectors.sqlite`, or an explicit
  reconstructed cache via `--future-db`, or all 23 original hash-pinned TON CSVs
  via `--data-root`. The latter rebuilds a future-only cache; it does not retrain.

The public percentile JSONs are used unchanged (cutoffs 30 and 27). There is no
search over percentiles or thresholds on the future test.
If `prepare` reconstructed inputs, pass its
`reconstructed_inputs/test_vectors.sqlite` as `future --future-db PATH` to avoid
scanning the raw collection a second time.

## Commands

Run from the repository root in the revision Python environment. Substitute
paths for your installation; every output directory must be new.

```powershell
python .\revision039\numerics\run_numerics039.py prepare --root . --prior-run E:\ids-update-lab\runs\ids-completion-030 --output E:\ids-revision039-results\numerics-prepared
python .\revision039\numerics\run_numerics039.py future --root . --prior-run E:\ids-update-lab\runs\ids-completion-030 --data-root E:\TON_IoT\Network_dataset --output E:\ids-revision039-results\export-future
python .\revision039\numerics\run_numerics039.py mcu --root . --prepared E:\ids-revision039-results\numerics-prepared --port COM13 --board-id esp32s3-a0f262ebb558 --provision --output E:\ids-revision039-results\numerics-board1-Og
```

The MCU command explicitly **replaces laboratory firmware and laboratory model
state**, verifies the ROM MAC before writing, then provisions each of the four
model families. It sends each mutation once and preserves all receipts. Use only
the intended lab board. `--prebuilt-root PATH` selects another matrix of the same
`lr_bundle/`, `dt_bundle/`, `mlp_float_bundle/`, `mlp_int8_bundle/` layout, such as
the optimized039 binaries. Keep board/build outputs separate.
Before patching, the runner validates template family/ABI, ESP image checksums,
and pinned flashing-file hashes from the039 build metadata (or frozen030 kit
manifest). The delivered039 numerical core is also exercised by the native
public-model test when a C++ compiler is available.

## Interpretation

The panel contains 1024 additional unique inputs, excluding original258 when
those vectors are available. A fixed seed, role/class sampling, explicit range
probes and targeted boundary searches replace the old byte-sorted slice.
Actual category counts and per-feature coverage are reported, including any
duplicate shortfall. Synthetic probes have no IDS ground-truth labels.

Numerical discrepancies are preserved and the prespecified panel continues;
they do not cause automatic tuning, deletion of inputs, or an early declaration
of success. Protocol, identity and malformed-response errors stop the run.
`status: complete` means the protocol completed; check
`all_numerical_checks_agree`, mismatch counts and raw observations separately.
Probability tolerance is 2e-6; decision mismatch tolerance is zero. Firmware
that exposes `q_score` also enables direct integer-code comparison. Old030
firmware does not expose it, and no bit-exact-code claim is made for that build.

The full future evaluation reports row, equal-vector and capped-frequency
metrics, by day/type, clipping counts on unique vectors, and disagreement with
**both B-I8 and B-F32**. Conflicting labels are preserved. Results remain
post-review analysis of an already explored period, not an untouched test.

## Software checks

```powershell
python -m unittest discover -s .\revision039\numerics\tests -v
```

The fixtures are synthetic software validation. They are not observations from
the physical MCU or from TON_IoT.
