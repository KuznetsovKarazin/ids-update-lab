# Revision039: reviewer experiments for make-4623436

Original software author: **Oleksandr Kuznetsov**. The manuscript's author list is unchanged.

This is a new experiment kit based on commit `2da88c0407e878a2bd4f07bda4429f83ace8de81`.
Published stage020/025/028/030/031 measurements and source files are preserved.
Running this kit creates **new** evidence; prepared binaries, simulations and software
tests are never described as measurements on the author's ESP32-S3.

Read [START_HERE_RU.md](START_HERE_RU.md) for the short Windows procedure.

## Scope and reviewer mapping

| Experiment | Reviewer comments | Fixed design and output |
|---|---|---|
| Temporal scenario coverage and new A/B releases | R1.1–2; R3.7,11 | Original scenario plus up to two supported chronological scenarios; coverage-led selection before predictions; all fixed model families |
| Threshold stability and longer calibration windows | R1.3 | Frozen B parameters, repeated calibration, temporal blocks, separate common later test; ties preserved |
| Frozen percentile exports on future traffic | R1.6–7; R2.2 | Existing 99.9-percentile transferred/recalibrated artifacts; no future-test tuning; separate B-I8 and B-F32 references |
| Expanded host/device numerical panel | R1.5,7,8; R2.1 | Approximately 1024 additional distinct real/stress/boundary inputs, all eight features; labels and score errors separately |
| Optimized build and second board | R1.9 | ESP-IDF5.3.2, 160MHz, Og/O2; same datasets/protocols; ten paired cost blocks per family per board/build |
| Streaming compressed full image | R1.11 | Package/raw image/zlib image; MCU reconstruction, authentication and activation; actual A→B and version-only B→C, reused targets |
| Physical power cuts | R1.10 | Separate Pico2/external-switch setup, phase-triggered cuts, voltage evidence and journal rotation; not part of ordinary USB launch |

R1.4 and R1.12 permit a scope explanation instead of a new IDS or a production
secure-boot implementation. R3.1–6,8–10,12–13 primarily require manuscript
organization, explicit definitions/configurations and point-by-point answers.
This kit does not edit the manuscript or mark any editorial comment accepted.

## Scientific constraints

- TON_IoT has already been explored. These are reviewer-driven experiments with
  newly frozen execution rules, not a newly untouched dataset.
- Temporal scenarios must preserve ordering, flow-containment and the original
  60-second internal margins. B fitting excludes both calibration roles.
- Selection uses coverage, not model accuracy. If a requested cohort cannot be
  supported, the coverage report must say so; no random mixing repairs chronology.
- Scores, thresholds, class frequencies and tied-score groups have different roles.
  Calibration FPR is an empirical constraint, not a guaranteed future error rate.
- Real traffic and synthetic numerical stress inputs are identified separately.
  Synthetic stress vectors have no invented IDS ground-truth labels.
- Zero observed numerical disagreement does not prove equivalence for all inputs.
  Mismatches are preserved, not removed by changing the test or silently widening
  a label tolerance.
- New integer-export comparisons distinguish preservation of B-I8 from agreement
  with B-F32. A better approximation of F32 can still change an approved I8 release.
- Hardware repetitions on one board do not become independent boards. Results are
  grouped by board, build, family, policy and transition.
- MCU handler time, USB end-to-end time, reboot and flash-request bytes remain
  separate. Requested flash bytes are not measured lifetime/wear.
- Physical power failure requires actual supply interruption. A software reset,
  a switch command, and verified rail collapse are different evidence levels.
- Public development signing keys exercise the authentication path. Production
  key secrecy, secure boot, flash encryption and physical snapshot rollback are
  outside the security claim.

## Execution and preservation

`run_revision039.py inspect` searches the specified original workspace for the
original training outputs and all 23 pinned TON CSVs. It lists serial ports but
does not open or modify the MCU. Ambiguous paths require explicit arguments.

`prepare`, `pc`, `mcu`, and `all` create fresh step directories. Successful steps
are reused only after hashes and their command match. Failed/incomplete device
operations are not automatically retried. Their original logs remain intact.
`STATUS039.json` distinguishes execution completion, multiple-board coverage and
the still-separate power-cut campaign; it never silently declares all reviews closed.

After each complete MCU campaign, cost analysis runs automatically. `analyze` can
create an additional fresh report after more evidence is collected.
Each acquisition or analysis command archives the new campaign, including partial failures. ZIPs have
SHA-256 inventories and CRC verification. Large reconstructible SQLite caches
are excluded explicitly. NPZ samples and input panels may contain dataset-derived
data: result archives are for private analysis until redistribution terms are checked.
No raw CSV source files, original energy traces or old runs are deleted.

The default searches for the original `runs/ids-completion-030/training` directory;
use `--prior-run` if it was moved during preservation. If absent, the kit uses the
published, hash-pinned frozen models and reconstructs missing samples from the
original CSVs. Use `--data-root` to point to another disk. If source/sample inputs are unavailable, the affected analysis
stops with a prerequisite report, rather than substituting synthetic data.

## Layout

- `science/`: temporal coverage, fitting, future metrics, threshold stability.
- `numerics/`: expanded panel, frozen quantizer follow-up, signed MCU parity runs.
- `baseline/`: raw/compressed/full-package comparison and decompressor tests.
- `analysis/`: automatic cost tables and paired bootstrap intervals; separate board/build strata.
- `firmware/`: isolated revision firmware, instrumentation disabled in timing builds.
- `build/`: reproducible Og/O2/phase builds, metadata, ready-to-flash templates.
- `powercut/`: Pico2 controller, gated wiring configuration and separate experiment.
- `tests/`: coordinator evidence-preservation checks.

Dependencies are isolated in `.venv039`. The build uses its own SDK environment.
The Windows launcher does not require activation of a PowerShell virtual environment.
