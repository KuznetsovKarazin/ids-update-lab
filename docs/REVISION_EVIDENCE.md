# Evidence guide for the revised manuscript

This guide connects the revised article **Preserving Detector Semantics in TinyML
Updates: Pipeline Contracts and the Limits of Compatible Export** to its numerical
evidence. It was prepared on 27 October 2026. The historical software baseline is
commit `2da88c0407e878a2bd4f07bda4429f83ace8de81`; this documentation update does not
change its firmware, models, thresholds, or recorded experiment outcomes.

## Start with the public compact subset

[`revision_evidence054/`](../revision_evidence054/) contains ten CSV tables and six
saved JSON summaries copied byte for byte from the manuscript's Supplementary
Material S1. Its [provenance inventory](../revision_evidence054/PROVENANCE.json)
records each source archive entry, file size and SHA-256. The source is
`revision_supplement051.zip`, 35,199,436 bytes, SHA-256:

```text
c1b2b7b7fb9c7f2a9a232454c7bf8d897f22ae2dff216785d9dba216ec0fac18
```

Run this from the Git repository root with Python 3 and its standard library:

```bash
python revision_evidence054/verify_subset.py
```

The checker verifies the 16 original payload hashes, reconstructs 384 nonempty
median values from 480 saved cost observations, checks numerical summaries against
52 model rows, reconstructs threshold/future metrics from saved counts or masses,
and checks the P1 audit's denominators. It does not evaluate the full traffic
corpus, replay primary serial logs, train a model, or contact hardware. A successful
check establishes preservation and aggregate consistency, not universal correctness
of the detector or storage implementation.

**Availability update, 1 November 2026:** the full S1 package, historical primary
logs, later acquisition sources and exact prebuilt artifacts are now publicly
restorable from this repository. Use [REPRODUCTION056.md](REPRODUCTION056.md) for
hash-pinned download/restoration and complete audit commands. The reserved DOI and
historical draft release are not download dependencies.

## How manuscript names map to preserved identifiers

| Manuscript label | Preserved identifier | Question addressed |
|---|---|---|
| Scenario S1 | `original030` | Original chronological A/B release comparison |
| Scenario S2 | `window_C0038` / candidate `C0038` | Second, overlapping chronological scenario |
| Scenario S3 | `window_C0083` / candidate `C0083` | Third, overlapping chronological scenario |
| H1 | series020 baseline and journal rotation | Early LR/DT package/export/image and software-checkpoint controls |
| H2 | series025 erase ablation | Full-slot versus necessary-prefix erase requests |
| H3 | series030 hardware and series031 energy analysis | Four-family installation, restricted-panel numerics and USB-scenario energy |
| H4 | series039/040 installation matrix | Packages, raw images and compressed images with `-Og` and `-O2` |
| P1 | series045 with 046/048/049 continuations | Physical supply interruption with preserved initial endpoints |
| Separate power-only control | series047 | 100 power cycles outside the 200-attempt P1 experiment |

Scenario S1 and **Supplementary Material S1** are different objects. The restricted
panel contains 258 distinct inputs; the stratified panel contains 1024 inputs
(512 real, 256 random, 128 range/grid and 128 boundary inputs). Reusing inputs
across configurations or builds does not create independent traffic examples.

## Evidence to inspect for each result

Paths in the final column are relative to the extracted S1 directory
`revision_supplement051/`, except the explicitly historical H1–H3 rows. Original
`source` fields inside CSV/JSON records retain their archive-era path names; use
the provenance inventory rather than treating every such string as a Git path.

| Result | Public files in `revision_evidence054/` | Primary evidence location in S1 |
|---|---|---|
| Three temporal scenarios and compatible export | `tables/temporal041_overview.csv`, `tables/temporal041_compatible_exports.csv`, `summaries/temporal_plan.json` | `evidence041/source_evidence041/pc/temporal-runs/{original030,window_C0038,window_C0083}/`; each contains full evaluation and day/type outputs |
| 6/12/24-hour calibration sensitivity | `tables/threshold041_windows.csv`, `summaries/threshold_windows.json` | `evidence041/source_evidence041/pc/threshold/threshold_stability.json`, protocol and resampling records |
| Eight frozen quantization/export artifacts | Four `tables/future043_*.csv` files, `summaries/future043.json` | `evidence043/revision039-pc-043/future/evaluation.json` and associated protocol; source code in `evidence043/revision039-pc-043/supplement_code043/` |
| Stratified numerical panel | `tables/mcu040_numerics_models.csv`, `summaries/numerics_Og.json`, `summaries/numerics_O2.json` | `evidence040/revision039-recovery040/mcu/esp32s3-a0f262ebb558/{Og,O2}/numerics/`; panel/models/goldens in `evidence040/revision039-recovery040/prepared/numerics/` |
| H4 installation cost | `tables/mcu040_cost_observations.csv`, `tables/mcu040_cost_medians.csv` | `evidence040/revision039-recovery040/analysis/costs-recovery040-esp32s3-a0f262ebb558/` and individual `evidence040/revision039-recovery040/mcu/` observation/event streams |
| P1 physical supply interruption | `summaries/final200_audit_independent.json` | `powercut/final200-original.zip`, `powercut/checkpoint186-original.zip`, `powercut/audit_final200_independent.py` |
| H1–H3 and historical energy | Sources in this repository; primary logs available through revision056 artifact restoration | Historical companion archive: `runs/020-series-001/`, `runs/020-journal-rotation/`, `runs/esp32-erase-025-series/`, `runs/ids-completion-030/hardware/`, `runs/ids-completion-030-energy-031/`, `fnb58-idle-030.cfn` |

The plan summary deliberately retains `status: planned` and `models_trained: false`:
it describes scenario selection, not the completed evaluations. Their completed
status and sizes are recorded in the temporal overview and primary run summaries.
Similarly, `status: complete` means that acquisition or analysis finished; it does
not override recorded mismatches, unavailable endpoints, or an incomplete
original two-board matrix.

## What the added evidence establishes

**Temporal/export evidence.** The three scenarios contain 7,462,871, 11,468,146
and 10,994,486 future rows and 24 configurations each. They overlap and come from
an already explored collection; they are not three independent untouched tests.
Probability-preserving LR export has no observed changed labels in those tests.
Other transformations, threshold representations and integer exports require
separate checks. The scenarios do not contain the requested mixed future cohort
needed to establish retention of old attacks alongside new ones.

**Numerical agreement.** Each compiler build evaluates 26 configurations on the
same 1024 inputs: 26,624 inferences per build. Seven host/device label differences
and nine integer-code differences remain in each build. The zero differences on
the real/random subsets do not erase the boundary cases. Native host traces can
explain plausible arithmetic mechanisms but are not direct traces of every MCU
intermediate. Per-channel weight exports were evaluated on the host, not through
a newly implemented per-channel MCU runtime; QAT remains untested.

**Installation costs.** H4 contains 480 measured installations: ten blocks for
2 builds × 4 families × 3 policies × 2 transitions. All measured cells on the one
available board are complete; the originally planned second board was unavailable.
The `-O2`, A-to-B package MCU medians are 31.736 ms (LR), 30.575 ms (DT), 34.984 ms
(MLP-F32) and 29.895 ms (MLP-I8). Raw/compressed full-image and USB intervals are
separately reported with their own boundaries. Compression is not delta OTA;
full-image writes remain full-image writes. H4 adds no energy measurement, physical
flash-lifetime estimate, or second-architecture result.

**Physical supply interruption.** All 200 planned attempts were recorded:
166 `old_valid`, 31 `new_valid`, and three `no_response` endpoints. Of the 188
ADC-confirmed rail-off traces, 166 recovered to old and 19 to new expected states;
three were unavailable within the nominal recovery window. The other 12 attempts
had no confirmed cut and selected the new state. All eight targeted phases had
25 attempts, but zero attempts independently confirm voltage collapse inside the
exact targeted flash phase. Late successful old-state checks for attempts 61,
113 and 186 are preserved separately and do not relabel their initial endpoints.
The standalone 100-cycle power control is separate from these 200 attempts. The
intermittent recovery failure cause is not established.

## Verification with the full supplementary package

After extracting `revision_supplement051.zip`, enter `revision_supplement051/`:

```bash
python verify_supplement051.py
```

This broader check binds saved numerical responses to raw serial records and frozen
references, and checks cost and temporal/threshold/future tables against selected
primary JSON files. It still does not rerun all neural-network inference over the
source traffic corpus.

For the P1 primary-log audit, first extract `powercut/checkpoint186-original.zip`
into a new `checkpoint186/` directory, then run from `revision_supplement051/`:

```bash
python powercut/audit_final200_independent.py --archive powercut/final200-original.zip --checkpoint-run checkpoint186/run --output final200-recomputed.json
```

The auditor checks the final archive's 399 manifest entries, preserved checkpoint
prefixes, trial IDs/delays, raw/parsed serial consistency, 2364 frozen-reference
control comparisons, 197 replay rejections and 188 ADC OFF traces. No serial port
is opened and device power is not changed.

The complete original consolidated 040–043 archive is separately retained as
`ids-update-lab-results-2026-10-24.zip` (317,485,120 bytes, SHA-256
`faa77b6e0c35e272e0e569e3afb839a5d4ecd7ef26de9612f9d18c4e69bdf839`).
The original final P1 archive has SHA-256
`8993dc6c11dd940f89995a75d29b9e0e3272f35fb11e674f94bd895695693ce3`.
An archive hash identifies exact bytes; it does not itself make that archive
publicly available or prove the scientific interpretation.

## Dependencies and preserved history

The compact subset needs only Python 3. Full supplementary auditors use their
documented Python/native dependencies. Repeating training or complete future
evaluation requires the original 23 hash-pinned TON_IoT CSVs and reconstructed
inputs under the source provider's terms. Large traffic arrays, caches, raw packet
records and full source datasets are not added to this Git update. See the
[historical reproduction guide](../release/REPRODUCE.md) for reconstruction and
baseline host tests. The complete later acquisition kit is not claimed to be
included in this compact update; inspect each S1 script's dependencies before use.

Original failed analyses, repaired analyses, calibration-only diagnostics and
future-test evaluations remain separate. The 042 host overflow repair did not
change models or thresholds; 043 added the eighth frozen artifact and distinguished
raw from effective clipping. Earlier evidence and old manifests are retained as
provenance, not silently replaced with successful outcomes.

The current root `MANIFEST.sha256.json` covers this documentation/subset update.
The original software manifest is preserved at
`release/provenance/MANIFEST_1.0.0_2da88c0.json`. Verify that original manifest against
the historical commit, not the updated README. No manuscript source, reviewer
correspondence, production key or unpublished signing credential is included.
