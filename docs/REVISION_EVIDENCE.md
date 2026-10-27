# Evidence guide for the revised manuscript

This guide connects the revised article **Preserving Detector Semantics in TinyML
Updates: Pipeline Contracts and the Limits of Compatible Export** to its numerical
evidence. It was prepared on 27 October 2026. The historical software baseline is
commit `2da88c0407e878a2bd4f07bda4429f83ace8de81`. This update changes documentation
only; it does not change firmware, models, thresholds, or recorded experiment
outcomes, and it does not add the later experimental payloads to the public tree.

## Availability and verification scope

The revised manuscript is accompanied by Supplementary Material S1,
`revision_supplement051.zip`. That archive is supplied through the manuscript
submission, not from this Git tree. The paths below refer to files inside that
archive or to the explicitly identified earlier evidence archive. They are not
links to nonexistent repository files.

The historical GitHub `v1.0.0` release was still a draft on 27 October 2026.
Publication of the reserved identifier `10.5281/zenodo.22978008` has not been
verified. Neither the draft release nor that identifier is presented as a working
public evidence download. The current repository remains useful for its public
baseline code, original analysis tools and reproduction instructions.

S1 preserves selected source files byte for byte and includes its own manifest and
verifier. It adds a reading guide without reclassifying earlier outcomes. The full
original experiment archives are distinct from this selected submission supplement.
A successful integrity check establishes preservation of included bytes; it does
not itself establish universal detector correctness or production security.

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

## Where to find the supporting records in S1

All paths in this table are relative to the extracted `revision_supplement051/`
directory. Original `source` fields inside records retain their archive-era names;
consult `SELECTION051.json` when mapping them to the selected supplement.

| Result | Tables or guide in S1 | Supporting records in S1 |
|---|---|---|
| Three chronological scenarios | `tables/temporal041_overview.csv`, `tables/temporal041_compatible_exports.csv` | `evidence041/source_evidence041/pc/temporal-runs/{original030,window_C0038,window_C0083}/` |
| Calibration-window sensitivity | `tables/threshold041_windows.csv` | `evidence041/source_evidence041/pc/threshold/threshold_stability.json`, protocol and resampling records |
| Frozen quantization/export artifacts | Four `tables/future043_*.csv` files | `evidence043/revision039-pc-043/future/evaluation.json`; source code in `evidence043/revision039-pc-043/supplement_code043/` |
| Stratified host/device panel | `tables/mcu040_numerics_models.csv` | `evidence040/revision039-recovery040/mcu/esp32s3-a0f262ebb558/{Og,O2}/numerics/`; panel/models/goldens in `evidence040/revision039-recovery040/prepared/numerics/` |
| H4 installation cost | `tables/mcu040_cost_observations.csv`, `tables/mcu040_cost_medians.csv` | `evidence040/revision039-recovery040/analysis/costs-recovery040-esp32s3-a0f262ebb558/` and individual `evidence040/revision039-recovery040/mcu/` observation/event streams |
| P1 supply interruption | `powercut/final200_audit_independent.json` | `powercut/final200-original.zip`, `powercut/checkpoint186-original.zip`, `powercut/audit_final200_independent.py` |
| Editorial terminology and evidence boundaries | `README_EN.txt`, and `READ_ME_FIRST053.txt` at the outer ZIP root | Original manifests and selection records remain unchanged |

The earlier H1–H3 primary logs were not newly added to S1 or to this documentation
update. Their historical companion-archive paths include
`runs/020-series-001/`, `runs/020-journal-rotation/`,
`runs/esp32-erase-025-series/`, `runs/ids-completion-030/hardware/`,
`runs/ids-completion-030-energy-031/`, and `fnb58-idle-030.cfn`.
Their code and reports remain in the public baseline repository.

The scenario-plan summary retains `status: planned` and `models_trained: false`
because it describes selection, not the later completed evaluations. Likewise,
`status: complete` means that execution finished; it does not override recorded
mismatches, unavailable endpoints, or the incomplete original two-board matrix.

## Interpretation of the additional experiments

The revised study extends temporal checks, threshold calibration, integer export,
compiler-build comparison and physical supply interruption. These extensions
answer different questions and should not be pooled into one success rate.

The three chronological scenarios overlap and come from an already explored
collection. They are not three independent untouched tests, and they do not
supply the requested mixed future cohort needed to establish retention of old
attacks alongside new ones. Threshold sensitivity is not a guarantee of future
false-positive rate. The later eight-artifact host evaluation is distinct from
the earlier calibration-only diagnostics. Per-channel weight exports were evaluated
on the host; QAT and a per-channel MCU runtime remain untested.

The expanded numerical panel retains the observed host/device differences in both
compiler builds. Agreement on selected real/random inputs does not erase boundary
cases. Native host traces can explain plausible arithmetic mechanisms but are not
direct records of every MCU intermediate. Separate builds reuse the same inputs.

H4 measures package, raw-image and compressed-image installation on one available
board. The originally planned second board was unavailable. Compression is not
delta OTA, and full-image writes remain full-image writes. Measurement boundaries
for MCU handlers and USB end-to-end time differ and are reported separately. H4
adds no new energy measurement or physical flash-lifetime estimate.

P1 includes physical supply interruption, extending the earlier software-checkpoint
experiments. The original unavailable recovery endpoints remain in the results;
later successful observations do not reclassify them. Attempts without a confirmed
cut are not counted as successful recovery after physical supply loss. Independent
verification of voltage collapse within the exact targeted flash phase is still
absent. The separate power-only control does not prove the cause of intermittent
USB/COM recovery failures.

## Offline verification with the full S1 archive

After extracting `revision_supplement051.zip`, enter `revision_supplement051/`:

```bash
python verify_supplement051.py
```

This Python-standard-library check verifies selected-file hashes, binds saved
numerical responses to raw serial records and frozen references, and checks cost
and temporal/threshold/future tables against selected primary JSON files. It does
not independently rerun all neural-network inference over the source traffic
corpus and does not contact hardware.

For the P1 primary-log audit, first extract `powercut/checkpoint186-original.zip`
into a new `checkpoint186/` directory, then run from `revision_supplement051/`:

```bash
python powercut/audit_final200_independent.py --archive powercut/final200-original.zip --checkpoint-run checkpoint186/run --output final200-recomputed.json
```

The auditor checks the final archive manifest, preserved checkpoint prefixes,
planned trial IDs/delays, ordered raw/parsed serial consistency, frozen-reference
controls, replay rejections and ADC OFF traces. The saved unavailable endpoints and
later observations remain separate. No serial port is opened and device power is
not changed. These commands require S1; they cannot run from this documentation-only
Git update without that archive.

## Dependencies and preserved history

Repeating training or complete future evaluation requires the original 23
hash-pinned TON_IoT CSVs and reconstructed inputs under the source provider's terms.
Large traffic arrays, caches and full source datasets are not added to this Git
update. See the [historical reproduction guide](../release/REPRODUCE.md) for baseline
reconstruction and host tests. The complete later acquisition kit is not claimed
to be included here; inspect each S1 script's dependencies before use.

Original failed analyses, repaired analyses, calibration-only diagnostics and
future-test evaluations remain separate. The 042 host overflow repair did not
change models or thresholds; 043 added the eighth frozen artifact and distinguished
raw from effective clipping. Earlier evidence and old manifests are retained as
provenance, not silently replaced with successful outcomes.

The current root `MANIFEST.sha256.json` covers this documentation update. The
original software manifest is preserved at
`release/provenance/MANIFEST_1.0.0_2da88c0.json`. Verify that original manifest against
the historical commit, not the updated README. No manuscript source, reviewer
correspondence, new experimental payload or signing credential is included in this
update.
