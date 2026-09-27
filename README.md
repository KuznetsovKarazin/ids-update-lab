# IDS Update Lab

**Software and Experimental Evidence for Preserving Detector Semantics in TinyML Updates**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22978008.svg)](https://doi.org/10.5281/zenodo.22978008)

- Release: **1.0.0** · [GitHub](https://github.com/KuznetsovKarazin/ids-update-lab) · [Versioned archive](https://doi.org/10.5281/zenodo.22978008)
- [Reproduction guide](release/REPRODUCE.md) · [License scope](LICENSE_SCOPE.md)
- Original software author: **Oleksandr Kuznetsov** ([ORCID](https://orcid.org/0000-0003-2331-6326)).
- The associated article retains its six authors, listed separately in [AUTHORS.md](AUTHORS.md).

This project studies how an embedded intrusion detector can retain the semantics of a validated inference pipeline when it is updated. The deployment contract covers ordered features, preprocessing, model parameters, decision thresholds, and, where applicable, quantization parameters. Experiments compare signed pipeline packages, compatible parameter export where implemented, and full-image replacement on one ESP32-S3 board.

The primary result is a deployment study. It does not establish a new state-of-the-art detector, production security certification, or resilience to physical power removal.

## Evidence at a glance

| Evidence | Series | Interpretation |
|---|---|---|
| Three update strategies, occupied/clean slot states, 30 repetitions per defined cell | 020 | Historical LR/DT implementation; analyze separately from later firmware |
| Requested flash erase length: 64 KiB vs 4 KiB, 30 pairs per family | 025 | LR/DT ablation; flash slot capacity remains 64 KiB |
| Complete TON source diagnostics and temporal role coverage | 028 | Establishes the data-selection context and earlier exploratory exposure |
| Temporal A/B models: LR, DT, MLP-F32 and MLP-I8 | 030 | Frozen protocol after exploratory analysis; train/calibration roles separated |
| Common temporal evaluation: 7,462,871 rows and 3,782,505 unique feature vectors across four days | 030 | Row, feature-vector and capped-frequency weighting; not an untouched confirmatory test |
| MCU campaign: 112 sessions, 5,412 accepted updates, 7,664 inferences, 0 label mismatches | 030 | Hardware agreement on 258 fixed inputs; repeated evaluations are not independent test examples |
| 48 negative checks, 24 software checkpoint interruptions and 236 verified reboots | 030 | 24 dedicated negative controls plus 24 post-interruption replay checks |
| 80 energy blocks: 4 families × 2 methods × 10 blocks | 030/031 | USB-scenario estimates with explicit analysis provenance and measurement limits |

Counts above are summarized in [the historical closure report](closure032/RESEARCH_CLOSURE_RU.md). It documents what was checked and the limits of independent reproduction. Original failed summaries and subsequent repair outputs remain separate; a failed historical run is never relabelled as successful.

## Main numerical results

### Detection behavior before and after retraining

The table reports the common subsequent TON test with **row weighting**. All values are percentages. BA is balanced accuracy, `(recall + 100 − FPR) / 2`. A and B denote complete, internally consistent releases, not isolated weight files.

| Model family | A recall | A FPR | A BA | B recall | B FPR | B BA |
|---|---:|---:|---:|---:|---:|---:|
| LR | 22.595 | 9.859 | 56.368 | 16.941 | 12.053 | 52.444 |
| DT | 20.240 | 12.577 | 53.831 | 8.979 | 0.426 | 54.277 |
| MLP-F32 | 36.871 | 21.310 | 57.780 | 43.801 | 2.151 | 70.825 |
| MLP-I8 | 12.676 | 22.221 | 45.227 | 44.428 | 2.190 | 71.119 |

These results do not support a blanket claim that every retrained model improves. The test contains attack types absent from A's fitting/calibration history; the A-known attack cohort is empty. The 1% empirical calibration FPR target does not guarantee 1% future-test FPR. All 24 pipeline conditions, row/vector/cap100 weighting, attack types and days are retained in `runs/ids-completion-030/training/evaluation.json` and related files **in the Zenodo evidence archive**, not in the GitHub tree. Consult that archive's manifest for the included paths and remaining data dependencies.

### Semantic consistency and compatible export

| Substitution/export compared with complete B | Changed decisions, row-weighted | Main observation |
|---|---:|---|
| Compatible LR export, probability-preserving | 0 observed | Same test labels and operating point |
| Compatible LR export, decision-preserving | 0 observed | Same test labels and operating point |
| MLP-F32 first-layer conversion | 0 observed | Float32 evaluation agreed on the observed test |
| MLP-I8 first-layer conversion and requantization | **448,098 / 7,462,871 = 6.004%** | FPR **2.190% → 28.810%**; recall **44.428% → 47.208%**; BA **71.119% → 59.199%** |
| MLP-I8 with stale input quantization scale | 3.448% | Input quantization is part of the deployed function |
| MLP-I8 with directly reused old threshold code | 8.403% | BA happens to rise to 75.529%; a changed operating point is still not the approved B function |

Zero observed disagreement is not an exhaustive certificate for every float32 input. The MLP-I8 result concerns the implemented symmetric, maximum-absolute per-tensor quantizer and conversion; it is not an impossibility theorem for all integer-compatible exports. No general impossibility of tree-threshold conversion is claimed.

**Frequency matters.** Under equal total weight per feature vector, MLP-I8 compatible-export disagreement is 5.275%, while FPR changes from 4.015% to 4.895%. The top 20 vectors account for 528,962 test rows (7.09%) and 230,681 changed decisions (51.48%). On the remaining rows, FPR still rises from 3.044% to 7.389%. Repeated vectors amplify the row-level impact; these counts must not be presented as independent attack patterns or sessions.

### Cost on the ESP32-S3

The final runtime uses **ESP-IDF 5.3.2, 160 MHz CPU and debug-oriented `-Og` optimization**, on one ESP32-S3FH4R2 with 4 MB flash and 2 MB PSRAM. Values below are medians of ten paired blocks, using the B-to-C reused-slot observation. The requested erase policy is the necessary prefix of the 64 KiB model slot, not a claim that the slot itself is only 4 KiB.

| Family | Signed package, bytes | Package MCU interval, ms | Full-image MCU intervals summed, ms | Package USB end-to-end, s | Full-image USB end-to-end, s |
|---|---:|---:|---:|---:|---:|
| LR | 448 | 28.718 | 1209.134 | 0.0825 | 10.6948 |
| DT | 1104 | 31.736 | 1210.146 | 0.0884 | 10.6955 |
| MLP-F32 | 1588 | 29.310 | 1206.139 | 0.0887 | 10.6923 |
| MLP-I8 | 840 | 31.490 | 1207.111 | 0.0871 | 10.6888 |

The full application image is **339,504 bytes**; the complete signed artifact is **339,844 bytes**, including 84 bytes of metadata and a 256-byte signature. Application-protocol TX is 685,239 bytes for the full image, versus 904/2216/3184/1688 bytes for the four packages. These are the implemented wire encodings, not theoretical lower bounds. Host gaps and full-image reboot are excluded from the MCU interval accounting. The component interval and sum of OTA handler intervals have different boundaries, so their ratio is scoped implementation cost rather than a universal algorithmic speedup. USB time includes the stop-and-wait protocol and must be reported separately.

### Earlier controls: compatible LR export and erase length

Series020 used its own fixed firmware/transport and **30 observations per cell**. Its timings are not pooled with series030. The LR-compatible policy used the same **448-byte signed container and storage path** as the package; it did not implement a minimum-size weights-only format.

| Family/policy, series020 | First-fill MCU interval, ms | Reused-slot MCU interval, ms |
|---|---:|---:|
| LR package | 9.406 | 39.886 |
| LR compatible export | 9.481 | 38.030 |
| LR full image | 879.352 | 1318.289 |
| DT package | 10.976 | 39.631 |
| DT full image | 880.473 | 1320.626 |

Series025 changed the **requested erase extent**, comparing the full 64 KiB slot with the necessary 4 KiB prefix, on reused slots with 30 paired blocks per family:

| Family | 64 KiB median, ms | 4 KiB median, ms | Median paired difference, ms | 95% paired block bootstrap CI, ms |
|---|---:|---:|---:|---:|
| LR | 40.897 | 27.646 | −13.650 | [−15.907, −11.461] |
| DT | 40.599 | 28.956 | −11.547 | [−13.453, −8.752] |

The paired difference is calculated from within-block differences, not by subtracting the two marginal medians. These intervals characterize repeatability on one board under the block-resampling assumptions. Requested erase/program bytes are workload proxies, not measured flash lifetime or a count of the flash chip's internal commands.

### Exploratory energy estimates

The continuous FNB58 capture provides **ten blocks per family/policy**: 128 accepted package updates or four full-image updates per block, with a 200 ms pause after every update. Values are medians of block-level per-update estimates, in **mJ/update**. Gross energy includes the scenario's baseline consumption; above-idle energy subtracts the recorded baseline over the corresponding duration.

| Family | Package gross | Full-image gross | Package above idle | Full-image above idle |
|---|---:|---:|---:|---:|
| LR | 56.174 | 2249.210 | 7.970 | 401.216 |
| DT | 57.699 | 2253.398 | 8.624 | 402.531 |
| MLP-F32 | 58.207 | 2249.510 | 8.986 | 403.589 |
| MLP-I8 | 57.204 | 2247.909 | 8.206 | 401.278 |

These values describe the paced **USB update scenario**, including verification, delays and full-image reboot; they are not isolated flash energy. Integration uses recorded voltage/current samples. Coarse marker localization was repaired post hoc in031, with the same independent validation checks and integration formulas. The instrument was not independently calibrated; the inconsistent accumulated NRG counter is not used as a calibrated reference. Raw samples, counter observations, repair rationale and sensitivity analyses remain in the companion evidence archive. The tables support exploratory scenario comparisons, not a metrological accuracy claim.

### Later calibration diagnostics: scope and reference representation

These are host calculations on the saved B calibration sample: **102,088 records**, comprising 2088 normal and 100,000 attack records. They neither rerun the full future test nor add MCU measurements.

A recurring normal vector has one source packet and 63 source IP bytes, with the other six features zero. Its 380 repetitions account for 380 of the 421 false positives of the transferred max-abs integer export. This template alone exceeds the calibration budget of 20 false positives nineteenfold. Raising the threshold suppresses it but sharply reduces attack recall. Weighting distinct vectors equally gives a different view of this recurrence effect.

| Calibration condition | FPR, % | Attack recall, % | Interpretation |
|---|---:|---:|---|
| Max-abs export, transferred cutoff | 20.163 | 71.623 | Frequent normal template dominates false positives |
| Max-abs export, recalibrated cutoff | 0.048 | 23.933 | Row-level FPR limit recovered at a substantial recall cost |
| Fixed 99.9th-percentile input/activation ranges, transferred cutoff | 0.623 | 70.189 | Same template classified as normal |
| Fixed 99.9th-percentile ranges, recalibrated cutoff | 0.718 | 71.631 | Useful calibration operating point; changed decision function |

Per-channel **weight** scales alone, while retaining the original max-abs activation grids, did not resolve the max-abs export's calibration trade-off. Changing the input/activation range estimator largely avoids that trade-off on this saved calibration sample. This is a representation-specific diagnostic, not a claim about an independently evaluated new detector.

The reference matters. Complete B-F32 and B-I8 disagree on **4883/102,088 = 4.783%** of calibration decisions, each using its own calibrated threshold. The recalibrated percentile export disagrees on **3029 records (2.967%)** with B-F32 and **7606 records (7.450%)** with B-I8. Thus it is closer to floating-point B on these inputs while still changing the approved integer release. Pairwise disagreement rates cannot be subtracted to isolate an additive quantization error.

### Figures and manuscript

The release contains numerical evidence, figures, the apparatus photograph, tabulated results and plotting scripts. The manuscript and its LaTeX submission package are maintained separately and are not included in the public release. The scientific evidence retains its original experiment identifiers; manuscript revisions do not relabel or alter frozen measurements.

## Artifact layout

| Path | Contents |
|---|---|
| `host/`, `firmware/`, `tests/`, `examples/` | Original framework and synthetic tests |
| `research030/` | Final frozen training and MCU kit; all 175 original manifest entries restored |
| `recovery031/` | Energy localization repair and validation |
| `completion020/`, `stage025/`, `research028/` | Earlier fixed protocols, controls and data diagnostics |
| `paper037/` | Figures, plotting and diagnostic code, tabulated results and derived summaries |
| `closure032/`, `finalization032/` | Historical evidence index and closure reports |
| `release/` | Current reproduction instructions, integrity checker and preservation provenance |
| `runs/` (evidence archive) | Preserved results, training exports, event logs and analysis outputs |
| `fnb58*.cfn` (evidence archive) | Original meter captures, including the continuous stage030 trace |

The GitHub tree is the code and presentation distribution. The companion Zenodo
evidence archive includes the 24 frozen model exports, training provenance,
80 cost-event logs, hardware/energy timelines, recovered energy outputs and
original CFN captures. Each archive has its own file manifest. They share a
release root layout: extract into separate directories for inspection; combine
only into a fresh working directory when reproducing an analysis.

Raw TON CSVs, sampled NPZ arrays, exported dataset check vectors and the complete
per-record SQLite evaluation database are not redistributed. The source manifest
identifies the required files. Missing input arrays must be reconstructed from
lawfully obtained sources before post-hoc diagnostics can run. The public release
is not a copy of the entire private experimental workspace.

Current release instructions are in English; historical protocols and laboratory reports, including `*_RU.md`, are in Russian.

Historical failed runs and repaired analyses remain distinct. Old run dates,
paths and software version strings are evidence, not current instructions.
The old release036 publication helper is omitted from this release; its original
candidate manifests remain under `release/provenance/` for audit, not as current
completeness claims.

## Reproduction

1. **Verify included bytes.** Check the release manifest and SHA-256 values before running analysis. Integrity checks establish preservation, not scientific correctness.
2. **Rebuild figures and summary tables.** Run the manuscript plotting scripts against their preserved numerical evidence. This does not require a new MCU campaign.
3. **Reproduce host diagnostics.** Use the saved models and calibration/fitting arrays required by each diagnostic. Read its plan and dependency list. Where arrays cannot be redistributed, obtain/reconstruct them from the pinned sources before execution.
4. **Repeat training and future evaluation.** Obtain the original 23 TON source CSVs and verify the hashes in `research030/training/vendor/source_manifest.json`. Install the frozen requirements and follow `research030/START_HERE_RU.md` in a new output directory. The full CSV corpus is larger than the compact artifact.
5. **Repeat MCU experiments.** Preserve existing runs first; use the documented board, partition scheme, firmware binaries, and serial transport. Firmware commands replace the lab image and model storage. Keep outputs in fresh directories.
6. **Recompute energy.** Use the original CFN, hardware timeline, and stage031 repair. Preserve the diagnostic failure and corrected analysis as distinct records. Do not apply a hand-chosen multiplicative correction to make meter counters agree.

A dedicated Windows environment for the original campaign can be prepared without touching the board:

```powershell
py -3.13 -m venv .venv-reproduce
.\.venv-reproduce\Scripts\python.exe -m pip install -r .\research030\requirements.txt
```

Training and hardware protocols are frozen records. Historical pre-experiment wording remains in original kit instructions; the current article and evidence reports describe completed work. Keep published source files unchanged and write reproduction outputs elsewhere.

## Interpretation and limits

The temporal series was frozen after exploratory inspection of TON days. Fitting and threshold calibration use assigned roles, but the subsequent series is not an untouched confirmatory study. Row, equal-vector, and frequency-capped metrics answer different questions; recurring feature vectors are not independent observations. Empty attack cohorts have undefined recall.

The MCU comparison uses one ESP32-S3. Its 7664 inference calls reuse 258 check vectors, chosen deterministically, with narrow feature coverage: 257 vary along a slice characterized by one destination packet and destination IP byte count. These checks support the observed export/runtime path, not uniform numerical agreement throughout the eight-dimensional input space.

Storage interruptions are software resets at completed-operation checkpoints. No physical power cut inside erase/program was tested. Secure Boot and eFuse anti-rollback were not enabled or validated. The laboratory's explicitly public development signing key in `research030/hardware_codec/` is for reproducibility and provides no production signing secrecy.

MCU timing describes the instrumented ESP-IDF build at `-Og` and the stated measurement boundaries. The integer and floating-point kernels were not optimized to establish an architecture-wide inference-speed ranking. Requested flash bytes measure the workload, not physical flash lifetime. Delta OTA and a second MCU architecture were not evaluated.

Energy results are secondary, paced-USB scenario estimates from an independently uncalibrated FNB58. The record includes alignment repair and sensitivity analyses. This supports comparison of the recorded workloads, not an absolute metrological or battery-life claim.

## Citation, funding, and licensing

Cite the original software as a work by Oleksandr Kuznetsov, using the exact released archive version specified by `CITATION.cff`. Cite the associated article with its six-author list separately. Retain its Git tag/commit and file manifest when reproducing results. The artifact DOI and journal article DOI identify different objects.

This research was funded by the Committee of Science of the Ministry of Science and Higher Education of the Republic of Kazakhstan (Grant No. BR249014/0224).

Original software is MIT-licensed; original non-code study materials are CC-BY-4.0. See [LICENSE_SCOPE.md](LICENSE_SCOPE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for component-specific terms. Source datasets and third-party components retain their own terms.
