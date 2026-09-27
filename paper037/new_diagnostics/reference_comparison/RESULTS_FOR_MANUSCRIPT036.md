# Representation-reference comparison, revision 036

## Ready-to-use results paragraph

The choice of reference also affects the measured disagreement. On the same calibration rows, the original B-F32 and B-I8 detectors differ in 4883 decisions (4.783%). The percentile exports differ from B-F32 in 3863 cases (3.784%) with the transferred cut and 3029 cases (2.967%) after recalibration, compared with 7.337% and 7.450%, respectively, against B-I8. Thus these exports are closer to the float detector's decisions than the original int8 representation is, while still changing the behavior of the int8 release. The B-F32/B-I8 comparison includes both the numerical representation and its separately calibrated operating point; it does not isolate quantization error. We therefore retain B-I8 as the reference for int8 release identity and report B-F32 as the source-model reference.

## Table 5 columns

All differences below are on **102,088 saved B calibration rows**, comprising 2088 normal and 100,000 attack records. The two percentage columns are row-weighted. No retraining, threshold fitting, quantizer fitting, future-test evaluation, or MCU experiment was performed in this comparison.

| Existing Table 5 row | Changed vs B-F32, count | Changed vs B-F32, % | Changed vs B-I8, count | Changed vs B-I8, % |
|---|---:|---:|---:|---:|
| Original B-I8 | 4883 | 4.783 | 0 | 0.000 |
| Per-tensor max-abs, transferred cut | 10341 | 10.129 | 6692 | 6.555 |
| Per-tensor max-abs, recalibrated | 50057 | 49.033 | 49702 | 48.685 |
| Per-channel weights, transferred cut | 10266 | 10.056 | 6637 | 6.501 |
| Per-channel weights, recalibrated | 50423 | 49.392 | 50070 | 49.046 |
| 99.9th-percentile grid, transferred cut | 3863 | 3.784 | 7490 | 7.337 |
| 99.9th-percentile grid, recalibrated | 3029 | 2.967 | 7606 | 7.450 |

Suggested column headings: **Changed vs F32 (%)** and **Changed vs I8 (%)**. The caption should identify these as disagreements on calibration rows, preserving the current statement that the export variants are host diagnostics. A comparison against B-F32 does not make these rows a new held-out quality estimate.

## Numerical rules and interpretation

B-F32 uses its frozen float32 probability threshold 0.9053554534912109 with a strict `>` comparison. B-I8 uses its frozen integer logit cut 10 with `>=`, and output step 0.2972041666507721. Its probability metadata, 0.9512948989868164, does not replace the integer decision rule. The percentile candidates retain their saved cuts 30 and 27. No cut was altered for this audit.

The 4883 B-F32/B-I8 differences comprise 9 normal and 4874 attack rows. They include 2230 changes from a normal to an attack decision and 2653 in the reverse direction. These are disagreement counts, not error counts. Differences between rates relative to two references should not be subtracted and interpreted as an additive causal quantization effect.

Against B-F32, the percentile transferred variant changes 7 normal and 3856 attack decisions; the recalibrated variant changes 5 normal and 3024 attack decisions. Against B-I8, the corresponding counts are 8 normal plus 7482 attack decisions, and 8 normal plus 7598 attack decisions. Complete two-by-two decision contingency counts for all 13 model pairs are preserved in the JSON and CSV.

## Reproduction and checks

Run from `paper036` with Python 3.12 and NumPy 2.3.5:

```sh
python new_diagnostics/reference_comparison/compare_references036.py
python new_diagnostics/reference_comparison/test_reference_comparison036.py
```

The main script reads the immutable models in `evidence_inputs/training`, the inherited posthoc exports in `new_analysis`, and the percentile artifacts in `new_diagnostics/quantization`. It records SHA-256 hashes and the Python/NumPy versions. The calibration NPZ is read, never modified. `table5_reference_columns036.csv` contains the seven rows for the manuscript table.

The independent test executes dense layers neuron by neuron, separately from the vectorized reference, and recomputes all 102,088 predictions for each of the eight models. All **816,704 decisions** and all 13 pairwise disagreement counts agree. The test also checks int32 accumulator bounds. This verification concerns the host numerical implementation and introduces no new hardware result.
