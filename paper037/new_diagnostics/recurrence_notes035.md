# Calibration recurrence audit (revision 035)

Run `python new_diagnostics/recurrence_audit035.py` from the paper directory. The script evaluates all 24 frozen 030 variants plus the five fixed 034 quantization variants on the retained B calibration sample. It fits no model and changes no threshold. SHA-256 hashes of the exact inputs are written to `recurrence_findings035.json`.

## Confirmed findings

The vector `[0,0,0,0,1,63,0,0]`, in the declared order of the eight features, occurs in **380 of 2,088 normal B-calibration rows** (18.199%). It has no attack-labelled occurrence in this sample. Its original B MLP-I8 score is 5; compatible per-tensor export changes it to 21, with transferred threshold 10. It therefore causes **380 of 421 false positives** (90.261%). All vectors with code 21 contribute 391 normal rows, so the recurring template accounts for 380/391 of that score bin. The other 11 rows belong to other vectors.

The accepted false-positive count under the fixed 1% rule is floor(0.01 × 2088) = 20. Because the template alone contributes 380 rows, it exceeds the entire budget by a factor of 19. A single deterministic code cutoff satisfying this rule must exceed 21. The frozen recalibration procedure selects cutoff 22: one false positive remains, and attack recall changes from 71.623% to 23.933%. This is a direct consequence of the template's frequency and score shift **together with** the fixed row-weighted constraint. It should not be presented as an inevitable general property of quantization or threshold recalibration.

| Fixed variant | Cutoff | Template code | FP / 2088 | Row FPR (%) | Paper vector-weighted FPR (%) | Normal-only vector FPR (%) | Calibration recall (%) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Original B | 10 | 5 | 19 | 0.910 | 1.194 | 1.193 | 73.531 |
| Per-tensor, transferred cutoff | 10 | 21 | 421 | 20.163 | 2.139 | 2.260 | 71.623 |
| Per-tensor, recalibrated cutoff | 22 | 21 | 1 | 0.048 | 0.063 | 0.063 | 23.933 |
| Per-channel, transferred cutoff | 10 | 20 | 419 | 20.067 | 2.014 | 2.134 | 72.198 |
| Per-channel, recalibrated cutoff | 21 | 20 | 0 | 0 | 0 | 0 | 23.564 |

The reviewer’s **2.26%** is correct for a distinct-normal-vector definition: 36 falsely classified vectors / 1593 distinct vectors occurring in normal calibration rows. The paper's existing definition gives each raw vector total weight one across **all** calibration rows and preserves proportional label shares. Under this definition the result is **2.13946%**, with normal mass 1591.039659; original B is 1.19419%. The difference comes from two conflicting-label vectors:

- `[0,0,0,0,1,52,0,0]`: 2 normal and 505 attack rows;
- `[0,0,0,0,1,67,0,0]`: 2 normal and 54 attack rows.

Use the existing paper definition in the main table for consistency. If quoting 2.26%, explicitly call it equal weight per distinct **normal** vector. This distinction changes the number, not the central recurrence finding.

## Suggested main-text paragraph

The calibration loss of recall is driven largely by one recurring normal template. The vector with one source packet and 63 source IP bytes, with all six other features zero, occurs in 380 of the 2,088 normal calibration records. Its integer score changes from 5 in B MLP-I8 to 21 after compatible per-tensor export, so this template accounts for 380 of the export's 421 false positives. It alone exceeds the 20-record false-positive budget nineteenfold. A cutoff satisfying the fixed 1% rule must therefore lie above 21; the selected cutoff of 22 reduces recall from 71.62% to 23.93%. With the paper's equal-vector weighting, which preserves proportional shares of conflicting labels, calibration FPR changes from 1.19% for B to 2.14% for the transferred export, compared with 0.91% to 20.16% by rows. Thus the cost of recalibration depends jointly on the export-induced score change, recurrent traffic, and the chosen calibration objective.

For the design recommendations: Report threshold sensitivity under both operational row frequencies and equal-vector weights, and inspect which templates consume the false-positive budget. A large contribution by a frequent template can be operationally important; reweighting the diagnostic does not remove its actual false alarms or justify silently changing the frozen objective.

## Future-test top-20: what is and is not established

The retained full-test summary establishes 146,462 normal rows in the top-20-vector cohort. Original B has 1,034 false positives there (0.705985%); compatible per-tensor export has 96,768 (66.07038%). Thus a frequency-sensitive effect is independently observed in both the calibration analysis and the future-test cohort analysis.

The **identity** of the dominant future-test vector is not established by the available artifacts. `research030/training/run_training030.py` selects the 20 raw keys directly from SQLite but writes only cohort aggregates. The original `review030/input/ARCHIVE_MANIFEST.json` explicitly lists `training/test_vectors.sqlite` as excluded (538,853,376 bytes; reproducible cache). No vector-level future-test frequency table is retained. The full-TON 028 top-20 contains a different population and does not include the 63-byte vector; it cannot decide membership in the later temporal-test top-20. Do not connect the two results by claiming they involve the same template. A source-level query of the original SQLite on the user's machine could resolve this later without changing any model or threshold.

Suitable wording: “Both analyses show that recurring inputs can amplify an export-induced change. The retained cohort summaries do not identify whether the same template dominates both periods.”

## Backdoor recall: summary evidence and limit

The retained future-test class summary contains 508,116 backdoor-labelled rows. Original A MLP-I8 detects 9 (0.001771%); B LR detects 256 (0.050382%). The other six original A/B variants detect 507,546–507,816 rows (99.8878–99.9410%). These counts are reproduced in `recurrence_backdoor035.csv`.

This verifies sharply different behavior by model, but **does not verify** the reviewer's hypothesis that backdoor is nearly a single recurring vector. Class-specific unique-vector counts, per-vector backdoor multiplicities, and a backdoor/top-20 intersection are absent from the retained 030 summaries. Near-binary class recall alone cannot distinguish a repeated template from a broad but well-separated class region. State the observed difference and, if useful, identify concentration as an unresolved explanation. Avoid saying that several attack types have very few unique vectors unless an actual class-specific count is supplied.

All new calibration quantities are resubstitution diagnostics, not independent future-test quality estimates. No MCU run or physical experiment was performed for this audit.
