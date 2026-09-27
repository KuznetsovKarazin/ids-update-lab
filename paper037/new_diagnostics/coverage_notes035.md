# Coverage audit of the frozen MCU implementation checks

The 24 files under `evidence_inputs/training/hardware_vectors/` contain exactly the same 258 distinct little-endian float32 input vectors. Their byte keys are sorted. The saved selection statement is consistent with the original implementation in `research030/training/run_training030.py`, function `evaluate`: `SELECT key FROM vectors ORDER BY key LIMIT 258`, followed by `np.frombuffer(..., '<f4')`. Selection preceded model predictions.

## Finding and interpretation

The reviewer correctly identifies limited coverage, and the direct audit makes the extent precise:

- The first six features (`duration`, `src_bytes`, `dst_bytes`, `missed_bytes`, `src_pkts`, `src_ip_bytes`) are zero in **all 258 inputs**.
- One input is the all-zero vector.
- Each of the remaining 257 inputs has `dst_pkts = 1` and a distinct `dst_ip_bytes` value between **40 and 3008**.
- Consequently, **514/2064 = 24.903%** of the scalar input entries are nonzero. The nonzero-feature-count distribution is exactly `{0: 1, 2: 257}`.
- The frequent calibration template `[0,0,0,0,1,63,0,0]` is absent from this MCU-check set.

Little-endian byte order is not numerical order. For example, the saved sequence includes `dst_ip_bytes` values 128, 512, 129, 516; the byte-sort rule itself should not be described as selecting the numerically smallest values. In this dataset it selects a zero prefix that severely restricts the exercised raw-input subspace. The two remaining raw features also covary within a narrow pattern: apart from the zero vector, only one feature varies.

The saved B calibration and fitting samples span nonzero values for every feature, confirming that this is a restriction of the implementation-check selection rather than a property of the entire available data. Their descriptive ranges and zero fractions are in `coverage_audit035.json`; they must not be substituted for the distribution of the full future test.

No new MCU run was performed. The original numerical agreement measurements remain observations on these 258 inputs. They support the correctness of the exercised cases and update/restart invariants, but do not establish broad numerical input-space coverage or threshold-boundary coverage.

## Proposed main-text wording

> The 258 distinct implementation-check inputs cover a narrow slice of the feature space: one input is all zero, while the remaining 257 have zero values in the first six features, one destination packet, and 40–3008 destination IP bytes (Table S[coverage]); the observed MCU agreement therefore applies to this restricted input set.

An additional limitation sentence, if the main text already defines the set:

> A larger stratified MCU-check set, spanning every feature, score boundary, and frequent traffic template, would provide broader numerical coverage.

## Supplement table

`coverage_table035.tex` provides eight feature rows, with range, zero count, zero fraction, and number of distinct values. It includes a caption that all 24 model/ablation input files share the same 258 inputs.

## Reference decisions (not ground-truth classes)

For canonical model files, A_DT predicts 2 of 258 inputs positive and B_MLP-I8 predicts 3 positive; the other six A/B canonical configurations predict all 258 negative. These are reference model outputs, not dataset labels. They should not be reported as class composition or as an estimate of FPR/recall. The JSON audit records the reference decision count and probability range for every file.

## Reproduction and provenance

Run:

```bash
python new_diagnostics/coverage_audit035.py
```

The script uses NumPy, reads the frozen saved vectors and model feature order, writes only `coverage_*` derived outputs, and runs no inference. It records SHA-256 for every input file and for the model metadata source. Outputs are `coverage_audit035.json`, `coverage_features035.csv`, and `coverage_table035.tex`.
