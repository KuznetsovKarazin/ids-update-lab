# Revision 034 post-hoc export analysis

## Recommendation

Include a short subsection and compact table, with its **calibration-data diagnostic** scope in the heading/caption. It directly tests the reviewer's practical suggestion without adding new hardware work or pretending to have a new independent test. It shows that recalibration is necessary to re-establish a selected empirical FPR constraint in this example but is **not sufficient to preserve the detector**. Avoid a universal claim that every int8 export requires or can be repaired by recalibration.

The existing full-test rows (including 6.004% changed decisions and 28.810% FPR) remain untouched. The new results concern the saved B calibration sample: 2,088 normal records and 100,000 sampled attacks. These attack samples were not used to select thresholds; their recall is a diagnostic on the calibration period, not an independent future-test estimate.

## Exact results

| Host reference / export | Integer cut | FP / 2,088 | Calibration FPR (%) | TP / 100,000 | Calibration recall (%) | Changed vs B on 258 checks |
|---|---:|---:|---:|---:|---:|---:|
| Original B int8 | 10 | 19 | 0.9100 | 73,531 | 73.531 | 0 |
| Per-tensor export, transferred cut | 10 | 421 | 20.1628 | 71,623 | 71.623 | 0 |
| Per-tensor export, recalibrated cut | 22 | 1 | 0.0479 | 23,933 | 23.933 | 3 |
| Per-channel export, transferred cut | 10 | 419 | 20.0670 | 72,198 | 72.198 | 0 |
| Per-channel export, recalibrated cut | 21 | 0 | 0 | 23,564 | 23.564 | 3 |

The per-channel alternative changes weight scales to one scale per output channel; it preserves the fitting-derived input and activation grids of the frozen export. Thus it is a controlled comparison of weight quantizers, not a search for an optimal quantized representation. It uses per-channel Q31 multipliers and is **host-only**; the existing MCU payload/runtime supports scalar layer scales. No new claim of MCU correctness or hardware cost is made for it.

The large calibration-FPR jump cannot be repaired by a small cutoff adjustment: 391 normal calibration records share integer output score 21 in the per-tensor export. The permissive cutoff satisfying the <=1% empirical FPR rule must therefore increase from 10 to 22, dropping calibration attack recall by 47.690 percentage points relative to that exported model, and by 49.598 points relative to original B. In the per-channel case 392 normal records share score 20, and the chosen cutoff becomes 21. These are observed score ties, not evidence that the records share one exact raw vector.

Both transferred exports preserve all decisions on the 258 saved checks while changing many calibration decisions and, for the original per-tensor export, 6.004% of the full-test decisions. This is an especially clear reason to label the MCU vectors as implementation checks. Their original selection was the first 258 unique float32 feature vectors in little-endian byte order, without consulting predictions; it was not a representative random traffic sample.

## Suggested paper prose

We next examined whether the converted int8 network could be repaired by recalibrating its threshold. This post-hoc host analysis used the saved B calibration sample and retained the original empirical 1% FPR rule. With its transferred cutoff, the per-tensor export classified 421 of 2,088 normal records as attacks (20.16%). Recalibration reduced this count to one, but attack recall on the same calibration period fell from 71.62% to 23.93%. The discrete output distribution explains the large change: 391 normal records had score 21, so the selected integer cutoff increased from 10 to 22. A per-output-channel weight quantizer, evaluated with the same activation grids, produced a similar trade-off. Recalibration can therefore restore the selected false-positive constraint while substantially changing the detector. These calibration diagnostics support re-evaluating both false positives and attack recall after conversion; they do not establish the future-test performance of the recalibrated models.

## Pointwise-bound attempt (supplement / repository, not main contribution)

A conservative analytic bound was implemented using exact rational arithmetic. It propagates input quantization/clipping, weight and bias quantization, fixed-point multiplier error, integer requantization rounding and saturation. On the 258 saved checks it encloses every actual integer output but certifies **0 / 258** agreements with original B: the bound is too loose. Report this as an unsuccessful supplementary calculation if discussing it; do not present it as a partial decision certificate or inflate the contribution. No numerical-only comparisons were relabelled as guarantees.

For each reference layer let x_j be its exact rational real-arithmetic activation, E_j a bound on the corresponding dequantized integer activation error, w_jk and b_k its stored float32 coefficients viewed as exact dyadic rationals, and q_w,jk, q_b,k the integer coefficients with scales s_x, s_w, s_y. Define

D_k = |s_x s_w q_b,k - b_k| + sum_j (|w_jk| E_j + |s_w q_w,jk - w_jk| (|x_j| + E_j)).

If r = M / 2^s is the deployed Q31 multiplier, the pre-clipping error bound is

D_k + |s_y r - s_x s_w| A_k + s_y/2,

where A_k = |q_b,k| + sum_j |q_w,jk| min(127, floor((|x_j| + E_j)/s_x)) bounds the integer accumulator magnitude. Clipping and ReLU are 1-Lipschitz; any clipping of the ideal centre outside the representable output range adds its explicit distance. Input errors are exact |q_input s_input - x_input| for the host-frozen normalized float32 inputs. Final bounds are converted to integer code intervals with exact ceil/floor. An agreement is certified only if the whole interval lies on the same side of the export cutoff as the original B decision.

This is a mathematical reference-graph statement conditional on those computed preprocessing values. It is not a guarantee for unseen inputs or unspecified MCU libm behavior. The unused numerical slack is visible in `pointwise_certificate034.csv`.

## Reproduction and checks

`python paper034/new_analysis/analyze_export034.py`

`python paper034/new_analysis/test_export034.py`

The numerical checks cover (i) reduction of per-channel to scalar quantization when per-channel weight maxima coincide, with exact prediction equality on 4,096 broad inputs; (ii) rational error enclosure on 64 extra, broadly distributed and saturation-stressing inputs; and (iii) the calibration tie rule and immutability of the frozen model. The main analysis also verifies bounds on all 258 check vectors.

Input hashes and all generated host models are preserved. The local NumPy range recomputation differs from the frozen input scale by 5.96e-8 (all integer weights and biases reproduce); the frozen activation grids are retained, and the comparison does not silently regenerate the original quantizer.
