#!/usr/bin/env python3
"""Create the report/table directly from preserved diagnostic outputs."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
d = json.loads((HERE / 'percentile_diagnostics035.json').read_text())
names = {
    'B_original': 'Original B',
    'maxabs_transferred': 'Per-tensor max-abs, transferred cut',
    'maxabs_recalibrated': 'Per-tensor max-abs, recalibrated',
    'per_channel_transferred': 'Per-channel weights, transferred cut',
    'per_channel_recalibrated': 'Per-channel weights, recalibrated',
    'percentile999_transferred': '99.9th-percentile grid, transferred cut',
    'percentile999_recalibrated': '99.9th-percentile grid, recalibrated'}

table = r'''\begin{table}[t]
\caption{Posthoc calibration diagnostics for the original int8 detector and compatible exports. The calibration sample contains 2088 normal and 100,000 attack rows. FPR, recall, and changed-decision rates are percentages; FP is a count. Equal-vector FPR assigns each distinct eight-feature vector total weight one, preserving within-vector class proportions. Changed decisions are measured against original B on these same calibration rows. All exports are host diagnostics.}
\label{tab:posthoc035}
\small
\setlength{\tabcolsep}{4pt}
\begin{tabular}{lrrrrrr}
\toprule
Variant & Cut & FP & Row FPR & Vector FPR & Recall & Changed \\
\midrule
'''
md = '| Variant | Cut | FP | Row FPR (%) | Equal-vector FPR (%) | Recall (%) | Changed decisions (%) |\n|---|---:|---:|---:|---:|---:|---:|\n'
for row in d['rows']:
    values = [str(row['q_threshold']), str(row['false_positives']),
              f"{100 * row['calibration_FPR']:.3f}",
              f"{100 * row['equal_vector_FPR']:.3f}",
              f"{100 * row['calibration_recall']:.3f}",
              f"{100 * row['row_changed_fraction']:.3f}"]
    table += names[row['variant']] + ' & ' + ' & '.join(values) + r' \\' + '\n'
    md += '| ' + names[row['variant']] + ' | ' + ' | '.join(values) + ' |\n'
table += '\\bottomrule\n\\end{tabular}\n\\end{table}\n'
(HERE / 'posthoc_table035.tex').write_text(table)

report = '''# Fixed percentile-grid diagnostic, revision 035

## Main finding

The additional control changes the interpretation of the earlier export result. The large calibration recall loss after recalibrating the max-absolute export is avoidable in this case: a single 99.9th-percentile activation grid retains 71.631% calibration recall at 0.718% empirical row-weighted FPR. Original B has 73.531% recall and 0.910% FPR. The recalibrated max-absolute export had 23.933% recall at 0.048% FPR. These are operating-point diagnostics on the reused calibration data, not independent estimates of future detection performance.

The percentile candidate still changes 7606 of 102,088 calibration decisions (7.450%) relative to original B; transferring the original B cut changes 7490 (7.337%). Thus acceptable aggregate calibration metrics and preservation of the original detector's decisions remain different requirements. This result supports an argument for validating the numerical export, not a claim that compatible int8 export is generally impractical.

## Fixed design

`POSTHOC_PLAN035.md` was written before calculating the new candidate. Exactly one percentile, 99.9, was selected. The converted float network retains the A mean and scale and the frozen affine-converted first layer. Quantization ranges were calculated only from the 251,373 saved B fitting rows. No weights were retrained. No calibration or future-test observations selected the percentile or ranges.

Each scalar activation extent is `np.percentile(np.abs(float32_tensor).ravel(), 99.9, method="linear")`, with NumPy **2.3.5**. Both input and layer output grids use this rule; hidden activation ranges are calculated after ReLU in the frozen float network. Weight grids remain per-tensor maximum-absolute. Scales are extent/127, floored at 1e-8 and stored in float32. Symmetric codes [-127,127], integer biases, Q31 multipliers, ties-away rounding, saturation, and the bounded accumulator contract are retained. This is a host-only alternative numerical export; its performance has not been measured on the board.

The first candidate transfers the original B integer logit cut to the new output grid. The second uses B calibration **normal rows only** to choose the most permissive integer cut satisfying empirical row FPR <=1%; ties are excluded as a group. Attack rows report recall and do not select the cut. Neither candidate underwent the full temporal future-test evaluation.

## Full calibration table

''' + md + '''
The full CSV additionally reports equal-vector recall, exact decision-change counts, and the 258 saved check-input results. All seven configurations use the same 2088 normal and 100,000 attack calibration rows. There are 68,515 distinct raw float32 vectors. Inverse-frequency weights are computed over all calibration rows before class conditioning; the normal weighted mass is 1591.039659 and the attack weighted mass is 66,923.960341. This definition preserves class proportions for mixed-label vectors and matches the main article's estimand.

Both percentile candidates change 3/258 decisions relative to B on the saved hardware check vectors. These checks use preserved, selected input vectors and measure host decision agreement; they do not add detection-quality data or new MCU observations.

## Quantization grids and the frequent normal vector

The frozen max-absolute export's input step is 0.398126841; the percentile candidate's step is 0.089695945. The hidden-layer output steps change from 0.385347784 and 0.344616085 to 0.091379531 and 0.077003986. The logit step changes from 0.297204167 to 0.099436104. Smaller steps trade range coverage for numerical resolution; this experiment changes all four activation grids together and does not identify a unique responsible layer.

For `[0,0,0,0,1,63,0,0]`, which appears as 380 normal calibration rows and no attack rows, the original B model produces code 5 and a normal decision at cut 10. The frozen max-absolute export produces code 21 and an attack decision at cut 10. Its recalibrated cut 22 rejects this vector, together with many attack rows tied at or below that score. The percentile export produces code -42, yielding a normal decision under both transferred cut 30 and recalibrated cut 27. Raw codes across different grids are not directly comparable: dequantized logits are 1.4860 (B), 6.2413 (max-absolute export), and -4.1763 (percentile export). The complete layer traces and scales are included in the JSON output.

## Clipping and numerical implementation

On the B fitting rows, the percentile candidate clips 1971/2,010,984 input elements (0.0980%); on B calibration it clips 996/816,704 (0.1220%). After accounting for hidden ReLU, effective clipping affects 3406 first-hidden, 1137 second-hidden, and 476 output elements on the fitting sample, and 7786, 195, and 21 respectively on calibration. Negative hidden codes that would be discarded by ReLU are counted separately from effective clipping. These diagnostic counts neither select nor discard the candidate.

The new max-absolute mode exactly reproduces the current frozen `model030.quantize` algorithm. Compared with the historical export artifact, its recomputed input scale differs by two float32 ULPs (0.398126900 rather than 0.398126841), and the first Q31 multiplier differs by 206. All other numerical fields match. The recomputation changes one calibration output code and no calibration decisions, no fitting codes, no check-input codes, and no target-vector code. The reported max-absolute control always uses the historical artifact; no baseline was silently replaced. The archived source and NumPy version define the primary percentile calculation, including float32 interpolation semantics.

Independent checks compare 1024 broad-range inputs with a scalar Python-integer implementation, verify analytic int32 accumulator and int64 product/rounding bounds, verify tie rounding and percentile interpolation, check the minimal calibration cut, and reproduce the inherited per-channel controls. The original B and all previously frozen outputs remain unchanged. The saved JSON contains hashes of input models, samples, numerical source, and the prespecified plan.

## Reproduction

From the `paper035` directory, with Python 3.12 and NumPy 2.3.5:

```sh
python new_diagnostics/quantization/analyze_percentile035.py
python new_diagnostics/quantization/test_percentile035.py
python new_diagnostics/quantization/write_report035.py
```

The first command reads `evidence_inputs/training` and the inherited `new_analysis` per-channel artifacts. It writes two new candidate models, the complete JSON report, and the CSV. The second is a host numerical verification. The third regenerates this report and the LaTeX table. The primary candidates and the original plan are preserved with hashes; results are posthoc calibration diagnostics, not a new full-test or hardware experiment.
'''
(HERE / 'RESULTS_FOR_MANUSCRIPT035.md').write_text(report)
(HERE / 'requirements.txt').write_text('numpy==2.3.5\n')
print('Wrote RESULTS_FOR_MANUSCRIPT035.md and posthoc_table035.tex')
