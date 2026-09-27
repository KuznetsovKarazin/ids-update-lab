# Calibration revision: verified results and manuscript text

The script `audit_calibration034.py` independently implements the exported numerical contract and re-scores all eight frozen models on the stored A/B calibration NPZ files. It does not import `model030.py`, refit models, select new thresholds or change stage030 artifacts. All false-positive and true-positive counts exactly reproduce `calibration.json`. The script also checks daily and attack-type aggregate rates against their confusion cells. The full common-test raw predictions are not independently rerun here.

## Suggested main-text passage, methods

We used calibration to fix the decision threshold after fitting. For each model, the threshold was the most permissive cut that classified at most 1% of its normal calibration records as attacks, without splitting equal scores. Floating-point models use a strict comparison with the stored threshold; the integer MLP uses an integer threshold code. Only normal records determine the cut. Attack records are retained to describe the resulting recall, so poor recall does not trigger a different threshold or model selection. Table~\ref{tab:calibration} gives the observed counts for all eight complete pipelines.

B calibration contains 2,088 normal records, allowing at most 20 false positives under this rule. One additional false positive changes its empirical rate by 0.0479 percentage points. Repeated scores make the available operating points coarser still. This empirical constraint is not a confidence bound on the future false-positive rate: controlling the calibration proportion and controlling population error are different statistical objectives \citep{Tong2018NP}. We therefore report the calibration counts directly, without treating a binomial interval computed from those same threshold-selection records as a future-FPR guarantee. Temporal dependence between flow records is a further reason not to interpret their number as a count of independent Bernoulli trials.

## Suggested main-text passage, results/discussion

The calibration table explains why the updated tree is unusually conservative. Its chosen threshold detects only 6 of 100,000 calibration attacks, with 2 false positives among 2,088 normal records. Another 20 normal records and 63,617 attacks have exactly the score at the excluded boundary. Including that tied score would raise calibration recall to 63.623%, but would also produce 22 false positives, or 1.054%, exceeding the fixed limit. The recorded operating point follows directly from the threshold rule and the tree's discrete scores. We retain it in the comparison because lowering the threshold after seeing these results would change the protocol. Thus the tree's low recall should be interpreted as the behavior of this fitted tree at this prescribed operating point, rather than a general limitation of decision trees.

## Suggested concise supplement paragraph

The added audit re-scores the frozen calibration samples and checks that the stored cut excludes an indivisible group of tied scores: for every model the observed false-positive count is at most the allowed count, while including all normal records at the boundary would exceed it. No attack labels are used in this threshold check. Counts for attacks tied at the same score are descriptive. No post-hoc threshold is substituted into the common-test results. Tables~\ref{tab:daily-complete} and~\ref{tab:types-complete} report the complete pipelines by day and traffic type; the accompanying CSV files additionally include all 24 semantic variants and their confusion cells.

## Why the requested Clopper--Pearson intervals are not added

The reviewer is right to question the information in 2,088 normal records. However, an ordinary Clopper--Pearson interval assumes a fixed classifier applied to independent Bernoulli trials. Here these records selected the classifier's threshold, and flow independence is not established. Adding that interval as a validated confidence statement about future FPR would not solve the problem. The revision instead provides exact observed counts, the available false-positive budget (20), the empirical resolution (0.0479 percentage points), tied-score diagnostics, and the lack of a population guarantee. A future prospective study could use an order-statistic Neyman--Pearson calibration bound under its sampling assumptions and then evaluate it on an independent traffic collection. That is a different calibration procedure and is not retrofitted to this experiment.

Tong, Feng and Li (2018), DOI 10.1126/sciadv.aao1659, explicitly distinguish a constraint on empirical type-I error from probabilistic population-error control and derive order-statistic procedures for the latter. Primary full text: https://pmc.ncbi.nlm.nih.gov/articles/PMC5804623/ . This reference supports the distinction; it does not establish independence or a guarantee for the present traffic data.

## Integration files

- `calibration_table.tex`: complete main-text table with wrapper, label `tab:calibration`.
- `daily_complete_table.tex`: 32-row supplement table of recall/FPR/BA for A/B on all four days; requires `longtable`.
- `attack_type_complete_table.tex`: seven traffic-type rows, all eight pipelines; normal row is FPR, others are recall.
- `calibration_audit.csv` and `.json`: exact thresholds, counts, ties, provenance.
- `day_completeAB.csv`, `traffic_type_completeAB.csv`: unrounded descriptive results and confusion cells.
- `day_all24.csv`, `traffic_type_all24.csv`: equivalent complete tables for all semantic variants.
- `additional_reference.bib`: verified primary statistical source.

No figure or test threshold has been changed. Full-data test metrics remain the frozen stage030 outputs.
