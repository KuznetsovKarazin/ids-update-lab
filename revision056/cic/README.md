# Independent-dataset release experiment: CICIoT2023

The protocol was publicly fixed at commit
[`5c66bda03fa84b050181460a663500144d3990c5`](https://github.com/KuznetsovKarazin/ids-update-lab/tree/5c66bda03fa84b050181460a663500144d3990c5/revision056)
before fitting or new model predictions. Its exact SHA-256 is
`4258a311a34b6f630edfc0c15544bd549e54baf2cfe6445fe738415d40fdaa04`.
This is host computation on a second dataset, not a C3 measurement.

## Inputs and scope

Twelve CSV shards were selected from the complete 169-file catalog of version 1
of `akashdogra/cic-iot-2023`, the mirror used by the referenced `iot-audit` project.
Selection uses a filename hash, before observing labels or predictions. All 12
SHA-256 values, sizes, provider/mirror URLs and the complete catalog are published
in [`../results/cic/`](../results/cic/). Source CSVs occupy 1,026,044,402 bytes and
contain 3,482,483 rows; no rows were rejected by the finite/nonnegative feature gate.

The eight features are `flow_duration`, `Header_Length`, `Rate`, `Tot sum`, `Min`,
`Max`, `Std`, `IAT`, in that order and in the original CSV units. This is a new
feature contract. It is not a relabelling of the TON feature contract, a test of
a TON-trained detector on CIC, or a reproduction of another project's notebook.
Only exact `BenignTraffic` is normal; 33 named attack labels are explicitly checked.

The canonical eight-feature float32 vector determines one of five disjoint atomic
roles by SHA-256. Identical admitted vectors cannot cross those roles, regardless
of label. B fitting extends A fitting with its separate added-fit role. Calibration
normals select the 1% empirical FPR target; no test threshold tuning is performed.
The original 030 fitting algorithms/hyperparameters and seed are reused. The
`model_configuration` field in `environment.json` preserves the base TON fitting
configuration verbatim; `feature_names_override_only` and the protocol specify
the actual CIC contract. Its old temporal/uncertainty description does not apply
to this experiment.

**This split is not chronological and does not establish capture/session
independence.** Related flows can remain in different roles even when exact feature
duplicates cannot. It is a controlled release-update experiment on a selected
second-dataset subset, not a full-corpus CIC benchmark or a claim of deployment
generalization. The test contains 871,507 rows and 698,150 distinct feature vectors.

## Complete B releases: descriptive test results

Percentages; macro recall gives equal weight to each of the 33 observed attack
labels. Macro recall is an additional descriptive breakdown calculated after the
frozen experiment, not a tuning objective or a prespecified primary endpoint.

| Model | Row recall | Row FPR | Macro attack recall |
|---|---:|---:|---:|
| LR | 96.782 | 1.034 | 51.911 |
| DT | 97.523 | 0.735 | 65.438 |
| MLP-F32 | 98.565 | 0.831 | 73.058 |
| MLP-I8 | 98.528 | 0.623 | 71.946 |

High row recall coexists with poor detection of some types. For example, B-I8
detects 11.554% of 251 DictionaryBruteForce rows and 14.182% of 5768
MITM-ArpSpoofing rows. The full [`by_type.csv`](../results/cic/by_type.csv) reports
all types and their support; rare-type percentages should not be overinterpreted.
These results do not remove the low-recall limitation of the chronological TON test.

All 24 release/component/export conditions are retained, under row,
equal-vector and frequency-cap-100 weighting. Effects are smaller than on TON:
I8 compatible conversion/requantization changes 443/871,507 decisions (0.050831%),
while both LR compatible exports and the F32 first-layer conversion change zero
observed decisions. Several stale component conditions also happen to change zero
decisions here. No parameter was adjusted to increase a disagreement. Zero observed
changes are not an all-input equivalence proof; the magnitude of inconsistency is
dataset-, release- and representation-dependent.

## Reproduce

Use Python 3.12 and a separate virtual environment with
`python -m pip install -r revision056/requirements-host.lock.txt`.
Run from the repository root, using fresh directories outside it:

```bash
python revision056/cic/verify_published.py
python revision056/cic/fetch_pinned.py --output ../cic056-data
python revision056/cic/run_cic.py --data-root ../cic056-data --output ../cic056-reproduced
python revision056/cic/audit_cic.py --data ../cic056-data --result ../cic056-reproduced --output ../cic056-audit.json
```

`fetch_pinned.py` retrieves the exact published version and verifies every source
hash. `download_cic.py` preserves the original acquisition procedure; it is not the
preferred reproduction command because a live mirror can gain a later version.
`run_cic.py` writes reconstructible samples and a grouped test SQLite database
locally. They are omitted from the published result subset and explicitly listed
in `PUBLIC_RESULT_MANIFEST.json`; the original full-run manifest remains intact.
Byte-for-byte NPZ/SQLite container equality is not required across platforms.

The separate audit re-reads all source CSVs, independently rebuilds role/type/vector
counts, re-scores the frozen models, and checks 72 aggregate and 2448 per-type metric
cells. It shares `model030.py` as the numerical model evaluator, so it is not an
independent implementation of that kernel. The shipped `audit.json` records the
completed audit. Software tests use synthetic fixtures and add no scientific rows.

The 057 packaging correction explicitly excludes transient SQLite sidecars from
the delivered-file list. All 39 delivered files verify; scientific result bytes
and the original full-run manifest are unchanged.
