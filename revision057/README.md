# Second-round results and reproduction

The two physical C3 acquisitions are complete. This directory adds an analysis of
the preserved measurements and manuscript table generators; it does not change
the frozen 056 protocol, firmware, inputs, or original outcomes.

| Quantity | C3-1 | C3-2 |
|---|---:|---:|
| ROM MAC | `10:00:3b:cb:8d:70` | `10:00:3b:cc:2c:c4` |
| Detected flash | 4 MB | 4 MB |
| Numerical evaluations | 26,624 | 26,624 |
| Host-reference label differences | 7 | 7 |
| Probability errors above 2e-6 | 9 | 9 |
| Integer-code differences / comparisons | 9 / 10,240 | 9 / 10,240 |
| Measured A-to-B installations | 120 | 120 |
| Excluded warm-up installations | 120 | 120 |
| Negative controls passed | 160 | 160 |

Both boards use ESP-IDF 5.3.2, 160 MHz and `-O2`. They were acquired sequentially
using the same host connection. Each board has 124 ROM-bound provisioning logs.
The 720 installation-check inferences per board have no label mismatch; they are
separate from the broader numerical panel, whose discrepancies remain visible.

The two C3 boards have identical saved probabilities, labels and integer codes.
Compared with S3 `-O2`, labels and codes agree, while two reported probabilities
differ by at most 5.9e-11. This refers to serialized telemetry, not unrecorded
intermediate floating-point bits. The largest host-reference error remains 0.424.

Package processing medians are 85.02–87.69 ms on C3 versus about 30–35 ms on S3.
Matching C3 raw/compressed-image to package ratios range from 14.20 to 15.60;
the earlier roughly 40-fold result remains S3-specific. C3 board-to-board cell
medians differ by at most 1.059% relative to board 1. These are descriptive
three-board observations, not a population generalizability guarantee. No C3
power interruption, energy measurement or production security test is claimed.

## Reproduce without hardware

Use Python 3.12+ and a clean checkout. These commands use the standard library:

```bash
python release/verify_release.py --root .
python revision056/cic/verify_published.py
python release/restore_artifacts056.py --artifact c3_panel056 --destination .
python release/restore_artifacts056.py --artifact c3_primary057 --destination ../c3-evidence057
python release/restore_artifacts056.py --artifact revision040_primary056 --destination ../historical-evidence057
python revision057/analyze_extension057.py --board ../c3-evidence057/c3-board1-056 --board ../c3-evidence057/c3-board2-056 --historical ../historical-evidence057 --output ../analysis057
```

Use a fresh analysis output directory. The auditor verifies campaign hashes and
all numerical response/observation bindings, recomputes discrepancies and the
120-cell matrix for each board, then compares the original S3 receipts. No serial
port is opened. `results/` contains the published output, with hashes and CSV/TeX
tables. `primary_inventory.json` lists all 4044 preserved primary files and their
original paths/hashes. The public artifact restores their exact bytes; original
uploaded ZIP hashes identify the two source containers separately.

The C3 input models and numerical panel are the original TON-based artifacts.
The new CIC models were evaluated on the host, not acquired on C3. For CIC source
downloads, refitting and a complete raw-CSV rescan, see
[`revision056/cic/README.md`](../revision056/cic/README.md). Its protocol was public
before fitting; all 24 conditions, all three weightings, all 33 attack types and
unfavorable results remain available. The source-rescan audit shares the model
evaluation kernel while independently accumulating role/group/confusion counts.

## Packaging correction

The first 056 public-result manifest incorrectly included SQLite `-shm` and `-wal`
sidecars, although Git excluded them. They are now explicitly listed as omitted
transient cache state. All 39 delivered scientific files verify in a fresh
checkout. No model, prediction, confusion count, source manifest, frozen protocol
or original full-run manifest was altered to make the check pass.

## Complete earlier reproduction map

[`docs/REPRODUCTION056.md`](../docs/REPRODUCTION056.md) supplies the historical
sources, primary archives, exact firmware, full-data requirements, figure/table
commands and audit entry points. Historical unavailable endpoints, missing
independently verified phase timing, and the unmet two-S3 target remain unchanged.
Earlier files under `revision056/validation/` describe the preparation-time state;
the physical measurements and new verification are documented here.

`photos/` preserves both original photographs. Their role is apparatus
documentation; ROM identity and raw receipts bind the measurements to hardware.
