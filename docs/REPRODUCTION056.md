# Public reproduction entry point

The repository URL was already present in earlier manuscript versions. Revision
056 addresses the substantive availability gap: it adds the later acquisition
sources, firmware/build procedure, exact prebuilt artifacts, primary logs and
offline auditors, with direct public artifact access. A journal attachment, a
private link, the historical draft release and the reserved DOI are not required.

## Start with verification

Use Python 3.12+. A fresh virtual environment is recommended. Run from the repository
root. The first two checks use only the standard library:

```bash
python release/verify_release.py --root .
python revision056/cic/verify_published.py
python -m pip install -r revision056/requirements-host.lock.txt
python revision_evidence054/verify_subset.py
python -m pytest revision056/tests -q
```

Exact source data remain with their providers. Raw full TON/CIC corpora, large
training-row arrays and SQLite caches are excluded; reconstruction code, source
hashes, selection rules, trained models, protocols and measured MCU receipts are
provided. The 1024-input frozen MCU panel is supplied as a reproducibility input,
including its retained/synthetic categories. It is not a new traffic test set.

## Restore public artifacts

The [`artifact registry`](../release/artifacts056/manifest.json) pins every archive
and every part by SHA-256. Parts are ordinary files in this public Git repository,
not Git LFS pointers. Splitting avoids GitHub's individual-file limit. The standard
library helper joins and verifies them before extraction. Identical archived files
may be stored once by content hash; restoration recreates their original paths and
bytes and writes the complete source-to-file inventory. Existing different files
are never overwritten.

```bash
# Full historical primary logs and retained S1; fresh destination recommended.
python release/restore_artifacts056.py --artifact historical_primary056 --artifact revision040_primary056 --artifact science041_043_primary056 --artifact supplement051 --destination ../ids-evidence056

# Exact historical S3 templates and new C3 templates/panel, in this checkout.
python release/restore_artifacts056.py --artifact s3_prebuilt039 --artifact c3_prebuilt056 --artifact c3_panel056 --destination .
```

A source-only checkout can add `--download --ref COMMIT_SHA` to retrieve missing
parts from a fixed public commit. The file hashes are checked even when downloading.
Full clones already contain the parts and need no network for restoration. Source
CSV reconstruction is a separate operation under the provider's access terms.

## Result → code → primary evidence

Paths in the last column are relative to `../ids-evidence056/` after restoration.
The published acquisition sources retain their original stage names. These names
identify protocol history; they are not additional independent replications.

| Result | Executable sources | Primary evidence |
|---|---|---|
| H1 package/compatible/full-image comparison and checkpoint tests | `completion020/`, `host/`, `firmware/` | `runs/020-series-001/`, `runs/020-journal-rotation/` |
| H2 erase-extent ablation | `stage025/` | `runs/esp32-erase-025-series/` |
| S1 fitting, all 24 conditions, frequency/type/day analysis | `research030/training/run_training030.py`, `model030.py` | `runs/ids-completion-030/training/` |
| H3 four-family updates and retained numerical panel | `research030/tools/hardware030.py`, `research030/firmware/` | `runs/ids-completion-030/hardware/` |
| USB-scenario energy with preserved post-hoc repair | `recovery031/recover_energy031.py`, its helpers | `runs/ids-completion-030/`, `runs/ids-completion-030-energy-031/`, `fnb58-idle-030.cfn` |
| H4 raw/package/compressed OTA; Og and O2 | `revision039/baseline/run_baseline039.py`, `revision039/build/build039.py`, `revision039/firmware/`, `revision039/analysis/analyze_costs039.py` | `revision039-recovery040/` (480 measured installations on one S3) |
| Stratified S3 numerical panel | `revision039/numerics/run_numerics039.py` | `revision039-recovery040/prepared/numerics/`, `revision039-recovery040/mcu/` |
| Three overlapping temporal scenarios and calibration windows | `revision039/science/run_science039.py` | `revision039-pc-041/`, retained successful outputs also in S1 `evidence041/` |
| Additional numerical/quantization recovery and frozen future evaluation | `recovery042/`, `supplement043/` | `revision039-pc-042/`, `revision039-pc-043/` |
| P1 physical power interruption and separately reviewed late recovery | `revision039/powercut/`, `power045/`, `power046/`, `diagnostic113/`, `power048/`, `power049/` | S1 `powercut/final200-original.zip`, `checkpoint186-original.zip`, raw/parsed traces and admission records |
| Separate 100-cycle power control | `power047/` | Preserved inside final P1 archive; not part of its 200 attempts |
| Independent-dataset CIC experiment | `revision056/cic/` | `revision056/results/cic/` in Git; exact source CSV hashes and URLs included |
| Two-board C3 replication | `revision056/build_c3.py`, `revision056/firmware/`, `revision056/hardware/` | `c3_primary057` public archive; [057 raw-receipt audit and results](../revision057/README.md) |

The P1 records retain 166 old, 31 new and three unavailable initial endpoints,
188 confirmed rail-off traces and zero confirmed exact-phase cuts. Late checks
remain separate. Nothing in this publication upgrades those outcomes.

## Recompute saved-evidence results

```bash
python ../ids-evidence056/revision_supplement051/verify_supplement051.py
python revision039/analysis/analyze_costs039.py --campaign ../ids-evidence056/revision039-recovery040 --output ../h4-recomputed056
python paper037/analysis/plot_science.py --output ../figures056/figures
python paper037/analysis/plot_hardware.py --output ../figures056/figures
python release/rebuild_revision_tables056.py --output ../revision-tables056
```

For the full P1 audit, extract the preserved checkpoint ZIP into a fresh directory:

```bash
python -m zipfile -e ../ids-evidence056/revision_supplement051/powercut/checkpoint186-original.zip ../checkpoint186
python ../ids-evidence056/revision_supplement051/powercut/audit_final200_independent.py --archive ../ids-evidence056/revision_supplement051/powercut/final200-original.zip --checkpoint-run ../checkpoint186/run --output ../p1-recomputed056.json
```

The historical H4 analyzer intentionally reports `status: incomplete` for its
original two-S3-board target: one S3 was measured. It still recomputes all 480
recorded observations (zero missing cells on that board). The new two-C3 protocol
is separate and does not retroactively complete that earlier target.

These audits bind numerical observations to raw serial bytes and frozen references,
recompute measured cost cells, and preserve incomplete/failed historical endpoints.
Rebuilding figures/tables from saved aggregates does not repeat training or collect
new measurements. The six later tables are generated as standalone numeric tabular
fragments; captions/colour/layout remain manuscript presentation choices.

## Repeat computations or acquisition

- Original TON sampling, source hashes, refitting, cache reconstruction and energy
  commands: [`release/REPRODUCE.md`](../release/REPRODUCE.md). No new full TON fit is
  claimed for revision 056.
- Independent CIC CSV retrieval, fitting and full raw-source audit:
  [`revision056/cic/README.md`](../revision056/cic/README.md).
- New C3 board acquisition and two-board analysis:
  [`revision056/README.md`](../revision056/README.md).
- Historical S3 protocols and explicit CLI arguments: `revision039/README.md`,
  `revision039/science/README_RU.md`, `revision039/numerics/README.md`, and the stage
  directories' original instructions. Replace historical `revision040-kit` with
  this checkout's absolute path when a `--root`/`--kit` argument is requested.

Historical integration tests that need a specific **pre-continuation incident
snapshot** are explicitly skipped unless their named fixture paths/environment
variables are supplied. A final 200-trial log must not be substituted for the
61-/113-/186-trial snapshot expected by an admission test. The shipped validation
log states the skips; they are not counted as passing hardware tests.

## Source preservation and small packaging changes

Historical code is recovered from the original 039–049 kits. Two files use the
actually applied 045 USB CDC DTR fix; their pre-fix bytes are retained under
`release/provenance/pre_usb_fix045/`. The science prior verifier now locates the
unchanged historical manifest at `release/provenance/MANIFEST_1.0.0_2da88c0.json`
instead of assuming the current root manifest still describes release 1.0.0.
Two test fixture paths are adapted to the public checkout. These packaging edits
do not change algorithms or reclassify historical measurements. Original sources
also remain in the hash-pinned S1/primary evidence containers where recorded.

The public development signing key is intentionally a laboratory reproducibility
fixture. Secure Boot, production key custody and eFuse anti-rollback are outside
these experiments. No device is contacted by the restoration or audit commands.
