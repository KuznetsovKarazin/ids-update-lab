# Reproducing the released study

The release separates preserved measurements, author-written analysis code, and source data obtained from third parties. The software author is Oleksandr Kuznetsov. The article has its own six-author byline.

The release does not include the original TON_IoT CSV corpus, extracted fitting/calibration rows, the full future-test database, or dataset-derived hardware input vectors. This is a distribution decision; no new license is assigned to those data. The source manifest records the exact filenames, sizes, acquisition URLs, and locally computed SHA-256 values. The hashes identify the bytes used in the study; they are not publisher-authenticated checksums.

## What can be reproduced

| Task | Inputs in the release | Additional requirement |
|---|---|---|
| Rebuild scientific figures and tables | Curated numerical JSON, plotting scripts | Python, NumPy, Matplotlib |
| Inspect original trained functions | 24 saved model/variant JSON files and model evaluator | Python and NumPy |
| Recompute the 80 energy blocks | Original CFN, hardware timeline, accepted-update receipts, stage031 repair | Code and evidence extracted together; frozen Python dependencies |
| Run host protocol/unit tests | Source, complete synthetic fixtures and an optional isolated test helper | pytest; a C++ compiler for native source tests |
| Reconstruct excluded fitting/calibration inputs | Frozen sampler, source manifest, content fingerprints | Obtain all 23 exact TON_IoT CSV files under the source provider's terms |
| Re-run post-hoc 034–036 analyses | Frozen models, analysis code and published outputs | Reconstruct the excluded inputs first |
| Train again and evaluate the complete temporal test | Original training/evaluation code and protocol | Exact source CSV corpus, time and local disk space |
| Repeat MCU measurements | Frozen firmware, codec, protocol and runner | ESP32-S3 lab hardware and reconstructed experiment inputs |

The historical `REPRODUCTION_GAPS036.json` files describe the original preparation candidate, before the publication audit restored missing owned metadata, models and timing receipts. They are preservation records, not a claim that every listed dependency remains absent. Earlier kits also refer to files outside their public distributions. The final release manifest binds the delivered files; the commands below identify supported entry points explicitly.

## Verify the release

Run `python release/verify_release.py --root .` before analysis. The manifest excludes only itself; additional local outputs do not change the verification of preserved inputs.

## Prepare a separate environment

From a directory containing `research030/`, install the original campaign requirements in a new environment. On Windows:

```powershell
py -3.13 -m venv .venv-reproduce
.\.venv-reproduce\Scripts\python.exe -m pip install -r .\research030\requirements.txt
.\.venv-reproduce\Scripts\python.exe -m pip install matplotlib pytest
```

On Linux/macOS, use the equivalent virtual-environment Python executable. Native C++ tests also need a C++17 compiler and, for the full native simulator, OpenSSL development libraries. Software checks do not produce new MCU measurements.

## Rebuild figures without data or hardware

The two scripts use preserved, source-linked aggregate JSON files. Write the outputs to a separate directory:

```powershell
.\.venv-reproduce\Scripts\python.exe .\paper037\analysis\plot_science.py --output ..\ids-reproduced-figures\figures
.\.venv-reproduce\Scripts\python.exe .\paper037\analysis\plot_hardware.py --output ..\ids-reproduced-figures\figures
```

`plot_science.py` also writes its four LaTeX tables beside the figure directory. Rebuilding a figure checks presentation from saved aggregates; it does not rerun inference over 7.46 million traffic records. The older `build_*_evidence.py` scripts document curation against the original workspace layout and are not required for this step.

## Recompute energy from the original recording

Extract the code and evidence so that one directory contains `research030/`, `recovery031/`, `runs/ids-completion-030/`, and `fnb58-idle-030.cfn`. The following operation is offline and does not contact the board:

```powershell
.\.venv-reproduce\Scripts\python.exe .\recovery031\recover_energy031.py --kit .\research030 --run .\runs\ids-completion-030 --cfn .\fnb58-idle-030.cfn --output ..\ids-energy-reproduced
```

The output directory must not exist and must lie outside the original run. The repair verifies the original hardware receipts, update counts and model versions before integrating the recorded voltage/current. The published result has 80 blocks. Preserve both the original failed marker analysis and the successful stage031 repair: the latter is a post-hoc repair, not a successful prespecified analysis. FNB58 measurements remain exploratory USB-scenario estimates, with no independent instrument calibration.

## Host checks without a board

The complete synthetic fixtures are included in `examples/synthetic_demo/` and
`examples/instrumented_synthetic/`. Their original signed package bytes and public
keys were recovered from the preserved firmware, without re-signing or changing
any measured image. The contracts and 63 synthetic golden records per fixture
were regenerated with the published generator; `provenance.json` records the
source image, offset and hash. These are plumbing checks, not detection results.

From the release root, using the environment prepared above:

```powershell
.\.venv-reproduce\Scripts\python.exe -m pip install -e .
.\.venv-reproduce\Scripts\python.exe -m ids_update_lab verify --package .\examples\synthetic_demo\release-B.sids --public-key .\examples\synthetic_demo\public.pem --contract .\examples\synthetic_demo\feature_contract.json
.\.venv-reproduce\Scripts\python.exe -m pytest tests -q
```

Tests that require the full native simulator are explicitly skipped until it is
built. On Linux, with C++17 and OpenSSL development libraries installed:

```bash
bash tools/build_native.sh
python -m pytest tests -q
python -m ids_update_lab run --experiment examples/instrumented_synthetic --native build/native/ids_update_native --native-store ../ids-native-store --output ../ids-native-run
```

Use fresh store and output directories. The checked-in native header matches
`instrumented_synthetic`; the older `synthetic_demo` key instead matches the
historical `synthetic_smoke` and `usb_buffered` images. These commands do not contact
hardware. Do not substitute one fixture's public key for another.

For an additional isolated host-only test copy, the existing helper remains
available:

```powershell
.\.venv-reproduce\Scripts\python.exe .\publication_tools\generate_host_fixtures.py --release-root . --output ..\ids-host-test-copy --run-tests
```

That helper leaves the release unchanged, generates a temporary key in memory,
and does not copy the historical fixtures or native executable. Its synthetic
files are only for its selected host tests and are not compatible with the
published firmware keys.

## Reconstruct excluded TON inputs without retraining

1. Obtain the 23 `Network_dataset_*.csv` files identified by `research030/training/vendor/source_manifest.json`. Follow the source provider's terms. The recorded source is a versioned mirror; the sampler rejects a different file size or SHA-256.
2. Extract the software and evidence together. Keep published files unchanged.
3. Run the publication helper, with output outside the release:

```powershell
.\.venv-reproduce\Scripts\python.exe .\publication_tools\reconstruct_analysis_inputs.py --release-root . --data-root D:\TON_IoT_network --output ..\ids-reconstructed-inputs
```

The helper calls the unchanged stage030 sampler, copies the 24 published model JSON files without fitting them, and checks each reconstructed array by dtype, shape and SHA-256 of its C-order content. NPZ ZIP compression and container bytes can vary between platforms, so container equality is not used as a substitute for array equality. It derives the 258 check inputs from the original byte-order selection rule and verifies their input-content digest. Original authored prediction outputs are then restored to those inputs and the complete original Windows JSON file hashes are checked. A separate new host prediction comparison reports any floating-point differences. Restoration of authored predictions is not a new MCU measurement.

The fingerprint companion contains hashes and authored model outputs, not raw traffic vectors. The helper does not train a detector, change a threshold, evaluate the complete future test, or communicate with hardware. It retains the regenerated SQLite cache locally; do not assume that regenerated database-container bytes match the original database.

The same command writes `row_identifiers/sample_rows.csv.gz` and `row_identifiers/row_references.json`. Each CSV record gives the role, array position, source filename, zero-based CSV data-record index, and original encoded row ID. The row index starts at the first parsed record after the header; it is not a physical text-line number. These references are exported only after every reconstructed sample array, including `row_ids`, matches its frozen content hash. The release contains the deterministic selection recipe and these verification hashes; the row-reference CSV is generated locally, not claimed to be an already deposited list.

The selection recipe uses the source-file order in `source_manifest.json`, not a newly sorted directory listing. It applies the frozen temporal intervals, 60-second internal margins, flow-containment and numeric-contract rules, then the fixed SplitMix64 bottom-k sampler within each class/type stratum. Its seed and caps are recorded in `research030/training/run_training030.py`. The five outputs preserve the original array order and weights. The 258 check inputs are distinct future-test vectors selected by the SQLite `ORDER BY key LIMIT 258` rule; they are not 258 independently sampled CSV rows. Their reconstructed float32 input bytes are checked against the published digest.

For an author who already retains the original five NPZ files, the row list can also be exported without reacquiring or scanning the corpus:

```powershell
.\.venv-reproduce\Scripts\python.exe .\publication_tools\export_row_identifiers.py --samples .\runs\ids-completion-030\training\samples --output ..\ids-sample-row-identifiers
```

This command verifies all arrays before writing references and exports no feature values or labels. A successful export from existing samples is not a fresh reconstruction from the 23 CSV files.

During the publication audit, exact restoration of all 24 original check-vector JSONs was verified against preserved inputs and outputs. The standalone prediction comparison had zero label mismatches, with probability differences up to 4.62e-7 across platforms. The complete 23-CSV reconstruction was **not** rerun in the publication audit. A fingerprint mismatch stops the helper and must be investigated rather than bypassed.

The original frozen full-training manifest includes omitted data-dependent files and a database hash. The helper's reconstructed directory is therefore an analysis-input directory, not automatically a byte-for-byte substitute for an original `--reuse-training` directory.

## Re-run post-hoc calibration diagnostics

The 380/421 recurring-template result and the B-F32 reference comparison use the original `B_cal` sample (102,088 rows); the percentile range control additionally uses `B_fit`. Their preserved arrays, including labels, weights and row identities, are all covered by `DATA_INPUT_FINGERPRINTS037.json`. The percentile script also consumes the reconstructed 258 check inputs. Thus none of these calculations requires a newly trained model or a replacement calibration sample.

Use reconstructed inputs with the published frozen models, not newly refitted model parameters. For the reference comparison, write a fresh output directory:

```powershell
.\.venv-reproduce\Scripts\python.exe .\paper037\new_diagnostics\reference_comparison\compare_references036.py --source ..\ids-reconstructed-inputs --previous-analysis .\paper037\new_analysis --exports .\paper037\new_diagnostics\quantization --output ..\ids-reference-comparison-reproduced
```

For the percentile diagnostic:

```powershell
.\.venv-reproduce\Scripts\python.exe .\paper037\new_diagnostics\quantization\analyze_percentile035.py --source ..\ids-reconstructed-inputs --previous-analysis .\paper037\new_analysis --output ..\ids-percentile-reproduced
```

The original stage034 diagnostic writes beside its script. If rerunning that script, first copy its complete analysis directory to a separate working location, then pass `--source` explicitly. Do not run a write-in-place analysis inside the verified release.

These are calculations on saved calibration/fitting inputs; they do not establish new future-test performance. Model identifiers and original study limitations remain unchanged.

## Full retraining and new MCU work

The host-only training entry point is `research030/training/run_training030.py`; its options are shown by `--help`. It requires the exact source corpus and a fresh output directory. A repeated training run is a new computational replication. Numerical differences across Python, NumPy, BLAS, scikit-learn and hardware must be reported, not silently substituted into the original evidence.

The hardware entry point is `research030/run030.py`. Read `research030/START_HERE_RU.md` and inspect the intended board, partitions and port before running it. It replaces laboratory firmware and model storage. The release does not provide evidence of physical power-cut recovery, production Secure Boot, eFuse anti-rollback, another MCU architecture, or delta OTA.
