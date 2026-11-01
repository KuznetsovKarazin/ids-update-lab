# Revision 039 cost analysis

Original software author: Oleksandr Kuznetsov.

This script analyzes the measured package, raw-image and compressed-image update
campaign. It does not connect to a board, fit a model, modify existing evidence,
or treat prepared artifacts and native tests as hardware measurements.

Run it with the same Python environment used for revision 039. NumPy is the only
nonstandard dependency. From the repository root on Windows:

```powershell
& 'E:\ids-update-lab\.venv039\Scripts\python.exe' `
  '.\revision039-kit\revision039\analysis\analyze_costs039.py' `
  --campaign 'E:\ids-update-lab\runs\revision039' `
  --output 'E:\ids-update-lab\runs\revision039\analysis\costs-001'
```

The output must be a new directory. Use a different output name for a later
analysis after another board finishes. Do not place output inside the immutable
`campaign/mcu` evidence tree. The standard coordinator result pack includes
analysis saved elsewhere inside the campaign directory.

## Input validation

The script reads `mcu/<board-id>/<Og|O2>/costs/summary.json`, its acquisition plan,
and its SHA-256 evidence manifest. It also verifies the corresponding
`prepared/costs-<Og|O2>` manifest and build metadata, so an optimization label is
not inferred only from a directory name. Preserve these prepared files when
moving or extracting a campaign.

Each completed board/build must contain exactly:

- 10 blocks, numbered 1 through 10;
- LR, DT, floating-point MLP and integer MLP;
- package (`bundle`), raw image (`whole`) and compressed image (`compressed`);
- one A-to-B reused-slot update and one B-to-C reused-slot update per trial.

This is 120 trials and 240 measured observations per board/build. Warm-up updates,
individual chunks, repeated inference calls and provisioning are not additional
cost replicates. Pilot runs with fewer blocks or families require a separate
analysis; this script does not silently combine them with the frozen campaign.

Duplicate cells, wrong board/version identities, changed sealed files, inconsistent
byte accounting, and a `complete` summary with missing cells are rejected. A
failed/incomplete acquisition is reported with its missing cells and produces no
estimates. Other complete board/build runs can still be summarized. No missing
observation is replaced or inferred. An entirely empty campaign produces an
incomplete coverage report with no measurements.

## Statistics and scope

Every board, optimization, model family and transition is a separate analysis
stratum. The script reports the median, descriptive p95, minimum and maximum over
the ten blocks for each policy. NumPy linear interpolation defines percentiles;
ten observations do not support a tail-latency guarantee.

Comparisons are package minus raw image, package minus compressed image, and
compressed image minus raw image. Policy observations are matched by the same
block number. The estimate is the **median of the ten within-block differences**,
not the difference between two medians. The 95% percentile interval uses 10,000
fixed-seed bootstrap draws of those paired blocks. Both policy values always use
the same sampled block. The output records each seed and the difference direction.

Boards, builds, families and the two correlated transitions are never pooled.
Intervals describe within-board repeatability in the recorded implementation;
they are not population-level guarantees, and they are not adjusted for multiple
comparisons. Completion of both builds on at least two distinct board IDs is
required for `cost_matrix_complete: true`. This does not mark all reviewer
experiments complete.

Timing and storage quantities remain separate:

| Quantity | Meaning |
| --- | --- |
| `handler_active_ms` | Instrumented device installation work. For OTA, begin + chunk handlers + finalize; nested write/hash time is not added again. Excludes transport waits and reboot. |
| `usb_total_ms` | Host interval through verification of the running release. Full-image paths include reboot; package updates have no reboot. Excludes provisioning and subsequent inference checks. |
| `signed_artifact_bytes` | Signed package envelope, or encoded image plus signed-manifest overhead. |
| `update_command_tx_bytes` | ASCII update-command bytes, including hex encoding; excludes responses, STATUS/REBOOT commands and USB framing. |
| Model and journal bytes | Separate requested package model-region and selector-journal erase/write counts. |
| Image-partition bytes | Requested erase/write counts for the uncompressed application image, even when transport is compressed. OTA metadata work is excluded. |

The script does not add the different flash scopes into a misleading grand total.
Requested bytes are not physical cell-wear measurements. The JSON contains a full
metric dictionary.

## Outputs and exit status

- `analysis.json`: validation, coverage, source hashes, methods, observations,
  descriptive statistics, paired comparisons and limitations.
- `observations.csv`: normalized measured observations from complete runs only.
- `policy_summary.csv`: per-policy median/p95 summaries, without pooling.
- `paired_comparisons.csv`: paired estimates and bootstrap intervals.
- `missing_cells.csv`: exact missing board/build/block/family/policy/transition cells.
- `result_manifest.json`: hashes of the generated outputs.

Exit code 0 means the analysis/report completed. Check `status` and
`cost_matrix_complete` in `analysis.json`: an incomplete campaign is a valid report,
not a successful acquisition. Invalid or altered inputs produce exit code 2 and a
failure record, without a statistical result. An existing output directory is
never overwritten.

Run the offline synthetic tests with:

```powershell
python -m unittest discover -s revision039/analysis/tests -p 'test_*.py' -v
```

Test fixtures are synthetic and are never archived as experimental results.
