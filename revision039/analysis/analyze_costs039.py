#!/usr/bin/env python3
"""Analyze measured revision039 costs without pooling boards or MCU builds.

Original software author: Oleksandr Kuznetsov.
Only complete, hash-verified 10-block cost runs produce estimates. Incomplete
runs produce a coverage report; no missing observation is imputed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import sys

import numpy as np

FAMILIES = ("lr", "dt", "mlp_float", "mlp_int8")
POLICIES = ("bundle", "whole", "compressed")
OPTIMIZATIONS = ("Og", "O2")
TRANSITIONS = {"A_to_B_reused": 3, "B_to_C_same_parameters_reused": 4}
BLOCKS = tuple(range(1, 11))
BOOTSTRAP_DRAWS = 10_000
SEED = 25092026
EXPECTED_CELLS = set(itertools.product(BLOCKS, FAMILIES, POLICIES, TRANSITIONS))
EXPECTED_TRIALS = len(BLOCKS) * len(FAMILIES) * len(POLICIES)
PAIRS = (("bundle", "whole"), ("bundle", "compressed"), ("compressed", "whole"))
METRICS = {
    "handler_active_ms": {"unit": "ms", "description": "Instrumented installation processing only; package engine total or OTA begin + chunk handlers + finalize. Transport waits and reboot are excluded. Nested write/hash timings are not added again."},
    "usb_total_ms": {"unit": "ms", "description": "Host interval from update initiation through status verification. Whole/compressed image paths include reboot and readiness confirmation; package path has no reboot. Provisioning, warm-up and later inference checks are excluded."},
    "signed_artifact_bytes": {"unit": "bytes", "description": "Signed package envelope, or encoded application image plus 84-byte manifest metadata and 256-byte signature."},
    "update_command_tx_bytes": {"unit": "bytes", "description": "Host-to-device ASCII update-command bytes, including hexadecimal encoding and line terminators. Excludes STATUS/REBOOT commands, responses and USB framing; not physical link traffic."},
    "model_erase_bytes": {"unit": "bytes", "description": "Requested package model-region erase bytes; not measured flash wear."},
    "model_write_bytes": {"unit": "bytes", "description": "Requested package model-region write bytes, including eight slot-metadata bytes."},
    "journal_erase_bytes": {"unit": "bytes", "description": "Requested selector-journal erase bytes reported by the package installation."},
    "journal_write_bytes": {"unit": "bytes", "description": "Requested selector-journal write bytes reported by the package installation."},
    "image_partition_erase_bytes": {"unit": "bytes", "description": "Requested full-image partition erase bytes. ESP-IDF OTA metadata work is excluded."},
    "image_partition_write_bytes": {"unit": "bytes", "description": "Uncompressed application-image bytes written, including for compressed transport. ESP-IDF OTA metadata work is excluded."},
    "raw_image_bytes": {"unit": "bytes", "description": "Uncompressed application-image size."},
    "encoded_bytes": {"unit": "bytes", "description": "Transferred image body before hexadecimal command encoding; zlib bytes for compressed policy."},
}


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nonnegative_integer(value, name):
    if type(value) is not int or value < 0:
        raise ValueError("Expected nonnegative integer: " + name)
    return value


def verify_evidence(directory, required=False, required_files=("summary.json", "plan.json")):
    directory = Path(directory).resolve()
    manifest = directory / "evidence_manifest.json"
    if not manifest.is_file():
        if required:
            raise ValueError("Completed run lacks evidence_manifest.json: " + str(directory))
        return {"status": "unsealed_incomplete_run"}
    pins = read(manifest).get("sha256")
    if not isinstance(pins, dict) or not set(required_files).issubset(pins):
        raise ValueError("Evidence manifest lacks required pinned files: " + repr(required_files))
    for relative, expected in pins.items():
        path = (directory / relative).resolve()
        if not path.is_relative_to(directory) or "\\" in relative or not path.is_file() or sha(path) != expected:
            raise ValueError("Evidence SHA256 mismatch: " + str(directory / relative))
    return {"status": "verified", "files": len(pins), "manifest_sha256": sha(manifest)}


def validate_plan(path, board, required):
    if not path.is_file():
        if required:
            raise ValueError("Completed run lacks plan.json")
        return
    plan = read(path)
    if plan.get("stage") != "039" or plan.get("board_id") != board:
        raise ValueError("Cost plan stage/board identity mismatch")
    keys = [(r.get("block"), r.get("family"), r.get("policy")) for r in plan.get("plan", [])]
    expected = set(itertools.product(BLOCKS, FAMILIES, POLICIES))
    if len(keys) != len(expected) or set(keys) != expected:
        raise ValueError("Cost plan must contain the frozen 10-block, four-family, three-policy matrix")


def verify_prepared(campaign, optimization):
    """Bind Og/O2 labels to sealed build metadata, not just directory names."""
    directory = campaign / "prepared" / ("costs-" + optimization)
    evidence = verify_evidence(directory, required=True, required_files=("artifacts.json",))
    artifacts = read(directory / "artifacts.json")
    if artifacts.get("stage") != "039" or set(artifacts.get("families", {})) != set(FAMILIES):
        raise ValueError("Prepared cost artifacts have incorrect stage/families")
    for family in FAMILIES:
        for policy in ("bundle", "whole"):
            metadata = artifacts["families"][family].get("policies", {}).get(policy, {}).get("build_metadata", {})
            if any(metadata.get(k) != v for k, v in (("stage", "039"), ("family", family), ("policy", policy), ("optimization", optimization))):
                raise ValueError("Prepared build metadata disagrees with board/build analysis stratum")
            if metadata.get("phase_gpio") is not None:
                raise ValueError("Phase-instrumented firmware cannot enter the timing comparison")
    return evidence


def row_metrics(row):
    """Preserve distinct timing/byte scopes; do not invent a flash grand total."""
    for field in ("device_active_us", "host_elapsed_ns", "artifact_bytes", "tx_wire_bytes"):
        nonnegative_integer(row.get(field), field)
    if row["host_elapsed_ns"] == 0 or row["artifact_bytes"] == 0:
        raise ValueError("Measured host time and artifact size must be positive")
    metrics = {
        "handler_active_ms": row["device_active_us"] / 1000.,
        "usb_total_ms": row["host_elapsed_ns"] / 1_000_000.,
        "signed_artifact_bytes": row["artifact_bytes"],
        "update_command_tx_bytes": row["tx_wire_bytes"],
    }
    if row["policy"] == "bundle":
        fields = ("model_erase_bytes", "model_write_bytes", "journal_erase_bytes", "journal_write_bytes")
        if row.get("model_write_bytes") != row["artifact_bytes"] + 8:
            raise ValueError("Package model-write accounting differs from artifact + metadata")
        if row.get("model_erase_bytes") != math.ceil((row["artifact_bytes"] + 8) / 4096) * 4096:
            raise ValueError("Package sector-erase accounting mismatch")
        if row.get("response", {}).get("timing_us", {}).get("total") != row["device_active_us"]:
            raise ValueError("Package handler time differs from recorded response")
    else:
        fields = ("image_partition_erase_bytes", "image_partition_write_bytes", "raw_image_bytes", "encoded_bytes")
        if row.get("otadata_flash_work_included") is not False:
            raise ValueError("Unexpected OTA metadata accounting scope")
        if row.get("artifact_bytes") != row.get("encoded_bytes", -1) + 340:
            raise ValueError("Signed image-artifact accounting mismatch")
        raw = row.get("raw_image_bytes")
        nonnegative_integer(raw, "raw_image_bytes")
        if raw == 0 or row.get("image_partition_write_bytes") != raw or row.get("image_partition_erase_bytes") != math.ceil(raw / 4096) * 4096:
            raise ValueError("Image partition accounting mismatch")
        if row.get("ready", {}).get("device_active_us") != row["device_active_us"]:
            raise ValueError("OTA handler time differs from recorded response")
    for field in fields:
        metrics[field] = nonnegative_integer(row.get(field), field)
    return metrics


def validate_summary(summary, board):
    """Reject duplicates and a falsely complete matrix; expose incomplete cells."""
    if summary.get("stage") != "039" or summary.get("board_id") != board:
        raise ValueError("Summary stage/board identity mismatch")
    if summary.get("status") not in ("complete", "failed", "running"):
        raise ValueError("Unrecognized cost summary status")
    if summary.get("expected_measured_observations") != len(EXPECTED_CELLS):
        raise ValueError("Only the frozen 240-observation cost matrix is supported; pilot runs are separate")
    observations = summary.get("cost_observations")
    if not isinstance(observations, list):
        raise ValueError("Missing cost_observations list")
    trials = nonnegative_integer(summary.get("completed_trials"), "completed_trials")
    if trials > EXPECTED_TRIALS:
        raise ValueError("Too many completed trials")
    if observations and (summary.get("measurement_origin") != "actual_mcu" or summary.get("hardware_access_attempted") is not True):
        raise ValueError("Cost observations must originate from actual MCU acquisition")
    indexed = {}
    for row in observations:
        key = (row.get("block"), row.get("family"), row.get("policy"), row.get("transition"))
        if type(row.get("block")) is not int or key not in EXPECTED_CELLS:
            raise ValueError("Unexpected block/family/policy/transition: " + repr(key))
        if key in indexed:
            raise ValueError("Duplicate measured block cell: " + repr(key))
        if row.get("board_id") != board or row.get("measured") is not True or type(row.get("version")) is not int or row["version"] != TRANSITIONS[key[3]]:
            raise ValueError("Observation identity, measured flag or transition version mismatch")
        indexed[key] = row_metrics(row)
    missing = sorted(EXPECTED_CELLS - indexed.keys())
    complete = summary["status"] == "complete"
    if complete and (missing or trials != EXPECTED_TRIALS):
        raise ValueError("Completed summary has missing measured block cells or trials")
    return indexed, missing, complete


def paired_statistics(left, right, seed=SEED):
    """Median of paired differences, resampling the SAME block on both sides."""
    if set(left) != set(BLOCKS) or set(right) != set(BLOCKS):
        raise ValueError("Paired inference requires exactly the same ten complete block IDs")
    a = np.asarray([left[b] for b in BLOCKS], dtype=np.float64)
    b = np.asarray([right[b] for b in BLOCKS], dtype=np.float64)
    if not np.isfinite(a).all() or not np.isfinite(b).all():
        raise ValueError("Nonfinite paired observations")
    differences = a - b
    draws = np.random.default_rng(seed).integers(0, len(BLOCKS), size=(BOOTSTRAP_DRAWS, len(BLOCKS)))
    replicates = np.median(differences[draws], axis=1)
    low, high = np.percentile(replicates, [2.5, 97.5], method="linear")
    return {"n_pairs": len(BLOCKS), "paired_median_difference": float(np.median(differences)),
            "ci95_low": float(low), "ci95_high": float(high), "bootstrap_draws": BOOTSTRAP_DRAWS,
            "bootstrap_seed": int(seed)}


def summarize_run(indexed, board, optimization):
    groups = defaultdict(dict)
    observations = []
    for (block, family, policy, transition), metrics in sorted(indexed.items()):
        groups[(family, transition, policy)][block] = metrics
        observations.append({"board_id": board, "optimization": optimization, "block": block,
                             "family": family, "policy": policy, "transition": transition, **metrics})
    summaries, comparisons = [], []
    for (family, transition, policy), by_block in sorted(groups.items()):
        for metric in sorted(by_block[1]):
            values = np.asarray([by_block[b][metric] for b in BLOCKS], dtype=np.float64)
            median, p95 = np.percentile(values, [50, 95], method="linear")
            summaries.append({"board_id": board, "optimization": optimization, "family": family,
                              "transition": transition, "policy": policy, "metric": metric,
                              "unit": METRICS[metric]["unit"], "n_blocks": len(BLOCKS),
                              "median": float(median), "p95": float(p95),
                              "minimum": float(values.min()), "maximum": float(values.max())})
    for family, transition, (left, right) in itertools.product(FAMILIES, TRANSITIONS, PAIRS):
        a, b = groups[(family, transition, left)], groups[(family, transition, right)]
        identity = "|".join((str(SEED), board, optimization, family, transition, left, right))
        seed = int.from_bytes(hashlib.sha256(identity.encode("utf-8")).digest()[:8], "little")
        for metric in sorted(a[1].keys() & b[1].keys()):
            result = paired_statistics({k: v[metric] for k, v in a.items()}, {k: v[metric] for k, v in b.items()}, seed)
            comparisons.append({"board_id": board, "optimization": optimization, "family": family,
                                "transition": transition, "policy": left, "reference_policy": right,
                                "metric": metric, "unit": METRICS[metric]["unit"], **result})
    return observations, summaries, comparisons


def analyze_campaign(campaign):
    campaign = Path(campaign).resolve()
    if not campaign.is_dir():
        raise ValueError("Campaign directory does not exist")
    protocol_path = campaign / "protocol.json"
    if protocol_path.is_file():
        protocol = read(protocol_path)
        if protocol.get("paired_cost_repetitions_per_board_build_family") != 10 or set(protocol.get("families", [])) != set(FAMILIES) or set(protocol.get("cost_policies", [])) != set(POLICIES) or set(protocol.get("optimizations", [])) != set(OPTIMIZATIONS):
            raise ValueError("Campaign protocol differs from the frozen cost-analysis matrix")
    else:
        protocol = {}
    boards = sorted(p.name for p in (campaign / "mcu").glob("*") if p.is_dir())
    for board in boards:
        if not re.fullmatch(r"esp32s3-[0-9a-f]{12}", board):
            raise ValueError("Unrecognized board directory: " + board)
        unexpected = [p.parent.parent.name for p in (campaign / "mcu" / board).glob("*/costs/summary.json") if p.parent.parent.name not in OPTIMIZATIONS]
        if unexpected:
            raise ValueError("Unsupported build directories: " + repr(unexpected))
    runs, observations, summaries, comparisons, missing_rows = [], [], [], [], []
    prepared = {}
    for board, optimization in itertools.product(boards, OPTIMIZATIONS):
        directory = campaign / "mcu" / board / optimization / "costs"
        path = directory / "summary.json"
        run = {"board_id": board, "optimization": optimization,
               "source": path.relative_to(campaign).as_posix(), "estimates_generated": False}
        if not path.is_file():
            missing = sorted(EXPECTED_CELLS)
            run.update(status="missing_summary", observations=0)
        else:
            summary = read(path)
            indexed, missing, complete = validate_summary(summary, board)
            run.update(status=summary["status"], observations=len(indexed), summary_sha256=sha(path),
                       evidence=verify_evidence(directory, required=complete))
            validate_plan(directory / "plan.json", board, required=complete)
            if complete:
                if optimization not in prepared:
                    prepared[optimization] = verify_prepared(campaign, optimization)
                if read(directory / "plan.json").get("artifact_manifest_sha256") != prepared[optimization]["manifest_sha256"]:
                    raise ValueError("Measured run is not bound to this optimization's prepared artifacts")
                run["prepared_artifacts"] = prepared[optimization]
                rows, policy, paired = summarize_run(indexed, board, optimization)
                observations.extend(rows)
                summaries.extend(policy)
                comparisons.extend(paired)
                run["estimates_generated"] = True
        run["missing_observations"] = len(missing)
        runs.append(run)
        for block, family, policy, transition in missing:
            missing_rows.append({"board_id": board, "optimization": optimization, "block": block,
                                 "family": family, "policy": policy, "transition": transition})
    completed_boards = [b for b in boards if all(any(r["board_id"] == b and r["optimization"] == o and r["estimates_generated"] for r in runs) for o in OPTIMIZATIONS)]
    target_boards = 2
    matrix_complete = len(completed_boards) >= target_boards and all(r["estimates_generated"] for r in runs)
    return {
        "schema": "revision039_cost_analysis_v1", "status": "complete" if matrix_complete else "incomplete",
        "created_utc": datetime.now(timezone.utc).isoformat(), "campaign": str(campaign),
        "source_protocol_sha256": sha(protocol_path) if protocol_path.is_file() else None,
        "numpy_version": np.__version__, "analysis_code_sha256": sha(__file__),
        "target_boards": target_boards, "discovered_board_ids": boards, "complete_board_ids": completed_boards,
        "additional_distinct_boards_required": max(0, target_boards - len(boards)),
        "cost_matrix_complete": matrix_complete, "all_reviewer_experiments_complete": False,
        "runs": runs, "metrics": METRICS,
        "method": {"observation_unit": "one paired block per board, optimization, family and transition",
                   "blocks": list(BLOCKS), "percentile_method": "NumPy linear interpolation",
                   "bootstrap": "10000 paired whole-block percentile draws; 2.5th and 97.5th quantiles of the median of within-block policy differences",
                   "difference_direction": "policy minus reference_policy; negative means a smaller value for policy",
                   "pooling": "none across boards, optimization builds, families or the two correlated transitions",
                   "incomplete_runs": "coverage only; no estimates from partial/failed acquisitions"},
        "limitations": ["Intervals describe within-board repeatability in this recorded implementation, not population-level hardware generalization.",
                        "With ten blocks, the descriptive p95 uses interpolation and is not a tail-latency guarantee.",
                        "Bootstrap intervals are descriptive and unadjusted for multiple comparisons.",
                        "Raw/compressed image flash counts exclude OTA metadata; package journal bytes are reported separately. Requested bytes are not measured wear.",
                        "This analysis does not establish numerical equivalence, energy consumption, production security or physical power-cut recovery."],
        "observations": observations, "policy_summary": summaries, "paired_comparisons": comparisons,
        "missing_cells": missing_rows,
    }


def write_csv(path, rows, fields):
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(out, result):
    save(out / "analysis.json", result)
    identity = ["board_id", "optimization", "family", "transition"]
    write_csv(out / "policy_summary.csv", result["policy_summary"], identity + ["policy", "metric", "unit", "n_blocks", "median", "p95", "minimum", "maximum"])
    write_csv(out / "paired_comparisons.csv", result["paired_comparisons"], identity + ["policy", "reference_policy", "metric", "unit", "n_pairs", "paired_median_difference", "ci95_low", "ci95_high", "bootstrap_draws", "bootstrap_seed"])
    write_csv(out / "observations.csv", result["observations"], identity + ["block", "policy"] + list(METRICS))
    write_csv(out / "missing_cells.csv", result["missing_cells"], identity + ["block", "policy"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Fresh analysis directory; existing output is never overwritten")
    args = parser.parse_args(argv)
    campaign, out = args.campaign.resolve(), args.output.resolve()
    if out.is_relative_to(campaign / "mcu"):
        parser.error("Keep analysis outside the immutable campaign/mcu evidence tree")
    out.mkdir(parents=True, exist_ok=False)
    try:
        result = analyze_campaign(campaign)
        write_outputs(out, result)
        print(json.dumps({"status": result["status"], "complete_board_ids": result["complete_board_ids"],
                          "policy_summary_rows": len(result["policy_summary"]), "paired_comparison_rows": len(result["paired_comparisons"]),
                          "missing_observations": len(result["missing_cells"]), "output": str(out)}), flush=True)
        return 0
    except Exception as exc:
        save(out / "analysis.json", {"schema": "revision039_cost_analysis_v1", "status": "failed", "error": str(exc), "estimates_generated": False})
        print("Cost analysis rejected input: " + str(exc), file=sys.stderr)
        return 2
    finally:
        save(out / "result_manifest.json", {"sha256": {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file() and p.name != "result_manifest.json"}})


if __name__ == "__main__":
    raise SystemExit(main())
