#!/usr/bin/env python3
"""Revision 039 temporal and calibration experiments. Author: Oleksandr Kuznetsov.

Fresh output directories only. Original research030 files/results are never edited.
This is a reviewer-driven, post-exploration analysis, not an untouched test.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import sys

for _thread_option in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[_thread_option] = "1"
import numpy as np

SEED = 25092026
STATUS = "reviewer-driven protocol frozen before new fitting; collection previously explored"
PUBLIC_MANIFEST_SHA256 = "d23c9f5da35e4c1e68afd99acb7795f4031065c81888ca9c726c7f259bdbc56c"
ROLES = ("A_fit", "A_cal", "B_fit_added", "B_cal", "common_test")
SETTINGS = {
    "seed": SEED, "minimum_role_class_rows": 1000,
    "additional_scenarios": 2, "minimum_future_hours": 24,
    "calibration_hours": [6, 12, 24], "added_fit_multipliers": [1, 2, 4],
    "boundary_gap_seconds": 60, "threshold_target_fpr": 0.01,
    "threshold_replicates": 1000, "threshold_time_block_minutes": [15, 30, 60],
    "larger_calibration_hours": [6, 12, 24],
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def epoch(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Protocol timestamps must have explicit timezone")
    return parsed.timestamp()


def load_modules(root):
    directory = Path(root) / "research030" / "training"
    if not (directory / "run_training030.py").is_file():
        raise ValueError("--root must be the IDS Update Lab repository root")
    sys.path.insert(0, str(directory))
    import run_training030 as training
    spec = importlib.util.spec_from_file_location("coverage039_reused028", Path(root) / "research028/tools/coverage028.py")
    coverage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coverage)
    return training, coverage


def code_hashes(root):
    paths = [Path(__file__), Path(root) / "research030/training/run_training030.py",
             Path(root) / "research030/training/model030.py",
             Path(root) / "research030/training/vendor/audit_ton_full.py",
             Path(root) / "research028/tools/coverage028.py"]
    return {str(p.relative_to(root)).replace("\\", "/"): sha(p) for p in paths}


def fresh_output(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=False)
    return path


def finish(out, summary):
    write_json(out / "summary.json", summary)
    files = {str(p.relative_to(out)).replace("\\", "/"): sha(p)
             for p in sorted(out.rglob("*")) if p.is_file() and p.name != "result_manifest.json"}
    write_json(out / "result_manifest.json", {"sha256": files, "summary": summary})
    print(json.dumps(summary, ensure_ascii=False), flush=True)


def valid_batches(training, sources):
    for source in sources:
        training.progress("revision039_scan", file=source["file"])
        for tokens, ts, labels, kinds, ids, duration in training.batches(source):
            raw, valid, _, _ = training.valid_numeric(tokens)
            valid &= np.isfinite(ts) & np.isfinite(duration) & (duration >= 0)
            yield tuple(x[valid] for x in (raw, ts, labels, kinds, ids, duration))
        stat = Path(source["path"]).stat()
        if (stat.st_size, stat.st_mtime_ns) != (source["bytes"], source["mtime_ns"]):
            raise ValueError("Source changed during scan: " + source["file"])


def validate_protocol(protocol):
    """Reject overlap and role reuse before touching fitting code."""
    intervals = protocol["intervals"]
    bounds = []
    for role in ROLES:
        if len(intervals[role]) != 1:
            raise ValueError("039 scenarios require one contiguous interval per atomic role")
        lo, hi = map(epoch, intervals[role][0])
        if not lo < hi:
            raise ValueError("Empty temporal role: " + role)
        bounds.append((lo, hi))
    for left, right in zip(bounds, bounds[1:]):
        if left[1] > right[0]:
            raise ValueError("Temporal roles overlap or are out of order")
    expected = intervals["A_fit"] + intervals["B_fit_added"]
    if intervals.get("B_fit", expected) != expected:
        raise ValueError("B_fit must exclude both calibration roles")
    if protocol.get("flow_boundary_enforcement", {}).get("gap_seconds", 60) != 60:
        raise ValueError("Frozen 60-second boundary gap required")
    return bounds


def protocol_from_intervals(intervals, identifier):
    protocol = {"schema": "039_temporal_protocol_v1", "scenario_id": identifier,
                "study_status": STATUS, "intervals": intervals,
                "flow_boundary_enforcement": {"gap_seconds": 60},
                "B_fit_rule": "A_fit union B_fit_added; both calibration intervals excluded"}
    validate_protocol(protocol)
    return protocol


def support_from_counts(counts):
    support = {}
    for role in ROLES:
        support[role] = {
            "class_counts": [sum(n for (label, _), n in counts[role].items() if label == k) for k in (0, 1)],
            "types": {kind: sum(n for (label, key), n in counts[role].items() if key == kind)
                      for kind in sorted({key for _, key in counts[role]})},
            "attack_types": sorted(kind for (label, kind), n in counts[role].items() if label == 1 and n),
        }
    known_a = set(support["A_fit"]["attack_types"])
    known_b = known_a | set(support["B_fit_added"]["attack_types"])
    exposed = set().union(*(set(support[r]["attack_types"]) for r in ROLES[:-1]))
    groups = {"known_A": 0, "added_B": 0, "fully_unexposed": 0, "calibration_exposed_only": 0}
    for (label, kind), n in counts["common_test"].items():
        if label == 0:
            continue
        group = "known_A" if kind in known_a else "added_B" if kind in known_b else "fully_unexposed" if kind not in exposed else "calibration_exposed_only"
        groups[group] += n
    return {"roles": support, "future_attack_cohorts": groups}


def exact_candidate_counts(training, sources, candidates):
    """One second CSV pass, sharing identical role intervals among candidates."""
    interval_keys = {}
    for candidate in candidates:
        effective = training.effective_intervals(candidate["protocol"])
        candidate["effective"] = effective
        for role in ROLES:
            interval_keys.setdefault(tuple(effective[role][0]), Counter())
    for raw, ts, labels, kinds, ids, duration in valid_batches(training, sources):
        end = ts + duration
        strata = list(set(zip(labels.tolist(), kinds.tolist())))
        encoded = {s: (labels == s[0]) & (kinds == s[1]) for s in strata}
        for (lo, hi), counter in interval_keys.items():
            chosen = (ts >= lo) & (end < hi)
            if chosen.any():
                for stratum, mask in encoded.items():
                    n = int(np.count_nonzero(chosen & mask))
                    if n:
                        counter[stratum] += n
    for candidate in candidates:
        counts = {role: interval_keys[tuple(candidate["effective"][role][0])] for role in ROLES}
        candidate["coverage"] = support_from_counts(counts)
        candidate["eligible"] = all(min(v["class_counts"]) >= SETTINGS["minimum_role_class_rows"]
                                    for v in candidate["coverage"]["roles"].values())
        candidate.pop("effective")


def select_scenarios(candidates, extra=2):
    original = next(c for c in candidates if c["id"] == "original030")
    chosen = [original]
    pool = [c for c in candidates if c["id"] != "original030" and c["eligible"]]
    selected_starts = {epoch(original["protocol"]["intervals"]["common_test"][0][0])}
    selected_intervals = {json.dumps(original["protocol"]["intervals"], sort_keys=True)}
    while pool and len(chosen) < extra + 1:
        pool = [c for c in pool if json.dumps(c["protocol"]["intervals"], sort_keys=True) not in selected_intervals]
        if not pool:
            break
        def key(c):
            groups = c["coverage"]["future_attack_cohorts"]
            mixed = min(groups["known_A"], groups["added_B"]) >= SETTINGS["minimum_role_class_rows"]
            start = epoch(c["protocol"]["intervals"]["common_test"][0][0])
            # Prefer retention only until represented, then a distinct future start.
            retention_already = any(min(x["coverage"]["future_attack_cohorts"]["known_A"], x["coverage"]["future_attack_cohorts"]["added_B"]) >= SETTINGS["minimum_role_class_rows"] for x in chosen)
            return (not (mixed or retention_already), start in selected_starts, start,
                    c.get("calibration_hours", 0), c.get("added_fit_hours", 0), c["id"])
        candidate = min(pool, key=key)
        chosen.append(candidate)
        selected_starts.add(epoch(candidate["protocol"]["intervals"]["common_test"][0][0]))
        selected_intervals.add(json.dumps(candidate["protocol"]["intervals"], sort_keys=True))
        pool.remove(candidate)
    return chosen


def plan_command(args, out):
    training, coverage = load_modules(args.root)
    write_json(out / "selection_rules_before_data.json", {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "settings": SETTINGS, "study_status": STATUS, "code_sha256": code_hashes(args.root),
        "selection": "Original + two eligible distinct protocols: first prefer old+added cohort support; then distinct future start; chronological tie-break; never predictive scores",
        "minimum_support_rule": "1000 normal and 1000 attack rows in every atomic role after 60s margins and flow containment; mixed cohort preference requires 1000 each; unseen is not mandatory",
    })
    sources = training.find_sources(args.root, args.data_root)
    bins = defaultdict(Counter)
    for raw, ts, labels, kinds, ids, duration in valid_batches(training, sources):
        hours = np.floor(ts / 3600).astype(np.int64) * 3600
        for t, label, kind in zip(hours, labels, kinds):
            bins[int(t)][(int(label), str(kind))] += 1
    with (out / "hourly_counts.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["utc_hour", "stage", "label", "type", "rows"])
        for t in sorted(bins):
            for (label, kind), count in sorted(bins[t].items()):
                writer.writerow([utc(t), "valid_raw_contract", label, kind, count])
    coverage.build_coverage(out / "hourly_counts.csv", out / "coverage_before_purge")
    definitions = json.loads((out / "coverage_before_purge/candidate_intervals.json").read_text())
    with (out / "coverage_before_purge/coverage_candidates.csv").open(encoding="utf-8", newline="") as f:
        before = {r["candidate_id"]: r for r in csv.DictReader(f)}
    original = json.loads((Path(args.root) / "research030/protocol/coverage_selection.json").read_text())
    validate_protocol(original)
    candidates = [{"id": "original030", "role": "original_protocol_replication", "protocol": original}]
    for definition in definitions:
        identifier = definition.pop("candidate_id")
        row = before[identifier]
        if any(int(row[f"{role}_{label}"]) < SETTINGS["minimum_role_class_rows"] for role in ROLES for label in ("normal", "attack")):
            continue
        if epoch(definition["common_test"][0][1]) - epoch(definition["common_test"][0][0]) < SETTINGS["minimum_future_hours"] * 3600:
            continue
        candidates.append({"id": "window_" + identifier, "role": "additional_temporal_scenario",
                           "protocol": protocol_from_intervals(definition, identifier),
                           "calibration_hours": int(row["calibration_hours"]),
                           "added_fit_hours": int(row["B_added_fit_hours"])})
    exact_candidate_counts(training, sources, candidates)
    selected = select_scenarios(candidates)
    document = {
        "schema": "revision039_science_plan_v1", "study_status": STATUS,
        "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "settings": SETTINGS, "training_config": training.CONFIG,
        "code_sha256": code_hashes(args.root), "sources": sources,
        "candidate_count_before_purge": len(definitions),
        "exact_candidates": candidates, "scenarios": selected,
        "mixed_retention_scenario_available": any(min(c["coverage"]["future_attack_cohorts"]["known_A"], c["coverage"]["future_attack_cohorts"]["added_B"]) >= 1000 for c in candidates if c["eligible"]),
        "requested_scenario_count": 3, "actual_scenario_count": len(selected),
        "scope": "Overlapping future windows are not independent replications. No all-cohort availability is presumed. Historical non-training retention is a separate diagnostic, never a replacement future cohort.",
        "models_loaded": False, "models_trained": False, "predictions_used_for_selection": False,
    }
    write_json(out / "plan.json", document)
    (out / "plan.sha256").write_text(sha(out / "plan.json") + "\n", encoding="ascii")
    finish(out, {"status": "planned", "scenario_count": len(selected), "mixed_retention_scenario_available": document["mixed_retention_scenario_available"], "models_trained": False})


def verify_plan(path, root):
    path = Path(path)
    expected = path.with_suffix(".sha256").read_text(encoding="ascii").strip()
    if sha(path) != expected:
        raise ValueError("Plan hash differs: create a new plan instead of editing the frozen plan")
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan["schema"] != "revision039_science_plan_v1" or plan["settings"] != SETTINGS:
        raise ValueError("Plan schema/settings mismatch")
    if plan["code_sha256"] != code_hashes(root):
        raise ValueError("Code changed after planning; create a fresh plan before fitting")
    return plan


def run_command(args, out):
    training, _ = load_modules(args.root)
    import sklearn
    plan = verify_plan(args.plan, args.root)
    sources = training.find_sources(args.root, args.data_root)
    signature = lambda items: [(s["file"], s["sha256"], s["bytes"]) for s in items]
    if signature(sources) != signature(plan["sources"]):
        raise ValueError("Data hashes differ from frozen plan")
    selected = [s for s in plan["scenarios"] if not args.scenario or s["id"] == args.scenario]
    if not selected:
        raise ValueError("Requested scenario was not selected in frozen plan")
    write_json(out / "plan_copy.json", plan)
    summaries = {}
    for scenario in selected:
        if not scenario["eligible"]:
            raise ValueError("Frozen scenario fails after-purge support: " + scenario["id"])
        protocol = scenario["protocol"]
        validate_protocol(protocol)
        target = out / scenario["id"]
        target.mkdir()
        for name in ("samples", "models", "hardware_vectors"):
            (target / name).mkdir()
        write_json(target / "protocol_lock_before_data_and_predictions.json", {
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "temporal_protocol": protocol, "config": training.CONFIG, "study_status": STATUS,
            "plan_sha256": sha(args.plan), "code_sha256": code_hashes(args.root),
            "numpy": np.__version__, "sklearn": sklearn.__version__, "python": sys.version, "platform": platform.platform(),
        })
        arrays, support = training.prepare_data(sources, protocol, target)
        expected_counts = {role: scenario["coverage"]["roles"][role]["class_counts"] for role in ROLES}
        if any(support[role]["class_counts"] != expected_counts[role] for role in ROLES):
            raise ValueError("Retained support differs from frozen plan; fitting not started")
        models = training.fit_models(arrays, target)
        result = training.evaluate(models, support, target)
        result.update(status="complete", study_status=STATUS, hardware_access_attempted=False,
                      physical_power_loss_tested=False, scientific_full_result=True)
        finish(target, result)
        summaries[scenario["id"]] = result
    finish(out, {"status": "complete", "scenarios": summaries, "study_status": STATUS, "hardware_access_attempted": False})


def weighted_cut(scores, weights, integer=False, target=0.01):
    scores = np.asarray(scores)
    weights = np.asarray(weights, dtype=np.int64)
    if scores.ndim != 1 or weights.shape != scores.shape or not np.isfinite(scores).all() or np.any(weights < 0):
        raise ValueError("Invalid calibration scores/weights")
    if integer and np.any(scores != np.floor(scores)):
        raise ValueError("Integer runtime scores must be exact integer codes")
    n = int(weights.sum())
    if n == 0:
        raise ValueError("No resampled normal records")
    order = np.argsort(scores, kind="stable")
    rank = n - math.floor(target * n) - 1
    boundary = scores[order[np.searchsorted(np.cumsum(weights[order]), rank, side="right")]]
    return int(boundary) + 1 if integer else float(np.float32(boundary))


class ScoreDistribution:
    """Evaluate arbitrary cuts in logarithmic time after one held-out score sort."""

    def __init__(self, scores, labels):
        scores, labels = np.asarray(scores), np.asarray(labels)
        if scores.ndim != 1 or labels.shape != scores.shape or not np.isfinite(scores).all() or not np.isin(labels, [0, 1]).all():
            raise ValueError("Invalid held-out scores or labels")
        order = np.argsort(scores, kind="stable")
        self.scores = scores[order]
        self.attacks_prefix = np.cumsum(labels[order], dtype=np.int64)
        self.n1 = int(self.attacks_prefix[-1]) if len(scores) else 0
        self.n0 = len(scores) - self.n1

    def metrics(self, cut, integer=False):
        index = int(np.searchsorted(self.scores, cut if integer else np.float32(cut), side="left" if integer else "right"))
        fn = int(self.attacks_prefix[index - 1]) if index else 0
        tn = index - fn
        fp, tp = self.n0 - tn, self.n1 - fn
        return {"FP": fp, "TP": tp, "normal": self.n0, "attack": self.n1,
                "FPR": fp / self.n0 if self.n0 else None,
                "recall": tp / self.n1 if self.n1 else None}


def score_metrics(scores, labels, cut, integer=False):
    scores, labels = np.asarray(scores), np.asarray(labels)
    pred = scores >= cut if integer else scores > np.float32(cut)
    normal, attack = labels == 0, labels == 1
    fp, tp = int(np.count_nonzero(pred & normal)), int(np.count_nonzero(pred & attack))
    n0, n1 = int(normal.sum()), int(attack.sum())
    return {"FP": fp, "TP": tp, "normal": n0, "attack": n1,
            "FPR": fp / n0 if n0 else None, "recall": tp / n1 if n1 else None}


def bootstrap_thresholds(scores, timestamps, integer=False, repeats=1000, seed=SEED,
                         block_minutes=None, interval=None):
    """Conditional threshold sensitivity; no future-FPR confidence guarantee."""
    scores = np.asarray(scores)
    timestamps = np.asarray(timestamps, dtype=np.float64)
    if len(scores) != len(timestamps) or not len(scores) or not np.isfinite(timestamps).all():
        raise ValueError("Need finite timestamps for every normal calibration score")
    rng = np.random.default_rng(seed)
    cuts, empty = [], 0
    if not np.isfinite(scores).all() or (integer and np.any(scores != np.floor(scores))):
        raise ValueError("Invalid calibration scores")
    order = np.argsort(scores, kind="stable")
    blocks = None
    if block_minutes is not None:
        if block_minutes <= 0 or interval is None or interval[1] <= interval[0]:
            raise ValueError("Time bootstrap requires positive block duration and interval")
        if np.any(timestamps < interval[0]) or np.any(timestamps >= interval[1]):
            raise ValueError("Calibration timestamp outside declared interval")
        width = block_minutes * 60
        blocks = np.floor((timestamps - interval[0]) / width).astype(int)
        count = math.ceil((interval[1] - interval[0]) / width)
    for _ in range(repeats):
        if blocks is None:
            weights = np.bincount(rng.integers(0, len(scores), len(scores)), minlength=len(scores))
        else:
            multiplicity = np.bincount(rng.integers(0, count, count), minlength=count)
            weights = multiplicity[blocks]
        if weights.sum() == 0:
            empty += 1
            continue
        total = int(weights.sum())
        rank = total - math.floor(SETTINGS["threshold_target_fpr"] * total) - 1
        boundary = scores[order[np.searchsorted(np.cumsum(weights[order]), rank, side="right")]]
        cuts.append(int(boundary) + 1 if integer else float(np.float32(boundary)))
    return {"method": "iid_row_resampling" if blocks is None else "nonoverlapping_time_block_resampling",
            "block_minutes": block_minutes, "blocks_including_empty": None if blocks is None else count,
            "occupied_blocks": None if blocks is None else len(np.unique(blocks)),
            "requested_draws": repeats, "empty_draws": empty, "cuts": cuts,
            "cut_quantiles_2.5_50_97.5": np.quantile(cuts, [.025, .5, .975]).tolist() if cuts else None,
            "interpretation": "Empirical resampling sensitivity; quantiles are not a population-FPR guarantee; dependence beyond chosen blocks is unresolved"}


def summarize_scores(cal_scores, cal_ts, cal_end, test_scores, test_labels, start, ends,
                     integer=False, repeats=1000, blocks=(15, 30, 60)):
    cal_scores, cal_ts, cal_end = (np.asarray(v) for v in (cal_scores, cal_ts, cal_end))
    if cal_scores.ndim != 1 or cal_ts.shape != cal_scores.shape or cal_end.shape != cal_scores.shape:
        raise ValueError("Calibration score and time arrays must have the same shape")
    if not np.isfinite(cal_ts).all() or not np.isfinite(cal_end).all() or np.any(cal_end < cal_ts):
        raise ValueError("Invalid calibration flow times")
    if not ends or not all(np.isfinite(e) and e > start + 120 for e in ends):
        raise ValueError("Calibration windows must leave both frozen margins")
    holdout = ScoreDistribution(test_scores, test_labels)
    records = []
    for end in ends:
        mask = (cal_ts >= start + 60) & (cal_end < end - 60)
        scores, times = cal_scores[mask], cal_ts[mask]
        if len(scores) == 0:
            records.append({"end_utc": utc(end), "status": "no_normal_records"})
            continue
        cut = weighted_cut(scores, np.ones(len(scores), np.int64), integer)
        methods = [bootstrap_thresholds(scores, times, integer, repeats, block_minutes=minutes,
                                        interval=(start + 60, end - 60)) for minutes in (None, *blocks)]
        # Evaluate distinct cuts once; never select a threshold using test outcomes.
        unique = sorted({cut} | {value for m in methods for value in m["cuts"]})
        metrics = {str(value): holdout.metrics(value, integer) for value in unique}
        for method in methods:
            for metric in ("FPR", "recall"):
                values = [metrics[str(value)][metric] for value in method["cuts"]]
                values = [v for v in values if v is not None]
                method[metric + "_sensitivity_quantiles_2.5_50_97.5"] = np.quantile(values, [.025, .5, .975]).tolist() if values else None
        records.append({"end_utc": utc(end), "normal_rows": len(scores), "cut": cut,
                        "calibration": score_metrics(scores, np.zeros(len(scores)), cut, integer),
                        "common_holdout": metrics[str(cut)], "resampling": methods,
                        "holdout_by_cut": metrics})
    return records


def threshold_fixture(args, out):
    data = np.load(args.scores, allow_pickle=False)
    required = {"cal_scores", "cal_ts", "cal_end", "test_scores", "test_labels", "test_ts", "cal_start", "cal_ends", "integer"}
    if not required.issubset(data.files):
        raise ValueError("Score NPZ needs fields: " + ", ".join(sorted(required)))
    start, ends = float(data["cal_start"]), data["cal_ends"].astype(float).tolist()
    if not ends or not np.isfinite(data["test_ts"]).all() or len(data["test_ts"]) != len(data["test_scores"]) or np.any(data["test_ts"] < max(ends) + 60):
        raise ValueError("Common holdout must start after largest calibration window + 60s")
    report = summarize_scores(data["cal_scores"], data["cal_ts"], data["cal_end"], data["test_scores"],
                              data["test_labels"], start, ends, bool(data["integer"]), args.repeats)
    write_json(out / "threshold_stability.json", {"schema": "039_threshold_v1", "origin": "caller_supplied_scores",
               "source_sha256": sha(args.scores), "results": report, "not_claimed_as_TON_reproduction": True})
    finish(out, {"status": "complete_score_analysis", "measurement_origin": "caller_supplied_scores", "models_trained": False})


def verified_prior(root, prior):
    """Verify saved artifacts before parsing models or computing predictions.

    Completed private/039 runs use their own result manifest. Public frozen
    models use the original distribution manifest and pinned 030 protocol.
    A directory without either verifiable provenance is not guessed to be 030.
    """
    root, prior = Path(root), Path(prior)
    families = ("lr", "dt", "mlp_float", "mlp_int8")
    names = ["B_" + f for f in families]
    names += ["A_" + f for f in families if (prior / "models" / ("A_" + f + ".json")).is_file()]
    manifest_path = prior / "result_manifest.json"
    protocol_path = prior / "protocol_lock_before_data_and_predictions.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pins = manifest["sha256"]
        needed = ["protocol_lock_before_data_and_predictions.json"] + ["models/" + n + ".json" for n in names]
        for relative in needed:
            path = prior / relative
            if relative not in pins or not path.is_file() or sha(path) != pins[relative]:
                raise ValueError("Prior-run manifest mismatch: " + relative)
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))["temporal_protocol"]
        origin = "completed_run_result_manifest"
    else:
        if protocol_path.exists():
            raise ValueError("Prior protocol lock exists without result_manifest.json; cannot verify completed run")
        manifest_path = root / "release/provenance/MANIFEST_1.0.0_2da88c0.json"
        if not manifest_path.is_file():
            manifest_path = root / "MANIFEST.sha256.json"
        if not manifest_path.is_file() or sha(manifest_path) != PUBLIC_MANIFEST_SHA256:
            raise ValueError("Pinned public release manifest mismatch or missing")
        pins = {entry["path"]: entry["sha256"] for entry in json.loads(manifest_path.read_text(encoding="utf-8"))["files"]}
        protocol_path = root / "research030/protocol/coverage_selection.json"
        protocol_relative = "research030/protocol/coverage_selection.json"
        if sha(protocol_path) != pins[protocol_relative]:
            raise ValueError("Pinned original temporal protocol mismatch")
        for name in names:
            path = prior / "models" / (name + ".json")
            reference = "paper037/evidence_inputs/training/models/" + name + ".json"
            if not path.is_file() or sha(path) != pins[reference]:
                raise ValueError("Pinned public model mismatch: " + name)
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
        origin = "pinned_public_models_and_original030_protocol"
    validate_protocol(protocol)
    models = {name: json.loads((prior / "models" / (name + ".json")).read_text(encoding="utf-8")) for name in names}
    provenance = {"origin": origin, "manifest_path": str(manifest_path), "manifest_sha256": sha(manifest_path),
                  "protocol_path": str(protocol_path), "protocol_sha256": sha(protocol_path),
                  "verified_model_sha256": {name: sha(prior / "models" / (name + ".json")) for name in names}}
    return protocol, models, provenance


def threshold_command(args, out):
    if args.scores:
        return threshold_fixture(args, out)
    if not args.prior_run or not args.data_root:
        raise ValueError("threshold needs --prior-run TRAINING_DIR and --data-root TON_CSV, or --scores NPZ")
    training, _ = load_modules(args.root)
    prior = Path(args.prior_run)
    protocol, all_models, prior_provenance = verified_prior(args.root, prior)
    start = epoch(protocol["intervals"]["B_cal"][0][0])
    original_end = epoch(protocol["intervals"]["B_cal"][0][1])
    test_end = epoch(protocol["intervals"]["common_test"][-1][1])
    ends = sorted({original_end} | {start + 3600 * h for h in SETTINGS["larger_calibration_hours"] if start + 3600 * h >= original_end})
    ends = [e for e in ends if test_end - e >= SETTINGS["minimum_future_hours"] * 3600]
    if not ends:
        raise ValueError("No calibration extension leaves the frozen minimum 24-hour common holdout")
    models = {name[2:]: model for name, model in all_models.items() if name.startswith("B_")}
    a_models = {name[2:]: model for name, model in all_models.items() if name.startswith("A_")}
    # A calibration was excluded from BOTH fitting populations. Its attacks
    # permit a retrospective diagnostic, never a future retention claim.
    historical = defaultdict(lambda: {"rows": 0, "detected": Counter()})
    known_a_types = set()
    effective = training.effective_intervals(protocol)
    sources = training.find_sources(args.root, args.data_root)
    write_json(out / "threshold_protocol_before_predictions.json", {
        "schema": "039_threshold_protocol_v1", "study_status": STATUS, "settings": SETTINGS,
        "created_utc": datetime.now(timezone.utc).isoformat(), "code_sha256": code_hashes(args.root),
        "numpy": np.__version__, "python": sys.version, "platform": platform.platform(),
        "repeats": args.repeats, "verified_prior": prior_provenance,
        "models_sha256": {name: sha(prior / "models" / ("B_" + name + ".json")) for name in models},
        "historical_A_models_sha256": {name: sha(prior / "models" / ("A_" + name + ".json")) for name in a_models},
        "calibration_start": utc(start), "calibration_ends": [utc(e) for e in ends],
        "common_holdout": [utc(max(ends) + 60), utc(test_end)], "sources": sources,
        "weights_frozen": True, "threshold_selection_uses_test": False,
        "larger_window_rule": "Fixed B weights; extend calibration forwards; all windows use common holdout after longest window; 60s margins and complete flow containment",
    })
    # Disk-backed row caches keep memory bounded during CSV inference. The cache
    # stores scores, labels, and timestamps, never raw traffic features.
    cal_dtype = np.dtype([("score", "<f8"), ("ts", "<f8"), ("end", "<f8")])
    test_dtype = np.dtype([("score", "<f8"), ("label", "u1")])
    for name in models:
        (out / (name + "_cal.bin")).touch()
        (out / (name + "_test.bin")).touch()
    for raw, ts, labels, kinds, ids, duration in valid_batches(training, sources):
        flow_end = ts + duration
        fit_lo, fit_hi = effective["A_fit"][0]
        known_a_types.update(kinds[(labels == 1) & (ts >= fit_lo) & (flow_end < fit_hi)].tolist())
        historical_lo, historical_hi = effective["A_cal"][0]
        old_mask = (labels == 1) & (ts >= historical_lo) & (flow_end < historical_hi)
        if old_mask.any():
            historical_kinds = kinds[old_mask]
            predictions = {"B_" + name: training.predict(model, raw[old_mask])[1] for name, model in models.items()}
            predictions.update({"A_" + name: training.predict(model, raw[old_mask])[1] for name, model in a_models.items()})
            for kind in np.unique(historical_kinds):
                chosen = historical_kinds == kind
                historical[str(kind)]["rows"] += int(chosen.sum())
                for name, pred in predictions.items():
                    historical[str(kind)]["detected"][name] += int(pred[chosen].sum())
        cal_mask = (labels == 0) & (ts >= start + 60) & (flow_end < max(ends) - 60)
        test_mask = (ts >= max(ends) + 60) & (flow_end < test_end)
        if np.any(cal_mask & test_mask):
            raise AssertionError("Calibration/test overlap")
        for name, model in models.items():
            if cal_mask.any():
                scores = training.predict(model, raw[cal_mask], True)[2]
                arr = np.empty(len(scores), dtype=cal_dtype)
                arr["score"], arr["ts"], arr["end"] = scores, ts[cal_mask], flow_end[cal_mask]
                with (out / (name + "_cal.bin")).open("ab") as f:
                    f.write(arr.tobytes())
            if test_mask.any():
                scores = training.predict(model, raw[test_mask], True)[2]
                arr = np.empty(len(scores), dtype=test_dtype)
                arr["score"], arr["label"] = scores, labels[test_mask]
                with (out / (name + "_test.bin")).open("ab") as f:
                    f.write(arr.tobytes())
    reports = {}
    for name, model in models.items():
        if not (out / (name + "_cal.bin")).stat().st_size or not (out / (name + "_test.bin")).stat().st_size:
            raise ValueError("No retained calibration normals or holdout records")
        cal = np.memmap(out / (name + "_cal.bin"), dtype=cal_dtype, mode="r")
        test = np.memmap(out / (name + "_test.bin"), dtype=test_dtype, mode="r")
        reports[name] = summarize_scores(cal["score"], cal["ts"], cal["end"], test["score"], test["label"], start, ends,
                                        model["kind"] == "mlp_int8", args.repeats)
        del cal, test
    write_json(out / "threshold_stability.json", {"schema": "039_threshold_v1", "results": reports,
               "limitations": "Resampling quantiles describe calibration sensitivity, not population-error control or independent temporal confidence. Longer calibration changes the common holdout population."})
    write_json(out / "historical_retention.json", {
        "status": "complete" if len(a_models) == len(models) else "partial_missing_A_models",
        "population": "full retained attack population in historical A_cal, excluded from both fits",
        "independent_future_test": False, "known_A_types": sorted(known_a_types),
        "limitations": "Retrospective diagnostic on previously inspected calibration traffic. Does not replace a mixed old/new future scenario. Types absent from A fitting are explicitly excluded from the retention claim.",
        "by_type": {kind: {"known_to_A": kind in known_a_types, "rows": values["rows"],
                            "detected": dict(values["detected"]),
                            "recall": {name: count / values["rows"] for name, count in values["detected"].items()}}
                    for kind, values in sorted(historical.items())},
    })
    finish(out, {"status": "complete", "models_trained": False, "models_evaluated": len(models),
                 "calibration_window_count": len(ends), "study_status": STATUS})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run", "threshold"):
        p = commands.add_parser(name)
        p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
        p.add_argument("--data-root", type=Path)
        p.add_argument("--output", type=Path, required=True)
        if name == "run":
            p.add_argument("--plan", type=Path, required=True)
            p.add_argument("--scenario", help="Run exactly one scenario already selected in plan")
        if name == "threshold":
            p.add_argument("--prior-run", type=Path)
            p.add_argument("--scores", type=Path, help="Direct-score NPZ; see README for strict schema")
            p.add_argument("--repeats", type=int, default=SETTINGS["threshold_replicates"])
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    if getattr(args, "repeats", 1) < 1:
        parser.error("--repeats must be positive")
    out = fresh_output(args.output)
    try:
        {"plan": plan_command, "run": run_command, "threshold": threshold_command}[args.command](args, out)
    except Exception as exc:
        write_json(out / "summary.json", {"status": "failed", "command": args.command, "error": str(exc),
                   "models_or_measurements_not_claimed_complete": True,
                   "prerequisites": "Original 23 SHA256-pinned TON CSVs for plan/run; verified completed training directory OR paper037/evidence_inputs/training public frozen models for threshold"})
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
