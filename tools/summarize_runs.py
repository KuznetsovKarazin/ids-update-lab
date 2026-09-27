#!/usr/bin/env python3
"""Summarize immutable IDS Update Lab trials without merging provenance.

Python standard library only. Raw run files are read, never changed. Missing or
failed trials remain visible; absent measurements are null rather than zero.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def percentile(values, q):
    """Linear interpolation at rank (n-1)*q; singleton quantiles equal its value."""
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q
    lo = math.floor(rank)
    hi = math.ceil(rank)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)


def describe(values):
    clean = [float(v) for v in values if finite(v)]
    if not clean:
        return {"n": 0, "median": None, "p95": None, "min": None, "max": None, "iqr": None}
    return {"n": len(clean), "median": statistics.median(clean), "p95": percentile(clean, .95),
            "min": min(clean), "max": max(clean),
            "iqr": percentile(clean, .75) - percentile(clean, .25)}


def read_json(path, errors):
    try:
        obj = strict_loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("expected a JSON object")
        return obj
    except (OSError, ValueError) as exc:
        errors.append(f"{path.name}: {exc}")
        return {}


def read_jsonl(path, errors):
    rows = []
    if not path.exists():
        return rows
    try:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    row = strict_loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("expected a JSON object")
                    rows.append(row)
                except ValueError as exc:
                    errors.append(f"{path.name}:{line_number}: {exc}")
    except OSError as exc:
        errors.append(f"{path.name}: {exc}")
    return rows


def strict_loads(text):
    def reject_constant(value):
        raise ValueError(f"nonfinite JSON number {value}")
    return json.loads(text, parse_constant=reject_constant)


def first(mapping, *names, default=None):
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def flatten(mapping, prefix=""):
    for name, value in mapping.items():
        key = f"{prefix}.{name}" if prefix else name
        if isinstance(value, dict):
            yield from flatten(value, key)
        else:
            yield key, value


def response(event):
    for key in ("response", "device", "parsed", "rx"):
        if isinstance(event.get(key), dict):
            return event[key]
    return event


def phase_of(row):
    return str(first(row, "phase", "stage", default="unspecified"))


def predictions_summary(rows, tolerance):
    """Compare each observed result separately against each explicitly logged reference."""
    buckets = {}
    for row in rows:
        observed = response(row)
        if isinstance(row.get("observed"), dict):
            observed = row["observed"]
        refs = {name: row[name] for name in ("expected_A", "expected_B", "expected_B_model_only")
                if isinstance(row.get(name), dict)}
        if isinstance(row.get("expected"), dict):
            refs[str(row.get("expected_release", "logged_expected"))] = row["expected"]
        for name, ref in refs.items():
            key = (phase_of(row), name)
            item = buckets.setdefault(key, {"phase": key[0], "reference": name, "observations": 0,
                "valid_label_pairs": 0, "label_mismatches": 0, "valid_probability_pairs": 0,
                "probability_tolerance_exceeded": 0, "errors": [], "record_ids": set()})
            item["observations"] += 1
            item["record_ids"].add(str(row.get("record_id", f"missing-id-{item['observations']}")))
            a, b = observed.get("label"), ref.get("label")
            if a in (0, 1) and b in (0, 1):
                item["valid_label_pairs"] += 1
                item["label_mismatches"] += int(a != b)
            a, b = observed.get("probability"), ref.get("probability")
            if finite(a) and finite(b):
                error = abs(a - b)
                item["errors"].append(error)
                item["valid_probability_pairs"] += 1
                item["probability_tolerance_exceeded"] += int(error > tolerance["absolute"] + tolerance["relative"] * abs(b))
    result = []
    for item in buckets.values():
        errors = item.pop("errors")
        item["unique_record_ids"] = len(item.pop("record_ids"))
        item["max_probability_error"] = max(errors) if errors else None
        item["p99_probability_error"] = percentile(errors, .99) if errors else None
        item["missing_label_pairs"] = item["observations"] - item["valid_label_pairs"]
        item["missing_probability_pairs"] = item["observations"] - item["valid_probability_pairs"]
        result.append(item)
    return sorted(result, key=lambda x: (x["phase"], x["reference"]))


def timing_summary(events, predictions):
    """Only fields with an explicit time suffix are timing measurements."""
    buckets = {}
    for source, rows in (("events", events), ("predictions", predictions)):
        for row in rows:
            observed = response(row)
            operation = str(first(row, "action", "command_kind", "operation", default=observed.get("event", "unknown")))
            for name, value in flatten(row):
                if not finite(value):
                    continue
                leaf = name.rsplit(".", 1)[-1]
                unit = next((suffix for suffix in ("ns", "us", "ms", "seconds") if leaf.endswith("_" + suffix)), None)
                if unit is None or "timestamp" in leaf or "utc" in leaf or leaf in ("time_us", "time_ms"):
                    continue
                key = (source, phase_of(row), operation, name, unit)
                buckets.setdefault(key, []).append(value)
    return [{"source": key[0], "phase": key[1], "operation": key[2], "field": key[3],
             "unit": key[4], **describe(values)} for key, values in sorted(buckets.items())]


def summarize_run(directory):
    directory = directory.resolve()
    errors = []
    manifest_path = next((directory / name for name in ("manifest.json", "run_manifest.json")
                          if (directory / name).is_file()), directory / "manifest.json")
    manifest = read_json(manifest_path, errors)
    events_path = directory / "events.jsonl"
    predictions_path = directory / "observations.jsonl"
    if not predictions_path.exists() and (directory / "predictions.jsonl").exists():
        predictions_path = directory / "predictions.jsonl"
    events = read_jsonl(events_path, errors)
    predictions = read_jsonl(predictions_path, errors)
    summary_path = directory / "summary.json"
    summary = read_json(summary_path, errors) if summary_path.exists() else {}
    observations = [response(x) for x in events]
    policies = {str(x["policy"]) for x in observations if x.get("policy") is not None}
    policies.update(str(response(x)["policy"]) for x in predictions if response(x).get("policy") is not None)
    manifest_policy = first(manifest, "policy", "update_policy")
    if manifest_policy is not None:
        policies.add(str(manifest_policy))
    if len(policies) > 1:
        errors.append("Conflicting policies in manifest/device observations: " + ", ".join(sorted(policies)))
    policy = next(iter(policies)) if len(policies) == 1 else "unknown_or_conflicting"
    execution = first(manifest, "execution_origin", "execution_provenance", "measurement_origin", "runtime", default="unknown")
    if execution == "unknown" and manifest.get("hardware_measured") is True:
        execution = "actual_mcu"
    data_origin = manifest.get("data_origin", "unknown")
    device_origins = {x.get("data_origin") for x in observations + [response(x) for x in predictions] if x.get("data_origin")}
    if device_origins and device_origins != {data_origin}:
        errors.append("Device and manifest data origins differ: " + repr(sorted(device_origins)))
    run_state = first(summary, "status", "outcome", default=first(manifest, "status", default="unknown"))
    failure = first(summary, "error", "failure", default=manifest.get("error"))
    if failure:
        errors.append(str(failure))
    elif run_state not in ("complete", "completed", "success"):
        errors.append(f"trial status is {run_state!r}; not a completed trial")
    if not events_path.exists():
        errors.append("events.jsonl is missing")
    if not summary_path.exists():
        errors.append("summary.json is missing; trial may be incomplete")
    if not predictions_path.exists():
        errors.append("observations.jsonl is missing; no inference comparison evidence")
    fingerprint = {k: v for k, v in flatten(manifest) if "sha256" in k or k.endswith("hash") or ".hashes." in k}
    for name in ("build", "chip"):
        if isinstance(manifest.get("initial_status"), dict) and name in manifest["initial_status"]:
            fingerprint["initial_status." + name] = manifest["initial_status"][name]
    tolerance = manifest.get("numerical_tolerance", {"absolute": 2e-6, "relative": 0.0})
    if not isinstance(tolerance, dict) or not all(finite(tolerance.get(k)) and tolerance[k] >= 0 for k in ("absolute", "relative")):
        errors.append("invalid numerical_tolerance; protocol default used for descriptive comparison")
        tolerance = {"absolute": 2e-6, "relative": 0.0}
    identity = {"execution_origin": execution, "data_origin": data_origin, "policy": policy,
        "checkpoint": manifest.get("checkpoint", "unspecified"),
        "fault_kind": manifest.get("fault_kind", "unspecified"),
        "campaign_stage": first(manifest, "campaign_stage", "run_stage", default="unspecified"),
        "board_id": manifest.get("board_id") or "unrecorded", "artifact_fingerprints": fingerprint,
        "numerical_tolerance": tolerance}
    # Unknown metadata must never cause unrelated trials to be pooled.
    if execution == "unknown" or data_origin == "unknown" or policy == "unknown_or_conflicting" or not fingerprint or identity["campaign_stage"] == "unspecified" or (execution == "actual_mcu" and identity["board_id"] == "unrecorded"):
        identity["ungrouped_run"] = str(directory)
    group_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]
    wire = []
    for row in events:
        kind = str(first(row, "command_kind", "operation", default=""))
        command = first(row, "command", "tx", default="")
        if not kind and isinstance(command, str):
            kind = command.partition(" ")[0]
        if kind.upper().startswith(("UPDATE", "FW_")):
            for name in ("wire_bytes", "tx_bytes", "bytes_sent"):
                if finite(row.get(name)):
                    wire.append({"action": row.get("action", "unspecified"), "operation": kind, "field": name, "bytes": row[name]})
                    break
    updates = [x for x in observations if x.get("event") in
               ("update", "fw_begin", "fw_end", "fw_ready", "fw_error", "fw_abort", "fault_checkpoint")]
    file_hashes = {p.name: digest(p) for p in (manifest_path, events_path, predictions_path, summary_path) if p.is_file()}
    return {"run_path": str(directory), "run_id": directory.name, "group_id": group_id,
        "identity": identity, "run_status": run_state, "has_report_errors": bool(errors), "report_errors": errors,
        "manifest": manifest, "source_summary": summary, "source_file_sha256": file_hashes,
        "event_rows": len(events), "prediction_rows": len(predictions),
        "numerical_tolerance": tolerance,
        "tolerance_source": "manifest" if "numerical_tolerance" in manifest else "protocol_default",
        "comparisons": predictions_summary(predictions, tolerance), "timings": timing_summary(events, predictions),
        "update_wire_observations": wire, "update_wire_bytes": sum(x["bytes"] for x in wire) if wire else None,
        "candidate_B_wire_bytes": sum(x["bytes"] for x in wire if x["action"] == "candidate_B") if any(x["action"] == "candidate_B" for x in wire) else None,
        "update_outcomes": updates}


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def show(value):
    if value is None:
        return "not recorded"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(runs, groups):
    lines = ["# Run report", "", "Generated from existing raw logs; no measurements are inferred from missing fields.",
        "Native simulation and synthetic fixtures are preparation checks, not MCU or TON_IoT results.",
        "Each directory is one trial. Repeated records and repeated trials on one board are not independent boards.", "",
        "## Provenance groups", "", "Groups remain separate by execution/data origin, policy, checkpoint, campaign stage, board and artifact hashes.", "",
        "| Group | Execution | Data | Policy | Checkpoint | Trials | Reports with errors |", "| --- | --- | --- | --- | --- | ---: | ---: |"]
    for group in groups:
        ident = group["identity"]
        lines.append("| " + " | ".join(show(x) for x in (group["group_id"], ident["execution_origin"], ident["data_origin"],
            ident["policy"], ident["checkpoint"], group["trial_count"], group["reports_with_errors"])) + " |")
    for run in runs:
        lines += ["", f"## Trial: {show(run['run_id'])}", "", f"Source: `{run['run_path']}`", "",
            f"Group: `{run['group_id']}`. Logged status: **{show(run['run_status'])}**.",
            f"Candidate B transmit bytes: {show(run['candidate_B_wire_bytes'])}. All logged UPDATE/FW command bytes including rejection controls: {show(run['update_wire_bytes'])}.",
            f"Probability tolerance ({run['tolerance_source']}): absolute {show(run['numerical_tolerance']['absolute'])}; relative {show(run['numerical_tolerance']['relative'])}."]
        if run["report_errors"]:
            lines += ["", "Report errors / incomplete evidence:", ""] + [f"- {show(x)}" for x in run["report_errors"]]
        lines += ["", "| Phase | Explicit reference | Label mismatches / valid pairs | Missing label pairs | Max probability error | Over tolerance / valid pairs |",
            "| --- | --- | ---: | ---: | ---: | ---: |"]
        for item in run["comparisons"]:
            lines.append("| " + " | ".join(show(x) for x in (item["phase"], item["reference"],
                f"{item['label_mismatches']}/{item['valid_label_pairs']}", item["missing_label_pairs"], item["max_probability_error"],
                f"{item['probability_tolerance_exceeded']}/{item['valid_probability_pairs']}")) + " |")
        if not run["comparisons"]:
            lines += ["", "No observed/reference pairs were available."]
        lines += ["", "| Source / phase | Operation / field | Unit | n | Median | p95 | Min | Max |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"]
        for item in run["timings"]:
            lines.append("| " + " | ".join(show(x) for x in (item["source"] + "/" + item["phase"], item["operation"] + "/" + item["field"],
                item["unit"], item["n"], item["median"], item["p95"], item["min"], item["max"])) + " |")
        if not run["timings"]:
            lines += ["", "No explicitly unit-labelled timing fields were available."]
    lines += ["", "Probability test: `abs(observed-reference) <= absolute + relative*abs(reference)`, with each trial's declared tolerance.",
        "Quantiles use linear interpolation at rank `(n-1)*q`; a singleton has identical min/median/p95/max.",
        "Host exchange times include transport/host work. Firmware times reflect only the instrumented device operation.",
        "On native runs, even firmware-named timings are host simulation timings. A p95 from a small sample is descriptive, not a tail guarantee.",
        "No classification-quality metric is inferred from agreement with a model reference. Raw failure reasons remain in report.json.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", nargs="+", required=True, type=Path, help="explicit immutable run directories")
    parser.add_argument("--output", required=True, type=Path, help="new report directory; never overwritten")
    args = parser.parse_args(argv)
    paths = [p.resolve() for p in args.runs]
    if len(set(paths)) != len(paths):
        parser.error("the same run directory was supplied more than once")
    if args.output.exists():
        parser.error("output already exists; choose a new report directory")
    if any(args.output.resolve().is_relative_to(path) for path in paths):
        parser.error("output must be outside every raw run directory")
    runs = [summarize_run(p) for p in paths]
    groups = {}
    for run in runs:
        group = groups.setdefault(run["group_id"], {"group_id": run["group_id"], "identity": run["identity"],
            "trial_count": 0, "reports_with_errors": 0, "run_ids": []})
        group["trial_count"] += 1
        group["reports_with_errors"] += int(run["has_report_errors"])
        group["run_ids"].append(run["run_id"])
    report = {"report_format_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
        "measurement_policy": "No pooling across provenance groups; no missing measurements replaced by zero.",
        "probability_tolerance": "per trial, from manifest or clearly marked protocol default",
        "quantile_method": "linear interpolation at (n-1)*q", "groups": list(groups.values()), "runs": runs}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    (args.output / "report.md").write_text(render_markdown(runs, report["groups"]), encoding="utf-8")
    base = lambda run: {"run_id": run["run_id"], "run_path": run["run_path"], "group_id": run["group_id"],
                        **{k: v for k, v in run["identity"].items() if not isinstance(v, dict)}}
    comparison_rows = [{**base(run), **item} for run in runs for item in run["comparisons"]]
    timing_rows = [{**base(run), **item} for run in runs for item in run["timings"]]
    wire_rows = [{**base(run), **item} for run in runs for item in run["update_wire_observations"]]
    trial_rows = [{**base(run), "run_status": run["run_status"], "report_errors": " | ".join(run["report_errors"]),
        "event_rows": run["event_rows"], "prediction_rows": run["prediction_rows"], "candidate_B_wire_bytes": run["candidate_B_wire_bytes"],
        "update_wire_bytes": run["update_wire_bytes"]} for run in runs]
    common = ["run_id", "run_path", "group_id", "execution_origin", "data_origin", "policy", "checkpoint", "fault_kind", "campaign_stage", "board_id"]
    write_csv(args.output / "trials.csv", trial_rows, common + ["run_status", "report_errors", "event_rows", "prediction_rows", "candidate_B_wire_bytes", "update_wire_bytes"])
    write_csv(args.output / "comparisons.csv", comparison_rows, common + ["phase", "reference", "observations", "unique_record_ids", "valid_label_pairs", "label_mismatches",
        "missing_label_pairs", "valid_probability_pairs", "missing_probability_pairs", "max_probability_error", "p99_probability_error", "probability_tolerance_exceeded"])
    write_csv(args.output / "timings.csv", timing_rows, common + ["source", "phase", "operation", "field", "unit", "n", "median", "p95", "iqr", "min", "max"])
    write_csv(args.output / "wire_bytes.csv", wire_rows, common + ["action", "operation", "field", "bytes"])
    errors = sum(run["has_report_errors"] for run in runs)
    print(json.dumps({"report": str(args.output.resolve()), "trials": len(runs), "groups": len(groups), "reports_with_errors": errors}))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
