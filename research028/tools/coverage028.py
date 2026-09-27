#!/usr/bin/env python3
"""Metadata-only chronological split coverage; never fits or selects a model.

Input is an aggregated CSV with utc_hour (or utc_day), stage, label, type,
rows. UTC bins are complete half-open hours/days. Only valid_raw_contract
counts enter prospective split coverage; invalid inputs are not imputations.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
GROUPS = ("normal", "attack_known_A", "attack_added_B", "attack_unseen_B")
ROLES = ("A_fit", "A_cal", "B_fit_added", "B_fit", "B_cal", "common_test")


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def read_histogram(path: Path):
    """Return timestamp -> {(label, attack_type): rows}, and bin width."""
    bins = defaultdict(Counter)
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        time_field = "utc_hour" if "utc_hour" in fields else "utc_day"
        if not {time_field, "stage", "label", "type", "rows"} <= fields:
            raise ValueError("Expected utc_hour or utc_day, stage, label, type, rows")
        width = timedelta(hours=1) if time_field == "utc_hour" else timedelta(days=1)
        for index, row in enumerate(reader, 2):
            if row["stage"] != "valid_raw_contract":
                continue
            if time_field == "utc_day":
                when = datetime.combine(date.fromisoformat(row[time_field]), time(), UTC)
            else:
                when = datetime.fromisoformat(row[time_field].replace("Z", "+00:00"))
                if when.tzinfo is None:
                    raise ValueError(f"Line {index}: utc_hour must have an explicit UTC offset")
            when = when.astimezone(UTC)
            if when.minute or when.second or when.microsecond:
                raise ValueError(f"Line {index}: unaligned time bin")
            if time_field == "utc_day" and when.hour:
                raise ValueError(f"Line {index}: unaligned day bin")
            try:
                count = int(row["rows"])
                label = int(row["label"])
            except ValueError as exc:
                raise ValueError(f"Line {index}: invalid integer") from exc
            if count < 0 or label not in (0, 1) or not row["type"].strip():
                raise ValueError(f"Line {index}: invalid count, label, or type")
            if count:
                bins[when][label, row["type"].strip()] += count
    if not bins:
        raise ValueError("No positive valid_raw_contract counts in histogram")
    return dict(bins), width


class Counts:
    """Prefix counts make many metadata-only candidate windows inexpensive."""
    def __init__(self, bins, bin_width):
        self.times = sorted(bins)
        self.start = self.times[0]
        self.end = self.times[-1] + bin_width
        self.keys = sorted({key for counts in bins.values() for key in counts})
        self.prefix = {}
        for key in self.keys:
            values = [0]
            for when in self.times:
                values.append(values[-1] + bins[when].get(key, 0))
            self.prefix[key] = values

    def between(self, left, right):
        i, j = bisect.bisect_left(self.times, left), bisect.bisect_left(self.times, right)
        return Counter({key: values[j] - values[i] for key, values in self.prefix.items()
                        if values[j] != values[i]})


def candidate_coverage(counts: Counts, a_fit_end, a_cal_end, b_fit_added_end,
                       b_cal_end):
    """Group membership depends on types observed in fitting rows, never calibration."""
    if not counts.start < a_fit_end < a_cal_end < b_fit_added_end < b_cal_end < counts.end:
        raise ValueError("Need nonempty chronological windows within collection bounds")
    roles = {
        "A_fit": counts.between(counts.start, a_fit_end),
        "A_cal": counts.between(a_fit_end, a_cal_end),
        "B_fit_added": counts.between(a_cal_end, b_fit_added_end),
        "B_cal": counts.between(b_fit_added_end, b_cal_end),
        "common_test": counts.between(b_cal_end, counts.end),
    }
    # Holding A calibration out of B fitting prevents threshold-selection records
    # from silently changing roles. It is a fixed conservative protocol choice.
    roles["B_fit"] = roles["A_fit"] + roles["B_fit_added"]
    known_a = {kind for (label, kind), n in roles["A_fit"].items() if label == 1 and n}
    known_b = {kind for (label, kind), n in roles["B_fit"].items() if label == 1 and n}
    groups = dict.fromkeys(GROUPS, 0)
    group_types = {key: set() for key in GROUPS}
    for (label, kind), n in roles["common_test"].items():
        if label == 0:
            group = "normal"
        elif kind in known_a:
            group = "attack_known_A"
        elif kind in known_b:
            group = "attack_added_B"
        else:
            group = "attack_unseen_B"
        groups[group] += n
        group_types[group].add(kind)
    assert sum(groups.values()) == sum(roles["common_test"].values())
    return roles, groups, group_types, known_a, known_b


def candidate_boundaries(counts: Counts, bin_width):
    """Fixed grid: calibration 6/12/24h; added fit 1/2/4 calibration blocks.

    Daily histograms cannot resolve half days and therefore expose only 24h.
    Candidate anchors are the ends of occupied UTC grid blocks. No performance
    or prediction is inspected; candidates with empty roles remain in output.
    """
    hours_options = (6, 12, 24) if bin_width <= timedelta(hours=1) else (24,)
    for hours in hours_options:
        width = timedelta(hours=hours)
        seconds = int(width.total_seconds())
        anchors = sorted({datetime.fromtimestamp(
            (int(when.timestamp()) // seconds + 1) * seconds, UTC)
            for when in counts.times})
        for multiplier in (1, 2, 4):
            for anchor in anchors:
                a_cal_end = anchor + width
                b_added_end = a_cal_end + multiplier * width
                b_cal_end = b_added_end + width
                if counts.start < anchor and b_cal_end < counts.end:
                    yield hours, multiplier, (anchor, a_cal_end, b_added_end, b_cal_end)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(path, rows, fieldnames):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_coverage(input_csv: Path, output_dir: Path):
    input_csv, output_dir = Path(input_csv), Path(output_dir)
    bins, bin_width = read_histogram(input_csv)
    counts = Counts(bins, bin_width)
    output_dir.mkdir(parents=True, exist_ok=False)
    candidates, detail, test_detail, exposure_detail, bounds_document = [], [], [], [], []
    for index, (hours, multiplier, boundaries) in enumerate(candidate_boundaries(counts, bin_width), 1):
        ident = f"C{index:04d}"
        roles, groups, group_types, known_a, known_b = candidate_coverage(counts, *boundaries)
        a_end, ac_end, ba_end, bc_end = boundaries
        row = {
            "candidate_id": ident, "calibration_hours": hours,
            "B_added_fit_hours": hours * multiplier,
            "A_fit_start_utc": iso(counts.start), "A_fit_end_utc": iso(a_end),
            "A_cal_end_utc": iso(ac_end), "B_added_fit_end_utc": iso(ba_end),
            "B_cal_end_utc": iso(bc_end), "test_end_utc": iso(counts.end),
            "known_A_attack_types": ";".join(sorted(known_a)),
            "added_B_attack_types": ";".join(sorted(known_b - known_a)),
        }
        empty_roles, one_class_roles = [], []
        for role in ROLES:
            normal = sum(n for (label, _), n in roles[role].items() if label == 0)
            attack = sum(n for (label, _), n in roles[role].items() if label == 1)
            row[f"{role}_normal"] = normal
            row[f"{role}_attack"] = attack
            if not (normal + attack):
                empty_roles.append(role)
            if not normal or not attack:
                one_class_roles.append(role)
            # Include global (label,type) combinations even when zero in this role.
            for label, kind in counts.keys:
                detail.append({"candidate_id": ident, "role": role, "label": label,
                               "type": kind, "rows": roles[role].get((label, kind), 0)})
        for group in GROUPS:
            row[f"test_{group}_rows"] = groups[group]
            test_detail.append({"candidate_id": ident, "group": group,
                                "rows": groups[group],
                                "types": ";".join(sorted(group_types[group]))})
        # A type absent from fitting can still have influenced supervised
        # calibration. Distinguish that from absence from every development role.
        calibration_types = {kind for role in ("A_cal", "B_cal")
                             for (label, kind), n in roles[role].items() if label == 1 and n}
        for exposure, types in (
                ("unseen_in_fit_but_seen_in_calibration", calibration_types - known_b),
                ("unseen_in_all_fit_and_calibration", group_types["attack_unseen_B"] - calibration_types)):
            count = sum(n for (label, kind), n in roles["common_test"].items()
                        if label == 1 and kind in types)
            observed_types = types & group_types["attack_unseen_B"]
            row[f"test_attack_{exposure}_rows"] = count
            exposure_detail.append({"candidate_id": ident, "exposure": exposure,
                                    "rows": count, "types": ";".join(sorted(observed_types))})
        assert (row["test_attack_unseen_in_fit_but_seen_in_calibration_rows"]
                + row["test_attack_unseen_in_all_fit_and_calibration_rows"]
                == groups["attack_unseen_B"])
        row["empty_roles"] = ";".join(empty_roles)
        row["single_or_no_class_roles"] = ";".join(one_class_roles)
        row["empty_test_groups"] = ";".join(group for group in GROUPS if not groups[group])
        row["all_four_test_groups_present"] = all(groups.values())
        row["all_fit_and_cal_roles_have_two_classes"] = not any(
            role in one_class_roles for role in ("A_fit", "A_cal", "B_fit", "B_cal"))
        row["selected"] = False
        candidates.append(row)
        bounds_document.append({
            "candidate_id": ident,
            "A_fit": [[iso(counts.start), iso(a_end)]],
            "A_cal": [[iso(a_end), iso(ac_end)]],
            "B_fit_added": [[iso(ac_end), iso(ba_end)]],
            "B_fit": [[iso(counts.start), iso(a_end)], [iso(ac_end), iso(ba_end)]],
            "B_cal": [[iso(ba_end), iso(bc_end)]],
            "common_test": [[iso(bc_end), iso(counts.end)]],
        })
    # Header is defined even when a small fixture has no eligible candidates.
    candidate_fields = list(candidates[0]) if candidates else ["candidate_id", "selected"]
    write_csv(output_dir / "coverage_candidates.csv", candidates, candidate_fields)
    write_csv(output_dir / "coverage_roles.csv", detail,
              ["candidate_id", "role", "label", "type", "rows"])
    write_csv(output_dir / "coverage_test_groups.csv", test_detail,
              ["candidate_id", "group", "rows", "types"])
    write_csv(output_dir / "coverage_unseen_exposure.csv", exposure_detail,
              ["candidate_id", "exposure", "rows", "types"])
    (output_dir / "candidate_intervals.json").write_text(
        json.dumps(bounds_document, indent=2) + "\n", encoding="utf-8")
    protocol = {
        "stage": "028", "purpose": "metadata_only_candidate_coverage",
        "source_csv_name": input_csv.name, "source_csv_sha256": sha256(input_csv),
        "input_bin_seconds": int(bin_width.total_seconds()),
        "analysis_population": "valid_raw_contract; includes known-vector overlaps",
        "collection_start_utc": iso(counts.start), "collection_end_exclusive_utc": iso(counts.end),
        "rows": sum(sum(c.values()) for c in bins.values()),
        "calibration_hours": [6, 12, 24] if bin_width <= timedelta(hours=1) else [24],
        "additional_fit_width_multipliers": [1, 2, 4],
        "anchor_rule": "end of each occupied UTC 6/12/24-hour grid block",
        "candidate_filter": "nonempty time intervals ending before final observed bin end; no class/count/performance filter",
        "test_end_rule": "end of final observed time bin; common subsequent test for A and B",
        "interval_semantics": "left inclusive, right exclusive",
        "B_fit_rule": "A_fit union B_fit_added; both calibration sets excluded",
        "known_type_rule": "positive-label type occurs in fitting rows; calibration types never define knowledge",
        "unseen_B_group_meaning": "absent from B fitting; not necessarily absent from calibration",
        "never_exposed_group_meaning": "absent from all A/B fitting and calibration rows",
        "predictions_computed": False, "models_loaded": False, "training_performed": False,
        "split_selected": False, "threshold_selected": False,
        "candidate_count": len(candidates),
        "candidates_with_all_four_test_groups": sum(r["all_four_test_groups_present"] for r in candidates),
        "candidates_with_two_class_fit_and_cal_roles": sum(r["all_fit_and_cal_roles_have_two_classes"] for r in candidates),
        "candidates_with_both_properties": sum(r["all_four_test_groups_present"] and r["all_fit_and_cal_roles_have_two_classes"] for r in candidates),
        "limitations": [
            "Counts establish label-type coverage, not predictive performance or a usable detector.",
            "Type labels do not establish attack-instance, session, host, or campaign independence.",
            "attack_unseen_B means unseen in fitting only; coverage_unseen_exposure.csv separates calibration-exposed from never-exposed attack types.",
            "No session purge/gap applied: these are candidate counts before final split enforcement.",
            "No quality scores, model predictions, or optimization over outcomes are used.",
            "Full collection was already explored; future series must be described as prespecified after exploratory analysis.",
            "An empty common-test group is reported as zero and must not later be silently removed or relabelled.",
            "Histogram counts must be recomputed after any session purge, validity rule, or training subsampling.",
        ],
    }
    (output_dir / "coverage_summary.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    result = {key: protocol[key] for key in (
        "candidate_count", "candidates_with_all_four_test_groups",
        "candidates_with_two_class_fit_and_cal_roles", "candidates_with_both_properties", "split_selected")}
    result["output_dir"] = str(output_dir)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = build_coverage(args.input, args.output)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
