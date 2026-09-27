"""Narrow TON_IoT logistic fixture. Splits are by identical float32 feature vectors.

This controls exact duplicate leakage, not temporal, device, or scenario leakage.
Input is an explicit local numeric-column subset; raw traffic extraction is outside scope.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform
import re

import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .artifacts import equivalent_release, sha256_file, write_json, write_releases
from .package import Model, PackageError, contract_hash, infer_many, load_private, new_contract, parse_payload


def check_feature_names(features):
    """Conservative block list supplements, and does not replace, dataset review."""
    if not 1 <= len(features) <= 16 or len(set(features)) != len(features):
        raise PackageError("provide 1..16 distinct numeric feature names explicitly")
    exact = {"label", "type", "target", "class", "attack", "attack_cat", "attack_type", "category",
        "src_ip", "dst_ip", "source_ip", "destination_ip", "id", "uid", "ts", "timestamp", "datetime", "date", "time", "index"}
    for feature in features:
        normalized = feature.lower().strip()
        if normalized in exact or re.search(r"(^|_)(label|target|attack|prediction|predicted|ground_truth|row_id)(_|$)", normalized):
            raise PackageError(f"target/identifier feature forbidden: {feature}")


def grouped_split(x, labels, seed):
    # Group AFTER cast to deployed representation so distinct float64 inputs that
    # collide in float32 cannot cross partitions. Normalize signed zero first.
    x = np.asarray(x, dtype=np.float32).copy()
    x[x == 0] = 0.0
    unique, inverse = np.unique(x, axis=0, return_inverse=True)
    low = np.full(len(unique), 2, dtype=np.int64)
    high = np.full(len(unique), -1, dtype=np.int64)
    np.minimum.at(low, inverse, labels)
    np.maximum.at(high, inverse, labels)
    if np.any(low != high):
        raise PackageError(f"{int(np.sum(low != high))} identical feature groups have contradictory labels; resolve explicitly before training")
    groups = np.arange(len(unique))
    try:
        train, held = train_test_split(groups, test_size=0.30, random_state=seed, stratify=low)
        val, test = train_test_split(held, test_size=0.50, random_state=seed + 1, stratify=low[held])
    except ValueError as exc:
        raise PackageError(f"insufficient independent groups for stratified train/validation/test: {exc}") from exc
    assignment = np.full(len(unique), -1, dtype=np.int8)
    assignment[train], assignment[val], assignment[test] = 0, 1, 2
    rows = {name: np.flatnonzero(assignment[inverse] == i) for i, name in enumerate(("train", "validation", "test"))}
    if any(len(np.unique(labels[idx])) != 2 for idx in rows.values()):
        raise PackageError("every split must contain both binary classes")
    return rows, inverse, low, assignment


def metrics(labels, predictions):
    return {"rows": len(labels), "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "confusion_matrix_labels_0_1": confusion_matrix(labels, predictions, labels=[0, 1]).tolist(),
        "per_class": classification_report(labels, predictions, labels=[0, 1], target_names=["normal", "attack"], output_dict=True, zero_division=0)}


def train_ton(args):
    features = [v.strip() for v in args.features.split(",")]
    origin = args.data_origin
    units = [v.strip() for v in args.units.split(",")]
    check_feature_names(features)
    if args.max_golden < 2:
        raise PackageError("--max-golden must be at least 2 for binary stratified sampling")
    contract = new_contract(features, units)
    source = Path(args.csv).resolve()
    output = Path(args.output)
    if output.exists():
        raise PackageError("output exists; use a new immutable experiment directory")
    key = load_private(args.private_key)
    frame = pd.read_csv(source, usecols=[*features, "label"])
    try:
        x = frame[features].apply(pd.to_numeric, errors="raise").to_numpy(dtype=np.float32)
        y_numeric = pd.to_numeric(frame["label"], errors="raise").to_numpy()
    except (ValueError, TypeError) as exc:
        raise PackageError("selected features and label must be numeric; no automatic encoding or imputation") from exc
    if not np.isfinite(x).all() or not np.isfinite(y_numeric).all():
        raise PackageError("nonfinite/missing input rejected; resolve explicitly, no silent row dropping")
    if not np.isin(y_numeric, [0, 1]).all() or len(np.unique(y_numeric)) != 2:
        raise PackageError("label must use 0=normal, 1=attack and contain both classes; confirm meaning against source")
    y = y_numeric.astype(np.int64)
    rows, inverse, group_labels, group_assignment = grouped_split(x, y, args.seed)
    train, val, test = (rows[k] for k in ("train", "validation", "test"))
    scaler = StandardScaler().fit(x[train])
    means = scaler.mean_.astype(np.float32)
    scales = scaler.scale_.astype(np.float32)
    normalized = (x[train] - means) / scales
    if not np.isfinite(normalized).all():
        raise PackageError("float32 preprocessing overflow")
    classifier = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, solver="lbfgs", random_state=args.seed)
    classifier.fit(normalized, y[train])
    if np.any(classifier.n_iter_ >= classifier.max_iter):
        raise PackageError("logistic regression did not converge; review feature conditioning")
    release_prefix = "TON" if origin == "TON_IoT" else "synthetic"
    model = Model(1, release_prefix + "-A", contract_hash(contract), tuple(map(float, means)), tuple(map(float, scales)),
        tuple(map(float, classifier.coef_[0].astype(np.float32))), float(np.float32(classifier.intercept_[0])))
    # Threshold selection has access to validation only. Fixed grid, tie nearest 0.5.
    val_prob, _ = infer_many(model, x[val])
    candidates = [float(np.float32(v)) for v in np.linspace(0.05, 0.95, 91)]
    selected = max(candidates, key=lambda t: (balanced_accuracy_score(y[val], val_prob > t), -abs(t - 0.5)))
    a = parse_payload(replace(model, threshold=selected).payload())
    b = parse_payload(equivalent_release(a, release=release_prefix + "-B").payload())
    all_metrics = {}
    for name, indices in rows.items():
        pa, ya = infer_many(a, x[indices])
        pb, yb = infer_many(b, x[indices])
        pm, ym = infer_many(b, x[indices], a)
        all_metrics[name] = {"bundle_A": metrics(y[indices], ya), "bundle_B": metrics(y[indices], yb),
            "model_only_B_factory_preprocessing": metrics(y[indices], ym),
            "A_B_label_disagreements": int(np.sum(ya != yb)),
            "A_B_max_probability_difference": float(np.max(np.abs(pa - pb))),
            "bundle_B_vs_stale_label_disagreements": int(np.sum(yb != ym))}
    # Gate the controlled mathematical-equivalence fixture BEFORE any export.
    for name, result in all_metrics.items():
        if result["A_B_label_disagreements"] or result["A_B_max_probability_difference"] > 2e-6:
            raise PackageError(f"float32 A/B equivalence gate failed on {name}; do not treat this fixture as equivalent")
    # Seeded stratified sample of distinct test groups; every group appears once.
    _, positions = np.unique(inverse[test], return_index=True)
    candidates = test[np.sort(positions)]
    if len(candidates) > args.max_golden:
        try:
            chosen, _ = train_test_split(candidates, train_size=args.max_golden, random_state=args.seed + 2, stratify=y[candidates])
        except ValueError as exc:
            raise PackageError(f"cannot draw requested stratified board sample: {exc}") from exc
        chosen = np.sort(chosen)
    else:
        chosen = candidates
    output.mkdir(parents=True, exist_ok=False)
    write_releases(output, a, b, contract, key, origin)
    np.savez_compressed(output / "split_indices.npz", train_rows=train, validation_rows=val, test_rows=test,
        row_group_id=inverse, group_split_0train_1val_2test=group_assignment, golden_rows=chosen)
    pa, ya = infer_many(a, x[chosen]); pb, yb = infer_many(b, x[chosen]); pm, ym = infer_many(b, x[chosen], a)
    with (output / "golden.jsonl").open("w") as stream:
        for j, index in enumerate(chosen):
            row = {"record_id": int(index), "group_id": int(inverse[index]), "data_origin": origin, "split": "test", "label": int(y[index]), "raw": x[index].tolist(),
                "expected_A": {"probability": float(pa[j]), "label": int(ya[j])},
                "expected_B": {"probability": float(pb[j]), "label": int(yb[j])},
                "expected_B_model_only": {"probability": float(pm[j]), "label": int(ym[j])}}
            stream.write(json.dumps(row, allow_nan=False) + "\n")
    manifest = {"data_origin": origin, "source_filename": source.name, "source_sha256": sha256_file(source),
        "rows": len(x), "independent_exact_feature_groups": len(group_labels), "seed": args.seed,
        "features_ordered": features, "units_ordered": units, "schema_sha256": contract_hash(contract).hex(),
        "label_mapping_assertion": "source label 0=normal, 1=attack; operator must verify source provenance",
        "split": "70/15/15 of unique float32 feature groups, stratified by binary label; duplicate rows stay together",
        "limitations": ["exact duplicate grouping does not establish device, endpoint, temporal, or scenario independence", "input feature list requires domain review beyond automatic target/identifier blocklist", "B is controlled equivalent normalization, not evidence of concept drift adaptation", "metrics here are host_float32; no physical MCU measurement"],
        "scaler_fit_rows": "train only", "estimator": {"name": "LogisticRegression", "C": 1.0, "class_weight": "balanced", "max_iter": 2000, "solver": "lbfgs"},
        "threshold_selection": {"split": "validation", "criterion": "balanced_accuracy", "grid": [0.05, 0.95, 91], "tie": "nearest 0.5", "selected": a.threshold},
        "test_used_for_selection": False, "versions": {"python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__, "sklearn": sklearn.__version__},
        "equivalence_gate_passed": True, "equivalence_gate": {"max_probability_tolerance": 2e-6, "allowed_label_disagreements": 0, "scope": "all frozen train, validation, and test rows; gate checks deployment fixture, no model selection"},
        "golden_selection": {"method": "stratified random sample of distinct test float32 feature groups", "seed": args.seed + 2, "rows": len(chosen), "normal": int(np.sum(y[chosen] == 0)), "attack": int(np.sum(y[chosen] == 1)), "purpose": "board correctness and latency sample; not a replacement for full held-out host metrics"},
        "partition_rows": {name: len(index) for name, index in rows.items()}, "hardware_measured": False}
    write_json(output / "metrics_host_float32.json", all_metrics)
    write_json(output / "training_manifest.json", manifest)
    write_json(output / "sha256_manifest.json", {p.name: sha256_file(p) for p in sorted(output.iterdir()) if p.is_file()})
    print(json.dumps({"created": str(output), "data_origin": origin, "hardware_measured": False,
        "test_A_B_disagreements": all_metrics["test"]["A_B_label_disagreements"]}))
