#!/usr/bin/env python3
"""Build the signed synthetic compatibility control; private key stays external."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
from ids_update_lab.package import infer, load_private, load_public, sign, verify


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("source", "output", "private-key", "compiler-dir"):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.compiler_dir))
    from compatible_export import compile_for_factory
    if args.output.exists():
        raise FileExistsError("use a new output directory")
    pub = load_public(args.source / "public.pem")
    key = load_private(args.private_key)
    if key.public_key().public_numbers() != pub.public_numbers():
        raise ValueError("private key does not match source public identity")
    original = [(args.source / f"release-{c}.sids").read_bytes() for c in "ABC"]
    models = [verify(blob, pub) for blob in original]
    if [m.version for m in models] != [1, 2, 3]:
        raise ValueError("expected A/B/C versions 1/2/3")
    compiled = [models[0]]
    audits = {}
    for letter, model in zip("BC", models[1:]):
        result, audit = compile_for_factory(model, models[0], release=f"synthetic-{letter}c", mode="probability")
        compiled.append(result)
        audits[letter] = audit
    envelopes = [original[0]] + [sign(m, key) for m in compiled[1:]]
    for envelope in envelopes:
        verify(envelope, pub, models[0].schema, len(models[0].means))
    rows = [json.loads(line) for line in (args.source / "golden.jsonl").read_text().splitlines() if line.strip()]
    max_error = 0.0
    mismatches = 0
    for row in rows:
        canonical_p, canonical_label = infer(models[1], row["raw"])
        row["reference_coherent_original_B"] = {"probability": canonical_p, "label": canonical_label}
        for letter, model in zip("AB", compiled[:2]):
            p, label = infer(model, row["raw"])
            row[f"expected_{letter}"] = {"probability": p, "label": label}
        p, label = infer(compiled[1], row["raw"], preprocessing=compiled[0])
        row["expected_B_model_only"] = {"probability": p, "label": label}
        max_error = max(max_error, abs(p - canonical_p))
        mismatches += int(label != canonical_label)
    if mismatches:
        raise ValueError("compiled control changed a golden label")
    args.output.mkdir(parents=True)
    for name in ("public.pem", "feature_contract.json"):
        shutil.copyfile(args.source / name, args.output / name)
    for letter, envelope in zip("ABC", envelopes):
        (args.output / f"release-{letter}.sids").write_bytes(envelope)
    golden = "".join(json.dumps(row, allow_nan=False) + "\n" for row in rows)
    (args.output / "golden.jsonl").write_text(golden, encoding="utf-8")
    provenance = json.loads((args.source / "provenance.json").read_text())
    provenance.update({
        "update_semantics": "factory_preprocessing_compatible",
        "compatibility_source_B_payload_sha256": sha(models[1].payload()),
        "fixed_factory_A_payload_sha256": sha(models[0].payload()),
        "probabilities_preserved": True,
        "probability_preservation_scope": "real-arithmetic transformation; float32 audited on listed vectors, not globally exact",
        "threshold_adjustment_logit": 0,
        "package_sha256": {f"release-{c}.sids": sha(b) for c, b in zip("ABC", envelopes)},
        "golden_source_sha256": sha((args.source / "golden.jsonl").read_bytes()),
        "golden_sha256": sha(golden.encode()),
        "compatibility_compilation": audits,
        "compatibility_binding": "host checks factory artifact identity; wire-v1 does not authenticate a separate factory-preprocessing fingerprint",
        "hardware_measured": False,
    })
    summary = {"records": len(rows), "data_origin": "synthetic_plumbing", "label_disagreements_vs_coherent_B": mismatches,
        "max_probability_delta_vs_coherent_B": max_error, "hardware_measured": False,
        "warning": "synthetic numerical/transport control, not a trained IDS effectiveness result"}
    for name, value in (("provenance.json", provenance), ("fixture_summary.json", summary)):
        (args.output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
