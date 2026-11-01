#!/usr/bin/env python3
"""Continue revision039 in a separate recovery040 campaign.

Original software author: Oleksandr Kuznetsov.
Historical evidence remains immutable. Imported numerical discrepancies remain
discrepancies; an execution-complete receipt is not a numerical agreement claim.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT.parent
spec = importlib.util.spec_from_file_location("recovery040_coordinator", ROOT / "run_revision039.py")
coord = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coord)


def verify_completed(source, name, relative_product):
    source = Path(source).resolve()
    receipt_path = source / "steps" / (name + ".json")
    receipt = coord.read(receipt_path)
    if receipt.get("status") != "complete" or receipt.get("returncode") != 0:
        raise ValueError("Only completed successful steps can be imported: " + name)
    product = source / relative_product
    pins = receipt.get("outputs_sha256")
    if not isinstance(pins, dict) or not pins:
        raise ValueError("Source step has no output hashes: " + name)
    for relative, expected in pins.items():
        path = (product / relative).resolve()
        if "\\" in relative or not path.is_relative_to(product.resolve()) or not path.is_file() or coord.sha(path) != expected:
            raise ValueError("Source evidence changed: " + name + "/" + relative)
    if coord.evidence_files(product) != pins:
        raise ValueError("Source step contains untracked or missing files: " + name)
    log = source / "logs" / (name + ".log")
    if not log.is_file() or coord.sha(log) != receipt.get("log_sha256"):
        raise ValueError("Source log changed: " + name)
    return {"name": name, "product": relative_product, "receipt_sha256": coord.sha(receipt_path),
            "outputs_sha256": pins, "log_sha256": coord.sha(log)}


def inspect_source(args):
    source = Path(args.source).resolve()
    if not re.fullmatch(r"esp32s3-[0-9a-f]{12}", args.board_id):
        raise ValueError("Invalid board ID")
    if coord.read(source / "protocol.json") != coord.PROTOCOL:
        raise ValueError("Source campaign protocol differs from the frozen revision039 protocol")
    imports = [verify_completed(source, "prepare-numerics", "prepared/numerics"),
               verify_completed(source, args.board_id + "-Og-numerics", "mcu/" + args.board_id + "/Og/numerics")]
    summary = coord.read(source / imports[1]["product"] / "summary.json")
    if any(summary.get(k) != v for k, v in {"status": "complete", "board_id": args.board_id,
            "models_completed": 26, "inferred_records": 26624, "measurement_origin": "actual_mcu"}.items()):
        raise ValueError("Historical Og numerical summary is incomplete or belongs to another board")
    artifacts = coord.read(source / imports[1]["product"] / "artifacts/artifacts.json")
    unchanged = {}
    for family in coord.FAMILIES:
        old = artifacts["families"][family]
        current = ROOT / "build/prebuilt/Og" / (family + "_bundle")
        for field, name in (("template_sha256", "ids_update_lab.bin"), ("template_metadata_sha256", "metadata.json")):
            if not (current / name).is_file() or coord.sha(current / name) != old[field]:
                raise ValueError("Historical numerics cannot be reused: Og bundle template changed: " + family + "/" + name)
        unchanged[family] = {"image_sha256": old["template_sha256"], "metadata_sha256": old["template_metadata_sha256"]}
    # Cost preparation requires only the public, frozen A/B models, not private
    # training samples or the original TON CSV files.
    training = KIT / "paper037/evidence_inputs/training"
    for family in coord.FAMILIES:
        for role in ("A", "B"):
            name = role + "_" + family + ".json"
            if coord.read(training / "models" / name) != coord.read(source / "prepared/numerics/models" / name):
                raise ValueError("Frozen cost model differs from historical numerical model: " + name)
    delivery = coord.verify_delivery()
    linkage = {}
    for opt in ("Og", "O2"):
        for family in coord.FAMILIES:
            base = ROOT / "build/prebuilt" / opt / (family + "_whole")
            meta = coord.read(base / "metadata.json")
            proof = meta.get("inflater_linkage", {})
            if (proof.get("status") != "verified" or proof.get("symbol") != "ids039_tinfl_decompress"
                    or proof.get("symbol_type") != "T" or proof.get("elf_sha256") != meta.get("elf_sha256")
                    or proof.get("updater_references") != ["ids039_tinfl_decompress"]):
                raise ValueError("Corrected inflater linkage is not proven: " + opt + "/" + family)
            proof_path = base / "inflater_linkage.json"
            if coord.sha(proof_path) != meta.get("files_sha256", {}).get("inflater_linkage.json") or coord.read(proof_path) != proof:
                raise ValueError("Inflater linkage proof is not pinned: " + opt + "/" + family)
            linkage[opt + "/" + family] = proof
    dependencies = {}
    for name in ("numpy", "scipy", "scikit-learn", "cryptography", "pyserial", "esptool"):
        dependencies[name] = importlib.metadata.version(name)
    return {"schema": "revision040_recovery_inspection_v1", "source": str(source), "board_id": args.board_id,
            "delivery": delivery, "training": str(training), "imports": imports,
            "dependencies": dependencies, "corrected_whole_inflater_linkage": linkage,
            "unchanged_Og_bundle_templates": unchanged,
            "historical_numerics": {k: summary.get(k) for k in ("inferred_records", "label_mismatches",
                "probability_tolerance_exceeded", "integer_code_mismatches", "max_probability_abs_error")},
            "source_files_sha256": coord.evidence_files(source),
            "hardware_access_attempted": False,
            "plan": ["preserve complete source campaign", "import unchanged Og numerics and frozen input panel",
                     "prepare corrected cost artifacts", "LR smoke for Og and O2, excluded from primary estimates",
                     "repeat full Og cost matrix", "acquire O2 numerics", "acquire full O2 cost matrix", "analyze and archive"],
            "energy_measured": False, "physical_power_loss_tested": False}


def copy_import(out, source, entry):
    product = out / entry["product"]
    shutil.copytree(source / entry["product"], product)
    name = entry["name"]
    shutil.copy2(source / "logs" / (name + ".log"), out / "logs" / (name + ".log"))
    old = coord.read(source / "steps" / (name + ".json"))
    # Keep original command/time intact and explicitly distinguish import from
    # a new hardware execution. The source receipt itself is also preserved.
    imported = dict(old)
    imported.update(product=str(product), evidence_origin="imported_unchanged_historical_measurement",
                    source_campaign=str(source), source_receipt_sha256=entry["receipt_sha256"], imported_utc=coord.utc())
    coord.save(out / "steps" / (name + ".json"), imported)


def initialize(out, report):
    source = Path(report["source"])
    binding = {k: report[k] for k in ("schema", "source", "board_id", "delivery", "imports",
               "unchanged_Og_bundle_templates", "source_files_sha256", "training")}
    if out.exists():
        if coord.read(out / "RECOVERY_BINDING.json") != binding:
            raise ValueError("Recovery source or delivered kit changed; preserve output and use a fresh directory")
        # Recheck both imported evidence and the preserved source copy on resume.
        for entry in report["imports"]:
            if coord.evidence_files(out / entry["product"]) != entry["outputs_sha256"]:
                raise ValueError("Imported numerical evidence changed")
        if coord.evidence_files(out / "source_evidence039") != report["source_files_sha256"]:
            raise ValueError("Preserved source campaign changed")
        return
    out.mkdir(parents=True, exist_ok=False)
    coord.save(out / "RECOVERY_BINDING.json", binding)
    coord.save(out / "protocol.json", coord.PROTOCOL)
    coord.save(out / "campaign.json", {"kind": "recovery040", "created_utc": coord.utc(), "kit": str(KIT),
               "delivery": report["delivery"], "board_id": report["board_id"], "source_campaign": str(source),
               "prior_costs": "preserved as pre-fix pilot only; excluded from primary cost analysis",
               "historical_numerics": report["historical_numerics"], "original_author": "Oleksandr Kuznetsov"})
    # Copy only regular evidence files. Do not traverse links or import caches.
    for relative in report["source_files_sha256"]:
        target = out / "source_evidence039" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    if coord.evidence_files(out / "source_evidence039") != report["source_files_sha256"]:
        raise ValueError("Source campaign changed while being preserved; no board was accessed")
    (out / "logs").mkdir()
    for entry in report["imports"]:
        copy_import(out, source, entry)


def run(args, report, out):
    source = Path(args.source).resolve()
    if out == source or source in out.parents or out in source.parents or out == KIT or KIT in out.parents:
        raise ValueError("Recovery output must be separate from the source campaign and delivered kit")
    if not args.port:
        raise ValueError("Run needs an explicit --port")
    for opt in ("Og", "O2"):
        product = out / "prepared" / ("costs-" + opt)
        coord.run_step(out, "prepare-costs-" + opt, coord.cmd("baseline/run_baseline039.py", "prepare",
            "--training", report["training"], "--prebuilt-root", ROOT / "build/prebuilt" / opt,
            "--output", product), product)
    # Both short smokes happen before the several-hour measurement campaign.
    # These runs exercise signatures, hash rejection, compressed stream rejection,
    # accepted updates, reboot and replay for the actual corrected images.
    for opt in ("Og", "O2"):
        product = out / "smoke" / opt
        coord.run_step(out, args.board_id + "-" + opt + "-smoke", coord.cmd("baseline/run_baseline039.py", "run",
            "--artifacts", out / "prepared" / ("costs-" + opt), "--port", args.port, "--board-id", args.board_id,
            "--output", product, "--repetitions", 1, "--families", "lr"), product)
    for opt in ("Og", "O2"):
        base = out / "mcu" / args.board_id / opt
        if opt == "O2":
            product = base / "numerics"
            coord.run_step(out, args.board_id + "-O2-numerics", coord.cmd("numerics/run_numerics039.py", "mcu",
                "--root", KIT, "--prepared", out / "prepared/numerics", "--output", product,
                "--port", args.port, "--board-id", args.board_id, "--prebuilt-root", ROOT / "build/prebuilt/O2",
                "--provision"), product)
        product = base / "costs"
        coord.run_step(out, args.board_id + "-" + opt + "-costs", coord.cmd("baseline/run_baseline039.py", "run",
            "--artifacts", out / "prepared" / ("costs-" + opt), "--port", args.port, "--board-id", args.board_id,
            "--output", product, "--repetitions", 10, "--families", ",".join(coord.FAMILIES)), product)
    coord.analyze(out, "recovery040-" + args.board_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "run"))
    parser.add_argument("--workspace", default=r"E:\ids-update-lab")
    parser.add_argument("--source")
    parser.add_argument("--output")
    parser.add_argument("--port")
    parser.add_argument("--board-id", default="esp32s3-a0f262ebb558")
    args = parser.parse_args(argv)
    workspace = Path(args.workspace).resolve()
    args.source = str(Path(args.source).resolve() if args.source else workspace / "runs/revision039")
    out = Path(args.output).resolve() if args.output else workspace / "runs/revision039-recovery040"
    initialized = False
    try:
        report = inspect_source(args)
        if args.command == "inspect":
            compact = {k: v for k, v in report.items() if k not in ("source_files_sha256", "imports")}
            compact["verified_source_files"] = len(report["source_files_sha256"])
            print(json.dumps(compact, indent=2, ensure_ascii=False))
            return 0
        print(json.dumps({"status": "source_verified", "historical_numerics": report["historical_numerics"],
                          "note": "Historical numerical disagreements are preserved, not waived."}), flush=True)
        source = Path(args.source).resolve()
        if out == source or source in out.parents or out in source.parents or out == KIT or KIT in out.parents:
            raise ValueError("Recovery output must be separate from the source campaign and delivered kit")
        initialize(out, report)
        initialized = True
        run(args, report, out)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print("error: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1
    finally:
        if initialized and (out / "RECOVERY_BINDING.json").is_file() and (out / "campaign.json").is_file():
            try:
                status = coord.summarize(out)
                status.update(recovery="040", historical_numerical_disagreements_preserved=True,
                              primary_costs_exclude_source_pilot_and_smoke=True)
                coord.save(out / "STATUS040.json", status)
                print(json.dumps(coord.pack(out), ensure_ascii=False), flush=True)
            except Exception as exc:
                print("Archive/status error; original evidence retained: " + str(exc), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
