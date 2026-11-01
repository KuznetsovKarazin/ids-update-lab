#!/usr/bin/env python3
"""Reviewer experiment coordinator. Original software: Oleksandr Kuznetsov.

Separate, immutable child runs; completed steps are hash-verified before reuse.
No physical power-cut is inferred from this ordinary USB campaign.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REV = ROOT / "revision039"
BASE = "2da88c0407e878a2bd4f07bda4429f83ace8de81"
FAMILIES = ("lr", "dt", "mlp_float", "mlp_int8")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
PROTOCOL = {
    "schema": "review_revision039_v1",
    "author": "Oleksandr Kuznetsov",
    "manuscript": "make-4623436",
    "base_commit": BASE,
    "study_status": "revision_after_exploratory_analysis_not_untouched_confirmation",
    "families": list(FAMILIES),
    "temporal_target": "original_plus_two_coverage_selected_scenarios_if_supported",
    "temporal_selection": "coverage_only_before_fitting_or_prediction",
    "calibration_target_fpr": 0.01,
    "new_numerical_panel_target": 1024,
    "numerical_panel_scope": "real_and_synthetic_stress_distinguished",
    "optimizations": ["Og", "O2"],
    "target_boards": 2,
    "paired_cost_repetitions_per_board_build_family": 10,
    "cost_policies": ["bundle", "whole", "compressed"],
    "cost_transitions": ["actual_A_to_B_reused_slot", "same_parameters_B_to_C_reused_slot"],
    "energy_campaign": "not_repeated",
    "physical_powercut": "separate_prerequisite_gated_campaign",
    "security_scope": "authenticated_installation_under_trusted_runtime_public_test_key",
    "no_global_float_equivalence_claim": True,
}


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(4 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def walk_files(directory):
    for base, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".venv"))
        for name in sorted(names):
            p = Path(base) / name
            if p.is_symlink():
                raise ValueError("Symlink is not an evidence file: " + str(p))
            if p.suffix not in (".pyc", ".pyo"):
                yield p


def verify_delivery():
    path = REV / "DELIVERY_MANIFEST.json"
    if not path.is_file():
        return {"status": "development_checkout", "base_commit": BASE}
    info = read(path)
    for relative, digest in info["sha256"].items():
        p = (ROOT / relative).resolve()
        if not p.is_relative_to(ROOT) or not p.is_file() or sha(p) != digest:
            raise ValueError("Delivered code/binary changed or missing: " + relative)
    return {"status": "verified", "files": len(info["sha256"]), "manifest_sha256": sha(path)}


def locate_prior(workspace, explicit=None):
    if explicit:
        candidates = [Path(explicit).resolve()]
    else:
        candidates = [workspace / "runs/ids-completion-030", workspace / "ids-completion-030"]
        if not any((p / "training/models/B_lr.json").is_file() for p in candidates):
            for base, dirs, files in os.walk(workspace):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".venv") and d != "revision039-kit"]
                p = Path(base)
                if p.name == "training" and (p / "models/B_lr.json").is_file() and p.parent.name == "ids-completion-030":
                    candidates.append(p.parent)
    found = []
    for p in candidates:
        t = p / "training" if (p / "training/models").is_dir() else p
        if (t / "models/B_lr.json").is_file() and t.resolve() not in found:
            found.append(t.resolve())
    if len(found) > 1:
        raise ValueError("Several original training directories; use --prior-run: " + str(found))
    return found[0] if found else None


def locate_data(workspace, explicit=None):
    entries = read(ROOT / "research030/training/vendor/source_manifest.json")["files"]
    names = {e["file"] for e in entries}
    if explicit:
        folders = [Path(explicit).resolve()]
    else:
        folders = []
        for base, dirs, files in os.walk(workspace):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".venv") and d != "revision039-kit"]
            if names.issubset(files):
                folders.append(Path(base).resolve())
    matches = [p for p in folders if all((p / name).is_file() for name in names)]
    if len(matches) > 1:
        raise ValueError("Several full TON directories; specify --data-root: " + str(matches))
    if not matches:
        return None
    p = matches[0]
    for e in entries:
        if (p / e["file"]).stat().st_size != e["bytes"]:
            raise ValueError("TON source size differs: " + str(p / e["file"]))
    return p


def inspect(args):
    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        raise ValueError("Workspace does not exist: " + str(workspace))
    prior = locate_prior(workspace, args.prior_run)
    if args.prior_run and prior is None:
        raise ValueError("Explicit --prior-run has no training/models/B_lr.json: " + args.prior_run)
    prior_origin = "original_local_training"
    if prior is None:
        prior = ROOT / "paper037/evidence_inputs/training"
        prior_origin = "published_frozen_models_without_private_samples"
        if not (prior / "models/B_lr.json").is_file():
            raise ValueError("Public frozen models are missing from the kit")
    data = locate_data(workspace, args.data_root)
    deps = {}
    for name in ("numpy", "scipy", "scikit-learn", "cryptography", "pyserial", "esptool"):
        try:
            deps[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            deps[name] = None
    try:
        from serial.tools.list_ports import comports
        ports = [{"port": p.device, "description": p.description, "serial_number": p.serial_number} for p in comports()]
    except ImportError:
        ports = []
    templates = {}
    for opt in ("Og", "O2"):
        d = REV / "build/prebuilt" / opt
        templates[opt] = {f + "_" + policy: (d / (f + "_" + policy) / "ids_update_lab.bin").is_file()
                          for f in FAMILIES for policy in ("bundle", "whole")}
    samples = {n: bool(prior and (prior / "samples" / (n + ".npz")).is_file()) for n in ("A_fit", "A_cal", "B_fit_added", "B_fit", "B_cal")}
    return {
        "schema": "revision039_preflight_v1", "utc": utc(), "workspace": str(workspace),
        "kit": str(ROOT), "delivery": verify_delivery(), "python": sys.version,
        "dependencies": deps, "serial_ports_no_device_opened": ports,
        "prior_training": str(prior) if prior else None, "prior_training_origin": prior_origin, "saved_samples": samples,
        "ton_directory": str(data) if data else None, "ton_full_hash_check": "child_before_analysis",
        "new_firmware_templates": templates,
        "ready_for_numerical_preparation": bool(prior and (samples["B_cal"] or samples["A_fit"] or data)),
        "ready_for_temporal_science": data is not None,
        "ready_for_new_cost_campaign": all(all(x.values()) for x in templates.values()),
        "physical_powercut": "requires_external_switch_and_verified_wiring; not_run_automatically",
        "second_board": "run_MCU_again_with_distinct_board_id; one_board_does_not_satisfy_R1.9",
        "hardware_access_attempted": False,
    }


def ensure_campaign(args, report):
    out = Path(args.output or Path(args.workspace) / "runs/revision039").resolve()
    if out == ROOT or ROOT in out.parents or out == Path(args.workspace).resolve():
        raise ValueError("Keep experiment output outside the delivered code directory")
    config_path = out / "campaign.json"
    protocol_path = out / "protocol.json"
    if config_path.exists():
        config = read(config_path)
        if read(protocol_path) != PROTOCOL:
            raise ValueError("Frozen campaign protocol differs; choose a fresh --output")
        if config["kit"] != str(ROOT) or config["workspace"] != report["workspace"]:
            raise ValueError("Campaign belongs to another kit/workspace; choose a fresh --output")
        if config.get("delivery") != report["delivery"]:
            raise ValueError("Kit changed since campaign initialization; preserve run and choose a new output")
        for key in ("prior_training", "ton_directory"):
            new = report[key]
            if config.get(key) and new and config[key] != new:
                raise ValueError("Input location changed for existing campaign: " + key)
            if not config.get(key) and new:
                config[key] = new
        save(config_path, config)
    else:
        out.mkdir(parents=True, exist_ok=False)
        config = {k: report[k] for k in ("workspace", "kit", "prior_training", "ton_directory", "delivery")}
        config.update(created_utc=utc(), python=sys.version, dependencies=report["dependencies"], platform=platform.platform())
        save(config_path, config)
        save(protocol_path, PROTOCOL)
    save(out / "last_preflight.json", report)
    return out, config


def evidence_files(directory):
    # Large SQLite caches are reconstructible, not silently claimed archived.
    return {str(p.relative_to(directory)).replace("\\", "/"): sha(p) for p in walk_files(directory)
            if not any(s in p.name for s in (".sqlite", ".db-wal", ".db-shm"))}


def run_step(out, name, argv, product):
    """Resume only verified completed steps, never replay a failed mutation."""
    receipt_path = out / "steps" / (name + ".json")
    if receipt_path.exists():
        receipt = read(receipt_path)
        if receipt["status"] != "complete":
            raise RuntimeError("Previous step is incomplete/failed; preserve it and use a fresh campaign output: " + name)
        if receipt["argv"] != argv:
            raise RuntimeError("Completed command differs: " + name)
        for rel, digest in receipt["outputs_sha256"].items():
            p = (product / rel).resolve()
            if not p.is_relative_to(product.resolve()) or not p.is_file() or sha(p) != digest:
                raise RuntimeError("Completed step output changed: " + name + "/" + rel)
        print("REUSE verified step: " + name, flush=True)
        return
    if product.exists():
        raise RuntimeError("Untracked existing step output; do not overwrite: " + str(product))
    log = out / "logs" / (name + ".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    receipt = {"name": name, "status": "started", "argv": argv, "started_utc": utc(), "product": str(product)}
    save(receipt_path, receipt)
    print("START " + name, flush=True)
    process = None
    try:
        env = dict(os.environ, PYTHONUTF8="1", PYTHONUNBUFFERED="1", OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1")
        with log.open("x", encoding="utf-8") as f:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", bufsize=1)
            for line in process.stdout:
                print(line, end="", flush=True)
                f.write(line)
                f.flush()
            code = process.wait()
        receipt["returncode"] = code
        if code:
            raise RuntimeError("Step failed; inspect " + str(log))
        if not product.is_dir():
            raise RuntimeError("Successful subprocess did not create its evidence directory")
        receipt.update(status="complete", outputs_sha256=evidence_files(product))
    except BaseException as exc:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        receipt.update(status="failed", error=type(exc).__name__ + ": " + str(exc))
        raise
    finally:
        receipt["finished_utc"] = utc()
        if log.exists():
            receipt["log_sha256"] = sha(log)
        save(receipt_path, receipt)


def cmd(script, *args):
    return [sys.executable, str(REV / script), *map(str, args)]


def prepare(out, config):
    prior = config["prior_training"]
    if not prior:
        raise ValueError("Original training inputs not found. Supply --prior-run E:\\ids-update-lab\\runs\\ids-completion-030")
    product = out / "prepared/numerics"
    argv = cmd("numerics/run_numerics039.py", "prepare", "--root", ROOT, "--prior-run", prior, "--output", product)
    if config["ton_directory"]:
        argv += ["--data-root", config["ton_directory"]]
    run_step(out, "prepare-numerics", argv, product)
    for opt in ("Og", "O2"):
        prebuilt = REV / "build/prebuilt" / opt
        if not all((prebuilt / (f + "_" + p) / "ids_update_lab.bin").is_file() for f in FAMILIES for p in ("bundle", "whole")):
            raise RuntimeError("New firmware is not built for " + opt + "; use revision039/build instructions")
        product = out / "prepared" / ("costs-" + opt)
        argv = cmd("baseline/run_baseline039.py", "prepare", "--training", prior, "--prebuilt-root", prebuilt, "--output", product)
        run_step(out, "prepare-costs-" + opt, argv, product)
    product = out / "prepared/powercut"
    run_step(out, "prepare-powercut-plan", cmd("powercut/run_powercut039.py", "plan", "--root", ROOT,
             "--model-a", Path(prior) / "models/A_mlp_float.json", "--model", Path(prior) / "models/B_mlp_float.json",
             "--output", product), product)


def pc(out, config):
    data, prior = config["ton_directory"], config["prior_training"]
    if not data:
        raise ValueError("Need 23 original TON CSVs. Supply --data-root <directory>; no substitute dataset will be used")
    plan = out / "pc/temporal-plan"
    run_step(out, "temporal-plan", cmd("science/run_science039.py", "plan", "--root", ROOT, "--data-root", data, "--output", plan), plan)
    run = out / "pc/temporal-runs"
    run_step(out, "temporal-runs", cmd("science/run_science039.py", "run", "--root", ROOT, "--data-root", data,
                                     "--plan", plan / "plan.json", "--output", run), run)
    if not prior:
        raise ValueError("Need --prior-run for frozen B calibration/export analyses")
    threshold = out / "pc/threshold"
    run_step(out, "threshold", cmd("science/run_science039.py", "threshold", "--root", ROOT, "--data-root", data,
                                 "--prior-run", prior, "--output", threshold), threshold)
    future = out / "pc/percentile-future"
    argv = cmd("numerics/run_numerics039.py", "future", "--root", ROOT, "--prior-run", prior,
               "--data-root", data, "--output", future)
    run_step(out, "percentile-future", argv, future)


def mcu(args, out, config):
    if not args.port or not args.board_id:
        raise ValueError("MCU operation needs --port COMxx and --board-id esp32s3-<12 hex MAC>")
    if not re.fullmatch(r"esp32s3-[0-9a-f]{12}", args.board_id):
        raise ValueError("Invalid board-id")
    prepare(out, config)
    for opt in ("Og", "O2"):
        prebuilt = REV / "build/prebuilt" / opt
        base = out / "mcu" / args.board_id / opt
        panel = base / "numerics"
        run_step(out, args.board_id + "-" + opt + "-numerics", cmd("numerics/run_numerics039.py", "mcu", "--root", ROOT,
                 "--prepared", out / "prepared/numerics", "--output", panel, "--port", args.port, "--board-id", args.board_id,
                 "--prebuilt-root", prebuilt, "--provision"), panel)
        costs = base / "costs"
        run_step(out, args.board_id + "-" + opt + "-costs", cmd("baseline/run_baseline039.py", "run", "--artifacts", out / "prepared" / ("costs-" + opt),
                 "--port", args.port, "--board-id", args.board_id, "--output", costs, "--repetitions", 10,
                 "--families", ",".join(FAMILIES)), costs)
    analyze(out, args.board_id)


def analyze(out, suffix=None):
    suffix = suffix or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    product = out / "analysis" / ("costs-" + suffix)
    run_step(out, "analysis-costs-" + suffix, cmd("analysis/analyze_costs039.py", "--campaign", out,
             "--output", product), product)


def summarize(out):
    steps = [read(p) for p in sorted((out / "steps").glob("*.json"))]
    boards = sorted(p.name for p in (out / "mcu").glob("esp32s3-*") if p.is_dir())
    done = {s["name"] for s in steps if s["status"] == "complete"}
    pc_done = {"temporal-plan", "temporal-runs", "threshold", "percentile-future"}.issubset(done)
    complete_boards = [b for b in boards if all(b + "-" + opt + "-" + phase in done for opt in ("Og", "O2") for phase in ("numerics", "costs"))]
    result = {
        "schema": "revision039_campaign_status_v1", "utc": utc(),
        "completed_steps": sorted(done), "failed_steps": [s["name"] for s in steps if s["status"] != "complete"],
        "pc_execution_complete": pc_done, "complete_board_ids": complete_boards,
        "cost_analysis_reports": [s["product"] for s in steps if s["status"] == "complete"
                                  and s["name"].startswith("analysis-costs-")],
        "multiple_board_execution_complete": len(complete_boards) >= 2,
        "physical_powercut_tested_by_this_coordinator": False,
        "all_reviewer_experiments_complete": False,
        "interpretation": "Execution status only. Scientific findings, coverage, numeric mismatches and separate physical-cut evidence require review.",
        "remaining": ["review_scientific_and_numerical_results", "separate_phase_triggered_physical_powercut"]
                     + ([] if len(complete_boards) >= 2 else ["repeat_MCU_on_second_ESP32S3"])
                     + ([] if pc_done else ["complete_PC_campaign"]),
    }
    save(out / "STATUS039.json", result)
    return result


def pack(out, archive=None):
    if not out.is_dir():
        raise ValueError("Campaign directory not found")
    if archive is None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        archive = out.parent / (out.name + "-results-" + stamp + ".zip")
    archive = Path(archive).resolve()
    if archive == out or out in archive.parents:
        raise ValueError("Archive must be outside campaign directory")
    members, excluded = [], []
    for p in walk_files(out):
        rel = p.relative_to(out).as_posix()
        if any(s in p.name for s in (".sqlite", ".db-wal", ".db-shm")) or p.suffix.lower() == ".zip":
            excluded.append({"path": rel, "bytes": p.stat().st_size, "reason": "reconstructible_database_cache_or_nested_archive"})
        else:
            members.append((p, out.name + "/" + rel))
    manifest = {"schema": "revision039_private_results_archive_v1", "created_utc": utc(),
                "sha256": {name: sha(p) for p, name in members}, "excluded": excluded,
                "distribution": "Private analysis package; may contain dataset-derived inputs. Review dataset permissions before public redistribution."}
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for p, name in members:
            z.write(p, name)
        z.writestr("ARCHIVE_MANIFEST.json", json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    with zipfile.ZipFile(archive) as z:
        bad = z.testzip()
        if bad:
            raise RuntimeError("Archive CRC failure: " + bad)
    result = {"archive": str(archive), "sha256": sha(archive), "files": len(members), "bytes": archive.stat().st_size,
              "excluded_files": len(excluded)}
    save(archive.with_suffix(".sha256.json"), result)
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("inspect", "prepare", "pc", "mcu", "all", "analyze", "status", "pack"))
    p.add_argument("--workspace", default=str(ROOT.parent))
    p.add_argument("--prior-run")
    p.add_argument("--data-root")
    p.add_argument("--output", help="New campaign directory outside kit; default WORKSPACE/runs/revision039")
    p.add_argument("--port")
    p.add_argument("--board-id")
    p.add_argument("--archive")
    a = p.parse_args(argv)
    out = None
    try:
        if a.command in ("analyze", "status", "pack"):
            out = Path(a.output or Path(a.workspace) / "runs/revision039").resolve()
            if not (out / "campaign.json").is_file():
                raise ValueError("No revision039 campaign at " + str(out))
            if a.command == "analyze":
                verify_delivery()
                analyze(out)
            value = pack(out, a.archive) if a.command == "pack" else summarize(out)
        else:
            report = inspect(a)
            if a.command == "inspect":
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0
            if any(v is None for v in report["dependencies"].values()):
                raise RuntimeError("Install revision039/requirements.txt in an isolated Python environment")
            out, config = ensure_campaign(a, report)
            if a.command in ("prepare", "all"):
                prepare(out, config)
            if a.command in ("pc", "all"):
                pc(out, config)
            if a.command in ("mcu", "all"):
                mcu(a, out, config)
            value = summarize(out)
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print("error: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1
    finally:
        if out is not None and (out / "campaign.json").is_file() and a.command not in ("status", "pack"):
            try:
                summarize(out)
                print(json.dumps(pack(out), ensure_ascii=False), flush=True)
            except Exception as exc:
                print("Archive/status error (original evidence retained): " + str(exc), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
