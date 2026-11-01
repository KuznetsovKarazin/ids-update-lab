"""Evidence preservation and orchestration checks. Author: Oleksandr Kuznetsov."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

import pytest

SPEC = importlib.util.spec_from_file_location("coordinator039", Path(__file__).resolve().parents[1] / "run_revision039.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def test_failed_mutation_is_not_replayed(tmp_path):
    script = tmp_path / "mutation.py"
    product = tmp_path / "product"
    script.write_text("from pathlib import Path\nimport sys\np=Path(sys.argv[1]);p.mkdir();(p/'attempt').write_text('once');raise SystemExit(9)\n")
    argv = [sys.executable, str(script), str(product)]
    with pytest.raises(RuntimeError):
        M.run_step(tmp_path, "mutation", argv, product)
    assert (product / "attempt").read_text() == "once"
    with pytest.raises(RuntimeError, match="Previous step"):
        M.run_step(tmp_path, "mutation", argv, product)
    assert json.loads((tmp_path / "steps/mutation.json").read_text())["returncode"] == 9


def test_completed_step_requires_same_command_and_bytes(tmp_path):
    script = tmp_path / "make.py"
    product = tmp_path / "product"
    script.write_text("from pathlib import Path\nimport sys\np=Path(sys.argv[1]);p.mkdir();(p/'evidence.json').write_text('{}')\n")
    argv = [sys.executable, str(script), str(product)]
    M.run_step(tmp_path, "prepare", argv, product)
    M.run_step(tmp_path, "prepare", argv, product)
    with pytest.raises(RuntimeError, match="command differs"):
        M.run_step(tmp_path, "prepare", argv + ["changed"], product)
    (product / "evidence.json").write_text('{"changed":true}')
    with pytest.raises(RuntimeError, match="output changed"):
        M.run_step(tmp_path, "prepare", argv, product)


def test_private_archive_preserves_failures_and_discloses_exclusion(tmp_path):
    out = tmp_path / "campaign"
    out.mkdir()
    M.save(out / "summary.json", {"status": "failed", "measurement_origin": "not_measured"})
    (out / "test_vectors.sqlite").write_bytes(b"rebuildable")
    (out / "sample.npz").write_bytes(b"private-derived-input")
    archive = tmp_path / "evidence.zip"
    receipt = M.pack(out, archive)
    with zipfile.ZipFile(archive) as z:
        assert json.loads(z.read("campaign/summary.json"))["status"] == "failed"
        assert z.read("campaign/sample.npz") == b"private-derived-input"
        manifest = json.loads(z.read("ARCHIVE_MANIFEST.json"))
        assert manifest["excluded"][0]["path"] == "test_vectors.sqlite"
        assert manifest["sha256"]["campaign/summary.json"] == M.sha(out / "summary.json")
    assert receipt["sha256"] == M.sha(archive)
    with pytest.raises(FileExistsError):
        M.pack(out, archive)


def test_one_board_never_reported_as_all_reviewer_experiments_complete(tmp_path):
    board = "esp32s3-a0f262ebb558"
    (tmp_path / "mcu" / board).mkdir(parents=True)
    for opt in ("Og", "O2"):
        for phase in ("numerics", "costs"):
            name = board + "-" + opt + "-" + phase
            M.save(tmp_path / "steps" / (name + ".json"), {"name": name, "status": "complete"})
    value = M.summarize(tmp_path)
    assert value["complete_board_ids"] == [board]
    assert value["multiple_board_execution_complete"] is False
    assert value["physical_powercut_tested_by_this_coordinator"] is False
    assert value["all_reviewer_experiments_complete"] is False


def test_ambiguous_training_location_requires_explicit_choice(tmp_path):
    for parent in (tmp_path / "runs/ids-completion-030", tmp_path / "ids-completion-030"):
        (parent / "training/models").mkdir(parents=True)
        (parent / "training/models/B_lr.json").write_text('{}')
    with pytest.raises(ValueError, match="Several original"):
        M.locate_prior(tmp_path)
    assert M.locate_prior(tmp_path, tmp_path / "runs/ids-completion-030") == (tmp_path / "runs/ids-completion-030/training").resolve()


def test_existing_workspace_is_not_replaced(tmp_path):
    args = argparse.Namespace(output=str(tmp_path), workspace=str(tmp_path))
    with pytest.raises(ValueError, match="outside"):
        M.ensure_campaign(args, {})
