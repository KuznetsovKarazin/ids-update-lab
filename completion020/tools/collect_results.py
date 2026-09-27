#!/usr/bin/env python3
"""Read-only evidence collector. Python standard library, Windows/Linux.

Includes every ordinary file in runs, including failed and incomplete runs.
Copies lab artefacts from a small allow-list and preserves original bytes.
Never connects to the MCU, edits evidence, overwrites an archive, or validates
scientific claims from status fields. Archive hashes certify copied bytes only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

DEFAULT_DIRS = ("runs", "research", "docs", "stage018", "stage019")
BLOCKED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "toolchains",
                "build", "dist", "site-packages", "data", "datasets"}
PRIVATE_MARKER = re.compile(br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
SENSITIVE = re.compile(r"(?:^|[-_.])(private|credentials?|secrets?|tokens?|passwords?)(?:[-_.]|$)", re.I)
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link(path: Path) -> bool:
    s = path.lstat()
    return path.is_symlink() or bool(getattr(s, "st_file_attributes", 0) & REPARSE)


def safe_relative(value: str) -> Path:
    normalized = value.replace("\\", "/")
    p = PurePosixPath(normalized)
    if p.is_absolute() or not p.parts or any(x in ("..", ".") or ":" in x for x in p.parts):
        raise ValueError(f"Not a safe relative path: {value!r}")
    return Path(*p.parts)


def exclusion(path: Path, root: Path) -> str | None:
    parts = path.relative_to(root).parts
    if any(x in BLOCKED_DIRS or x.endswith(".egg-info") or x.startswith(".") for x in parts):
        return "excluded_transient_or_data_path"
    if any(SENSITIVE.search(x) for x in parts) or path.suffix.lower() in (".key", ".p12", ".pfx"):
        return "excluded_sensitive_path"
    if path.suffix.lower() in (".zip", ".7z", ".tar", ".gz", ".pyc"):
        return "excluded_nested_archive_or_cache"
    return None


def collect(root: Path, output: Path, include: list[str] | None = None) -> dict:
    if is_link(root):
        raise ValueError("Project root must not be a symlink or junction")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Project root is not a directory")
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Refusing to overwrite {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    selected: set[Path] = set()
    omitted: list[dict] = []
    missing: list[str] = []

    def visit(path: Path) -> None:
        relative = path.relative_to(root).as_posix()
        if path.absolute() == output:
            return
        if is_link(path):
            omitted.append({"path": relative, "reason": "symlink_or_reparse_point"})
            return
        reason = exclusion(path, root)
        if reason:
            omitted.append({"path": relative, "reason": reason})
            return
        if path.is_dir():
            for child in sorted(path.iterdir()):
                visit(child)
        elif path.is_file():
            if path.resolve().is_relative_to(root):
                selected.add(path)
            else:
                raise ValueError(f"Path escaped project root: {relative}")

    for value in [*DEFAULT_DIRS, *(include or [])]:
        rel = safe_relative(value)
        current = root
        blocked = False
        for part in rel.parts:
            current = current / part
            if current.exists() or current.is_symlink():
                if is_link(current):
                    omitted.append({"path": str(rel), "reason": "symlink_or_reparse_ancestor"})
                    blocked = True
                    break
        if blocked:
            continue
        path = root / rel
        if path.exists():
            visit(path)
        else:
            missing.append(rel.as_posix())
    for p in sorted(root.iterdir()):
        if p.is_file() and (p.suffix.lower() == ".cfn" or p.name.lower().startswith(("readme", "protocol"))):
            visit(p)
    if not any(p.relative_to(root).parts[0] == "runs" for p in selected):
        raise ValueError("No ordinary run files found under root/runs; check --root")

    files: list[dict] = []
    summaries: list[dict] = []
    created = False
    try:
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            created = True
            for source in sorted(selected):
                rel = source.relative_to(root).as_posix()
                if is_link(source):
                    raise ValueError(f"Source changed to a link: {rel}")
                before = source.stat()
                data = source.read_bytes()
                after = source.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
                    raise RuntimeError(f"File changed during collection: {rel}. Stop active experiments first.")
                if PRIVATE_MARKER.search(data):
                    omitted.append({"path": rel, "reason": "private_key_content"})
                    continue
                target = "project/" + rel
                digest = hashlib.sha256(data).hexdigest()
                z.writestr(target, data)
                files.append({"path": target, "source_relative_path": rel,
                              "bytes": len(data), "sha256": digest})
                if rel.startswith("runs/") and source.name == "summary.json":
                    entry = {"path": target, "independently_verified": False,
                             "transcript_present": (source.parent / "transcript.jsonl").is_file()}
                    try:
                        obj = json.loads(data.decode("utf-8-sig"))
                        if isinstance(obj, dict):
                            for key in ("status", "stage", "measurement_origin", "data_origin", "policy",
                                        "inferred_records", "label_mismatches", "accepted_updates", "error"):
                                if key in obj:
                                    entry["reported_" + key] = obj[key]
                        else:
                            entry["parse_error"] = "summary_is_not_an_object"
                    except (ValueError, UnicodeError) as exc:
                        entry["parse_error"] = type(exc).__name__
                    summaries.append(entry)
            manifest = {
                "schema": "ids-update-lab-evidence-collection-v1",
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "source_root": str(root), "hardware_access_attempted": False,
                "evidence_modified": False,
                "claims_independently_verified": False,
                "scope": "All selected ordinary run files, including failed/incomplete runs; allow-listed supporting artefacts",
                "file_count": len(files), "files": files,
                "omitted": omitted, "missing_optional_paths": missing, "run_summaries": summaries,
            }
            z.writestr("COLLECTION_MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
            z.writestr("README_RU.txt", "Архив создан без обращения к MCU и без изменения исходных файлов.\n"
                       "project/runs содержит также неуспешные и незавершённые опыты.\n"
                       "COLLECTION_MANIFEST.json перечисляет SHA-256, исключения и статусы, сообщённые исходными summaries.\n"
                       "Статусы не являются независимой научной проверкой. Ключи, кэши, вложенные архивы и ссылки исключены.\n")
        with zipfile.ZipFile(output) as z:
            if z.testzip() is not None:
                raise RuntimeError("ZIP CRC validation failed")
            for f in files:
                if hashlib.sha256(z.read(f["path"])).hexdigest() != f["sha256"]:
                    raise RuntimeError("ZIP SHA-256 validation failed")
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise
    return {"status": "complete", "archive": str(output), "files": len(files),
            "run_summaries": len(summaries), "omitted": len(omitted),
            "bytes": output.stat().st_size, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "hardware_access_attempted": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True, help="Fresh ZIP path; never overwritten")
    p.add_argument("--include-relative", action="append", default=[], help="Additional path relative to project root")
    a = p.parse_args()
    try:
        print(json.dumps(collect(a.root, a.output, a.include_relative), ensure_ascii=False))
        return 0
    except (OSError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
