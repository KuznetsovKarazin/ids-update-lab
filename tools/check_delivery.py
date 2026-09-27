#!/usr/bin/env python3
"""Verify delivered files without opening a serial port or modifying anything."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "DELIVERY_V2_SHA256.json").read_text(encoding="utf-8"))
errors = []
for name, expected in manifest["files"].items():
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()):
        errors.append(f"unsafe path: {name}")
    elif not path.is_file():
        errors.append(f"missing: {name}")
    elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        errors.append(f"changed: {name}")
print(json.dumps({"status": "failed" if errors else "complete", "verified_files": len(manifest["files"]),
    "hardware_accessed": False, "errors": errors}, ensure_ascii=False))
sys.exit(bool(errors))
