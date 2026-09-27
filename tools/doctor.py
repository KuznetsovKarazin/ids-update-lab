"""Read-only host environment check; never flash, erase or contact a board."""
import importlib.metadata
import json
import platform
import shutil
import sys


def main():
    versions, missing = {}, []
    for name in ["numpy", "cryptography", "pandas", "scikit-learn", "pyserial"]:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
    ports = []
    if "pyserial" not in missing:
        from serial.tools.list_ports import comports
        ports = [{"port": p.device, "description": p.description} for p in comports()]
    print(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "packages": versions, "missing_packages": missing,
        "serial_ports": ports, "idf_py": shutil.which("idf.py"),
        "note": "ESP-IDF is only needed for rebuilding firmware; no device is opened by this check."
    }, indent=2))
    return int(bool(missing) or sys.version_info < (3, 10))


if __name__ == "__main__":
    raise SystemExit(main())
