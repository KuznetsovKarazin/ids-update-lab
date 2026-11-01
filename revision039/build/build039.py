#!/usr/bin/env python3
"""Build revision039 ESP32-S3 artifacts without touching a device.

Author: Oleksandr Kuznetsov. The frozen research030 source/artifacts are read-only.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
REVISION = REPO / "revision039"
FAMILIES = ("lr", "dt", "mlp_float", "mlp_int8")
POLICIES = ("bundle", "whole")
OPTIMIZATIONS = ("Og", "O2")
EXPECTED_IDF_COMMIT = "9d7f2d69f50d1288526d4f1027108e314e8c879f"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def settings_text(base: str, policy: str, optimization: str, phase_gpio: int | None) -> str:
    if policy not in POLICIES or optimization not in OPTIMIZATIONS:
        raise ValueError("unsupported policy or optimization")
    settings = {
        "CONFIG_IDS_BUNDLE_POLICY": "y" if policy == "bundle" else "n",
        "CONFIG_IDS_MODEL_ONLY_BASELINE": "n",
        "CONFIG_IDS_WHOLE_FIRMWARE_BASELINE": "y" if policy == "whole" else "n",
        "CONFIG_IDS_ERASE_NECESSARY_SECTORS": "y",
        "CONFIG_IDS_ERASE_FULL_SLOT": "n",
        "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160": "y",
        "CONFIG_FREERTOS_HZ": "100",
        "CONFIG_COMPILER_OPTIMIZATION_DEBUG": "y" if optimization == "Og" else "n",
        "CONFIG_COMPILER_OPTIMIZATION_PERF": "y" if optimization == "O2" else "n",
        "CONFIG_COMPILER_OPTIMIZATION_SIZE": "n",
        "CONFIG_COMPILER_OPTIMIZATION_NONE": "n",
        "CONFIG_ESPTOOLPY_FLASHMODE_DIO": "y",
        "CONFIG_ESPTOOLPY_FLASHFREQ_80M": "y",
        "CONFIG_IDS_PHASE_GPIO_ENABLED": "y" if phase_gpio is not None else "n",
    }
    if phase_gpio is not None:
        if not 0 <= phase_gpio <= 48:
            raise ValueError("phase GPIO must be in 0..48; verify board pin availability before wiring")
        settings["CONFIG_IDS_PHASE_GPIO"] = str(phase_gpio)
    # Remove overridden keys so Kconfig never depends on duplicate assignment order.
    lines = [line for line in base.splitlines() if line.split("=", 1)[0] not in settings]
    return "\n".join(lines + [f"{key}={value}" for key, value in settings.items()]) + "\n"


def parse_config(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line.startswith("CONFIG_") and "=" in line)


def verify_config(settings: dict[str, str], optimization: str, policy: str,
                  phase_gpio: int | None) -> None:
    expected = {
        "CONFIG_IDF_TARGET": '"esp32s3"',
        "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ": "160",
        "CONFIG_FREERTOS_HZ": "100",
        "CONFIG_ESPTOOLPY_FLASHMODE": '"dio"',
        "CONFIG_ESPTOOLPY_FLASHFREQ": '"80m"',
        "CONFIG_ESP_MAIN_TASK_STACK_SIZE": "65536",
        "CONFIG_IDS_ERASE_NECESSARY_SECTORS": "y",
        "CONFIG_COMPILER_OPTIMIZATION_DEBUG" if optimization == "Og" else "CONFIG_COMPILER_OPTIMIZATION_PERF": "y",
        "CONFIG_IDS_BUNDLE_POLICY" if policy == "bundle" else "CONFIG_IDS_WHOLE_FIRMWARE_BASELINE": "y",
    }
    if phase_gpio is not None:
        expected.update(CONFIG_IDS_PHASE_GPIO_ENABLED="y", CONFIG_IDS_PHASE_GPIO=str(phase_gpio))
    for key, value in expected.items():
        if settings.get(key) != value:
            raise RuntimeError(f"configuration gate {key}: expected {value}, got {settings.get(key)}")
    for key in ("CONFIG_SECURE_BOOT", "CONFIG_SECURE_FLASH_ENC_ENABLED", "CONFIG_SPIRAM"):
        if settings.get(key) == "y":
            raise RuntimeError(f"unsafe or noncomparable configuration: {key}")
    if phase_gpio is None and settings.get("CONFIG_IDS_PHASE_GPIO_ENABLED") == "y":
        raise RuntimeError("timing build unexpectedly has power-cut GPIO instrumentation")


def run_logged(command: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as log:
        log.write(json.dumps(command) + "\n")
        log.flush()
        environment = dict(os.environ, IDF_COMPONENT_MANAGER="0")
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
    if result.returncode:
        tail = "\n".join(path.read_text(errors="replace").splitlines()[-30:])
        raise RuntimeError(f"build command failed ({result.returncode}); log {path}\n{tail}")


def verify_inflater_symbols(elf_symbols: str, updater_undefined: str) -> dict:
    """Reject accidental calls into the ABI-incompatible ESP32-S3 ROM inflater."""
    symbol = "ids039_tinfl_decompress"
    references = {line.split()[-1] for line in updater_undefined.splitlines() if line.split()}
    if symbol not in references or any(name.startswith("tinfl_") for name in references):
        raise RuntimeError("OTA updater does not exclusively reference the namespaced project inflater")
    matches = [line.split() for line in elf_symbols.splitlines()
               if len(line.split()) == 3 and line.split()[-1] == symbol]
    if len(matches) != 1 or matches[0][1] not in ("T", "t"):
        raise RuntimeError("project inflater is absent or not linked as executable code in the ELF")
    address = int(matches[0][0], 16)
    if not (0x42000000 <= address < 0x44000000):
        raise RuntimeError("project inflater is outside ESP32-S3 mapped application flash")
    return {"status": "verified", "symbol": symbol, "symbol_type": matches[0][1],
            "address": f"0x{address:08x}", "updater_references": sorted(name for name in references if "tinfl" in name),
            "scope": "linked ELF and updater object; not an MCU execution test"}


def choices(value: str, allowed: tuple[str, ...]) -> list[str]:
    selected = value.split(",")
    if not selected or any(item not in allowed for item in selected) or len(set(selected)) != len(selected):
        raise argparse.ArgumentTypeError(f"choose unique comma-separated values from {allowed}")
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--families", type=lambda x: choices(x, FAMILIES), default=list(FAMILIES))
    parser.add_argument("--policies", type=lambda x: choices(x, POLICIES), default=list(POLICIES))
    parser.add_argument("--optimizations", type=lambda x: choices(x, OPTIMIZATIONS), default=list(OPTIMIZATIONS))
    parser.add_argument("--output", type=Path, default=REVISION / "build/prebuilt")
    parser.add_argument("--work", type=Path, default=Path("/tmp/ids039-build"))
    parser.add_argument("--phase-gpio", type=int, default=None,
                        help="enable a distinct instrumented build; check the selected pin against your board")
    parser.add_argument("--allow-other-idf", action="store_true",
                        help="record a noncanonical SDK instead of enforcing the v5.3.2 commit")
    parser.add_argument("--prepare-only", action="store_true", help="prepare sources/configs without invoking a compiler")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.work = args.work.resolve()
    source = REVISION / "firmware"
    if not source.is_dir():
        raise SystemExit(f"missing revision firmware: {source}")
    source_hashes = {str(p.relative_to(source)): sha(p.read_bytes())
                     for p in sorted(source.rglob("*")) if p.is_file()}
    manifest_name = "BUILD_METADATA" + (f"_phase_gpio{args.phase_gpio}" if args.phase_gpio is not None else "") + ".json"
    metadata = {
        "revision": "039", "author": "Oleksandr Kuznetsov", "status": "preparing",
        "hardware_accessed": False, "hardware_validation": "not performed",
        "public_development_key": True, "production_security_claim": False,
        "idf_component_manager": "disabled; all project components are vendored",
        "source_sha256": source_hashes, "phase_gpio": args.phase_gpio,
        "configurations": {}, "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    if not args.prepare_only:
        idf_path = Path(os.environ.get("IDF_PATH", ""))
        if not (idf_path / "tools/idf.py").is_file():
            raise SystemExit("Source ESP-IDF v5.3.2 export.sh first (IDF_PATH is absent/invalid)")
        commit = subprocess.check_output(["git", "-C", str(idf_path), "rev-parse", "HEAD"], text=True).strip()
        if commit != EXPECTED_IDF_COMMIT and not args.allow_other_idf:
            raise SystemExit(f"expected ESP-IDF v5.3.2 commit {EXPECTED_IDF_COMMIT}, got {commit}")
        submodules = subprocess.check_output(["git", "-C", str(idf_path), "submodule", "status", "--recursive"], text=True)
        if any(line and line[0] in "+-U" for line in submodules.splitlines()):
            raise SystemExit("SDK submodules are missing or do not match pinned SDK commits")
        metadata.update(sdk="ESP-IDF v5.3.2", sdk_commit=commit, sdk_submodules=submodules.splitlines(),
                        cmake=subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0],
                        ninja=subprocess.check_output(["ninja", "--version"], text=True).strip(),
                        python_packages=subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True).splitlines(),
                        compiler=subprocess.check_output(["xtensa-esp32s3-elf-g++", "--version"], text=True).splitlines()[0])
    save(args.output / manifest_name, metadata)
    sys.path.insert(0, str(REPO / "research030"))
    from hardware_codec import codec030 as codec
    prepared_worktrees = set()
    for family in args.families:
        for policy in args.policies:
            for optimization in args.optimizations:
                name = f"{family}_{policy}_{optimization}"
                if args.phase_gpio is not None:
                    name += f"_phase_gpio{args.phase_gpio}"
                work_key = f"{policy}_{optimization}" + (f"_phase_gpio{args.phase_gpio}" if args.phase_gpio is not None else "")
                work = args.work / work_key
                staged = work / "source"
                if work_key not in prepared_worktrees:
                    if staged.exists():
                        shutil.rmtree(staged)
                    staged.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(source, staged)
                    prepared_worktrees.add(work_key)
                # Frozen generator supplies a bootstrap envelope for runtime ABI only.
                # Real A/B releases are separately installed/patched by the experiment runner.
                (staged / "main/generated/model_contract.h").write_text(codec.header(family))
                defaults = settings_text((source / "sdkconfig.defaults").read_text(), policy, optimization, args.phase_gpio)
                config = work / "active.sdkconfig"
                config.write_text(defaults)
                (staged / "sdkconfig.selected").write_text(defaults)
                entry = {"stage": "039", "revision": "039", "family": family, "policy": policy, "optimization": optimization,
                         "source_sha256": source_hashes, "compressed_full_image_protocol": "FWZ_BEGIN/FWZ_CHUNK/FWZ_END/FWZ_ABORT",
                         "compressed_full_image_enabled": policy == "whole",
                         "phase_gpio": args.phase_gpio, "hardware_accessed": False,
                         "configuration_input_sha256": sha(defaults.encode()), "status": "prepared"}
                metadata["configurations"][name] = entry
                if args.prepare_only:
                    save(args.output / manifest_name, metadata)
                    continue
                print(f"BUILD {name}", flush=True)
                build = work / "build"
                base = ["idf.py", "-C", str(staged), "-B", str(build), "-D", "IDF_TARGET=esp32s3",
                        "-D", "SDKCONFIG=" + str(config), "-D", "SDKCONFIG_DEFAULTS=" + str(staged / "sdkconfig.selected")]
                run_logged(base + ["reconfigure", "build"], args.output / "logs" / f"{name}.log")
                run_logged(base + ["size"], args.output / "logs" / f"{name}-size.log")
                verify_config(parse_config(config), optimization, policy, args.phase_gpio)
                compile_commands = json.loads((build / "compile_commands.json").read_text())
                project_commands = [row["command"] for row in compile_commands
                                    if "/main/" in row["file"] or "/components/ids_core/" in row["file"]]
                unsafe_flags = ("-ffast-math", "-Ofast", "-ffinite-math-only", "-funsafe-math-optimizations", "-fassociative-math")
                if not project_commands or any(flag in command for command in project_commands for flag in unsafe_flags):
                    raise RuntimeError("missing project commands or unsafe floating-point flags found")
                if any("-ffp-contract=off" not in command for command in project_commands):
                    raise RuntimeError("floating-point contraction is not disabled for all project kernels")
                if any(f"-{optimization}" not in command for command in project_commands):
                    raise RuntimeError("expected optimization absent from a project compile command")
                inflater_linkage = None
                if policy == "whole":
                    elf_symbols = subprocess.check_output(["xtensa-esp32s3-elf-nm", str(build / "ids_update_lab.elf")], text=True)
                    updater_object = build / "esp-idf/main/CMakeFiles/__idf_main.dir/firmware_ota.cpp.obj"
                    updater_undefined = subprocess.check_output(["xtensa-esp32s3-elf-nm", "-u", str(updater_object)], text=True)
                    inflater_linkage = verify_inflater_symbols(elf_symbols, updater_undefined)
                    inflater_linkage.update(elf_sha256=sha((build / "ids_update_lab.elf").read_bytes()),
                                            linker_map_sha256=sha((build / "ids_update_lab.map").read_bytes()))
                dest = args.output / optimization / f"{family}_{policy}"
                if args.phase_gpio is not None:
                    dest = args.output / f"phase_gpio{args.phase_gpio}" / optimization / f"{family}_{policy}"
                for rel in ("ids_update_lab.bin", "bootloader/bootloader.bin", "partition_table/partition-table.bin",
                            "ota_data_initial.bin", "flash_args", "flasher_args.json", "compile_commands.json"):
                    target = dest / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(build / rel, target)
                shutil.copy2(config, dest / "sdkconfig")
                shutil.copy2(staged / "main/generated/model_contract.h", dest / "factory_model_contract.h")
                if inflater_linkage is not None:
                    save(dest / "inflater_linkage.json", inflater_linkage)
                image = (dest / "ids_update_lab.bin").read_bytes()
                info = codec.verify_image(image)
                if sha((build / "ids_update_lab.elf").read_bytes()) != info["elf_sha256"]:
                    raise RuntimeError("compiled ELF identity mismatch")
                patched = codec.patch_image(image, codec.sign_envelope(codec.bootstrap(family), 123, "patch-check039"))
                pinfo = codec.verify_image(patched)
                if pinfo["version"] != 123 or pinfo["elf_sha256"] != info["elf_sha256"]:
                    raise RuntimeError("patched image verification failed")
                entry.update(info, status="compiled_not_hardware_validated", runtime_abi=codec.ABI[family],
                             inflater_linkage=inflater_linkage,
                             schema=codec.SCHEMA.hex(), erase_policy="necessary_sectors",
                             template_region_offset=image.index(codec.MAGIC), patch_checksum_sha_verified=True,
                             files_sha256={str(p.relative_to(dest)): sha(p.read_bytes()) for p in sorted(dest.rglob("*")) if p.is_file() and p.name != "metadata.json"})
                save(dest / "metadata.json", entry)
                save(args.output / manifest_name, metadata)
    metadata.update(status="prepared_only" if args.prepare_only else "compiled_not_hardware_validated",
                    finished_utc=datetime.now(timezone.utc).isoformat())
    save(args.output / manifest_name, metadata)
    print(f"DONE: {metadata['status']}; no hardware accessed", flush=True)


if __name__ == "__main__":
    main()
