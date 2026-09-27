#!/usr/bin/env bash
# Compile the instrumented synthetic experiment. ESP-IDF must already be active.
set -euo pipefail
ids_project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ids_host_python="${IDS_HOST_PYTHON:-python3}"
ids_output=""
ids_sign_key=""
ids_check_only=0
usage() {
  cat <<'EOF'
Usage: bash tools/build_instrumented_v2.sh --output NEW_DIR [options]
  --python EXE    Host Python with host/requirements.txt installed.
  --sign-key PEM  Optional existing matching private key OUTSIDE the project.
  --check-only    Validate the environment and fixtures without creating output.
  --help         Show this help.
Builds bundle A, model_only A, whole_firmware A/B/C. No device access.
Relative paths are interpreted from the current working directory.
EOF
}
while (($#)); do
  case "$1" in
    --output|--python|--sign-key)
      [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 2; }
      case "$1" in --output) ids_output="$2";; --python) ids_host_python="$2";; --sign-key) ids_sign_key="$2";; esac
      shift 2;;
    --check-only) ids_check_only=1; shift;;
    --help|-h) usage; exit 0;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done
[[ -n "$ids_output" || "$ids_check_only" == 1 ]] || { usage >&2; exit 2; }
command -v idf.py >/dev/null || { echo 'Activate ESP-IDF 5.3.2 before running this script.' >&2; exit 2; }
: "${IDF_PATH:?Activate ESP-IDF 5.3.2 first}"
ids_sdk_version="$(idf.py --version)"
[[ "$ids_sdk_version" == 'ESP-IDF v5.3.2' ]] || { printf 'Expected ESP-IDF v5.3.2; got %s\n' "$ids_sdk_version" >&2; exit 2; }
ids_sdk_commit="$(git -C "$IDF_PATH" rev-parse HEAD)"
[[ "$ids_sdk_commit" == 9d7f2d69f50d1288526d4f1027108e314e8c879f ]] || { echo 'ESP-IDF commit does not match the validated v5.3.2 checkout.' >&2; exit 2; }
git -C "$IDF_PATH" diff HEAD --quiet --ignore-submodules=none || { echo 'ESP-IDF has tracked source or submodule changes.' >&2; exit 2; }
ids_submodule_status="$(git -C "$IDF_PATH" submodule status --recursive)"
if printf '%s\n' "$ids_submodule_status" | LC_ALL=C grep -q '^[+U-]'; then
  echo 'Initialize all ESP-IDF submodules at their pinned revisions.' >&2; exit 2
fi
command -v xtensa-esp32s3-elf-gcc >/dev/null || { echo 'ESP32-S3 compiler is missing from the active environment.' >&2; exit 2; }
ids_host_python="$(command -v "$ids_host_python")" || { echo 'Host Python executable not found.' >&2; exit 2; }
ids_fixtures="$ids_project_root/examples/instrumented_synthetic"
export PYTHONPATH="$ids_project_root/host${PYTHONPATH:+:$PYTHONPATH}"
# This validation reads the optional key but never copies or prints its contents.
ids_output="$("$ids_host_python" - "$ids_project_root" "$ids_output" "$ids_sign_key" <<'PY'
from pathlib import Path
import os, sys
from ids_update_lab.package import load_public, load_private, verify
root=Path(sys.argv[1]).resolve(); dest=Path(sys.argv[2]).resolve() if sys.argv[2] else None
fixtures=root/'examples/instrumented_synthetic'; public=load_public(fixtures/'public.pem')
for letter,version in [('A',1),('B',2),('C',3)]:
    if verify((fixtures/f'release-{letter}.sids').read_bytes(), public).version != version:
        raise SystemExit(f'Unexpected factory version in release-{letter}.sids.')
if dest is not None and (dest.exists() or dest.is_symlink()):
    raise SystemExit('Output must be a NEW directory; existing output is never overwritten.')
if dest is not None:
    for protected in [root/'firmware', root/'examples', root/'prebuilt']:
        if os.path.commonpath([str(dest),str(protected)]) == str(protected):
            raise SystemExit('Output must be outside firmware/, examples/ and prebuilt/.')
if sys.argv[3]:
    key=Path(sys.argv[3]).resolve()
    if os.path.commonpath([str(key),str(root)]) == str(root):
        raise SystemExit('Signing key must remain outside the project.')
    if dest is not None and os.path.commonpath([str(key),str(dest)]) == str(dest):
        raise SystemExit('Signing key must remain outside the output directory.')
    if load_private(key).public_key().public_numbers() != public.public_numbers():
        raise SystemExit('Signing key does not match examples/instrumented_synthetic/public.pem.')
print(str(dest) if dest else '')
PY
)"
if ((ids_check_only)); then echo 'Environment, versions and signed fixtures: PASS. No output created.'; exit 0; fi
# Exclusive creation also protects against a concurrent run using the same path.
"$ids_host_python" - "$ids_project_root" "$ids_output" <<'PY'
from pathlib import Path
import shutil,sys
root,dest=map(Path,sys.argv[1:]); dest.mkdir(parents=True,exist_ok=False)
for letter in ['A','B','C']:
    shutil.copytree(root/'firmware', dest/'sources'/letter, ignore=shutil.ignore_patterns(
        'build','build-*','sdkconfig','sdkconfig.old','managed_components','dependencies.lock','__pycache__'))
(dest/'logs').mkdir()
PY
for ids_release in A B C; do
  "$ids_host_python" -m ids_update_lab export-header \
    --package "$ids_fixtures/release-$ids_release.sids" \
    --public-key "$ids_fixtures/public.pem" --contract "$ids_fixtures/feature_contract.json" \
    --data-origin synthetic_plumbing \
    --output "$ids_output/sources/$ids_release/main/generated/model_contract.h" \
    --metadata-dir "$ids_output/sources/$ids_release/generated" \
    > "$ids_output/logs/export-$ids_release.log" 2>&1
done
for ids_mode in bundle model_only whole_firmware whole_firmware_B whole_firmware_C; do
  ids_release=A
  case "$ids_mode" in whole_firmware_B) ids_release=B;; whole_firmware_C) ids_release=C;; esac
  ids_source="$ids_output/sources/$ids_release"
  ids_build="$ids_output/build/$ids_mode"
  ids_defaults="$ids_source/sdkconfig.defaults"
  case "$ids_mode" in
    model_only) ids_defaults="$ids_defaults;$ids_source/sdkconfig.model_only";;
    whole_firmware*) ids_defaults="$ids_defaults;$ids_source/sdkconfig.whole_firmware";;
  esac
  mkdir -p "$ids_build"
  printf 'Building %s; log: %s\n' "$ids_mode" "$ids_output/logs/build-$ids_mode.log"
  idf.py -C "$ids_source" -B "$ids_build" -D "SDKCONFIG=$ids_build/sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$ids_defaults" -D IDF_TARGET=esp32s3 build \
    > "$ids_output/logs/build-$ids_mode.log" 2>&1
  idf.py -C "$ids_source" -B "$ids_build" size > "$ids_output/logs/size-$ids_mode.log" 2>&1
  python -m esptool --chip esp32s3 image_info --version 2 "$ids_build/ids_update_lab.bin" \
    > "$ids_output/logs/image-$ids_mode.log" 2>&1
done
if [[ -n "$ids_sign_key" ]]; then
  for ids_release in B C; do
    "$ids_host_python" "$ids_project_root/tools/firmware_ota.py" prepare \
      --image "$ids_output/build/whole_firmware_$ids_release/ids_update_lab.bin" \
      --factory-envelope "$ids_fixtures/release-$ids_release.sids" \
      --private-key "$ids_sign_key" --public-key "$ids_fixtures/public.pem" \
      --out "$ids_output/whole_${ids_release}_ota" > "$ids_output/logs/sign-$ids_release.log" 2>&1
    "$ids_host_python" "$ids_project_root/tools/firmware_ota.py" inspect \
      "$ids_output/whole_${ids_release}_ota" > "$ids_output/logs/verify-$ids_release.log" 2>&1
  done
fi
"$ids_host_python" - "$ids_project_root" "$ids_output" "$ids_sdk_commit" <<'PY'
from pathlib import Path
import hashlib,json,struct,sys,subprocess
from ids_update_lab.package import load_public,verify
root,out=map(Path,sys.argv[1:3]); fixtures=root/'examples/instrumented_synthetic'; public=load_public(fixtures/'public.pem')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest={'format':'instrumented-v2-build-reproduction','sdk_commit':sys.argv[3],
          'hardware_executed':False,'public_key_sha256':sha(fixtures/'public.pem'),
          'sdk_version':subprocess.check_output(['idf.py','--version'],text=True).strip(),
          'compiler':subprocess.check_output(['xtensa-esp32s3-elf-gcc','--version'],text=True).splitlines()[0],
          'host_python':sys.version.split()[0],
          'sdk_python':subprocess.check_output(['python','--version'],text=True).strip(),
          'cmake':subprocess.check_output(['cmake','--version'],text=True).splitlines()[0],
          'ninja':subprocess.check_output(['ninja','--version'],text=True).strip(),'builds':{}}
for mode in ['bundle','model_only','whole_firmware','whole_firmware_B','whole_firmware_C']:
    letter=mode[-1] if mode.endswith(('_B','_C')) else 'A'; version={'A':1,'B':2,'C':3}[letter]
    build=out/'build'/mode; source=out/'sources'/letter; image=(build/'ids_update_lab.bin').read_bytes()
    package=(fixtures/f'release-{letter}.sids').read_bytes()
    if verify(package,public).version!=version or image.count(package)!=1:
        raise SystemExit(f'{mode}: exact authenticated factory package is not embedded once.')
    if len(image)<80 or struct.unpack_from('<I',image,32)[0]!=0xabcd5432 or image[48:80].split(b'\0',1)[0]!=str(version).encode():
        raise SystemExit(f'{mode}: unexpected ESP-IDF application version/header.')
    cfg=(build/'sdkconfig').read_text()
    if 'CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=160' not in cfg:
        raise SystemExit(f'{mode}: expected CPU 160 MHz.')
    policy='IDS_BUNDLE_POLICY' if mode=='bundle' else ('IDS_MODEL_ONLY_BASELINE' if mode=='model_only' else 'IDS_WHOLE_FIRMWARE_BASELINE')
    if f'CONFIG_{policy}=y' not in cfg:
        raise SystemExit(f'{mode}: unexpected update policy.')
    source_files=[p for p in source.rglob('*') if p.is_file() and (p.suffix in ['.cpp','.h','.csv','.json'] or p.name=='CMakeLists.txt' or p.name.startswith(('sdkconfig.','Kconfig')))]
    names=['ids_update_lab.bin','bootloader/bootloader.bin','partition_table/partition-table.bin','ota_data_initial.bin','sdkconfig','flash_args','flasher_args.json']
    manifest['builds'][mode]={'app_version':version,'cpu_mhz':160,'image_bytes':len(image),
        'elf_sha256':sha(build/'ids_update_lab.elf'),'factory_envelope_sha256':sha(fixtures/f'release-{letter}.sids'),
        'source_sha256':{str(p.relative_to(source)):sha(p) for p in sorted(source_files)},
        'files':{name:{'path':str((build/name).relative_to(out)),'sha256':sha(build/name)} for name in names}}
(out/'BUILD_REPRODUCTION.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(out/'BUILD_REPRODUCTION.json')
PY
printf 'All five builds verified. Results: %s\n' "$ids_output"
