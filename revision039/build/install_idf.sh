#!/usr/bin/env bash
# Author: Oleksandr Kuznetsov. Installs build tools; never accesses a device.
set -euo pipefail
ids039_tools_root="${1:-$PWD/.ids039-tools}"
ids039_tools_root="$(realpath -m "$ids039_tools_root")"
ids039_sdk="$ids039_tools_root/esp-idf-v5.3.2"
ids039_expected_commit=9d7f2d69f50d1288526d4f1027108e314e8c879f
mkdir -p "$ids039_tools_root"
if [[ ! -d "$ids039_sdk/.git" ]]; then
  git clone --branch v5.3.2 --depth 1 https://github.com/espressif/esp-idf.git "$ids039_sdk"
fi
if [[ "$(git -C "$ids039_sdk" rev-parse HEAD)" != "$ids039_expected_commit" ]]; then
  echo "Refusing a noncanonical SDK in $ids039_sdk" >&2
  exit 1
fi
git -C "$ids039_sdk" submodule update --init --recursive --depth 1 --jobs 8
export IDF_TOOLS_PATH="$ids039_tools_root/idf-tools"
python3 "$ids039_sdk/tools/idf_tools.py" --non-interactive install xtensa-esp-elf esp32ulp-elf
python3 "$ids039_sdk/tools/idf_tools.py" --non-interactive install-python-env
# Host-side compiler front ends and package/header audit dependencies.
ids039_venv="$(find "$IDF_TOOLS_PATH/python_env" -mindepth 1 -maxdepth 1 -type d -name 'idf5.3_*_env' -print -quit)"
if [[ -z "$ids039_venv" ]]; then
  echo "ESP-IDF Python environment was not created" >&2
  exit 1
fi
ids039_build_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$ids039_venv/bin/python" -m pip install -r "$ids039_build_dir/python-environment.lock"
{
  printf '# Generated environment for revision039 builds; no flashing commands.\n'
  printf 'export IDF_TOOLS_PATH=%q\n' "$IDF_TOOLS_PATH"
  printf 'export IDF_PATH=%q\n' "$ids039_sdk"
  printf 'export IDF_PYTHON_ENV_PATH=%q\n' "$ids039_venv"
  printf 'export PATH=%q:$PATH\n' "$ids039_venv/bin:$ids039_sdk/tools:$IDF_TOOLS_PATH/tools/xtensa-esp-elf/esp-13.2.0_20240530/xtensa-esp-elf/bin:$IDF_TOOLS_PATH/tools/esp32ulp-elf/2.38_20240113/esp32ulp-elf/bin"
} > "$ids039_tools_root/activate_ids039.sh"
printf 'Ready. Source %s/activate_ids039.sh before build039.py.\n' "$ids039_tools_root"
