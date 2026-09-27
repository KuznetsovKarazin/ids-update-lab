#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$project_root/build/native"
"${CXX:-g++}" -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -ffp-contract=off \
  -I"$project_root/firmware/components/ids_core/include" \
  -I"$project_root/firmware/main/generated" \
  "$project_root/firmware/components/ids_core/ids_core.cpp" \
  "$project_root/firmware/components/ids_core/ids_protocol.cpp" \
  "$project_root/firmware/native/main.cpp" -lcrypto -o "$project_root/build/native/ids_update_native"
printf '%s\n' "$project_root/build/native/ids_update_native"
