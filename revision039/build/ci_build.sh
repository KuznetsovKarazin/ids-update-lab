#!/usr/bin/env bash
# Author: Oleksandr Kuznetsov. Build-only CI entry point; no hardware operations.
set -euo pipefail
ids039_ci_tools="${IDS039_CI_TOOLS:-/tmp/ids039-ci-tools}"
bash revision039/build/install_idf.sh "$ids039_ci_tools"
source "$ids039_ci_tools/activate_ids039.sh"
python -m unittest discover -s revision039/build -p 'test_build039.py' -v
python revision039/build/build039.py "$@"
