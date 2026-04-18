#!/usr/bin/env bash
# End-to-end smoke test: runs one example through the pipeline.
#
#   ./scripts/run_example.sh bof_01
#   ./scripts/run_example.sh null_01
#   ./scripts/run_example.sh intoverflow_01
#   ./scripts/run_example.sh uaf_01
#   ./scripts/run_example.sh safe_01
set -euo pipefail
cd "$(dirname "$0")/.."

name="${1:-bof_01}"
cand="benchmark/candidates/${name}.json"
if [[ ! -f "$cand" ]]; then
    echo "no candidate JSON for $name at $cand" >&2
    exit 2
fi

source ./.venv/bin/activate
python scripts/verify_one.py --candidate "$cand" --dump-harness
