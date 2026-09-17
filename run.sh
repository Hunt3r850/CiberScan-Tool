#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="python3"
if [[ -x "$project_dir/venv/bin/python" ]]; then
    python_bin="$project_dir/venv/bin/python"
fi

export PYTHONPATH="$project_dir${PYTHONPATH:+:$PYTHONPATH}"
exec "$python_bin" "$project_dir/src/cibersecurity_tool.py" "$@"
