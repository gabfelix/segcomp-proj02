#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec uv run --project "$project_dir" --no-editable python "$project_dir/demo/rodar_demo.py" "$@"
