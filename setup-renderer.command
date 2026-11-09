#!/bin/zsh
set -eu
cd -- "$(dirname -- "$0")"
if command -v python3.13 >/dev/null 2>&1; then
  task_python=python3.13
else
  task_python=python3
fi
if [[ ! -x .venv/bin/python ]]; then "$task_python" -m venv .venv; fi
.venv/bin/python -m pip install --disable-pip-version-check --requirement requirements-render.txt
.venv/bin/python setup_renderer.py
