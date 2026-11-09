#!/bin/zsh
set -eu
cd -- "$(dirname -- "$0")"
if [[ ! -x .venv/bin/python ]]; then
  print 'Run setup-renderer.command once, then open this launcher again.'
  exit 1
fi
exec .venv/bin/python labmap.py "$@"
