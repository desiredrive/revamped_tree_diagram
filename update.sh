#!/usr/bin/env bash
# SDA Pathfinder — update launcher (Linux).
# Double-click in your file manager or run `./update.sh` from a terminal.
# Stops here if Python 3 isn't on PATH; everything else is pure stdlib so
# no venv/dependencies are needed to update.

set -e
cd "$(dirname "$0")"

PY=""
for cand in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
    echo "Error: python3 not found on PATH. Install Python 3.10+ and retry." >&2
    exit 1
fi

exec "$PY" update.py "$@"
