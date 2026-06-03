#!/usr/bin/env bash
# Bootstrap + launch the SDA Fabric Troubleshooter.
# Creates a local .venv on first run, installs requirements, then serves on :8000.

set -euo pipefail

cd "$(dirname "$0")"

PY="${PYTHON:-python3.12}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Error: $PY not found. Install Python 3.12 (the bundled RADKit wheels are cp312)." >&2
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating virtualenv in .venv ..."
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

if [ ! -f ".venv/.installed" ] || [ requirements.txt -nt ".venv/.installed" ]; then
  echo "Installing dependencies ..."
  pip install --upgrade pip
  pip install -r requirements.txt
  touch .venv/.installed
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "Starting server on http://${HOST}:${PORT}"
exec uvicorn server:app --host "$HOST" --port "$PORT"
