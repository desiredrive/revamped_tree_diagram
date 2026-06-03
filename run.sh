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

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) VENDOR_DIR="vendor/linux-x86_64" ;;
  *) echo "Unsupported Linux architecture: $ARCH (only x86_64 wheels are bundled)." >&2; exit 1 ;;
esac

if [ ! -d ".venv" ]; then
  echo "Creating virtualenv in .venv ..."
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

STAMP=".venv/.installed"
NEED_INSTALL=0
[ -f "$STAMP" ] || NEED_INSTALL=1
[ "requirements.txt" -nt "$STAMP" ] && NEED_INSTALL=1
[ -d "$VENDOR_DIR" ] && [ -n "$(find "$VENDOR_DIR" -name '*.whl' -newer "$STAMP" 2>/dev/null)" ] && NEED_INSTALL=1
if [ "$NEED_INSTALL" = "1" ]; then
  echo "Installing dependencies ..."
  pip install --upgrade pip
  pip install -r requirements.txt
  if [ -d "$VENDOR_DIR" ] && ls "$VENDOR_DIR"/*.whl >/dev/null 2>&1; then
    pip install --upgrade "$VENDOR_DIR"/*.whl
  else
    echo "WARNING: no RADKit wheels in $VENDOR_DIR — login will fail." >&2
    echo "Place cisco_radkit_*.whl files into $VENDOR_DIR/ and re-run." >&2
  fi
  touch "$STAMP"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "Starting server on http://${HOST}:${PORT}"
exec uvicorn server:app --host "$HOST" --port "$PORT"
