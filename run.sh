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

WHEEL_DIR="radkit-wheels"

if ! ls "$WHEEL_DIR"/cisco_radkit_*.whl >/dev/null 2>&1; then
  cat >&2 <<EOF

================================================================
  RADKit wheels not found in ./$WHEEL_DIR/
================================================================

  Download the four RADKit 1.9.9 cp312 wheels for your OS from:

    https://radkit.cisco.com/downloads/release/

  Drop them into:

    $(pwd)/$WHEEL_DIR/

  Then re-run this script.

  See $WHEEL_DIR/README.txt for the exact filenames.

EOF
  exit 1
fi

"$PY" scripts/check_wheels.py || exit 1

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
[ -n "$(find "$WHEEL_DIR" -name 'cisco_radkit_*.whl' -newer "$STAMP" 2>/dev/null)" ] && NEED_INSTALL=1
if [ "$NEED_INSTALL" = "1" ]; then
  echo "Installing dependencies ..."
  pip install --upgrade pip
  pip install -r requirements.txt
  # --find-links (no --no-index): cisco-radkit-* resolve from the local
  # folder (they don't exist on pypi), and transitive deps like tabulate
  # come from pypi.
  pip install --upgrade --find-links "$WHEEL_DIR" \
    cisco-radkit-client cisco-radkit-common \
    cisco-radkit-genie cisco-radkit-service
  touch "$STAMP"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "Starting server on http://${HOST}:${PORT}"
exec uvicorn server:app --host "$HOST" --port "$PORT"
