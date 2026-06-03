#!/bin/bash
# SDA Pathfinder launcher — macOS.
# First run bootstraps a virtualenv and installs deps; subsequent runs
# `git pull` for updates and start the server.

set -e
cd "$(dirname "$0")"

log() { echo "[SDA Pathfinder] $*"; }
die() {
    osascript -e "display dialog \"$1\" buttons {\"OK\"} default button 1 with icon stop with title \"SDA Pathfinder\"" >/dev/null 2>&1 || true
    echo "ERROR: $1" >&2
    exit 1
}

# Pick a Python ≥ 3.12.
PY=""
for cand in python3.12 python3.13 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver=$("$cand" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || echo "")
        maj="${ver%.*}"; min="${ver#*.}"
        if [ "$maj" = "3" ] && [ "${min:-0}" -ge 12 ]; then PY="$cand"; break; fi
    fi
done
[ -n "$PY" ] || die "Python 3.12+ is required.\n\nInstall from python.org or run: brew install python@3.12"
log "Using $($PY --version)"

# Detect arch (informational only — wheels are tag-matched by pip).
ARCH=$(uname -m)
log "Architecture: $ARCH"

WHEEL_DIR="radkit-wheels"

if ! ls "$WHEEL_DIR"/cisco_radkit_*.whl >/dev/null 2>&1; then
    die "RADKit wheels not found.\n\nDownload the four RADKit 1.9.9 cp312 wheels for macOS from:\n   https://radkit.cisco.com/downloads/release/\n\nDrop them into:\n   $(pwd)/$WHEEL_DIR/\n\nThen run this launcher again."
fi

# Pre-flight: verify wheels match this Python + arch before pip sees them.
if ! "$PY" scripts/check_wheels.py 2> /tmp/sda_pf_wheel_err; then
    die "$(cat /tmp/sda_pf_wheel_err)"
fi

# Pull latest from GitHub (silent if not a git checkout).
if [ -d .git ] && command -v git >/dev/null 2>&1; then
    log "Checking for updates..."
    git pull --ff-only 2>/dev/null || log "git pull skipped (offline or local changes)"
fi

# Create / refresh venv.
if [ ! -d .venv ]; then
    log "Creating virtual environment..."
    "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Install deps when requirements.txt or wheels have changed.
STAMP=".venv/.installed"
NEED_INSTALL=0
[ -f "$STAMP" ] || NEED_INSTALL=1
[ "requirements.txt" -nt "$STAMP" ] && NEED_INSTALL=1
[ -n "$(find "$WHEEL_DIR" -name 'cisco_radkit_*.whl' -newer "$STAMP" 2>/dev/null)" ] && NEED_INSTALL=1
if [ "$NEED_INSTALL" = "1" ]; then
    log "Installing dependencies (one-time, ~1–2 min)..."
    pip install --quiet --upgrade pip
    python -m pip install --quiet -r requirements.txt
    # No version pins — Cisco ships mixed versions per platform (mac arm64
    # has some packages only at 1.9.5, others at 1.9.9). Let pip pick what's
    # in the folder.
    python -m pip install --quiet --upgrade --no-index --find-links "$WHEEL_DIR" \
        cisco-radkit-client cisco-radkit-common \
        cisco-radkit-genie cisco-radkit-service
    touch "$STAMP"
fi

# Open browser shortly after server is up.
( sleep 2 && open "http://127.0.0.1:8000" ) &

log "Starting on http://127.0.0.1:8000  (Ctrl+C to stop)"
exec python -m uvicorn server:app --host 127.0.0.1 --port 8000
