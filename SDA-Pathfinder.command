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

# Detect arch for vendor wheel selection.
ARCH=$(uname -m)
case "$ARCH" in
    arm64) VENDOR_DIR="vendor/macos-arm64" ;;
    x86_64) VENDOR_DIR="vendor/macos-x86_64" ;;
    *) die "Unsupported macOS architecture: $ARCH" ;;
esac

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

# Install deps when requirements.txt or vendor wheels have changed.
STAMP=".venv/.installed"
NEED_INSTALL=0
[ -f "$STAMP" ] || NEED_INSTALL=1
[ "requirements.txt" -nt "$STAMP" ] && NEED_INSTALL=1
[ -d "$VENDOR_DIR" ] && [ -n "$(find "$VENDOR_DIR" -name '*.whl' -newer "$STAMP" 2>/dev/null)" ] && NEED_INSTALL=1
if [ "$NEED_INSTALL" = "1" ]; then
    log "Installing dependencies (one-time, ~1–2 min)..."
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    if [ -d "$VENDOR_DIR" ] && ls "$VENDOR_DIR"/*.whl >/dev/null 2>&1; then
        pip install --quiet --upgrade "$VENDOR_DIR"/*.whl
    else
        log "WARNING: no RSA wheels in $VENDOR_DIR — login will fail."
        log "Place cisco_radkit_*.whl files into $VENDOR_DIR/ and re-run."
    fi
    touch "$STAMP"
fi

# Open browser shortly after server is up.
( sleep 2 && open "http://127.0.0.1:8000" ) &

log "Starting on http://127.0.0.1:8000  (Ctrl+C to stop)"
exec python -m uvicorn server:app --host 127.0.0.1 --port 8000
