#!/bin/bash
# SDA Pathfinder — update launcher (macOS).
# Double-click in Finder to check GitHub for a newer release and install it
# in place, or run from Terminal. Keeps the window open at the end so the
# user can read the output before it closes.

set -e
cd "$(dirname "$0")"

echo "===================================="
echo "  SDA Pathfinder — Update"
echo "===================================="
echo

PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver=$("$cand" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || echo "")
        maj="${ver%.*}"; min="${ver#*.}"
        if [ "$maj" = "3" ] && [ "${min:-0}" -ge 10 ]; then PY="$cand"; break; fi
    fi
done
if [ -z "$PY" ]; then
    osascript -e 'display dialog "Python 3.10+ is required to run the updater.\n\nInstall from https://www.python.org/downloads/ and try again." buttons {"OK"} default button 1 with icon stop with title "SDA Pathfinder — Update"' >/dev/null 2>&1 || true
    echo "ERROR: Python 3.10+ not found on PATH." >&2
    exit 1
fi

"$PY" update.py "$@" || RC=$?
echo
echo "(Press Return to close this window.)"
read -r _
exit "${RC:-0}"
