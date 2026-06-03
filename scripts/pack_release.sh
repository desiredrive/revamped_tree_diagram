#!/usr/bin/env bash
# Build a distributable zip of SDA Pathfinder for Cisco TAC.
#
# Output: dist/sda-pathfinder-<VERSION>.zip
#
# Contents: source tree + Linux x86_64 RADKit wheels + launcher scripts.
# Excludes: .git, __pycache__, .venv, *.pyc, collection_logfile.txt,
#           script_logs.txt, dist/, *.deb, vscode.deb, mac/windows wheel dirs
#           (they are empty in this beta).

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
VERSION="$(cat VERSION | tr -d '[:space:]')"
NAME="sda-pathfinder-${VERSION}"
OUT_DIR="${ROOT}/dist"
STAGE="${OUT_DIR}/${NAME}"

rm -rf "${STAGE}"
mkdir -p "${STAGE}"

echo "Staging ${NAME} ..."

rsync -a \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude 'dist' \
  --exclude 'collection_logfile.txt' \
  --exclude 'script_logs.txt' \
  --exclude '*.deb' \
  --exclude 'vendor/macos-arm64/*' \
  --exclude 'vendor/macos-x86_64/*' \
  --exclude 'vendor/windows-x86_64/*' \
  --exclude '.claude' \
  --exclude '.vscode' \
  ./ "${STAGE}/"

# Sanity: make sure linux wheels survived.
if ! ls "${STAGE}/vendor/linux-x86_64/"*.whl > /dev/null 2>&1; then
  echo "ERROR: Linux wheels missing from staged tree." >&2
  exit 1
fi

# Drop a SUPPORTED-PLATFORMS note so TAC users know what this beta covers.
cat > "${STAGE}/SUPPORTED-PLATFORMS.txt" <<'EOF'
SDA Pathfinder 1.0.0-beta.1 — supported platforms
==================================================

This beta ships RADKit wheels for Linux x86_64 (Python 3.12) only.

Tested:
  - RHEL / CentOS / Rocky 8+ (x86_64)
  - Ubuntu 22.04 / 24.04 (x86_64)

macOS (Intel + Apple Silicon) and Windows wheels are not bundled in this
beta. To run on those platforms, install RADKit 1.9.9 from cisco.com into
your Python 3.12 venv before launching.
EOF

cd "${OUT_DIR}"
rm -f "${NAME}.zip"
zip -qr "${NAME}.zip" "${NAME}"
echo "Built: ${OUT_DIR}/${NAME}.zip ($(du -h "${NAME}.zip" | cut -f1))"
