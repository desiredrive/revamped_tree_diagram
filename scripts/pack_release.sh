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
  --exclude '.claude' \
  --exclude '.vscode' \
  ./ "${STAGE}/"

# Sanity: make sure linux wheels survived.
if ! ls "${STAGE}/radkit-wheels/"cisco_radkit_*.whl > /dev/null 2>&1; then
  echo "ERROR: RADKit wheels missing from staged tree." >&2
  exit 1
fi

# Drop a SUPPORTED-PLATFORMS note so TAC users know what this beta covers.
cat > "${STAGE}/SUPPORTED-PLATFORMS.txt" <<'EOF'
SDA Pathfinder 1.0.0-beta.2 — supported platforms
==================================================

Tested:
  - RHEL / CentOS / Rocky 8+ (x86_64) — RADKit wheels bundled.
  - Ubuntu 22.04 / 24.04 (x86_64)     — RADKit wheels bundled.
  - macOS 13+ (Intel + Apple Silicon) — drop wheels into radkit-wheels/.
  - Windows 10 / 11 (x86_64)          — drop wheels into radkit-wheels/.

For macOS and Windows, download the four RADKit 1.9.9 cp312 wheels
for your OS from https://radkit.cisco.com/downloads/release/ and drop
them into the project's radkit-wheels/ folder before launching. See
INSTALL.md for the exact tag suffixes.
EOF

cd "${OUT_DIR}"
rm -f "${NAME}.zip"
zip -qr "${NAME}.zip" "${NAME}"
echo "Built: ${OUT_DIR}/${NAME}.zip ($(du -h "${NAME}.zip" | cut -f1))"
