"""Runtime configuration for the cloud entrypoint.

The standalone server reads no environment at all -- it is launched by run.sh
on a laptop and everything is relative to the repo. In a container nothing can
be assumed about the working directory, so every path is anchored to APP_ROOT
and every tunable is an env var with a sane default.

Kept dependency-free (stdlib os.environ) so importing this never drags anything
into the standalone path.
"""

import os
from pathlib import Path


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Repo root, resolved from this file rather than the CWD. Static assets, the
# VERSION file and templates are all read relative to this.
APP_ROOT = Path(__file__).resolve().parent.parent

# Writable scratch. On OpenShift the root filesystem is read-only and this
# points at an emptyDir (usually /tmp).
DATA_DIR = Path(os.environ.get("DATA_DIR", "/tmp/sda-pathfinder"))
LOG_DIR = DATA_DIR / "logs"

# Bind. 0.0.0.0 in a container -- a loopback bind is unreachable from the
# kubelet, so probes and the Service both fail.
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = _int("PORT", 8000)

# Session lifecycle. Sessions hold a live RSA connection and a worker thread,
# so they must be reaped; MAX_SESSIONS is what actually bounds pod memory.
SESSION_TTL_SECONDS = _int("SESSION_TTL_SECONDS", 8 * 3600)
SESSION_IDLE_TIMEOUT = _int("SESSION_IDLE_TIMEOUT", 1800)
MAX_SESSIONS = _int("MAX_SESSIONS", 50)
REAPER_INTERVAL_SECONDS = _int("REAPER_INTERVAL_SECONDS", 60)

EVENT_LOG_MAX = _int("EVENT_LOG_MAX", 5000)

# Set from the image build (CI git SHA). Without it _read_version shells out to
# git, which does not exist in the image, and the static-asset cache buster
# falls back to the VERSION file -- serving stale app.js across deploys.
APP_VERSION = os.environ.get("APP_VERSION") or None

# Cookies are Secure by default; only relax for local HTTP testing of the
# cloud entrypoint.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") not in ("0", "false", "False")


def session_logfile(session_id: str) -> Path:
    """Per-session collection log. One file per session is what keeps
    concurrent engineers from truncating and interleaving each other's."""
    return LOG_DIR / f"{session_id}.txt"
