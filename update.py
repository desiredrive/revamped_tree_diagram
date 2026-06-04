#!/usr/bin/env python3
"""SDA Pathfinder — standalone CLI updater.

Run by double-clicking ``update.command`` (macOS), ``update.bat`` (Windows),
or executing ``./update.sh`` on Linux. Works on any install — zip download
or git clone — as long as Python 3 is available.

Flow:
  1. Read local VERSION; query GitHub Releases for the newest published
     release (falling back to the most recent pre-release if no GA exists).
  2. If we're already on the latest, exit 0 with a friendly message.
  3. Otherwise: download the tarball to a temp file, extract to a temp dir,
     then copy files over the install directory — preserving per-machine
     state (.venv/, radkit-wheels/, collection_logfile.txt, .git/, and any
     ``*.local.*`` overrides).
  4. Stop the running server, if any, by walking lockfile / PID conventions
     used by the launcher scripts. (Skipped: portable PID detection is too
     fragile across uvicorn launch styles. The script just warns the user
     to close the app first.)

Stdlib only — must work before requirements.txt has been (re-)installed.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from typing import Any, Dict

# Override-able for forks / private mirrors.
GITHUB_REPO = os.environ.get("SDA_PATHFINDER_REPO", "desiredrive/revamped_tree_diagram")
ROOT = pathlib.Path(__file__).resolve().parent

# Files / directories never overwritten by an update — per-machine state.
PRESERVE_TOP_LEVEL = {
    ".venv",
    "venv",
    "radkit-wheels",
    "collection_logfile.txt",
    ".git",
}
PRESERVE_SUFFIXES = (".local.json", ".local.txt", ".local.yaml", ".local.yml")


# ----- version comparison ---------------------------------------------------

def _current_version() -> str:
    try:
        return (ROOT / "VERSION").read_text().strip()
    except OSError:
        return ""


def _semver_key(v: str) -> tuple:
    """Sort-key for tags like ``1.0.0``, ``1.0.0-beta.7``, ``v2.3.1``.

    Numeric segments compare numerically; suffixes ('beta', 'rc', …) sort
    before the same release with no suffix (``1.0.0-rc.1 < 1.0.0``).
    """
    v = v.strip().lstrip("v")
    if not v:
        return ((0,), 0, ())
    head, _, tail = v.partition("-")
    head_parts = tuple(int(s) if s.isdigit() else s for s in head.split("."))
    if not tail:
        return (head_parts, 1, ())
    tail_parts = tuple(int(s) if s.isdigit() else s for s in tail.split("."))
    return (head_parts, 0, tail_parts)


def _is_newer(latest: str, current: str) -> bool:
    if not latest:
        return False
    if not current:
        return True
    try:
        return _semver_key(latest) > _semver_key(current)
    except Exception:
        return latest != current


# ----- GitHub API -----------------------------------------------------------

def _http_get_json(url: str, timeout: float = 15.0) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "sda-pathfinder-updater",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _latest_release() -> Dict[str, Any]:
    """Return the newest non-draft release.

    Tries ``/releases/latest`` first (GA releases only — GitHub excludes
    drafts and pre-releases here); falls back to the full ``/releases``
    listing so beta tags still get picked up while the project is in beta.
    """
    base = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
    try:
        return _http_get_json(base + "/latest")
    except Exception:
        pass
    listing = _http_get_json(base + "?per_page=20")
    if not isinstance(listing, list):
        raise RuntimeError("unexpected /releases payload")
    non_draft = [r for r in listing if not r.get("draft")]
    if not non_draft:
        raise RuntimeError("no published releases on GitHub")
    return non_draft[0]


# ----- tarball extraction ---------------------------------------------------

def _strip_top_dir(name: str, top: str) -> str:
    """GitHub tarballs wrap everything in ``<owner>-<repo>-<sha>/``; strip it."""
    if not name.startswith(top + "/"):
        return ""
    return name[len(top) + 1:]


def _safe_extract(tar: tarfile.TarFile, top: str, dest: pathlib.Path) -> int:
    """Extract ``tar`` into ``dest``, stripping the top-level GitHub dir.

    Guards against path-traversal members even though GitHub tarballs are
    safe — defensive habit for any code that ingests external archives.
    """
    count = 0
    dest = dest.resolve()
    for m in tar.getmembers():
        rel = _strip_top_dir(m.name, top)
        if not rel:
            continue
        target = (dest / rel).resolve()
        if dest not in target.parents and target != dest:
            continue
        m.name = rel
        tar.extract(m, dest)
        count += 1
    return count


# ----- copy-into-place ------------------------------------------------------

def _is_preserved(rel: pathlib.PurePath) -> bool:
    if not rel.parts:
        return True
    if rel.parts[0] in PRESERVE_TOP_LEVEL:
        return True
    name = rel.parts[-1]
    return any(name.endswith(s) for s in PRESERVE_SUFFIXES)


def _copy_payload(payload: pathlib.Path) -> int:
    """Copy-overlay payload onto ROOT, preserving per-machine paths.

    Files present in the new release overwrite local copies; files that
    exist locally but not in the release are left in place. This means a
    file deleted upstream lingers across one upgrade cycle — strictly
    better than the alternative (accidentally deleting a user's local
    additions because they weren't in the tarball).
    """
    copied = 0
    for src in payload.rglob("*"):
        rel = src.relative_to(payload)
        if _is_preserved(rel):
            continue
        dst = ROOT / rel
        try:
            if src.is_dir():
                dst.mkdir(parents=True, exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied += 1
        except Exception as e:
            print(f"[update] warn: {rel}: {type(e).__name__}: {e}", file=sys.stderr)
    return copied


# ----- entrypoint -----------------------------------------------------------

def main(argv: list[str]) -> int:
    force = "--force" in argv or "-f" in argv
    current = _current_version() or "(unknown)"
    print(f"[update] installed: {current}")
    print(f"[update] checking github.com/{GITHUB_REPO} ...")
    try:
        rel = _latest_release()
    except Exception as e:
        print(f"[update] could not reach GitHub: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    tag = (rel.get("tag_name") or "").lstrip("v")
    tarball_url = rel.get("tarball_url")
    html_url = rel.get("html_url") or ""
    print(f"[update] latest release : {tag}{' (pre-release)' if rel.get('prerelease') else ''}")
    if html_url:
        print(f"[update] release page   : {html_url}")

    if not tag or not tarball_url:
        print("[update] release missing tag_name or tarball_url — aborting", file=sys.stderr)
        return 2

    if not force and not _is_newer(tag, current):
        print(f"[update] you are already on the latest release ({current}).")
        print("[update] pass --force to reinstall the same version anyway.")
        return 0

    print(f"[update] downloading {tarball_url} ...")
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="sda-pathfinder-update-"))
    try:
        tarball = tmp_dir / "release.tar.gz"
        req = urllib.request.Request(tarball_url, headers={"User-Agent": "sda-pathfinder-updater"})
        with urllib.request.urlopen(req, timeout=180) as resp, open(tarball, "wb") as fh:
            shutil.copyfileobj(resp, fh)
        print(f"[update] extracting ...")
        payload = tmp_dir / "payload"
        payload.mkdir()
        with tarfile.open(tarball, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                print("[update] empty tarball — aborting", file=sys.stderr)
                return 2
            top = members[0].name.split("/", 1)[0]
            extracted = _safe_extract(tar, top, payload)
        print(f"[update] extracted {extracted} files; applying to {ROOT} ...")
        copied = _copy_payload(payload)
        print(f"[update] copied {copied} files into the install directory.")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # VERSION file shipped in the tarball overwrites the old one — show it.
    new_ver = _current_version() or tag
    print()
    print(f"[update] done — now on {new_ver}.")
    print("[update] If SDA Pathfinder was running, restart it to pick up the new code.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[update] cancelled by user", file=sys.stderr)
        sys.exit(130)
