# SDA Pathfinder — Install Guide (TAC Engineers)

## One-time setup (≈ 5 minutes)

### Prerequisites
- **Python 3.12 or newer** — https://www.python.org/downloads/  (on Windows, check "Add Python to PATH" during install)
- **Git** — https://git-scm.com/downloads  (skip if you only want a snapshot copy)

### Get the code

**Recommended (auto-updating):**
```
git clone https://github.com/desiredrive/revamped_tree_diagram.git sda-pathfinder
cd sda-pathfinder
```

**Snapshot zip (no auto-update):** download
`sda-pathfinder-1.0.0-beta.1.zip` from
https://github.com/desiredrive/revamped_tree_diagram/releases/latest
and extract it.

## RADKit (RSA) wheels

SDA Pathfinder talks to fabric devices through Cisco RADKit.

| Platform           | Action                                                                 |
|--------------------|------------------------------------------------------------------------|
| Linux x86_64       | **Already bundled** in `vendor/linux-x86_64/` — nothing to do.         |
| macOS (Intel/ARM)  | Download RADKit 1.9.9 cp312 wheels, drop into `vendor/macos-arm64/` or `vendor/macos-x86_64/`. |
| Windows x86_64     | Download RADKit 1.9.9 cp312 wheels, drop into `vendor/windows-x86_64/`. |

Where to get the wheels: https://radkit.cisco.com/downloads/release/  → pick **1.9.9** → grab the four cp312 wheels for your OS:
- `cisco_radkit_client-1.9.9-cp312-…-<platform>.whl`
- `cisco_radkit_common-1.9.9-cp312-…-<platform>.whl`
- `cisco_radkit_genie-1.9.9-cp312-…-<platform>.whl`
- `cisco_radkit_service-1.9.9-cp312-…-<platform>.whl`

Drop all four into the matching `vendor/<platform>/` folder. The launcher installs them automatically on next start.

## Run it

| OS       | What to do                                       |
|----------|--------------------------------------------------|
| macOS    | Double-click **`SDA-Pathfinder.command`**        |
| Windows  | Double-click **`SDA-Pathfinder.bat`**            |
| Linux    | `./run.sh` from a terminal in the project folder |

That's it. On first run the launcher creates a virtualenv, installs
dependencies, and opens your browser at `http://127.0.0.1:8000`. Every
subsequent run pulls the latest changes from GitHub and starts the server.

## Stopping
Close the terminal window, or press **Ctrl+C** inside it.

## Updates
Just relaunch — the launcher does `git pull --ff-only` automatically.

## Troubleshooting

**"Python 3.12+ is required"** — install Python from python.org, then re-run.
On Windows, make sure "Add to PATH" was checked during install.

**Login fails / `radkit_client` import error** — the matching RSA wheels
aren't present for your platform. See `vendor/README.md` for which files
go where.

**"git pull skipped"** — you're either offline or have local edits. The
launcher continues with the current code — no harm done.

**Port 8000 in use** — close whatever else is using it, or edit the
`uvicorn` line at the bottom of the launcher to use a different port.
