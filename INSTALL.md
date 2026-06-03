# SDA Pathfinder — Install Guide (TAC Engineers)

## One-time setup (≈ 5 minutes)

### Prerequisites
- **Python 3.12 or newer** — https://www.python.org/downloads/  (on Windows, check "Add Python to PATH" during install)
- **Git** — https://git-scm.com/downloads  (skip if you only want a snapshot copy)

### Get the code
```
git clone https://github.com/<owner>/sda-pathfinder.git
cd sda-pathfinder
```
(Or download the repo as a zip and extract it — but you'll lose auto-update.)

## Run it

| OS       | What to do                                  |
|----------|---------------------------------------------|
| macOS    | Double-click **`SDA-Pathfinder.command`**   |
| Windows  | Double-click **`SDA-Pathfinder.bat`**       |

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
