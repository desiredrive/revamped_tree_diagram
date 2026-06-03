# SDA Pathfinder — Install Guide (TAC Engineers)

## One-time setup (≈ 5 minutes)

### Prerequisites
- **Python 3.10, 3.11, 3.12, or 3.13** — https://www.python.org/downloads/  (on Windows, check "Add Python to PATH" during install). RADKit supports 3.10–3.13; use whichever your RADKit wheels match.
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
| Linux x86_64       | **Already bundled** in `radkit-wheels/` — nothing to do.               |
| macOS / Windows    | Download four wheels and drop them into `radkit-wheels/`.              |

**For macOS / Windows:**

1. Go to https://radkit.cisco.com/downloads/release/ and pick **1.9.9**.
2. Download the four wheels for your OS — pick a `cp` tag matching your
   Python version (RADKit ships cp310, cp311, cp312, and cp313):
   - `cisco_radkit_client-1.9.9-cp3XX-...whl`
   - `cisco_radkit_common-1.9.9-cp3XX-...whl`
   - `cisco_radkit_genie-1.9.9-cp3XX-...whl`
   - `cisco_radkit_service-1.9.9-cp3XX-...whl`

   Pick the right tag suffix:
   - macOS Apple Silicon → `macosx_11_0_arm64`
   - macOS Intel → `macosx_10_15_x86_64`
   - Windows 64-bit → `win_amd64`
3. Drop all four into the project's `radkit-wheels/` folder.
4. Launch — the script installs them automatically.

You only do this once per machine. Mixing wheels for different platforms
in the folder is fine; pip picks the matching ones and ignores the rest.

## Run it

| OS       | What to do                                       |
|----------|--------------------------------------------------|
| macOS    | Double-click **`SDA-Pathfinder.command`**        |
| Windows  | Double-click **`SDA-Pathfinder.bat`**            |
| Linux    | `./run.sh` from a terminal in the project folder |

On first run the launcher creates a virtualenv, installs dependencies
+ RADKit wheels, and opens your browser at `http://127.0.0.1:8000`.
Every subsequent run pulls the latest changes from GitHub and starts
the server.

## Stopping
Close the terminal window, or press **Ctrl+C** inside it.

## Updates
Just relaunch — the launcher does `git pull --ff-only` automatically.

## Troubleshooting

**"Python 3.10–3.13 is required"** — install Python from python.org, then re-run.
On Windows, make sure "Add to PATH" was checked during install.

**"RADKit wheels not found in ./radkit-wheels/"** — see the RADKit section
above. Drop the four wheels into that folder and re-run the launcher.

**Login fails / `radkit_client` import error** — the wheels you dropped
don't match this OS / Python. They must be cp wheels for your Python
version (3.10/3.11/3.12/3.13) and your platform (see tag suffix list
above).

**"git pull skipped"** — you're either offline or have local edits. The
launcher continues with the current code — no harm done.

**Port 8000 in use** — close whatever else is using it, or edit the
`uvicorn` line at the bottom of the launcher to use a different port.

**RADKit install still fails (last-resort manual install)** — if the
launcher's pip step keeps failing, run these by hand from the project
folder:
```
source .venv/bin/activate          # macOS/Linux
# .venv\Scripts\activate           # Windows (PowerShell)
cd radkit-wheels
python3 -m pip install --find-links . "cisco_radkit_common==1.9.9"
python3 -m pip install --find-links . "cisco_radkit_service==1.9.9"
python3 -m pip install --find-links . "cisco_radkit_client==1.9.9"
python3 -m pip install --find-links . "cisco_radkit_genie==1.9.9"
cd ..
```
Then re-run the launcher — it skips the install step on second run.
