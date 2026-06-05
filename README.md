# SDA Pathfinder

A web-based troubleshooting tool for Cisco Software-Defined Access (SDA)
fabrics, built for TAC engineers. Drives a fabric through Cisco RADKit,
runs a scenario-specific chain of checks against the live devices, and
draws the result as an interactive topology with per-node check status.

```
RSA login → connect service → pick scenario → live topology + streamed checks
```

## Why

A real SDA call usually means jumping between Catalyst Center, several
Edges/Borders/Control Planes, and a wireless controller, running the
same shows over and over and stitching them together by hand. SDA
Pathfinder runs that walk for you — discovers the relevant devices from
Catalyst Center, executes the right shows on each, parses them with
Genie, correlates the findings across the path, and tells you which
check passed, warned, or failed and *why*. The output is a single page
you can hand to the customer or attach to the case.

## Scenarios

| Scenario | What it walks |
|---|---|
| **DHCP Troubleshooting** | Edge → snooping → relay → SVI → DHCP server, including helper-address sanity, DORA state, and queue drops on the anycast gateway. |
| **East-West Trace** | Source endpoint → SISF / L2-LISP / mapcache → destination endpoint, including SGT/SGACL evaluation, intra- vs. inter-VN, and underlay RIB/CEF/CDP path. |
| **Underlay Multicast** | Loopback PIM, neighbors, RP identification, RPF to RP, MSDP for anycast-RP sets, and end-to-end correlation between FHR and LHR. |

Each scenario runs a fixed chain of checks (everything under
[`checks/`](checks/)). A check is a small class that produces a
`CheckStatus` (`OK` / `WARN` / `FAIL` / `SKIP`) and a human-readable
body — the body shows up in the expandable detail row in the UI.

## Installation

About 5 minutes start to finish. The full guide with every troubleshooting
case lives in [INSTALL.md](INSTALL.md); the steps below are enough for the
common path.

### 1. Prerequisites

- **Python 3.10, 3.11, 3.12, or 3.13** — <https://www.python.org/downloads/>.
  On Windows, check **"Add Python to PATH"** during install. Use whichever
  version your RADKit wheels match.
- **Git** — <https://git-scm.com/downloads>. Optional if you grab the
  snapshot zip instead, but recommended (auto-updates via `git pull`).

### 2. Get the code

**Recommended — clone (auto-updating):**

```bash
git clone https://github.com/desiredrive/revamped_tree_diagram.git sda-pathfinder
cd sda-pathfinder
```

**Or — snapshot zip:** download the latest release from
<https://github.com/desiredrive/revamped_tree_diagram/releases/latest>
and extract it. Updates use the bundled CLI updater (see [Updates](#updates)).

### 3. Drop in the RADKit wheels

SDA Pathfinder talks to fabric devices through Cisco RADKit.

| Platform | What to do |
|---|---|
| Linux x86_64 | **Already bundled** in `radkit-wheels/` — nothing to do. |
| macOS / Windows | Download four wheels from <https://radkit.cisco.com/downloads/release/> and drop them into `radkit-wheels/`. |

For macOS / Windows, pick **RADKit 1.9.9** and download the four wheels
whose `cp` tag matches your Python version (`cp310` / `cp311` / `cp312` /
`cp313`):

- `cisco_radkit_client-1.9.9-cp3XX-…whl`
- `cisco_radkit_common-1.9.9-cp3XX-…whl`
- `cisco_radkit_genie-1.9.9-cp3XX-…whl`
- `cisco_radkit_service-1.9.9-cp3XX-…whl`

Pick the right platform tag suffix:

- macOS Apple Silicon → `macosx_11_0_arm64`
- macOS Intel → `macosx_10_15_x86_64`
- Windows 64-bit → `win_amd64`

Drop all four into `radkit-wheels/`. Mixing wheels for different platforms
in the folder is fine — pip picks the matching ones and ignores the rest.

### 4. Launch

| OS | Double-click… | …or from a terminal |
|---|---|---|
| macOS | `SDA-Pathfinder.command` | `./SDA-Pathfinder.command` |
| Windows | `SDA-Pathfinder.bat` | — |
| Linux | — | `./run.sh` |

On first launch the script:

1. Creates a `.venv/` virtualenv.
2. Installs FastAPI, uvicorn, and the rest of `requirements.txt`.
3. Installs RADKit from `radkit-wheels/` (with `https://radkit.cisco.com/pip`
   as the upstream index — the PyPI `cisco-radkit-*` packages are stubs
   that error out).
4. Opens your browser at <http://127.0.0.1:8000>.

Subsequent launches skip the install step and start in seconds. Stop the
app with **Ctrl+C** in the terminal or by closing the launcher window.

> **macOS Gatekeeper:** the first time you double-click any `.command`
> file, Gatekeeper may say *"… cannot be opened because it is from an
> unidentified developer."* Right-click the file → **Open** → **Open**.
> Only needed once per file.

### 5. Common install issues

| Symptom | Fix |
|---|---|
| `Python 3.10–3.13 is required` | Install Python from python.org. On Windows, re-run the installer with "Add to PATH" checked. |
| `RADKit wheels not found in ./radkit-wheels/` | See step 3 — download and drop in the four wheels for your OS. |
| Login fails with `radkit_client` import error | Wheels don't match your OS or Python version. Re-download the matching `cp` + platform tags. |
| Port 8000 already in use | Close whatever else is using it, or edit the `uvicorn` line at the bottom of the launcher. |
| RADKit install keeps failing | See the **last-resort manual install** section in [INSTALL.md](INSTALL.md#troubleshooting). |


## Using it

**Step 1 — RSA login.** Enter your Cisco email and pick PROD or STAGE.
SSO is the default; certificate is supported as a fallback.

**Step 2 — Connect to a service.** Enter the service serial (the
RADKit endpoint that owns the fabric you're troubleshooting). The page
remembers it for the rest of the session.

**Step 3 — Pick a scenario** (DHCP, East-West, or Underlay Multicast)
and fill in the scenario-specific inputs (e.g. source MAC + VLAN for
DHCP, source/dest IPs for East-West, multicast group for Underlay
Multicast).

**Step 4 — Watch the topology build.** Nodes are discovered as checks
run; each check appears in the expandable list under its target node
with a status icon. Failed checks include remediation hints — usually
the exact IOS command that fixes the symptom.

**Step 5 — Hand off the result.** Three download buttons in the
top-left of the topology view:

- **Download Log** — the full RADKit collection log (every command sent
  to every device + its raw output).
- **Download Topology** — a 1920×1080 JPEG of the current topology
  layout for pasting into a case.
- **Download Checks** — every check result, color-coded, as a PDF.

## Updates

Two paths, depending on how you installed:

- **Git checkout:** just relaunch the app. The launcher does
  `git pull --ff-only` automatically (silent if there are local edits
  or you're offline).
- **Snapshot zip:** double-click `Update-SDA-Pathfinder.command` (macOS),
  `Update-SDA-Pathfinder.bat` (Windows), or run `./update.sh` (Linux).
  The CLI updater hits the GitHub Releases API, downloads the newest
  release tarball, and copies it in place. Per-machine state is
  preserved: `.venv/`, `radkit-wheels/`, `collection_logfile.txt`,
  `.git/`, and any `*.local.*` files. Pass `--force` to reinstall the
  same version. Override the source repo with the
  `SDA_PATHFINDER_REPO=owner/repo` environment variable for forks or
  internal mirrors.

> **macOS Gatekeeper:** the first time you double-click any
> `.command` file, Gatekeeper may say *"… cannot be opened because it
> is from an unidentified developer."* Right-click the file → **Open**
> → **Open**. Only needed once per file.

See [CHANGELOG.md](CHANGELOG.md) for what's in each release.

## Architecture

```
                          +-----------------------------+
   browser  ───SSE────→   |  FastAPI server (server.py) |
                          +--------------+--------------+
                                         |
                              one worker thread per session
                                         |
                                         v
              +--------------------------+--------------------------+
              |  scenario chain                                     |
              |  (check_registry.py + checks/*.py)                  |
              +--------------------------+--------------------------+
                                         |
                                         v   collects state into RunContext
                          +--------------+--------------+
                          |  RADKit  → Catalyst Center  |
                          |          → fabric devices   |
                          +-----------------------------+
```

| Folder | Holds |
|---|---|
| [`server.py`](server.py) | FastAPI app — login, service connect, scenario kickoff, SSE event stream. |
| [`checks/`](checks/) | One file per check group (DHCP, East-West, Underlay Mcast, …). Each check is a class with `name`, `target_node_id`, `run(ctx)`, returning a `CheckResult`. |
| [`check_registry.py`](check_registry.py) | Wires the scenario chains — which checks run in which order for each scenario. |
| [`traffic_flows/`](traffic_flows/) | Higher-level "drive the fabric" orchestration that the checks call into. |
| [`routingmodules/`](routingmodules/), [`switchingmodules/`](switchingmodules/), [`securitymodules/`](securitymodules/), [`wirelessmodules/`](wirelessmodules/) | Genie-parsed device facts (PIM, MSDP, multicast routing, ACLs, SISF, WLC sessions, …). |
| [`catalystcenterapi/`](catalystcenterapi/) | Catalyst Center HTTP shims used during discovery. |
| [`radkit_cli.py`](radkit_cli.py) | The single chokepoint for every device CLI call — all `exec` + Genie parsing flows through here, so timeouts, retries, and logging live in one place. |
| [`static/`](static/) | Frontend (vanilla JS + Cytoscape + jsPDF). |
| [`scripts/`](scripts/) | Launcher helpers (`launcher.ps1`, `check_wheels.py`, `pack_release.sh`). |

## Adding a check

1. Subclass `Check` (in [`checks/base.py`](checks/base.py)) inside the
   appropriate `checks/<area>.py` module.
2. Set `name`, `target_node_id`, optionally `running_note` (advisory
   shown in the UI while the check executes), and implement `run(ctx)`
   to return a `CheckResult`.
3. Register it in [`check_registry.py`](check_registry.py) by adding it
   to the scenario's chain.
4. Read from / write to `ctx.state` to share data with later checks in
   the same run.

Conventions:

- `CheckResult.message` is **human-readable** — use bullets, labelled
  fields, and concrete remediation. No raw `repr()`, no "see logfile."
- Catch and surface RADKit / Genie errors with a useful message; never
  let an exception kill the worker.
- Don't trust device output to be parseable — guard against `None`
  returns and partial dicts.

## Releasing (maintainers)

1. Bump `VERSION`, add a section to `CHANGELOG.md`.
2. `git commit -m "Release v1.0.0-beta.N"` and `git tag v1.0.0-beta.N`.
3. `git push origin main && git push origin v1.0.0-beta.N`.
4. `gh release create v1.0.0-beta.N --title "SDA Pathfinder 1.0.0-beta.N" --notes-file <(awk '/## \[1\.0\.0-beta\.N\]/{f=1;next} /## \[/{f=0} f' CHANGELOG.md) --prerelease --target main`.

The CLI updater picks up pre-releases automatically when no GA tag
exists, so users on snapshot zips will see the new release immediately.

## Support

Open an issue or pull request on
<https://github.com/desiredrive/revamped_tree_diagram>. For TAC-internal
discussion, the maintainer is `jalejand@cisco.com`.
