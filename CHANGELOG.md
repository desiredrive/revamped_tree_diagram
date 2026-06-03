# Changelog

All notable changes to SDA Pathfinder are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0-beta.4] — 2026-06-03

Wheel pre-flight + tag-aware install — fixes the macOS/Windows install path
when the engineer downloads a wheel for the wrong Python or CPU.

### Added
- **`scripts/check_wheels.py`** — pre-flight that compares filenames in
  `radkit-wheels/` against the running interpreter (Python tag + OS + arch)
  and exits with an explicit "you've got `<wheel>`, you need
  `cp312-none-<platform>`" message instead of letting pip die with
  *"is not a supported wheel on this platform"*.

### Changed
- **Launchers** (`run.sh`, `SDA-Pathfinder.command`, `scripts/launcher.ps1`)
  call `check_wheels.py` after the empty-folder check and before pip.
- **Wheel install** switched from `pip install <whl>...` (which errors on
  any incompatible wheel in the list) to
  `pip install --no-index --find-links radkit-wheels/ cisco-radkit-*`
  (no version pins — Cisco ships mixed versions per platform, e.g. mac
  arm64 only has cp312 wheels for some packages at 1.9.5, others at
  1.9.9). pip picks the highest tag-compatible version per package.

## [1.0.0-beta.3] — 2026-06-03

Install-flow improvements for cross-platform TAC use.

### Changed
- **Single drop folder for RADKit wheels** — collapsed the per-platform
  `vendor/<platform>/` tree into a single `radkit-wheels/` folder.
  Engineers download the four wheels for their OS from
  https://radkit.cisco.com/downloads/release/ and drop them directly
  into that folder; pip picks the matching tag automatically. Linux
  wheels remain bundled, so Linux is still zero-touch.
- **Launchers** (`run.sh`, `SDA-Pathfinder.command`,
  `scripts/launcher.ps1`) print a clear "where to download / where to
  drop / re-run me" message and exit when `radkit-wheels/` is empty,
  instead of silently falling through to a broken venv.

### Removed
- `run.bat` (redundant with `SDA-Pathfinder.bat` → `launcher.ps1`).

## [1.0.0-beta.2] — 2026-06-03

Maintenance release: repo cleanup, no behavior changes.

### Changed
- **Repo layout** — collapsed 25 `checks_*.py` modules at the root into a
  single `checks/` package (`checks/base.py`, `checks/dhcp.py`,
  `checks/ew_*.py`, `checks/underlay_multicast*.py`, etc.).
  `from checks import Check, CheckResult, CheckStatus, RunContext` still
  works via package re-export.
- **`run.sh`** now installs the bundled RADKit wheels from
  `vendor/linux-x86_64/` on first launch (previously skipped — only the
  macOS launcher did this correctly).
- **`INSTALL.md`** spells out where to put RADKit wheels per platform
  and points at the GitHub Release zip for non-git installs.

### Removed
- Legacy CLI scripts that the FastAPI app does not import: `main.py`,
  `sandbox.py`, `genie_sandbox.py`, `offlinesandbox.py`, `mcastflow.py`,
  `dhcptroubleshooting.py` (the live one lives at
  `traffic_flows/dhcp_troubleshooting.py`), `hostonboardtshoot.py`,
  `wirelesstshoot.py`, `payloads.py`, `event_bus.py`,
  `DocumentationReference.py`, `api_reference`.

## [1.0.0-beta.1] — 2026-06-02

First public beta. Web-based SDA fabric troubleshooter built on FastAPI +
Cytoscape, driven by RADKit (RSA) for live device access and Catalyst Center
APIs for fabric metadata.

### Added

#### Scenarios
- **DHCP Troubleshooting** — end-to-end DHCP path validation: pool
  identification, DHCP parameters / SVI counters, DHCP-snooping client stats,
  PACL / VACL / RACL evaluation, fabric-wide DHCP server compatibility
  (Option-82 / DORA), Edge → Border → DHCP-server forwarding.
- **East-West Trace** — source / destination XTR profiling, source endpoint
  onboarding, L2-LISP map-cache + ETR registration, AR resolution on both
  sides, intra-vs-inter-XTR election, remote map-cache validation, fabric-site
  comparison, dynamic underlay multicast follow-up when the L2VNI is in
  flooding mode.
- **Underlay Multicast Validation** — standalone scenario covering FHR / LHR /
  per-RP profiling, SSM / multicast-range gating, register tunnel state, RPF
  to RP, IGMP, S,G + (\*,G) state, MSDP cross-domain peer / SA cache, full
  RPF-discovered path traversal, cross-device correlation (RP / group / SSM /
  ACL consistency).

#### Validation framework
- Structured `Check` chain with per-check status (OK / WARN / FAIL / SKIP /
  RUNNING) and human-readable bodies anchored on topology nodes.
- Dynamic check queueing — checks can append follow-up checks at runtime
  (used by EW → multicast handoff).
- PIM gating checks (BiDir, `spt-threshold infinity`) applied uniformly to
  FHR, LHR, and every discovered RP, default RIB only.
- East-West PACL + VACL bidirectional evaluation on both source and
  destination XTRs (RACL excluded — host-to-host intra-VRF only).

#### Topology + UI
- Live Cytoscape topology with role-aware icons (XTR, Border, Control Plane,
  WLC, AP, Underlay Switch, DHCP Server, Fabric cloud, Endpoint).
- CDP-discovered Border merging via IP de-duplication (no duplicate nodes
  when two roles share a hostname / mgmt IP).
- CEF-discovered RPF path rendering — each hop chained via `connect_to`
  with the resolved physical egress port as the edge label; terminal hops
  merge into FHR / RP without spawning a stray node.
- Per-node check panel, click-through expand, status badges, and live
  re-status as checks complete.
- Wireless onboarding flow (FEW): WLC discovery, endpoint profile,
  AccessTunnel resolve, fabric-edge MAC / roaming history / L2LISP stats,
  optional "treat as wired" override.

#### Server / runtime
- FastAPI app with SSE event stream for live check results.
- RSA login (SSO + certificate), service-serial selection, scenario picker.
- Session-scoped run manager with `Stop` / `Run Again` semantics.
- Downloadable artifacts: collection logfile, topology JPEG, **Checks PDF**
  (client-side jsPDF) with color-coded status tags.

#### Reliability
- CEF→CDP hop resolution order (CEF recursion first, CDP after to confirm
  egress) — prevents misrouted topology when CDP and CEF disagree.
- IP-based node de-duplication everywhere; alias map keeps subsequent
  `connect_to` references valid after a merge.
- Wireless-roam awareness: "Device-Tracking Missing Endpoint" / "VLAN None"
  on the original Edge after a roam is treated as expected, not a failure.
- Auth-session renderer distinguishes wireless tunnels (per-client state on
  WLC) from wired access ports with no active session, instead of dumping
  raw genie attributes.
- LISP auth-key / Pubsub source-of-truth handling aligned with field rules:
  Map-Register failures surface as auth errors (not session-down), DNAC
  `isPubSubEnabled` is treated as authoritative.

### Known limitations

- LHR-side underlay multicast (Stage 3) is structurally complete, but full
  cross-device S,G traversal across transit nodes (Stage 5) is not yet
  wired in.
- Standalone underlay-multicast UX entry (Stage 6) reuses the EW form — a
  dedicated picker form is planned.
- `traffic_flows/underlay_multicast.py:single_device_underlay_profiling`
  still uses `sys.exit` style flow control; wrappers catch `BaseException`,
  but a refactor is pending.
