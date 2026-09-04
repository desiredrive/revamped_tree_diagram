# SDA Pathfinder — cloud deployment

The cloud entrypoint (`cloud/server.py`) serves many TAC engineers from one
process. The standalone app (`server.py`, `run.sh`) is unchanged and still the
right thing for a single engineer on a laptop.

Both share the check engine (`checks/`, `traffic_flows/`, `radkit_cli.py`,
`scenario_runner.py`). Nothing in the engine imports `cloud/`.

## What differs from standalone

| | standalone | cloud |
|---|---|---|
| SSE | sync endpoint, one threadpool thread per open tab | async, no thread per connection |
| Collection log | one shared `collection_logfile.txt` | one file per session, owner-only download |
| Session auth | session id only | HttpOnly cookie checked against the id |
| Session cleanup | none | idle/TTL reaper + `MAX_SESSIONS` cap |
| Certificate login | supported | not offered (needs a key on disk and a stdin prompt) |
| Shutdown | — | SIGTERM tells each browser, then releases RSA clients |

Why async matters, measured on this machine with 200 concurrent streams:
standalone served `/version` in **12–14 s**; cloud served `/healthz` in **0–1 ms**.
Past a K8s probe timeout the kubelet would kill pods holding live sessions.

## Build

### On the cluster (the pipeline)

```bash
oc apply -f cloud/k8s/buildconfig.yaml
oc start-build sda-pathfinder --follow
```

Building on the cluster rather than a laptop matters here: the RADKit wheels
are **cp312 / linux-amd64 only**, so the build arch must match the runtime
arch, and `https://radkit.cisco.com/pip` has to be reachable from wherever the
build runs — the cluster is the environment that actually has to reach it.

Read the comments in [`k8s/buildconfig.yaml`](k8s/buildconfig.yaml) before
applying: `origin` is a GitHub SSH remote, which an internal cluster usually
cannot reach. Either mirror the repo internally and repoint `uri`, or attach a
deploy key. There is also a commented `buildArgs` block for a build-time proxy.

**Set `APP_VERSION`** to the git SHA when you build. It is the static-asset
cache buster — without it `_read_version` has no `.git` to read, falls back to
the `VERSION` file, and browsers keep serving stale `app.js` across deploys:

```bash
oc start-build sda-pathfinder \
  --build-arg=APP_VERSION=$(git rev-parse --short HEAD) --follow
```

### Locally (fast iteration)

```bash
podman build -f cloud/Dockerfile \
  -t sda-pathfinder:$(git rev-parse --short HEAD) \
  --build-arg APP_VERSION=$(git rev-parse --short HEAD) .
```

### Verifying dependencies without a container runtime

The dependency layer can be checked directly, which catches the likeliest build
failures:

```bash
python3.12 -m venv /tmp/dryrun
/tmp/dryrun/bin/pip install -r requirements.txt
/tmp/dryrun/bin/pip install --find-links ./radkit-wheels \
  --extra-index-url https://radkit.cisco.com/pip \
  cisco-radkit-client==1.9.9 cisco-radkit-common==1.9.9 \
  cisco-radkit-genie==1.9.9 cisco-radkit-service==1.9.9
/tmp/dryrun/bin/pip check
DATA_DIR=/tmp/d COOKIE_SECURE=0 /tmp/dryrun/bin/python -m uvicorn cloud.server:app --port 8000
```

Verified 2026-09-03 on Python 3.12: installs clean, `pip check` passes, app
serves. Note RADKit **downgrades** some packages `requirements.txt` installs
(`starlette` 1.6.0 → 0.52.1, `anyio`, `ncclient`). That is expected and fine —
RADKit is the more constrained dependency, which is why the Dockerfile installs
`requirements.txt` first and RADKit second. Do not reorder those steps.

## Deploy

```bash
oc apply -f cloud/k8s/deployment.yaml -f cloud/k8s/service.yaml
```

Then set the image ref in `deployment.yaml` to your registry.

### Things that will bite if changed

- **Sticky sessions are required, not an optimisation.** Sessions live in one
  pod's memory (a RADKit client cannot be serialised and is thread-bound), so a
  request routed to another pod 404s. The Route's cookie affinity is load-bearing.
- **`haproxy.router.openshift.io/timeout: 4h`** — the router's 30 s default
  would sever every SSE stream mid-collection.
- **No HPA.** Scaling in kills live troubleshooting sessions.
- **One uvicorn worker.** Multiple workers fork separate `sessions` dicts.
- **Readiness must not flip under load.** It gates endpoint membership, so going
  unready breaks *existing* sticky sessions. Capacity is refused at `/login`
  with a 503 instead.
- **A pod restart still ends its sessions** — engineers re-run SSO. That is
  inherent to holding a live RADKit client, not something config fixes.

### Networking

Egress to the RADKit cloud and the SSO IdP needs NetworkPolicy / proxy
coordination with Cisco IT. This is the most likely deployment-day blocker and
is worth starting before the image is ready.

## Configuration

All optional; defaults in `cloud/config.py`.

`DATA_DIR` `MAX_SESSIONS` `SESSION_IDLE_TIMEOUT` `SESSION_TTL_SECONDS`
`EVENT_LOG_MAX` `REAPER_INTERVAL_SECONDS` `APP_VERSION` `COOKIE_SECURE`
`HOST` `PORT`

## Local run

```bash
DATA_DIR=/tmp/sdapf COOKIE_SECURE=0 python -m uvicorn cloud.server:app --port 8000
```

`COOKIE_SECURE=0` is only for local HTTP; leave it set in any deployment.

## Upgrades from GitHub

The standalone app updates by rewriting its own source tree (`update.py`). A pod
must not do that: three replicas would drift to different versions, and any pod
that restarted would silently revert to whatever is baked into its image. The
container-native equivalent is that **a new commit produces a new image**, and
OpenShift rolls it out.

```bash
oc apply -f cloud/k8s/upgrade-cronjob.yaml
```

A CronJob polls GitHub for new commits on `main` and starts a build when the SHA
changes; the Deployment's ImageStream trigger then rolls the new image out.
Polling rather than a webhook because it only needs **outbound** access to
GitHub — an internal cluster can rarely accept an inbound webhook call.

Two behaviours worth knowing:

- **It defers while anyone is mid-collection.** Replacing a pod ends its
  sessions (a RADKit client cannot be moved) and forces those engineers to redo
  SSO. The job reads `/stats` from each pod and skips the build until the next
  tick if any scenario is running.
- **The SHA is recorded only after a successful build**, so a failed build is
  retried on the next tick rather than being skipped.

To ship immediately instead of waiting for the schedule:

```bash
oc start-build sda-pathfinder --commit=$(git rev-parse HEAD) \
  --build-arg=APP_VERSION=$(git rev-parse --short HEAD) --follow
```

To pause automatic upgrades: `oc patch cronjob sda-pathfinder-upgrade -p '{"spec":{"suspend":true}}'`

### Rollouts always interrupt sessions

There is no zero-downtime version of this. A session holds a live RADKit client
bound to one pod, so any pod replacement ends the sessions on it. The CronJob
avoids interrupting *active runs*, and browsers get a `server_shutdown` event
explaining what happened, but affected engineers still log in again. Schedule
accordingly.
