import json
import queue
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from radkit_client.sync import Client

from checks import Check, CheckResult, CheckStatus, RunContext
from radkit_cli import DEFAULT_LOGFILE
from scenario_runner import run_scenario as _run_scenario_chain


_STOP = object()  # sentinel to shut down a session's worker thread

# Cap on retained SSE events per session. A long-lived session with repeated
# runs would otherwise grow this list without bound.
EVENT_LOG_MAX = 5000

# Where this (single-user) server writes its collection log. Unchanged from
# the historical behaviour; the cloud entrypoint overrides it per session.
LOGFILE_PATH = DEFAULT_LOGFILE


@dataclass
class Session:
    session_id: str
    email: str
    domain: str
    method: str = "sso"  # sso | certificate
    passphrase: Optional[str] = None
    client: object = None
    client_cm: object = None
    sso_url: Optional[str] = None
    status: str = "starting"  # starting | waiting | ready | error
    error: Optional[str] = None
    # Service (RSA service_cloud) state
    service: object = None
    service_serial: Optional[str] = None
    service_name: Optional[str] = None
    service_status: str = "idle"  # idle | connecting | ready | error
    service_error: Optional[str] = None
    # Threading / queues
    lock: threading.Lock = field(default_factory=threading.Lock)
    commands: "queue.Queue" = field(default_factory=queue.Queue)
    # SSE event log: append-only list of events with monotonic ids. Drives
    # Last-Event-ID-based replay so a reconnecting browser (after a network
    # blip or a full page reload) catches up without losing anything.
    event_log: list = field(default_factory=list)
    event_log_cond: threading.Condition = field(default_factory=threading.Condition)
    event_counter: int = 0
    cancel_run: threading.Event = field(default_factory=threading.Event)
    # Lifecycle. `thread` lets teardown join the worker; `last_seen` is
    # refreshed by polling endpoints so an idle session can be reaped.
    thread: Optional[threading.Thread] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    closing: bool = False


def _do_login(sess: Session) -> None:
    """First command every session runs: complete SSO or certificate login."""
    client_cm = Client.create()
    c = client_cm.__enter__()
    sess.client = c
    sess.client_cm = client_cm

    if sess.method == "certificate":
        with sess.lock:
            sess.status = "waiting"
        result = c.certificate_login(
            identity=sess.email,
            domain=sess.domain,
            private_key_password=sess.passphrase,
        )
        # Don't keep the private-key password resident any longer than the
        # login that needs it.
        sess.passphrase = None
        # certificate_login returns PromptInterrupted (not raises) when it
        # couldn't get input it needed from stdin.
        from radkit_client.sync import PromptInterrupted
        if isinstance(result, PromptInterrupted):
            raise RuntimeError(
                "Certificate login was interrupted — RSA prompted for input "
                "(likely a missing or wrong private-key password)."
            )
        with sess.lock:
            sess.status = "ready"
        return

    resp = c.oauth_connect_only(identity=sess.email, domain=sess.domain)
    if resp is None:
        raise RuntimeError("RSA returned no OAuth response.")

    with sess.lock:
        sess.sso_url = str(resp.sso_url)
        sess.status = "waiting"

    c.sso_login(
        identity=sess.email,
        domain=sess.domain,
        oauth_connect_response=resp,
        open_browser=False,
    )

    with sess.lock:
        sess.status = "ready"


def _do_connect_service(sess: Session, payload: dict) -> None:
    serial = payload["serial"]
    with sess.lock:
        sess.service_serial = serial
        sess.service_status = "connecting"
        sess.service_error = None
    try:
        service = sess.client.service_cloud(serial).wait()
    except Exception as e:
        with sess.lock:
            sess.service_status = "error"
            sess.service_error = f"{type(e).__name__}: {e}"
        return
    # Best-effort name extraction; falls back to serial.
    name = getattr(service, "name", None) or getattr(service, "service_id", None) or serial
    with sess.lock:
        sess.service = service
        sess.service_name = str(name)
        sess.service_status = "ready"


def _emit(sess: Session, event: dict) -> None:
    """Append one event to the session's SSE log with a monotonic id."""
    event["ts"] = time.time()
    with sess.event_log_cond:
        sess.event_counter += 1
        event["id"] = sess.event_counter
        sess.event_log.append(event)
        # Keep the log bounded. Ids stay monotonic; a reconnecting client whose
        # Last-Event-ID has already been evicted is detected in the SSE handler
        # and told to resync rather than silently missing checks.
        if len(sess.event_log) > EVENT_LOG_MAX:
            del sess.event_log[:len(sess.event_log) - EVENT_LOG_MAX]
        sess.event_log_cond.notify_all()


def _do_run_scenario(sess: Session, payload: dict) -> None:
    """Run the Check chain for one scenario, streaming events as we go.
    Past events stay in the log so a reconnecting browser can still replay
    them — the frontend uses 'run_started' as the boundary for a fresh run.
    """
    sess.cancel_run.clear()
    _run_scenario_chain(
        payload=payload,
        service=sess.service,
        emit=lambda ev: _emit(sess, ev),
        cancelled=sess.cancel_run.is_set,
        logfile=LOGFILE_PATH,
    )


# Registry of command handlers. Each handler runs in the session's worker thread
# and receives (sess, payload). Add new commands here (e.g. "connect_service").
COMMANDS = {
    "login": lambda sess, _payload: _do_login(sess),
    "connect_service": _do_connect_service,
    "run_scenario": _do_run_scenario,
}


sessions: dict[str, Session] = {}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


def _read_version() -> dict:
    """Return version + short git commit if available."""
    info = {"version": "dev", "commit": None, "cert_login_enabled": True}
    try:
        with open("VERSION", "r") as f:
            info["version"] = f.read().strip() or "dev"
    except OSError:
        pass
    try:
        import subprocess
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=2,
        ).decode().strip()
        if sha:
            info["commit"] = sha
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ImportError):
        pass
    return info


@app.get("/version")
def get_version():
    return _read_version()


class LoginRequest(BaseModel):
    email: str
    domain: str
    method: str = "sso"
    passphrase: Optional[str] = None


@app.get("/")
def index():
    # Inject the current commit SHA as a cache-buster on the static assets so
    # browsers don't keep serving a stale app.js / styles.css after an update.
    info = _read_version()
    v = info.get("commit") or info.get("version") or "dev"
    try:
        with open("static/index.html", "r") as f:
            html = f.read()
    except OSError:
        return FileResponse("static/index.html")
    html = html.replace("/static/styles.css", f"/static/styles.css?v={v}")
    html = html.replace("/static/app.js", f"/static/app.js?v={v}")
    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)


@app.get("/logfile")
@app.get("/logfile/{sid}")
def download_logfile(sid: str = ""):
    # Single-user: there is one log regardless of session. The {sid} form
    # exists so the shared frontend can use one URL for both servers; the
    # cloud entrypoint uses it to serve only the caller's own log.
    import os
    path = LOGFILE_PATH
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"{path} not found")
    return FileResponse(path, media_type="text/plain",
                        filename=os.path.basename(path))


def _session_worker(sess: Session) -> None:
    """Long-lived per-session thread. RSA's sync API binds to this thread,
    so every RSA call for this session must come through here."""
    try:
        while True:
            cmd = sess.commands.get()
            if cmd is _STOP:
                return
            cmd_type, payload = cmd
            handler = COMMANDS.get(cmd_type)
            if handler is None:
                with sess.lock:
                    sess.status = "error"
                    sess.error = f"Unknown command: {cmd_type}"
                continue
            try:
                handler(sess, payload)
            except Exception as e:
                with sess.lock:
                    sess.status = "error"
                    sess.error = f"{type(e).__name__}: {e}"
    finally:
        if sess.client_cm is not None:
            try:
                sess.client_cm.__exit__(None, None, None)
            except Exception:
                pass


def terminate_session(sess: "Session", timeout: float = 10.0) -> None:
    """Shut a session down and release its RSA client.

    The worker's `finally` block is the only place client_cm.__exit__ runs, and
    the worker only returns on _STOP -- so without this the thread, its RSA
    connection and the session's buffers live for the lifetime of the process.
    """
    with sess.lock:
        if sess.closing:
            return
        sess.closing = True

    sess.cancel_run.set()
    sess.commands.put(_STOP)

    thread = sess.thread
    if thread is not None and thread.is_alive():
        # A worker mid-RADKit-call may outlast this; it is a daemon thread and
        # _STOP is already queued, so it exits once that call returns.
        thread.join(timeout=timeout)

    # Wake any SSE reader blocked on the condition so it can notice and finish.
    with sess.event_log_cond:
        sess.event_log_cond.notify_all()

    sessions.pop(sess.session_id, None)


@app.post("/login")
def login(req: LoginRequest):
    if req.method not in ("sso", "certificate"):
        raise HTTPException(
            status_code=400,
            detail=f"Unknown login method '{req.method}'.",
        )

    sid = uuid.uuid4().hex
    sess = Session(
        session_id=sid,
        email=req.email,
        domain=req.domain,
        method=req.method,
        passphrase=req.passphrase,
    )
    sessions[sid] = sess
    worker = threading.Thread(target=_session_worker, args=(sess,), daemon=True)
    sess.thread = worker
    worker.start()
    sess.commands.put(("login", None))
    return {"session_id": sid}


@app.get("/login/status/{sid}")
def login_status(sid: str):
    sess = sessions.get(sid)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")
    with sess.lock:
        return {
            "status": sess.status,
            "sso_url": sess.sso_url,
            "error": sess.error,
        }


class ServiceRequest(BaseModel):
    session_id: str
    serial: str


@app.post("/service")
def connect_service(req: ServiceRequest):
    sess = sessions.get(req.session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")
    if sess.status != "ready":
        raise HTTPException(status_code=409, detail="Session is not logged in yet")
    sess.commands.put(("connect_service", {"serial": req.serial.strip()}))
    return {"ok": True}


@app.get("/service/status/{sid}")
def service_status(sid: str):
    sess = sessions.get(sid)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")
    with sess.lock:
        return {
            "status": sess.service_status,
            "serial": sess.service_serial,
            "name": sess.service_name,
            "error": sess.service_error,
        }


class RunRequest(BaseModel):
    session_id: str
    payload: dict


@app.post("/run")
def run_scenario(req: RunRequest):
    sess = sessions.get(req.session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")
    if sess.service is None:
        raise HTTPException(status_code=400, detail="Service not connected.")
    sess.commands.put(("run_scenario", req.payload))
    return {"status": "queued"}


@app.post("/run/stop/{sid}")
def stop_run(sid: str):
    sess = sessions.get(sid)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")
    sess.cancel_run.set()
    return {"status": "cancelling"}


@app.get("/run/events/{sid}")
def run_events(sid: str, request: Request):
    sess = sessions.get(sid)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")

    # EventSource auto-resends the last id it received on reconnect — we use
    # that to replay any events the client missed during a network blip or a
    # full page reload. Prefer the Last-Event-ID header (set by the browser
    # on auto-reconnect) over ?since= (set once at initial open) so we don't
    # re-deliver events the client has already processed.
    since_q = request.query_params.get("since")
    last_id_hdr = request.headers.get("last-event-id")
    raw = last_id_hdr if last_id_hdr is not None else since_q
    try:
        start_after = int(raw) if raw else 0
    except ValueError:
        start_after = 0

    def _format(event: dict) -> str:
        try:
            payload = json.dumps(event)
        except (TypeError, ValueError) as e:
            payload = json.dumps({
                "type": "check_finished",
                "name": event.get("name") or "event",
                "target_node_id": event.get("target_node_id") or "xtr",
                "status": "warn",
                "message": f"Server could not serialize event: {type(e).__name__}: {e}",
                "ts": event.get("ts"),
                "id": event.get("id"),
            })
        return f"id: {event.get('id', '')}\ndata: {payload}\n\n"

    def event_stream():
        yield ": stream open\n\n"
        cursor = start_after  # last id already delivered to this client
        # If the client's cursor predates the oldest retained event, the gap
        # can't be replayed. Say so explicitly instead of resuming mid-gap and
        # leaving the client silently missing checks.
        if cursor:
            with sess.event_log_cond:
                oldest = sess.event_log[0].get("id", 0) if sess.event_log else 0
            if oldest and cursor < oldest - 1:
                yield _format({
                    "type": "replay_gap",
                    "id": cursor,
                    "ts": time.time(),
                    "message": (
                        "Some earlier events are no longer buffered; "
                        "reload to resync."
                    ),
                })
        while True:
            # Snapshot any backlog past the cursor without holding the lock
            # while yielding (yields can block on slow consumers).
            with sess.event_log_cond:
                pending = [e for e in sess.event_log if e.get("id", 0) > cursor]
            if pending:
                for ev in pending:
                    cursor = ev["id"]
                    yield _format(ev)
                continue
            # No new events yet — wait briefly. Heartbeats keep proxies and the
            # browser confident the stream is alive.
            with sess.event_log_cond:
                sess.event_log_cond.wait(timeout=3)
                has_new = any(e.get("id", 0) > cursor for e in sess.event_log)
            if not has_new:
                yield f": heartbeat {time.time()}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
