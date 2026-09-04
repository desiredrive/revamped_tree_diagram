"""SDA Pathfinder -- cloud entrypoint.

Serves many TAC engineers from one process, unlike the standalone server.py
which assumes a single local user. The differences that matter:

  * SSE is async. The standalone stream is a sync def holding a threadpool
    thread for the life of the connection, which deadlocks the server at ~40
    open tabs.
  * Each session gets its own collection log, and downloading one requires
    owning it.
  * Sessions carry a cookie, are checked for ownership, and are reaped.
  * Certificate login does not exist here -- it wants a key on disk and prompts
    on stdin, neither of which means anything in a shared pod.

The check engine (checks/, traffic_flows/, radkit_cli, ...) is shared verbatim
with the standalone app; nothing in this package is imported by it.
"""

import asyncio
import json
import queue
import signal
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from radkit_client.sync import Client

from scenario_runner import run_scenario

from . import config

_STOP = object()  # sentinel to shut down a session's worker thread

# Session cookie. Distinct from the router's affinity cookie: that one decides
# which pod you reach, this one proves which session is yours.
COOKIE_NAME = "sdapf_session"


@dataclass
class Session:
    session_id: str
    email: str
    domain: str
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
    # Append-only event log with monotonic ids, backing Last-Event-ID replay.
    # Bounded -- see _emit.
    event_log: list = field(default_factory=list)
    event_counter: int = 0
    # Live SSE readers. The worker thread pushes each new event into these
    # asyncio.Queues via call_soon_threadsafe, so readers never poll the log.
    subscribers: set = field(default_factory=set)
    cancel_run: threading.Event = field(default_factory=threading.Event)
    # Lifecycle
    thread: Optional[threading.Thread] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    closing: bool = False

    def touch(self) -> None:
        self.last_seen = time.time()


sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()

# Event loop captured at startup. _emit runs on a worker thread, where
# asyncio.get_running_loop() would raise, so the loop has to be grabbed once
# from the lifespan handler and reused.
_loop: Optional[asyncio.AbstractEventLoop] = None
_shutting_down = False


def _do_login(sess: Session) -> None:
    """First command every session runs. SSO only -- see module docstring."""
    client_cm = Client.create()
    c = client_cm.__enter__()
    sess.client = c
    sess.client_cm = client_cm

    resp = c.oauth_connect_only(identity=sess.email, domain=sess.domain)
    if resp is None:
        raise RuntimeError("RSA returned no OAuth response.")

    with sess.lock:
        sess.sso_url = str(resp.sso_url)
        sess.status = "waiting"

    # open_browser=False is required: the browser is on the engineer's laptop,
    # not in this pod. They follow sso_url themselves. The OAuth callback goes
    # to RSA, never to us, which is why sticky sessions are enough.
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
    name = getattr(service, "name", None) or getattr(service, "service_id", None) or serial
    with sess.lock:
        sess.service = service
        sess.service_name = str(name)
        sess.service_status = "ready"


def _emit(sess: Session, event: dict) -> None:
    """Append an event and fan it out to live SSE readers.

    Called from the session's worker thread. The append keeps Last-Event-ID
    replay working; the fan-out is what lets readers await instead of
    rescanning the log on a timer.
    """
    event["ts"] = time.time()
    with sess.lock:
        sess.event_counter += 1
        event["id"] = sess.event_counter
        sess.event_log.append(event)
        if len(sess.event_log) > config.EVENT_LOG_MAX:
            del sess.event_log[:len(sess.event_log) - config.EVENT_LOG_MAX]
        subscribers = list(sess.subscribers)

    if _loop is None:
        return
    for q in subscribers:
        try:
            _loop.call_soon_threadsafe(q.put_nowait, event)
        except RuntimeError:
            # Loop already closed (shutdown race) -- the reader is gone anyway.
            pass


def _do_run_scenario(sess: Session, payload: dict) -> None:
    """Run one scenario. Same chain as standalone, but logging to this
    session's own file so concurrent engineers don't overwrite each other."""
    sess.cancel_run.clear()
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    run_scenario(
        payload=payload,
        service=sess.service,
        emit=lambda ev: _emit(sess, ev),
        cancelled=sess.cancel_run.is_set,
        logfile=config.session_logfile(sess.session_id),
    )


COMMANDS = {
    "login": lambda sess, _payload: _do_login(sess),
    "connect_service": _do_connect_service,
    "run_scenario": _do_run_scenario,
}


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


def terminate_session(sess: Session, timeout: float = 10.0) -> None:
    """Stop a session's worker, release its RSA client, drop its log."""
    with sess.lock:
        if sess.closing:
            return
        sess.closing = True

    sess.cancel_run.set()
    sess.commands.put(_STOP)

    thread = sess.thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=timeout)

    # Unblock any live SSE reader so its generator can finish. Without this,
    # uvicorn waits on the open generators at shutdown and the pod is killed.
    with sess.lock:
        subscribers = list(sess.subscribers)
        sess.subscribers.clear()
    if _loop is not None:
        for q in subscribers:
            try:
                _loop.call_soon_threadsafe(q.put_nowait, None)
            except RuntimeError:
                pass

    try:
        config.session_logfile(sess.session_id).unlink(missing_ok=True)
    except OSError:
        pass

    with _sessions_lock:
        sessions.pop(sess.session_id, None)


def _reap_once(now: Optional[float] = None) -> int:
    """Terminate sessions past their TTL or idle timeout. Returns the count."""
    now = now if now is not None else time.time()
    with _sessions_lock:
        candidates = list(sessions.values())
    reaped = 0
    for sess in candidates:
        age = now - sess.created_at
        idle = now - sess.last_seen
        if age > config.SESSION_TTL_SECONDS or idle > config.SESSION_IDLE_TIMEOUT:
            terminate_session(sess)
            reaped += 1
    return reaped


def _begin_drain() -> None:
    """Tell every browser why its stream is ending, then release the sessions.

    Runs on SIGTERM rather than in the lifespan shutdown because uvicorn waits
    for open connections to close BEFORE running lifespan shutdown -- by then
    the SSE generators are already being abandoned and nothing we emit would
    reach anyone. Draining here lets each stream deliver a final event and
    return on its own, so uvicorn's wait finds nothing left to wait for.
    """
    global _shutting_down
    if _shutting_down:
        return
    _shutting_down = True

    with _sessions_lock:
        live = list(sessions.values())
    for sess in live:
        _emit(sess, {
            "type": "server_shutdown",
            "message": "Server is restarting — please log in again.",
        })
    # Give the streams a moment to flush that event before their queues close.
    time.sleep(0.5)
    for sess in live:
        terminate_session(sess, timeout=5.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # _emit runs on worker threads where get_running_loop() would raise, so
    # capture the loop once here for call_soon_threadsafe.
    global _loop
    _loop = asyncio.get_running_loop()
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Drain on SIGTERM, ahead of uvicorn's connection wait. Chained so uvicorn
    # still sees the signal and runs its own shutdown afterwards.
    prev_handler = None

    def _on_sigterm(signum, frame):
        threading.Thread(target=_begin_drain, daemon=True).start()
        if callable(prev_handler):
            prev_handler(signum, frame)

    try:
        prev_handler = signal.signal(signal.SIGTERM, _on_sigterm)
    except ValueError:
        # Not on the main thread (tests, embedded use) -- skip.
        pass

    async def reaper():
        while True:
            await asyncio.sleep(config.REAPER_INTERVAL_SECONDS)
            try:
                await asyncio.to_thread(_reap_once)
            except Exception:
                pass

    task = asyncio.create_task(reaper())
    try:
        yield
    finally:
        task.cancel()
        # Belt and braces: if we shut down for a reason other than SIGTERM
        # (uvicorn reload, an exception), still release the RSA clients.
        await asyncio.to_thread(_begin_drain)


app = FastAPI(lifespan=lifespan)
app.mount(
    "/static",
    StaticFiles(directory=str(config.APP_ROOT / "static")),
    name="static",
)


def _read_version() -> dict:
    """Version + build SHA. Unlike standalone this never shells out to git --
    there is no .git in the image, and APP_VERSION carries the CI SHA."""
    info = {"version": "dev", "commit": config.APP_VERSION,
            "cert_login_enabled": False}
    try:
        with open(config.APP_ROOT / "VERSION", "r") as f:
            info["version"] = f.read().strip() or "dev"
    except OSError:
        pass
    return info


def _require_session(sid: str, request: Request) -> Session:
    """Resolve a session, enforcing that the caller owns it.

    The session id travels in the URL (and so into access logs and Referer
    headers), so possession of the path alone is not proof of ownership -- the
    HttpOnly cookie set at /login is. Mismatches return 404 rather than 403 so
    this cannot be used to probe which ids exist.
    """
    sess = sessions.get(sid)
    if sess is None or sess.closing:
        raise HTTPException(status_code=404, detail="Unknown session")
    if request.cookies.get(COOKIE_NAME) != sid:
        raise HTTPException(status_code=404, detail="Unknown session")
    sess.touch()
    return sess


@app.get("/healthz")
async def healthz():
    """Liveness. Deliberately trivial: a pod busy with many sessions is
    healthy, and failing here would kill pods holding live sessions."""
    return {"ok": True}


@app.get("/readyz")
async def readyz():
    """Readiness. Must NOT go unready under load -- readiness controls endpoint
    membership, and with sticky sessions dropping out breaks EXISTING sessions,
    not just new ones. Only shutdown flips this."""
    if _shutting_down:
        raise HTTPException(status_code=503, detail="shutting down")
    return {"ok": True}


@app.get("/version")
async def get_version():
    return _read_version()


class LoginRequest(BaseModel):
    email: str
    domain: str


class ServiceRequest(BaseModel):
    session_id: str
    serial: str


class RunRequest(BaseModel):
    session_id: str
    payload: dict


@app.get("/")
async def index():
    from fastapi.responses import HTMLResponse
    info = _read_version()
    tag = info.get("commit") or info.get("version") or "dev"
    with open(config.APP_ROOT / "static" / "index.html") as f:
        html = f.read()
    # Cache-bust static assets per build so a deploy never serves stale JS.
    html = html.replace("styles.css?v=2", f"styles.css?v={tag}")
    html = html.replace("app.js", f"app.js?v={tag}")
    return HTMLResponse(html)


@app.post("/login")
async def login(req: LoginRequest, response: Response):
    if _shutting_down:
        raise HTTPException(status_code=503, detail="Server is restarting.")
    with _sessions_lock:
        if len(sessions) >= config.MAX_SESSIONS:
            # Refuse here rather than letting the pod OOM. Readiness stays up
            # on purpose -- going unready would evict live sticky sessions.
            raise HTTPException(
                status_code=503,
                detail="Server is at capacity; try again shortly.",
            )

    sid = uuid.uuid4().hex
    sess = Session(session_id=sid, email=req.email, domain=req.domain)
    with _sessions_lock:
        sessions[sid] = sess
    worker = threading.Thread(target=_session_worker, args=(sess,), daemon=True)
    sess.thread = worker
    worker.start()
    sess.commands.put(("login", None))

    response.set_cookie(
        COOKIE_NAME, sid,
        httponly=True, samesite="lax", secure=config.COOKIE_SECURE, path="/",
    )
    return {"session_id": sid}


@app.post("/logout")
async def logout(request: Request, response: Response):
    sid = request.cookies.get(COOKIE_NAME)
    sess = sessions.get(sid) if sid else None
    if sess is not None:
        await asyncio.to_thread(terminate_session, sess, 5.0)
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/login/status/{sid}")
async def login_status(sid: str, request: Request):
    sess = _require_session(sid, request)
    with sess.lock:
        return {
            "status": sess.status,
            "sso_url": sess.sso_url,
            "error": sess.error,
            "service_status": sess.service_status,
            "service_name": sess.service_name,
            "service_error": sess.service_error,
        }


@app.post("/service")
async def connect_service(req: ServiceRequest, request: Request):
    sess = _require_session(req.session_id, request)
    sess.commands.put(("connect_service", {"serial": req.serial}))
    return {"ok": True}


@app.get("/service/status/{sid}")
async def service_status(sid: str, request: Request):
    sess = _require_session(sid, request)
    with sess.lock:
        return {
            "status": sess.service_status,
            "name": sess.service_name,
            "error": sess.service_error,
        }


@app.post("/run")
async def run(req: RunRequest, request: Request):
    sess = _require_session(req.session_id, request)
    sess.commands.put(("run_scenario", req.payload))
    return {"ok": True}


@app.post("/run/stop/{sid}")
async def run_stop(sid: str, request: Request):
    sess = _require_session(sid, request)
    sess.cancel_run.set()
    return {"ok": True}


@app.get("/logfile/{sid}")
async def download_logfile(sid: str, request: Request):
    sess = _require_session(sid, request)
    path = config.session_logfile(sess.session_id).resolve()
    # Defence in depth: sid is validated above, but never serve outside LOG_DIR.
    if not path.is_relative_to(config.LOG_DIR.resolve()):
        raise HTTPException(status_code=404, detail="Not found")
    if not path.exists():
        raise HTTPException(status_code=404, detail="No collection log yet")
    return FileResponse(
        path, media_type="text/plain",
        filename=f"collection_logfile_{sid[:8]}.txt",
    )


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


@app.get("/run/events/{sid}")
async def run_events(sid: str, request: Request):
    """Live check stream.

    async on purpose. The standalone version is a sync def, so each open
    connection occupies one of FastAPI's ~40 threadpool threads for its entire
    lifetime and the server wedges once the tabs outnumber the pool. Here each
    reader is just a coroutine awaiting an asyncio.Queue that the worker thread
    feeds, so connections cost no threads and no polling.
    """
    sess = _require_session(sid, request)

    # EventSource resends the last id it saw on reconnect; prefer that header
    # over ?since= (set once at open) so we don't re-deliver events.
    since_q = request.query_params.get("since")
    last_id_hdr = request.headers.get("last-event-id")
    raw = last_id_hdr if last_id_hdr is not None else since_q
    try:
        start_after = int(raw) if raw else 0
    except ValueError:
        start_after = 0

    q: asyncio.Queue = asyncio.Queue(maxsize=1000)

    async def event_stream():
        yield ": stream open\n\n"
        cursor = start_after

        # Register before replaying, so events emitted during replay are queued
        # rather than lost in the gap between the two.
        with sess.lock:
            sess.subscribers.add(q)
            backlog = [e for e in sess.event_log if e.get("id", 0) > cursor]
            oldest = sess.event_log[0].get("id", 0) if sess.event_log else 0

        try:
            # Tell the client if its cursor predates what we still hold, rather
            # than resuming mid-gap and silently skipping checks.
            if cursor and oldest and cursor < oldest - 1:
                yield _format({
                    "type": "replay_gap",
                    "id": cursor,
                    "ts": time.time(),
                    "message": "Some earlier events are no longer buffered; reload to resync.",
                })

            for ev in backlog:
                cursor = ev["id"]
                yield _format(ev)

            while True:
                if await request.is_disconnected():
                    return
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=3)
                except asyncio.TimeoutError:
                    # Heartbeat keeps proxies and the browser confident the
                    # stream is alive.
                    yield f": heartbeat {time.time()}\n\n"
                    continue
                if ev is None:
                    # Session torn down (reap or shutdown) -- end the stream so
                    # uvicorn isn't left waiting on this generator.
                    return
                if ev.get("id", 0) <= cursor:
                    continue  # already delivered during replay
                cursor = ev["id"]
                yield _format(ev)
        finally:
            with sess.lock:
                sess.subscribers.discard(q)

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
    # Single worker: multiple workers would fork separate `sessions` dicts and
    # break the in-process model. Concurrency comes from replicas + stickiness.
    uvicorn.run(app, host=config.HOST, port=config.PORT, workers=1)
