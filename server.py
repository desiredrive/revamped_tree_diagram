import json
import queue
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from radkit_client.sync import create_context, Client

from checks import Check, CheckResult, CheckStatus, RunContext
from check_registry import build_check_chain


_STOP = object()  # sentinel to shut down a session's worker thread


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
    # Service (RADKIT service_cloud) state
    service: object = None
    service_serial: Optional[str] = None
    service_name: Optional[str] = None
    service_status: str = "idle"  # idle | connecting | ready | error
    service_error: Optional[str] = None
    # Threading / queues
    lock: threading.Lock = field(default_factory=threading.Lock)
    commands: "queue.Queue" = field(default_factory=queue.Queue)
    events: "queue.Queue" = field(default_factory=queue.Queue)


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
        # certificate_login returns PromptInterrupted (not raises) when it
        # couldn't get input it needed from stdin.
        from radkit_client.sync import PromptInterrupted
        if isinstance(result, PromptInterrupted):
            raise RuntimeError(
                "Certificate login was interrupted — RADKIT prompted for input "
                "(likely a missing or wrong private-key password)."
            )
        with sess.lock:
            sess.status = "ready"
        return

    resp = c.oauth_connect_only(identity=sess.email, domain=sess.domain)
    if resp is None:
        raise RuntimeError("RADKIT returned no OAuth response.")

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
    """Push one event onto the session's SSE queue."""
    event["ts"] = time.time()
    sess.events.put(event)


def _do_run_scenario(sess: Session, payload: dict) -> None:
    """Run the Check chain for one scenario, streaming events as we go."""
    # Drop any straggler events from a prior run so a fresh "Run Again"
    # doesn't replay stale state to the new SSE consumer.
    try:
        while True:
            sess.events.get_nowait()
    except queue.Empty:
        pass

    _emit(sess, {"type": "run_started", "scenario": payload.get("scenario")})

    chain = build_check_chain(payload)
    if not chain:
        _emit(sess, {
            "type": "run_complete",
            "ok": False,
            "message": f"No check chain defined for scenario '{payload.get('scenario')}'.",
        })
        return

    ctx = RunContext(payload=payload, service=sess.service)
    any_fail = False

    # Use an index so Checks can dynamically extend the chain at runtime via
    # CheckResult.data["queue_checks"] — used by BorderProfile to spawn one
    # Check per discovered border.
    chain = list(chain)
    i = 0
    while i < len(chain):
        check = chain[i]
        _emit(sess, {
            "type": "check_started",
            "name": check.name,
            "target_node_id": check.target_node_id,
        })
        try:
            result = check.run(ctx)
        except BaseException as e:
            # BaseException covers SystemExit from legacy helpers that call
            # sys.exit() on hard prerequisite failures — we want to surface the
            # error on the affected node, not tear down the worker thread.
            result = CheckResult(
                CheckStatus.FAIL,
                f"Unhandled exception in check: {type(e).__name__}: {e}",
            )

        event = {
            "type": "check_finished",
            "name": check.name,
            "target_node_id": check.target_node_id,
            "status": result.status.value,
            "message": result.message,
        }
        # Pass through any data the check wanted the UI to act on.
        if result.data.get("node_relabel"):
            event["node_relabel"] = result.data["node_relabel"]
        if result.data.get("node_tags") is not None:
            event["node_tags"] = result.data["node_tags"]
        if result.data.get("add_endpoint"):
            event["add_endpoint"] = result.data["add_endpoint"]
        if result.data.get("add_nodes"):
            event["add_nodes"] = result.data["add_nodes"]
        if result.data.get("node_rloc"):
            event["node_rloc"] = result.data["node_rloc"]
        if result.data.get("merge_into"):
            event["merge_into"] = result.data["merge_into"]
        _emit(sess, event)

        # Splice any dynamically-queued follow-up Checks right after the
        # current position so they run before any later static Checks.
        extra = result.data.get("queue_checks")
        if extra:
            chain[i+1:i+1] = list(extra)

        if result.status == CheckStatus.FAIL:
            any_fail = True
            # Do NOT break — the affected node turns red, the error is shown,
            # and remaining checks continue so the user sees the full picture.
        i += 1

    _emit(sess, {"type": "run_complete", "ok": not any_fail})


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


class LoginRequest(BaseModel):
    email: str
    domain: str
    method: str = "sso"
    passphrase: Optional[str] = None


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/logfile")
def download_logfile():
    import os
    path = "collection_logfile.txt"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="collection_logfile.txt not found")
    return FileResponse(path, media_type="text/plain", filename="collection_logfile.txt")


def _session_worker(sess: Session) -> None:
    """Long-lived per-session thread. RADKIT's sync API binds to this thread,
    so every RADKIT call for this session must come through here."""
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
    threading.Thread(target=_session_worker, args=(sess,), daemon=True).start()
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


@app.get("/run/events/{sid}")
def run_events(sid: str):
    sess = sessions.get(sid)
    if sess is None:
        raise HTTPException(status_code=404, detail="Unknown session")

    def event_stream():
        # Send one comment immediately so the browser EventSource opens.
        yield ": stream open\n\n"
        while True:
            try:
                event = sess.events.get(timeout=3)
            except queue.Empty:
                # Frequent heartbeats as real data events keep the SSE
                # connection visibly alive during long blocking checks where
                # the worker thread can be silent for a minute or more.
                yield f"data: {json.dumps({'type': 'heartbeat', 'ts': time.time()})}\n\n"
                continue
            if event is _STOP:
                break
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
                })
            yield f"data: {payload}\n\n"
            if event.get("type") == "run_complete":
                break

    return StreamingResponse(event_stream(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
