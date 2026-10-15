"""Scenario execution, shared by the standalone and cloud entrypoints.

The loop that walks a check chain and turns each CheckResult into a UI event is
identical for both; only where the collection log lands differs. Keeping it in
one place means a fix to check rendering reaches both apps.

The caller supplies an `emit(event: dict)` callable and a `cancelled()`
predicate, so this module stays free of any session/transport types.
"""

from checks import CheckResult, CheckStatus, RunContext
from check_registry import build_check_chain
from radkit_cli import set_logfile, append_to_logging_file


def run_scenario(payload: dict, service, emit, cancelled, logfile) -> None:
    """Run one scenario's check chain, emitting events as it goes.

    emit:      callable taking one event dict
    cancelled: callable returning True if the user asked to stop
    logfile:   path this run's collection log should be written to
    """
    emit({"type": "run_started", "scenario": payload.get("scenario")})

    # Bind the collection log for this run. Set here, on the thread that runs
    # the checks, so the checks -- and the border thread pool in
    # traffic_flows/iptransit.py, which copies this context -- all agree on the
    # destination.
    set_logfile(logfile)

    # Start each run from a clean file. Non-fatal: the run can still proceed.
    try:
        with open(logfile, "w"):
            pass
    except OSError:
        pass

    chain = build_check_chain(payload)
    if not chain:
        emit({
            "type": "run_complete",
            "ok": False,
            "message": f"No check chain defined for scenario '{payload.get('scenario')}'.",
        })
        return

    ctx = RunContext(payload=payload, service=service)
    any_fail = False

    # Use an index so Checks can dynamically extend the chain at runtime via
    # CheckResult.data["queue_checks"] — used by BorderProfile to spawn one
    # Check per discovered border.
    chain = list(chain)
    i = 0
    while i < len(chain):
        if cancelled():
            emit({
                "type": "run_complete",
                "ok": False,
                "cancelled": True,
                "message": "Collection cancelled by user.",
            })
            return
        check = chain[i]
        # A check can decline to appear at all. Used where the same check is
        # registered at two points in the chain and only one of them applies to
        # the run in hand -- emitting the other would paint a node for something
        # that never ran. Skipping here, before check_started, keeps the canvas
        # showing only the path actually taken.
        # NOTE: this is a manual-index loop -- advance `i` before continuing,
        # or the skip spins on the same check forever.
        applies = getattr(check, "applies", None)
        if callable(applies) and not applies(ctx):
            i += 1
            continue
        # Allow a previous check to remap subsequent target node ids — used by
        # WirelessFabricEdgeRedirect to redirect the wired chain to a
        # newly-spawned XTR node when the wireless endpoint roamed away from
        # the user's original input. Captured once and reused for
        # check_finished so a check that mutates the remap inside its own run()
        # still completes on the old node; only the NEXT iteration sees the new
        # mapping.
        remap = ctx.state.get("node_remap") or {}
        if getattr(check, "bypass_remap", False):
            target = check.target_node_id
        else:
            target = remap.get(check.target_node_id, check.target_node_id)
        emit({
            "type": "check_started",
            "name": check.name,
            "target_node_id": target,
            "note": getattr(check, "running_note", "") or "",
        })
        try:
            result = check.run(ctx)
        except BaseException as e:
            # BaseException covers SystemExit from legacy helpers that call
            # sys.exit() on hard prerequisite failures — we want to surface the
            # error on the affected node, not tear down the worker thread.
            #
            # The UI message carries only the exception type and text, which is
            # all a user can act on. The traceback is the only thing that says
            # WHERE it came from, so it goes to the collection log rather than
            # being discarded -- without it every crash here costs a debugging
            # session to re-localize.
            import traceback as _tb
            append_to_logging_file(
                f"[check-exception] {check.name}: "
                f"{type(e).__name__}: {e}\n{_tb.format_exc()}")
            result = CheckResult(
                CheckStatus.FAIL,
                f"Unhandled exception in check: {type(e).__name__}: {e}",
            )

        event = {
            "type": "check_finished",
            "name": check.name,
            "target_node_id": target,
            "status": result.status.value,
            "message": result.message,
        }
        # Pass through any data the check wanted the UI to act on.
        for key in ("node_relabel", "relabel_nodes", "add_endpoint", "add_nodes",
                    "add_edges", "node_rloc", "merge_into", "mark_fabric_wlc",
                    "mark_fabric_ap", "lisp_session_state"):
            if result.data.get(key):
                event[key] = result.data[key]
        # node_tags is meaningful when empty (it clears the tags), so it is
        # checked for presence rather than truthiness.
        if result.data.get("node_tags") is not None:
            event["node_tags"] = result.data["node_tags"]
        emit(event)

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

    emit({"type": "run_complete", "ok": not any_fail})
