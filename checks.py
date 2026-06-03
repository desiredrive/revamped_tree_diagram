"""Check abstraction for the web troubleshooter.

A Check is one discrete verification that the troubleshooter performs against
the fabric. Each Check:
  - Has a stable name and the topology node it targets.
  - Runs synchronously inside the per-session worker thread.
  - Returns a CheckResult describing pass/warn/fail + a human-readable message.
  - May read/write the shared run context to share findings with later checks.

This module deliberately holds no RSA or fabric-specific logic; concrete
checks live in their own modules and subclass `Check`.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CheckStatus(str, Enum):
    PENDING = "pending"     # queued, not yet run
    RUNNING = "running"     # currently executing
    OK = "ok"               # verification passed
    WARN = "warn"           # verification raised a non-fatal concern
    FAIL = "fail"           # verification failed; downstream checks may be unsafe
    SKIP = "skip"           # not applicable to this run (e.g. INFRA_VN-only check on non-INFRA run)


@dataclass
class CheckResult:
    status: CheckStatus
    message: str = ""
    # Free-form data the check wants to expose to later checks via the run context.
    # Example: profile_xtr stores {"hostname": "...", "loopback": "..."} here.
    data: dict = field(default_factory=dict)


class Check:
    """Base class for all web-troubleshooter checks.

    Subclasses set `name` and `target_node_id` as class attributes (or
    override them in __init__) and implement `run(ctx)`.
    """

    name: str = "unnamed-check"
    target_node_id: str = "xtr"

    def run(self, ctx: "RunContext") -> CheckResult:
        raise NotImplementedError


@dataclass
class RunContext:
    """Mutable state carried through one troubleshooting run.

    Holds the input payload (form values), the RSA service handle, and a
    free-form `state` dict that checks read from / write to. Earlier checks
    publish their findings into `state`; later checks pull them out.
    """

    payload: dict
    service: Any = None
    state: dict = field(default_factory=dict)
