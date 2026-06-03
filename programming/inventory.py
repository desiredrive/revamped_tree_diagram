"""Per-device expected-state inventory accumulated during a collection run.

Checks observe facts during their normal execution (a MAC is learned, a route
is resolved, an SGACL is consulted) and append them here. At the end of the
run, when no FAILs have surfaced, programming/sweep.py walks the inventory
and verifies each fact against the device's actual programming using the
primitives in programming/<category>.py.

Design contract:
  - Each fact is a frozen dataclass — value-equal facts collapse into a single
    set entry, so duplicate appends from overlapping checks are harmless.
  - Inputs are validated at append time (mandatory fields, canonicalization)
    so the sweep can trust the inventory.
  - Storage lives in ctx.state["device_inventory"] keyed by hostname; nothing
    is module-global, so concurrent runs cannot collide.
  - checks_*.py only import the add_expected_* helpers. Only programming/sweep.py
    imports the validators. No check module ever imports both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from programming.mac import canonicalize_mac


_INVENTORY_KEY = "device_inventory"


@dataclass(frozen=True)
class ExpectedMac:
    mac: str
    vlan: int
    interface: str


@dataclass(frozen=True)
class ExpectedRoute:
    prefix: str
    mask: int
    vrf: Optional[str] = None
    nexthop: Optional[str] = None


@dataclass(frozen=True)
class ExpectedInterface:
    interface: str
    kind: str  # "physical" | "svi" | "portchannel" | "lisp" | "tunnel" | "l2lisp" | "access_tunnel"


@dataclass(frozen=True)
class ExpectedMroute:
    group: str
    source: Optional[str]
    vrf: Optional[str] = None


@dataclass(frozen=True)
class ExpectedAuthSession:
    mac: str
    interface: str
    domain: Optional[str] = None  # "DATA" | "VOICE" | None


@dataclass(frozen=True)
class ExpectedSgacl:
    src_sgt: int
    dst_sgt: int
    rbacl: Optional[str] = None


@dataclass
class DeviceInventory:
    hostname: str
    macs: set[ExpectedMac] = field(default_factory=set)
    routes: set[ExpectedRoute] = field(default_factory=set)
    interfaces: set[ExpectedInterface] = field(default_factory=set)
    mroutes: set[ExpectedMroute] = field(default_factory=set)
    auth_sessions: set[ExpectedAuthSession] = field(default_factory=set)
    sgacls: set[ExpectedSgacl] = field(default_factory=set)


def _store(ctx) -> dict:
    return ctx.state.setdefault(_INVENTORY_KEY, {})


def get_inventory(ctx, hostname: str) -> DeviceInventory:
    """Lazy-create the per-device inventory keyed by hostname."""
    if not hostname:
        raise ValueError("hostname is required to attach inventory facts.")
    store = _store(ctx)
    inv = store.get(hostname)
    if inv is None:
        inv = DeviceInventory(hostname=hostname)
        store[hostname] = inv
    return inv


def all_inventories(ctx) -> dict[str, DeviceInventory]:
    """Snapshot used by programming/sweep.py at the end of the run."""
    return dict(_store(ctx))


def add_expected_mac(ctx, hostname: str, *, mac: str, vlan: int, interface: str) -> None:
    if vlan is None or str(vlan).strip().lower() in ("", "none"):
        raise ValueError("add_expected_mac: vlan is mandatory.")
    if not mac:
        raise ValueError("add_expected_mac: mac is mandatory.")
    if not interface:
        raise ValueError("add_expected_mac: interface is mandatory.")
    fact = ExpectedMac(
        mac=canonicalize_mac(mac),
        vlan=int(vlan),
        interface=interface.strip(),
    )
    get_inventory(ctx, hostname).macs.add(fact)


def add_expected_route(
    ctx,
    hostname: str,
    *,
    prefix: str,
    mask: int,
    vrf: Optional[str] = None,
    nexthop: Optional[str] = None,
) -> None:
    if not prefix:
        raise ValueError("add_expected_route: prefix is mandatory.")
    if mask is None:
        raise ValueError("add_expected_route: mask is mandatory.")
    fact = ExpectedRoute(
        prefix=prefix.strip(),
        mask=int(mask),
        vrf=vrf.strip() if isinstance(vrf, str) and vrf.strip() else None,
        nexthop=nexthop.strip() if isinstance(nexthop, str) and nexthop.strip() else None,
    )
    get_inventory(ctx, hostname).routes.add(fact)


def add_expected_interface(ctx, hostname: str, *, interface: str, kind: str) -> None:
    if not interface:
        raise ValueError("add_expected_interface: interface is mandatory.")
    if kind not in {"physical", "svi", "portchannel", "lisp", "tunnel", "l2lisp", "access_tunnel"}:
        raise ValueError(f"add_expected_interface: unknown kind {kind!r}.")
    fact = ExpectedInterface(interface=interface.strip(), kind=kind)
    get_inventory(ctx, hostname).interfaces.add(fact)


def add_expected_mroute(
    ctx,
    hostname: str,
    *,
    group: str,
    source: Optional[str] = None,
    vrf: Optional[str] = None,
) -> None:
    if not group:
        raise ValueError("add_expected_mroute: group is mandatory.")
    fact = ExpectedMroute(
        group=group.strip(),
        source=source.strip() if isinstance(source, str) and source.strip() else None,
        vrf=vrf.strip() if isinstance(vrf, str) and vrf.strip() else None,
    )
    get_inventory(ctx, hostname).mroutes.add(fact)


def add_expected_auth_session(
    ctx,
    hostname: str,
    *,
    mac: str,
    interface: str,
    domain: Optional[str] = None,
) -> None:
    if not mac:
        raise ValueError("add_expected_auth_session: mac is mandatory.")
    if not interface:
        raise ValueError("add_expected_auth_session: interface is mandatory.")
    fact = ExpectedAuthSession(
        mac=canonicalize_mac(mac),
        interface=interface.strip(),
        domain=domain.strip().upper() if isinstance(domain, str) and domain.strip() else None,
    )
    get_inventory(ctx, hostname).auth_sessions.add(fact)


def add_expected_sgacl(
    ctx,
    hostname: str,
    *,
    src_sgt: int,
    dst_sgt: int,
    rbacl: Optional[str] = None,
) -> None:
    if src_sgt is None or dst_sgt is None:
        raise ValueError("add_expected_sgacl: src_sgt and dst_sgt are mandatory.")
    fact = ExpectedSgacl(
        src_sgt=int(src_sgt),
        dst_sgt=int(dst_sgt),
        rbacl=rbacl.strip() if isinstance(rbacl, str) and rbacl.strip() else None,
    )
    get_inventory(ctx, hostname).sgacls.add(fact)
