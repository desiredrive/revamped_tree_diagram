"""NETCONF access to the 9800 wireless controllers.

Catalyst Center reaches a 9800 over NETCONF as well as SSH, so the AP's state
on its controller can be read as structured data instead of scraped from
`show` output. That matters here for three reasons:

  keys      Every operational list is keyed, and the 9800 honours a keyed
            subtree filter server-side. The AP chain already holds both the
            Ethernet MAC and the radio MAC, so one AP's record is fetched
            directly -- no table is retrieved and then filtered in Python.

  breadth   `ap-join-stats` carries the discovery, DTLS and join phases in a
            single record, with per-phase counters and failure types. The CLI
            spreads the same information over three commands and prints only
            the last event of each.

  parsing   There is no parser to go stale. A field is present under a known
            name or it is absent, rather than depending on a column layout.

The transport seam in `transport.py` covers RADKit exec and CatC HTTP; this is
a third kind of I/O and sits alongside it rather than inside it, because a
NETCONF session is long-lived and connection-oriented where those are single
request/response calls.
"""

from __future__ import annotations

import re
import threading
from contextvars import ContextVar
from typing import Any, Optional


#: The models the AP checks read. Short alias -> namespace, so a filter is
#: written as ns("ap_oper") rather than repeating a 70-character URI.
NS = {
    "ap_oper": "http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-access-point-oper",
    "ap_global": "http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-ap-global-oper",
    "general_cfg": "http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-general-cfg",
    "general_oper": "http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-general-oper",
    "lisp_oper": "http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-lisp-agent-oper",
}

#: Default NETCONF port on IOS-XE.
DEFAULT_PORT = 830


def netconf_mac(mac: str) -> str:
    """A MAC in the colon-separated form the 9800 keys its YANG lists on.

    This is the single most important conversion in this module. The rest of
    the app -- and every IOS `show` command -- uses the dotted-quad form
    (`3891.b70f.2600`), but the 9800 keys its operational lists on the
    colon-separated form (`38:91:b7:0f:26:00`). A dotted MAC in a subtree
    filter is not an error: the device matches nothing and returns an empty
    `<data/>`, which reads exactly like "this AP is not joined".

    That failure is silent and points at the AP rather than at the query, so
    the conversion happens here, once, and every caller goes through it.
    Anything that is not twelve hex digits is returned unchanged rather than
    mangled, so a malformed value reaches the device and fails there visibly.
    """
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexonly) != 12:
        return (mac or "").strip()
    h = hexonly.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def dotted_mac(mac: str) -> str:
    """The dotted-quad form, for reporting a NETCONF value in app terms."""
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexonly) != 12:
        return (mac or "").strip()
    h = hexonly.lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def strip_ns(tag: str) -> str:
    """An element tag without its `{namespace}` prefix."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def to_dict(element) -> Any:
    """An ElementTree element as nested dicts, namespaces dropped.

    Leaves become strings, containers become dicts, and a tag repeated at the
    same level becomes a list -- which is how YANG lists arrive. Text is
    stripped, and an element with no text and no children becomes "" rather
    than None: the 9800 emits empty leaves (`<ap-crash-file></ap-crash-file>`)
    to mean "nothing here", and "" compares the way callers expect.
    """
    children = list(element)
    if not children:
        return (element.text or "").strip()
    out: dict = {}
    for child in children:
        key = strip_ns(child.tag)
        value = to_dict(child)
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


def dig(data: Any, *path: str, default=None) -> Any:
    """Follow `path` through nested dicts, returning `default` if it breaks.

    The YANG trees are deep and partly optional -- `device-detail/wtp-version/
    sw-version` is four levels down and absent on an AP that never joined.
    Walking that with chained `.get()` calls obscures what is being read, and
    walking it with indexing raises on the AP this tool exists to diagnose.

    A list encountered mid-path takes its first entry, so a single-element
    YANG list reads the same as a container.
    """
    cur = data
    for key in path:
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def as_list(value) -> list:
    """A YANG list as a Python list whether it came back with 1 entry or many.

    ElementTree cannot tell a one-entry list from a container, so `to_dict`
    yields a bare dict for a single match and a list for several. Callers that
    iterate would silently iterate a dict's keys instead of its entries.
    """
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _quiet_ncclient() -> None:
    """Stop ncclient narrating every RPC onto the app's output.

    Raised to WARNING rather than disabled: a genuine transport error still
    reaches the log, while the per-RPC traffic does not.
    """
    import logging
    for name in ("ncclient", "ncclient.transport", "ncclient.operations"):
        logging.getLogger(name).setLevel(logging.WARNING)


class NetconfError(Exception):
    """A NETCONF session could not be opened, or a get was refused."""


class NetconfSession:
    """One NETCONF session to one controller, reused across checks.

    Opening a session costs an SSH handshake plus the capability exchange --
    about a second against this lab's WLC, and the AP chain issues a dozen
    gets. The session is therefore opened once per controller and cached on
    the run (see `session_for`), not opened per check.

    Every get is a *keyed* subtree filter. See the module docstring: the point
    of NETCONF here is that the device does the filtering.
    """

    def __init__(self, host: str, username: str, password: str,
                 port: int = DEFAULT_PORT, timeout: int = 90):
        self.host = host
        self.port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._mgr = None
        self._lock = threading.Lock()

    def connect(self):
        """Open the session, or return the one already open."""
        if self._mgr is not None:
            return self._mgr
        try:
            from ncclient import manager
        except ImportError as e:
            raise NetconfError(
                "ncclient is not installed; NETCONF reads are unavailable"
            ) from e
        # ncclient logs every RPC it sends and receives at INFO on the root
        # logger. Left alone that puts the full XML of each get into the
        # app's output, burying the check results it was called to produce.
        _quiet_ncclient()
        try:
            self._mgr = manager.connect(
                host=self.host, port=self.port,
                username=self._username, password=self._password,
                hostkey_verify=False,
                device_params={"name": "iosxe"},
                allow_agent=False, look_for_keys=False,
                timeout=self._timeout,
            )
        except Exception as e:
            raise NetconfError(
                f"NETCONF session to {self.host}:{self.port} failed — "
                f"{type(e).__name__}: {e}"
            ) from e
        return self._mgr

    def get_subtree(self, xml_filter: str) -> dict:
        """Run one subtree `get` and return the reply as nested dicts.

        Serialised on a lock: checks fan out across a thread pool, and one
        ncclient session is not safe to share between threads.
        """
        import xml.etree.ElementTree as ET
        with self._lock:
            mgr = self.connect()
            try:
                reply = mgr.get(filter=("subtree", xml_filter))
            except Exception as e:
                raise NetconfError(
                    f"NETCONF get on {self.host} failed — "
                    f"{type(e).__name__}: {e}"
                ) from e
        try:
            return to_dict(ET.fromstring(reply.xml))
        except ET.ParseError as e:
            raise NetconfError(
                f"NETCONF reply from {self.host} did not parse — {e}") from e

    def close(self):
        with self._lock:
            if self._mgr is not None:
                try:
                    self._mgr.close_session()
                except Exception:
                    # A session that cannot be closed cleanly is not worth
                    # failing a run over; the socket goes when the process does.
                    pass
                self._mgr = None


def _filter(alias: str, root: str, inner: str = "") -> str:
    """A subtree filter for one model's root container."""
    if not inner:
        return f'<{root} xmlns="{NS[alias]}"/>'
    return f'<{root} xmlns="{NS[alias]}">{inner}</{root}>'


def ap_capwap_data(session: NetconfSession, radio_mac: str) -> dict:
    """The AP's CAPWAP record, keyed on its radio MAC.

    This one record replaces most of `show ap summary`, `show ap uptime`,
    `show ap crash`, `show ap image summary` and the tag half of
    `show ap config general`: name, address, model, serial, state, tags,
    country, uptimes, image status and crash files are all inside it.

    Returns {} when the controller has no record of this AP -- which is the
    answer to "is it joined", not an error.
    """
    inner = f"<capwap-data><wtp-mac>{netconf_mac(radio_mac)}</wtp-mac></capwap-data>"
    data = session.get_subtree(_filter("ap_oper", "access-point-oper-data", inner))
    entries = as_list(dig(data, "data", "access-point-oper-data", "capwap-data"))
    return entries[0] if entries else {}


def ap_join_stats(session: NetconfSession, radio_mac: str) -> dict:
    """Discovery, DTLS and join counters for one AP, keyed on its radio MAC.

    The single most useful record for a join fault. It carries all three join
    phases with their own counters and failure types, where the CLI needs
    `show wireless stats ap discovery`, `show wireless dtls connections` and
    `show wireless stats ap join summary` to say the same thing -- each
    printing only the latest event.
    """
    inner = f"<ap-join-stats><wtp-mac>{netconf_mac(radio_mac)}</wtp-mac></ap-join-stats>"
    data = session.get_subtree(_filter("ap_global", "ap-global-oper-data", inner))
    entries = as_list(dig(data, "data", "ap-global-oper-data", "ap-join-stats"))
    return entries[0] if entries else {}


def ap_history(session: NetconfSession, ethernet_mac: str) -> dict:
    """Join/disjoin history for one AP, keyed on its *Ethernet* MAC.

    Note the key: `ap-history` is the one list in these models keyed on the
    Ethernet MAC rather than the radio MAC, matching
    `show wireless stats ap history`. Passing the radio MAC here returns
    empty, which would read as "this AP has never joined".
    """
    inner = (f"<ap-history><ethernet-mac>{netconf_mac(ethernet_mac)}"
             f"</ethernet-mac></ap-history>")
    data = session.get_subtree(_filter("ap_global", "ap-global-oper-data", inner))
    entries = as_list(dig(data, "data", "ap-global-oper-data", "ap-history"))
    if not entries:
        return {}
    entry = entries[0]
    # Unlike every other list here, `ap-history` answers an unknown Ethernet
    # MAC with a stub -- the MAC echoed back, an empty name and an all-zero
    # radio MAC -- instead of returning nothing. Taken at face value that
    # reads as an AP with a clean history, so the stub is discarded here
    # rather than in each caller.
    if not dig(entry, "ap-name") and not as_list(dig(entry, "ewlc-ap-state-ptr")):
        return {}
    return entry


def radio_mac_for_ethernet(session: NetconfSession, ethernet_mac: str) -> str:
    """The AP's radio MAC, looked up from the Ethernet MAC.

    The bridge between what the AP chain knows and what the controller keys
    on. The chain learns an AP's Ethernet MAC from the edge switch -- that is
    what a switch sees on the wire -- while almost every list here is keyed on
    the radio MAC. One keyed get crosses the gap.

    Returns "" when the controller has never seen this Ethernet MAC.
    """
    inner = (f"<ethernet-mac-wtp-mac-map><ethernet-mac>"
             f"{netconf_mac(ethernet_mac)}</ethernet-mac></ethernet-mac-wtp-mac-map>")
    data = session.get_subtree(_filter("ap_oper", "access-point-oper-data", inner))
    entries = as_list(
        dig(data, "data", "access-point-oper-data", "ethernet-mac-wtp-mac-map"))
    return dig(entries[0], "wtp-mac", default="") if entries else ""


def country_oper(session: NetconfSession) -> list:
    """Every configured regulatory country on the controller.

    Keyed on `country-code`, but the AP chain does not know which country to
    ask for until it has read the AP's own code, so the list is fetched whole:
    it is one entry per configured country, not one per AP, and stays small.
    """
    data = session.get_subtree(
        _filter("ap_oper", "access-point-oper-data", "<country-oper/>"))
    return as_list(dig(data, "data", "access-point-oper-data", "country-oper"))


#: One NETCONF session per controller, for the lifetime of a run. Keyed on
#: host so the dozen gets the AP chain issues share one handshake. A
#: ContextVar for the same reason transport.py uses one: checks fan out to a
#: ThreadPoolExecutor, and a thread-local would leave pool threads with no
#: cache and open a session per check.
_sessions: ContextVar[Optional[dict]] = ContextVar("netconf_sessions", default=None)


def session_for(host: str, username: str, password: str,
                port: int = DEFAULT_PORT) -> NetconfSession:
    """The run's session to `host`, opening one if this is the first ask."""
    cache = _sessions.get()
    if cache is None:
        cache = {}
        _sessions.set(cache)
    key = (host, port)
    session = cache.get(key)
    if session is None:
        session = NetconfSession(host, username, password, port)
        cache[key] = session
    return session


def close_sessions() -> None:
    """Close every session opened during this run."""
    cache = _sessions.get()
    if not cache:
        return
    for session in cache.values():
        session.close()
    cache.clear()


def credentials() -> Optional[tuple]:
    """NETCONF credentials for the controllers, or None if not configured.

    Every other device read in this app goes through RADKit, which carries its
    own SSO-backed authentication and needs no credentials here. NETCONF does
    not ride that session, so it needs its own -- and rather than invent a
    credential store, this reads three environment variables and treats their
    absence as "NETCONF is not configured".

    That absence is deliberately not an error: the checks that use NETCONF
    fall back to their CLI path when this returns None, so an operator who
    sets nothing sees exactly the behaviour they saw before.

        NETCONF_USERNAME   NETCONF_PASSWORD   NETCONF_PORT (optional, 830)
    """
    import os
    user = os.environ.get("NETCONF_USERNAME")
    password = os.environ.get("NETCONF_PASSWORD")
    if not (user and password):
        return None
    try:
        port = int(os.environ.get("NETCONF_PORT") or DEFAULT_PORT)
    except ValueError:
        port = DEFAULT_PORT
    return user, password, port


def session_for_wlc(mgmt_ip: str) -> Optional[NetconfSession]:
    """A session to one controller, or None when NETCONF is not configured."""
    creds = credentials()
    if not (creds and mgmt_ip):
        return None
    user, password, port = creds
    return session_for(mgmt_ip, user, password, port)
