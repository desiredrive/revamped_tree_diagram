"""Is the AP's radio MAC registered on each reachable control plane?

The controller registers the radio MAC into the INFRA_VN L2 instance, to
every control plane it holds a session with. A control plane that has no
record for it holds no record of the AP at all, however healthy the rest of
the fabric looks -- so this is read from each control plane in turn, not from
the controller.

One control plane missing the registration is a fabric fault with a known
cause, and it queues the LISP session flow for that control plane. Every
control plane missing it is a total failure: the AP is registered nowhere.

The command is

    show lisp instance-id <iid> ethernet <mac> internal

`internal` adds one thing over the plain form: the `WLC data length` field and
its hex payload, which carry the AP's address, its SGT and the L3 VNID. Some
versions do not support it, so the plain form is the fallback and the metadata
checks are skipped rather than failed when it is the one that answered.
"""

import re

from checks.base import Check, CheckResult, CheckStatus, RunContext
from checks.lisp_session import _cp_device


def parse_native_metadata(raw):
    """The device's OWN decode of the WLC payload, where it offers one.

    Newer IOS-XE prints a `Metadata:` block under `show lisp instance-id
    <iid> ethernet database wlc <mac>`::

        Metadata (hex):   00 01 00 22  00 01 00 0C  AC 13 05 0A ...
        Metadata:         IPv4 address: 172.19.5.10
                          Client SGT: 0
                          Client association time: 0

    Most releases do not, which is why `decode_wlc_metadata` exists. Where
    this block IS present it is ground truth and beats any local decode --
    it is the device reading its own structure, and it is what caught the
    SGT this module used to get wrong.

    Only the AP address is taken. The SGT is deliberately not read: AP
    onboarding ignores it, and the L3 VNID is not in this block at all.

    Returns None when the device printed no such block.
    """
    if not raw:
        return None
    m = re.search(r"Metadata:\s*IPv4 address:\s*(\d+\.\d+\.\d+\.\d+)",
                  raw)
    if not m:
        return None
    return {"ap_ip": m.group(1), "source": "device"}


def decode_wlc_metadata(hex_text):
    """The AP address and L3 VNID out of the `WLC data length` payload.

    The payload is TLV-structured: a 4-byte outer header wrapping inner
    entries that are themselves type(2) + length(2) + value. On the lab AP::

        00 01 00 22   outer: type 1, length 34
        00 01 00 0C   inner: type 1, length 12
        AC 13 05 0A   | AP address   172.19.5.10
        00 00 10 01   | L3 VNID      4097
        00 02 00 06   | (remainder of the 12-byte value)
        00 00 00 03   inner: type 2, length 6
        ...

    NO SGT is read here, deliberately. An earlier version reported one from
    bytes 20-23 and returned 3 for an AP the device itself decodes as
    `Client SGT: 0`. Bytes 20-23 are not a value at all -- they are the next
    inner TLV's header, so the "3" was the low byte of a LENGTH field being
    read as data. The AP's SGT is not what this check is about, and a wrong
    one is worse than none; see `extract_ip_and_sgt_fixed_positions` in
    `routingmodules.lisp`, which has its own SGT defect and is left alone
    because the CLI wireless flow depends on it.

    Newer IOS-XE decodes this payload itself (`Metadata:` in `show lisp
    instance-id <iid> ethernet database wlc <mac>`); older releases print
    only the hex, which is why it is decoded here at all.

    Returns a dict, with None for anything the payload is too short to hold.
    """
    out = {"ap_ip": None, "l3_vnid": None, "all_zero": None}
    tok = re.findall(r"\b[0-9A-Fa-f]{2}\b", hex_text or "")
    if not tok:
        return out

    # "Must not be all zeros": a payload the controller sent with nothing in
    # it, which is a different fault from one it never sent.
    out["all_zero"] = all(t == "00" for t in tok)

    def num(lo, hi):
        return int("".join(tok[lo:hi]), 16) if len(tok) >= hi else None

    # Past the outer TLV header (4 bytes) and the inner one (4 more). Both
    # sit inside the first inner value, which the header declares as 12
    # bytes -- so both are within bounds whenever that value is present.
    if len(tok) >= 16:
        try:
            out["ap_ip"] = ".".join(str(int(t, 16)) for t in tok[8:12])
        except ValueError:
            out["ap_ip"] = None
    out["l3_vnid"] = num(12, 16)
    return out


NOT_FOUND = re.compile(r"Could not find instance-id|%\s*No entries", re.I)


class ApRadioMacRegistration(Check):
    """The radio MAC's registration record on ONE control plane.

    Every condition below is read from the record the control plane holds.
    They are graded as faults in the fabric, so they warn: the run continues
    and the remaining control planes are still asked.
    """

    def __init__(self, cp_hostname, cp_mgmt, radio_mac, iid, catc_name,
                 node_id, edge_loopback=None):
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt
        self.radio_mac = radio_mac
        self.iid = iid
        self.catc_name = catc_name
        self.edge_loopback = edge_loopback
        self.target_node_id = node_id
        self.name = f"Radio MAC Registration — {cp_hostname}"
        self.running_note = "Reading the radio MAC's registration record."

    def _read(self, ctx, host):
        """The record, and which command form answered.

        `internal` first: it is the only form carrying the WLC metadata. A
        version that does not support it answers with an error rather than a
        record, so the plain form is tried next and the metadata checks are
        skipped rather than failed.
        """
        from radkit_cli import get_any_single_output
        from routingmodules.lisp import _parse_ipv4_server_raw

        base = f"show lisp instance-id {self.iid} ethernet server {self.radio_mac}"
        for cmd, form in ((f"{base} internal", "internal"), (base, "plain")):
            raw = get_any_single_output(host, cmd, ctx.service)
            if not raw:
                continue
            if NOT_FOUND.search(raw):
                # The control plane answered, and said it holds no record.
                return None, form, raw
            rec = _parse_ipv4_server_raw(raw, self.radio_mac, self.iid)
            if rec:
                return rec, form, raw
        return None, None, None

    def run(self, ctx: RunContext) -> CheckResult:
        try:
            cp = _cp_device(ctx, self.cp_hostname, self.catc_name, self.cp_mgmt)
            host = cp.profiled_device.hostname
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not reach {self.cp_hostname} to read the radio MAC's "
                f"registration ({type(e).__name__}: {e}).",
                data={"cp": self.cp_hostname})

        try:
            rec, form, _raw = self._read(ctx, host)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not read the registration for {self.radio_mac} on "
                f"{self.cp_hostname} ({type(e).__name__}: {e}).",
                data={"cp": self.cp_hostname})

        # Recorded for the trigger below, which decides between one control
        # plane missing it and all of them.
        reg = ctx.state.setdefault("ap_radio_reg", {})
        if rec is None:
            reg[self.cp_hostname] = False
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} holds no registration for the AP's radio "
                f"MAC {self.radio_mac} in instance {self.iid}.\n\n"
                f"The controller registers the radio MAC over its LISP "
                f"session to this control plane, so this control plane holds "
                f"no record of the AP at all. The session flow below says "
                f"why.",
                data={"cp": self.cp_hostname, "registered": False})
        reg[self.cp_hostname] = True

        state = (rec.get("state") or "").strip().lower()
        auth = rec.get("auth_failures") or 0
        etrs = rec.get("etrs") or []
        locs = rec.get("locators") or {}
        up = [ip for ip, l in locs.items()
              if (l.get("state") or "").lower() == "up"]
        # ALWAYS this control plane's own payload. Each control plane is
        # read separately precisely so one that is out of step with the
        # others is visible, and the AP address is part of what can differ.
        #
        # An earlier version preferred the EDGE's native decode here and
        # overwrote `ap_ip` with it. That is one answer spliced onto every
        # control plane's record: a Border2 holding a stale or different
        # address reported the edge's instead, hiding the single fault this
        # check exists to find. The device decode is still read -- it is
        # ground truth for the PAYLOAD FORMAT, and it caught the SGT this
        # module used to get wrong -- but it is cross-checked against what
        # each control plane holds, never substituted for it.
        meta = decode_wlc_metadata(rec.get("wlc_data_hex"))
        meta["source"] = "decoded"

        # Best-effort, and never fatal: most IOS-XE releases have no
        # `Metadata:` block, and the edge may be unreachable. Its absence is
        # the normal case.
        native_raw = None
        edge = ctx.state.get("xtr_hostname")
        if edge:
            try:
                from radkit_cli import get_any_single_output
                native_raw = get_any_single_output(
                    edge,
                    f"show lisp instance-id {self.iid} ethernet database wlc "
                    f"{self.radio_mac}", ctx.service)
            except BaseException:
                native_raw = None
        native = parse_native_metadata(native_raw)
        if native:
            meta["device_ap_ip"] = native["ap_ip"]
            # Agreement confirms this control plane is in step with the edge
            # AND that the local decode read the payload correctly.
            meta["agrees_with_device"] = (
                meta.get("ap_ip") == native["ap_ip"]
                if meta.get("ap_ip") else None)

        lines = [
            f"• EID {rec.get('eid_prefix') or self.radio_mac} in instance "
            f"{self.iid}, state {rec.get('state') or '—'}",
            f"• ETR: {', '.join(etrs) if etrs else '—'}",
            f"• Locators up: {', '.join(up) if up else 'none'}",
        ]
        if meta.get("ap_ip"):
            lines.append(
                f"• WLC metadata: AP {meta['ap_ip']}, L3 VNID "
                f"{meta['l3_vnid'] if meta['l3_vnid'] is not None else '—'}"
                + ("  (confirmed by the edge's own decode)"
                   if meta.get("agrees_with_device") else ""))

        faults = self._grade(rec, state, auth, etrs, up, meta, form)
        data = {"cp": self.cp_hostname, "registered": True, "state": state,
                "auth_failures": auth, "etrs": etrs, "locators_up": up,
                "metadata": meta, "command_form": form}
        if faults:
            return CheckResult(
                CheckStatus.WARN, "\n".join(lines + [""] + faults), data=data)
        return CheckResult(
            CheckStatus.OK,
            f"The AP's radio MAC {self.radio_mac} is registered on "
            f"{self.cp_hostname}:\n" + "\n".join(lines), data=data)

    def _grade(self, rec, state, auth, etrs, up, meta, form):
        """One bullet per condition that does not hold."""
        faults = []
        # Did this device print a WLC section at all? The AP bit and the
        # payload live there together, so their absence is one fact about
        # the release, not several faults in the registration.
        wlc_fields_present = (rec.get("wlc_ap_bit") is not None
                              or rec.get("wlc_data_length") is not None)

        if state != "complete":
            faults.append(
                f"  ⚠ The registration state is "
                f"{rec.get('state') or 'not reported'}, not complete. The "
                f"control plane has a partial record, so it cannot answer "
                f"map-requests for this radio MAC.")

        # Only while the state is NOT complete. A complete registration with
        # historic failures is a key that WAS wrong and has since been fixed;
        # reporting that as a fault on every run is noise.
        if auth and state != "complete":
            faults.append(
                f"  ⚠ {auth} authentication failure(s) on this "
                f"registration. The key between the controller and this "
                f"control plane does not match.")

        if not rec.get("reliable_transport"):
            faults.append(
                "  ⚠ The registration is not sourced by reliable "
                "transport. An AP registration is carried over the TCP "
                "session, so one that is not did not come from the "
                "controller's fabric session.")

        # Only where the device exposes the WLC fields at all. Not every
        # release prints them on a border even when it accepts `internal`,
        # and an absent field is then the release's silence, not a fault in
        # the registration. Graded as "not Set" it failed healthy records.
        if wlc_fields_present:
            bit = (rec.get("wlc_ap_bit") or "").strip().lower()
            if bit != "set":
                faults.append(
                    f"  ⚠ The WLC AP bit is "
                    f"{rec.get('wlc_ap_bit') or 'absent'}, not Set. The "
                    f"control plane does not see this registration as an "
                    f"AP's, so it is not treated as a fabric AP.")

        # The LOCATOR, not the ETR. On a radio-MAC registration the ETR is
        # the controller's WMI -- the controller is what registers it -- and
        # the edge's Loopback0 is what appears in the locator table, as the
        # RLOC the fabric reaches the AP through. Verified on Border1:
        # ETR 10.31.136.74 (the WMI), locator 172.19.1.68 (Edge2's Lo0).
        # Grading the ETR against the edge's Lo0 failed a healthy record.
        if self.edge_loopback and up and self.edge_loopback not in up:
            faults.append(
                f"  \u26a0 The locator for this registration is "
                f"{', '.join(up)}, not the edge's Loopback0 "
                f"{self.edge_loopback}. The control plane has the AP behind "
                f"a different RLOC than the switch it is attached to, so "
                f"traffic for it is sent to the wrong edge.")

        if not up:
            faults.append(
                "  ⚠ No locator for this registration is up, so the "
                "control plane will not hand this EID out in a map-reply.")

        if form == "plain":
            # Not a fault: the version does not support the command.
            faults.append(
                "  ℹ This version does not support the `internal` form, "
                "so the WLC metadata (AP address and L3 VNID) could not "
                "be read and was not checked.")
        elif not wlc_fields_present:
            # `internal` was accepted and the record is complete, but this
            # release prints no WLC section on this device. Nothing was
            # withheld by the controller -- there is simply nothing here to
            # read, which is not the same statement as "the metadata is
            # missing from the registration".
            faults.append(
                "  ℹ This control plane does not report the WLC metadata "
                "section, so the AP address and L3 VNID could not be read "
                "from it and were not checked. The registration itself is "
                "unaffected.")
        else:
            faults.extend(self._grade_metadata(rec, meta))
        return faults

    def _grade_metadata(self, rec, meta):
        faults = []
        # The edge decoded the same AP's metadata and got a different
        # address than this control plane holds. One of them is out of step,
        # and which control plane it is matters -- which is why this is
        # reported per control plane rather than resolved silently.
        if meta.get("agrees_with_device") is False:
            faults.append(
                f"  ⚠ This control plane holds AP address "
                f"{meta.get('ap_ip')} in the WLC metadata, but the edge "
                f"decodes the same AP's metadata as "
                f"{meta.get('device_ap_ip')}. The two disagree, so one of "
                f"them is carrying a stale registration.")
        length = rec.get("wlc_data_length")
        if not length:
            faults.append(
                "  ⚠ The registration carries no WLC metadata (data "
                "length 0 or absent). The controller registered the radio "
                "MAC without the AP's address, SGT and VNID, so the control "
                "plane cannot resolve the AP's identity from it.")
        elif meta.get("all_zero"):
            faults.append(
                f"  ⚠ The WLC metadata is {length} bytes of zeros. The "
                f"controller sent the field but filled none of it, so the "
                f"AP's address, SGT and VNID are all absent.")
        elif meta.get("ap_ip") in (None, "0.0.0.0"):
            faults.append(
                f"  ⚠ The WLC metadata carries no AP address "
                f"({meta.get('ap_ip') or 'unreadable'}). The AP registered "
                f"before it was addressed, or the controller has not learned "
                f"its address yet.")
        return faults


class ApRadioMacRegistrationVerdict(Check):
    """What the per-control-plane records add up to.

    Runs after every `ApRadioMacRegistration`, so `ap_radio_reg` is complete.

    Registered nowhere is a total failure: the AP cannot be reached through
    the fabric by any control plane, and nothing further in the run can
    succeed. Registered on some but not all is a fault on those control
    planes, and the LISP session flow for them is what explains it -- that is
    already queued by the session trigger, which reads the same sessions.
    """

    name = "Radio MAC Registration — Summary"
    running_note = "Weighing the registration across the control planes."

    def __init__(self, radio_mac, iid, node_id="wlc"):
        self.radio_mac = radio_mac
        self.iid = iid
        self.target_node_id = node_id

    def run(self, ctx: RunContext) -> CheckResult:
        reg = ctx.state.get("ap_radio_reg") or {}
        if not reg:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no control plane was asked for the radio "
                "MAC's registration.")

        yes = sorted(h for h, ok in reg.items() if ok)
        no = sorted(h for h, ok in reg.items() if not ok)
        data = {"registered_on": yes, "missing_on": no}

        if not yes:
            # The one state that stops the run: no control plane can answer a
            # map-request for this radio MAC, so the AP is reachable through
            # none of the fabric.
            ctx.state["ap_stop"] = (
                f"The AP's radio MAC {self.radio_mac} is registered on no "
                f"control plane.")
            return CheckResult(
                CheckStatus.FAIL,
                f"The AP's radio MAC {self.radio_mac} is registered on none "
                f"of the {len(no)} control plane(s) asked: "
                f"{', '.join(no)}.\n\n"
                f"No control plane can answer a map-request for it, so the "
                f"AP is not reachable through the fabric at all.", data=data)

        if no:
            return CheckResult(
                CheckStatus.WARN,
                f"The AP's radio MAC {self.radio_mac} is registered on "
                f"{', '.join(yes)} but not on {', '.join(no)}.\n\n"
                f"The fabric still resolves the AP through the control "
                f"plane(s) that hold it, so this is not an outage -- but a "
                f"control plane that holds no record cannot answer for the "
                f"AP if the others become unavailable. The LISP session "
                f"checks for {', '.join(no)} say why the registration is not "
                f"getting through.", data=data)

        return CheckResult(
            CheckStatus.OK,
            f"The AP's radio MAC {self.radio_mac} is registered on every "
            f"control plane asked: {', '.join(yes)}.", data=data)


class ApRadioMacRegistrationTrigger(Check):
    """Ask every resolved control plane for the radio MAC's registration.

    Queues one `ApRadioMacRegistration` per control plane, then the verdict
    that weighs them together.

    Runs after `ApWlcFabricControlPlane`, which resolves the control planes
    and their nodes, and BEFORE the LISP session trigger: a control plane
    missing the registration is what the session flow exists to explain, so
    the registration has to be read first.
    """

    def __init__(self, hostname, node_id):
        self.hostname = hostname
        self.target_node_id = node_id
        self.name = f"Radio MAC Registration — {hostname}"
        self.running_note = "Asking each control plane for the radio MAC."

    def run(self, ctx: RunContext) -> CheckResult:
        mac = (ctx.state.get("ap_wlc_radio_mac") or "").strip()
        if not mac:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's radio MAC is not known (see WLC AP "
                "State), and it is what the controller registers.")

        iid = ctx.state.get("ap_wlc_l2_vnid")
        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no INFRA_VN L2 instance was resolved on this "
                "controller, so there is no instance to ask about.")

        planes = ctx.state.get("ap_wlc_cp_planes") or []
        if not planes:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no control plane was resolved for this "
                "controller (see Fabric Control Plane).")

        # The edge the AP is attached to. Its Loopback0 is the RLOC the
        # fabric reaches the AP through, and so what the locator must be.
        edge_lo = (ctx.state.get("xtr_loopback") or "").strip() or None

        nodes = ctx.state.get("ap_wlc_cp_nodes") or {}
        queued = []
        for addr, host, mgmt in planes:
            node = nodes.get(addr) or nodes.get(host) or self.target_node_id
            queued.append(ApRadioMacRegistration(
                host, mgmt, mac, iid, ctx.state.get("catc_name"), node,
                edge_lo))
        queued.append(ApRadioMacRegistrationVerdict(
            mac, iid, self.target_node_id))

        return CheckResult(
            CheckStatus.OK,
            f"Asking {len(planes)} control plane"
            f"{'' if len(planes) == 1 else 's'} whether the AP's radio MAC "
            f"{mac} is registered in instance {iid}.",
            data={"queue_checks": queued})


# A WLC database entry that has only just appeared is not evidence of a stable
# AP: the entry is rebuilt each time the controller re-signals, so a short
# uptime here is how a flapping AP looks from the edge.
WLC_DB_FLAP_SECONDS = 180


def _uptime_seconds(text):
    """`Up time: 06:53:34` -> seconds, or None if it is not that shape.

    The device also prints forms like `1d02h` once the entry is older than a
    day. Those are far past any flap threshold, so they convert to a value
    above it rather than to None -- None means "could not tell", and an entry
    up for a day must never be read as unknown.
    """
    if not text:
        return None
    t = str(text).strip()
    m = re.match(r"^(\d+):(\d{2}):(\d{2})$", t)
    if m:
        h, mi, s = (int(g) for g in m.groups())
        return h * 3600 + mi * 60 + s
    m = re.match(r"^(\d+)([dwy])", t)
    if m:
        mult = {"d": 86400, "w": 604800, "y": 31536000}[m.group(2)]
        return int(m.group(1)) * mult
    return None


class ApFabricEdgeWlcDatabase(Check):
    """The AP's WLC database entry on the fabric edge itself.

    Everything else in this file asks a CONTROL PLANE what it holds for the
    radio MAC. This asks the edge what it was told to build. The controller
    signals the edge over its own LISP session, and the edge records the AP
    here -- so this entry is the edge's half of the registration, and the
    access tunnel is built from it.

    `Tunnel Update: Signalled` is the field that matters most: it is the
    edge saying it has been asked to bring the tunnel up. Anything else
    means the access-tunnel checks that follow are looking at a tunnel the
    edge was never told to build.
    """

    name = "AP WLC Database (Fabric Edge)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_wlc_l2_vnid")
        mac = (ctx.state.get("ap_wlc_radio_mac") or "").strip()

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's L2 LISP instance is unknown.")
        if not mac:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's radio MAC is unknown.")
        return self._evaluate(ctx, hostname, iid, mac)

    def _read(self, ctx, hostname, iid, mac):
        """The edge's WLC database entry, via the existing reader."""
        from routingmodules.lisp import LISPLocalDB
        # (eid, iid, device) -- the iid is normalised to int inside.
        db = LISPLocalDB(mac, iid, hostname)
        db.lispdbwlcentry(ctx.service)
        return db

    def _evaluate(self, ctx, hostname, iid, mac):
        try:
            db = self._read(ctx, hostname, iid, mac)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(
                e, f"show lisp instance-id {iid} ethernet database wlc {mac}")

        hw = (getattr(db, "hardware_address", None) or "").strip()
        data = {"l2_iid": iid, "radio_mac": mac, "edge": hostname}

        if not hw:
            return self._not_found(ctx, hostname, iid, mac, data)

        etype = (getattr(db, "etype", None) or "").strip()
        tunnel = (getattr(db, "tunnel_update", None) or "").strip()
        source_ms = (getattr(db, "source_ms", None) or "").strip()
        rloc = (getattr(db, "rloc", None) or "").strip()
        uptime = (getattr(db, "up_time", None) or "").strip()
        data.update({"type": etype, "tunnel_update": tunnel,
                     "source_ms": source_ms, "rloc": rloc, "up_time": uptime})
        ctx.state["ap_edge_wlc_db"] = dict(data)
        if source_ms:
            ctx.state["ap_edge_wlc_source_ms"] = source_ms
        return self._grade(ctx, hostname, iid, mac, db, data)

    def _not_found(self, ctx, hostname, iid, mac, data):
        """No entry at all: the edge was never told about this AP.

        The controller signals the edge over its LISP session, so an absent
        entry points at that session rather than at the edge. The Source MS
        would name which control plane to look at, but it is a field OF the
        entry -- absent here by definition -- so the AP's own control planes
        are flagged for the session flow instead.
        """
        data["found"] = False
        ctx.state["ap_edge_wlc_db_missing"] = True
        # Read by the LISP session trigger. Named separately from the
        # registration's own `ap_cp_reg_missing` so the two reasons for
        # walking the session flow stay distinguishable in the report.
        planes = ctx.state.get("ap_wlc_cp_planes") or []
        hosts = [h for h in (p.get("hostname") for p in planes) if h]
        if hosts:
            ctx.state["ap_edge_wlc_session_suspect"] = hosts

        return CheckResult(
            CheckStatus.WARN,
            f"{hostname} holds no WLC database entry for the AP's radio MAC "
            f"{mac} in instance {iid}. The controller signals this entry to "
            f"the edge over its LISP session, so the edge has never been "
            f"told about this AP -- there is nothing here for an access "
            f"tunnel to be built from."
            + (f" The LISP session between the edge and "
               f"{', '.join(hosts)} is checked next."
               if hosts else
               " The control planes to check the session against could not "
               "be resolved."),
            data=data)

    def _grade(self, ctx, hostname, iid, mac, db, data):
        etype = data["type"]
        tunnel = data["tunnel_update"]
        uptime = data["up_time"]
        secs = _uptime_seconds(uptime)
        data["up_time_seconds"] = secs

        lines = [
            f"• Hardware address: {mac}",
            f"• Type: {etype or '—'}",
            f"• Tunnel update: {tunnel or '—'}",
            f"• Source MS: {data['source_ms'] or '—'}",
            f"• RLOC: {data['rloc'] or '—'}",
            f"• Up time: {uptime or '—'}",
        ]

        findings = []

        # Not Signalled: the edge has the entry but was never asked to bring
        # the tunnel up. The access-tunnel checks still run -- they are what
        # show whether anything was built regardless -- but this is why.
        signalled = tunnel.lower() == "signalled"
        if not signalled:
            data["tunnel_signalled"] = False
            findings.append(
                f"  ⚠ Tunnel update is \"{tunnel or '—'}\", not "
                f"\"Signalled\". The edge holds the AP's entry but has not "
                f"been told to bring the access tunnel up. The access-tunnel "
                f"checks that follow will show what, if anything, was built.")
        else:
            data["tunnel_signalled"] = True

        # A freshly rebuilt entry. The entry is re-created each time the
        # controller re-signals, so a short uptime on a long-running fabric
        # means it has just been rebuilt -- the signature of an AP that is
        # flapping rather than one that has simply only just joined.
        if secs is not None and secs < WLC_DB_FLAP_SECONDS:
            data["possible_flap"] = True
            findings.append(
                f"  ⚠ This entry is only {uptime} old. It is rebuilt each "
                f"time the controller re-signals the AP, so unless the AP "
                f"has just joined, it is being torn down and rebuilt -- a "
                f"possible flap.")

        if etype and etype.lower() != "ap":
            findings.append(
                f"  ⚠ Type is \"{etype}\", not \"AP\". This entry is not the "
                f"access point's.")

        body = "\n".join(lines)
        if findings:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} holds the AP's WLC database entry, with "
                f"findings:\n\n" + body + "\n\n" + "\n".join(findings),
                data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{hostname} holds the AP's WLC database entry and has been "
            f"signalled to bring the access tunnel up:\n\n" + body,
            data=data)


class ApAccessTunnelStatistics(Check):
    """The edge's access-tunnel counters, and this AP's tunnel among them.

    `show access-tunnel statistics` answers two different questions at once:
    whether the platform has room to build tunnels at all, and what this
    particular AP's tunnel looks like. Both matter here -- an edge at its
    tunnel ceiling cannot onboard another AP no matter how healthy the
    registration is, and that limit is invisible from every other check.
    """

    name = "AP Access Tunnel Statistics"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        mac = (ctx.state.get("ap_wlc_radio_mac") or "").strip().lower()

        try:
            from radkit_cli import get_any_single_output
            from wirelessmodules.accesstunnels import (
                parse_access_tunnel_statistics)
            raw = get_any_single_output(
                hostname, "show access-tunnel statistics", ctx.service)
            stats = parse_access_tunnel_statistics(raw)
            # The same tunnel from the other command. `statistics` does not
            # carry the RLOC it is sourced from or its ports, and `summary`
            # does not carry the `*`, so neither answers on its own.
            # Genie parses the summary (ShowAccessTunnelSummary); it has no
            # parser for `statistics`, which is why that one is parsed by
            # hand above.
            from radkit_cli import get_single_output_genie
            from checks.ap_onboarding import _as_mapping
            summary = _as_mapping(get_single_output_genie(
                hostname, "show access-tunnel summary", ctx.service))
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, "show access-tunnel statistics")

        active, mx = stats.get("active"), stats.get("max")
        created, deleted = stats.get("created"), stats.get("deleted")
        data = {"edge": hostname, "active": active, "max": mx,
                "created": created, "deleted": deleted,
                "tunnels": stats.get("tunnels") or [],
                "summary": summary}

        if active is None:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} did not report its access-tunnel counters, so "
                f"neither the platform's tunnel capacity nor this AP's "
                f"tunnel could be read.", data=data)

        # Grouped under headers rather than printed as one flat list: the
        # counters describe the platform, the block below describes this
        # AP's tunnel, and reading them as a single run of bullets made the
        # two look like one set of facts about the same thing.
        lines = [
            "Platform counters",
            f"    Active tunnels     {active}"
            + (f" of {mx}" if mx is not None else ""),
            f"    Created            {created if created is not None else '—'}",
            f"    Deleted            {deleted if deleted is not None else '—'}",
        ]
        return self._grade(ctx, hostname, mac, stats, data, lines)

    def _grade(self, ctx, hostname, mac, stats, data, lines):
        active, mx = data["active"], data["max"]
        findings = []

        # At the ceiling. FAIL rather than WARN: this is not a fabric fault
        # to report and move past -- the platform cannot build another
        # tunnel, so every access-tunnel check after it is answering a
        # question the edge has no capacity to satisfy.
        at_capacity = mx is not None and active >= mx
        data["at_capacity"] = at_capacity

        # The summary's own tunnel count, recorded for the PD pass to compare
        # against what the hardware has programmed. Taken from `summary`
        # rather than from the statistics counter on purpose: these are two
        # independent views and the PD comparison is only meaningful against
        # the one that enumerates the interfaces.
        sum_count = (data.get("summary") or {}).get("data_tunnels_count")
        if sum_count is not None:
            from checks.ap_onboarding import record_pd_object
            data["summary_tunnel_count"] = sum_count
            record_pd_object(ctx, "interface_list",
                             radkit_hostname=hostname,
                             interface_type="access-tunnel",
                             count=sum_count)

        # This AP's own tunnel, by radio MAC.
        mine = None
        for t in data["tunnels"]:
            if mac and t.get("mac", "").lower() == mac:
                mine = t
                break
        data["ap_tunnel"] = mine

        if mine:
            ctx.state["ap_access_tunnel"] = dict(mine)
            lines.append("")
            lines.append("This AP's tunnel")
            lines.append(f"    Interface          {mine['name']}"
                         f"  (ifid {mine['ifid']})")
            lines.append(f"    AP IP (dest)       {mine['ap_ip']}")
            lines.append(f"    Uptime             {mine['uptime']}"
                         + (f" ({mine['times']})" if mine.get("times") else ""))
            # The same tunnel as the summary sees it. Genie keys the
            # summary by tunnel name, which is the only field both commands
            # share -- statistics has no RLOC, summary has no MAC.
            srow = ((data.get("summary") or {}).get("name") or {}).get(
                mine["name"]) or {}
            if srow:
                data["summary_tunnel"] = dict(srow)
                lines.append(
                    f"    RLOC (source)      {srow.get('rloc_ip') or '—'}")
                lines.append(
                    f"    Destination port   {srow.get('dst_port') or '—'}")
                sum_ip = (srow.get("ap_ip") or "").strip()
                if sum_ip and sum_ip != mine["ap_ip"]:
                    findings.append(
                        f"  ⚠ The two commands disagree on this tunnel's AP "
                        f"address: statistics says {mine['ap_ip']}, summary "
                        f"says {sum_ip}.")
                edge_lo = (ctx.state.get("xtr_loopback") or "").strip()
                if edge_lo and srow.get("rloc_ip") \
                        and srow["rloc_ip"].strip() != edge_lo:
                    findings.append(
                        f"  ⚠ The tunnel is sourced from "
                        f"{srow['rloc_ip']}, not the edge's Loopback0 "
                        f"{edge_lo}.")
            else:
                findings.append(
                    f"  ⚠ {hostname} lists tunnel {mine['name']} in its "
                    f"access-tunnel statistics but not in its summary, so "
                    f"the two views of the tunnel disagree.")

            # The access tunnel is an interface, so it is PD-eligible the
            # same way a physical port is: the PD pass will check that IOS's
            # view of it matches the hardware's.
            from checks.ap_onboarding import record_pd_object
            record_pd_object(ctx, "IFM", radkit_hostname=hostname,
                             interface=mine["name"])

            # The tunnel is live -- the device only lists it under "Active
            # Access Tunnels" while it is up -- so draw it. It runs alongside
            # the wired Edge-to-AP link rather than replacing it: the link is
            # the cable, this is the VXLAN overlay riding on it.
            data["add_edges"] = [{
                "source": "xtr", "target": "ap",
                "id_prefix": "access-tunnel",
                "label": f"{mine['name']} - VXLAN",
                "access_tunnel": True,
            }]

            if mine.get("ip_changed"):
                # The device's own legend: "* denotes AP IP and MAC change".
                # Reported, never graded. The flag is a historical marker --
                # the AP changed address at some point in this switch's
                # uptime -- and says nothing about whether the tunnel is
                # healthy now. The tunnel in front of it is up, so a past
                # address change is context, not a fault.
                lines.append("    AP IP/MAC changed  yes, since boot (`*`)")
        else:
            lines.append("")
            lines.append(f"• No active access tunnel for radio MAC "
                         f"{mac or '—'}.")
            # Nothing matched on MAC, but the AP may still be present in
            # either command under its address, or in statistics under a
            # tunnel the summary does not list. Those rows are the evidence
            # for WHY the tunnel is absent -- a row with the right IP and the
            # wrong MAC is a different fault from no row at all -- so they
            # are printed rather than being reduced to "not found".
            ap_ip = (ctx.state.get("ap_ip_metadata")
                     or ctx.state.get("ap_ip") or "").strip()
            sum_names = set(((data.get("summary") or {}).get("name")
                             or {}).keys())
            traces = []
            for t in data["tunnels"]:
                hit = []
                if mac and t.get("mac", "").lower() == mac:
                    hit.append("radio MAC")
                if ap_ip and t.get("ap_ip") == ap_ip:
                    hit.append("AP address")
                if t["name"] not in sum_names:
                    hit.append("absent from summary")
                if hit:
                    traces.append(
                        f"      {t['name']} ifid {t['ifid']} "
                        f"{t['ap_ip']} {t['mac']} up {t['uptime']} "
                        f"[{', '.join(hit)}]")
            for name, row in (((data.get("summary") or {}).get("name")
                               or {}).items()):
                if ap_ip and (row.get("ap_ip") or "").strip() == ap_ip:
                    traces.append(
                        f"      {name} (summary only) rloc "
                        f"{row.get('rloc_ip') or '—'} ap {ap_ip}")
            if traces:
                data["partial_tunnel_matches"] = traces
                findings.append(
                    f"  ⚠ No access tunnel for this AP, but {hostname} does "
                    f"carry rows that reference it:\n" + "\n".join(traces))

        if at_capacity:
            return CheckResult(
                CheckStatus.FAIL,
                f"{hostname} is at its access-tunnel ceiling: {active} active "
                f"of a maximum {mx}. No further access tunnel can be built on "
                f"this switch, so an AP without one cannot onboard here "
                f"regardless of its registration.\n\n" + "\n".join(lines),
                data=data)

        body = "\n".join(lines)
        if findings:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname}'s access-tunnel statistics, with "
                f"findings:\n\n" + body + "\n\n" + "\n".join(findings),
                data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{hostname}'s access-tunnel statistics:\n\n" + body, data=data)


class ApL2LispStatistics(Check):
    """The edge's L2LISP counters, read for the AP rather than for a client.

    `WirelessL2LispStats` already reads this command, and this check reuses
    the same module and parser. What differs is which half of the output
    matters. That check looks only at the error counters, and is gated on the
    wireless CLIENT flow (`is_few` and `wireless_sourcextr`), so it never runs
    in an AP chain.

    Here the control-message counters are the point: `Add AP` is the WLC
    notification arriving at the edge, and `Received` above `Succeeded` means
    the edge was told about an AP and could not act on it -- the one counter
    that distinguishes "the controller never told the edge" from "the edge was
    told and failed".
    """

    name = "AP L2LISP Statistics"
    target_node_id = "xtr"

    # WirelessL2LispStats excludes "update client rbm failed" and "idb not
    # found" as noisy. Only the first is carried over here. Its `idb not
    # found` exclusion also swallows `Update AP: idb NOT found` and
    # `Delete AP: idb NOT found`, and on an AP operation a missing idb is
    # exactly the failure this flow is looking for -- the access tunnel's
    # interface descriptor block is what the AP's tunnel is built on.
    _IGNORE = ("update client rbm failed",)

    #: The AP's own counters, graded separately from the client ones. Every
    #: counter in this command is reported, but in an AP chain a non-zero
    #: client counter is context while a non-zero AP counter is the finding.
    _AP_MARKER = "ap"

    def run(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        try:
            from routingmodules.lisp import L2LISPStatistics
            stats = L2LISPStatistics(hostname)
            stats.l2lispstatistics(ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, "show l2lisp statistics")

        parsed = getattr(stats, "l2lispstats", {}) or {}
        return self._grade(ctx, hostname, parsed)

    def _grade(self, ctx, hostname, parsed):
        msgs = parsed.get("control_messages") or {}
        errors = parsed.get("errors") or {}

        add_ap = msgs.get("Add AP") or {}
        recv = add_ap.get("received")
        ok = add_ap.get("succeeded")
        data = {"edge": hostname, "add_ap_received": recv,
                "add_ap_succeeded": ok, "control_messages": msgs}

        lines = []
        for label in ("Add AP", "Delete AP"):
            m = msgs.get(label) or {}
            if m:
                lines.append(f"• {label}: {m.get('received')} received, "
                             f"{m.get('succeeded')} succeeded")

        findings = []

        # The edge was notified and could not act on it. This is the gap the
        # check exists for: zero received means the controller never told the
        # edge, which is a different fault entirely and is reported below.
        if recv is not None and ok is not None and recv != ok:
            data["add_ap_shortfall"] = recv - ok
            findings.append(
                f"  ⚠ Add AP: {recv} received but {ok} succeeded. The edge "
                f"was told about an AP and did not complete the operation.")
        # Same rule for the teardown half. A Delete AP that was received and
        # did not succeed leaves state behind on the edge -- a stale access
        # tunnel or hash entry for an AP the controller has already let go.
        del_ap = msgs.get("Delete AP") or {}
        drecv, dok = del_ap.get("received"), del_ap.get("succeeded")
        data["delete_ap_received"] = drecv
        data["delete_ap_succeeded"] = dok
        if drecv is not None and dok is not None and drecv != dok:
            data["delete_ap_mismatch"] = True
            findings.append(
                f"  ⚠ Delete AP: {drecv} received but {dok} succeeded. The "
                f"edge was told to remove an AP and did not complete it, so "
                f"state for that AP may still be present here.")

        if recv == 0:
            data["add_ap_never_notified"] = True
            findings.append(
                f"  ℹ {hostname} has received no Add AP notification at all "
                f"since its counters were last cleared. If this AP is "
                f"expected to be onboarded here, the controller has not told "
                f"the edge about it.")

        # The switch's own mode flag for the metadata payload, carried in
        # the same output as the counters.
        toggles = parsed.get("toggles") or {}
        use_meta = toggles.get("Use AP info in WLC metadata")
        data["use_ap_info_in_wlc_metadata"] = use_meta
        # Reported, never graded. The user settled this: it is a mode flag,
        # not a fault, so neither value is a finding on its own.
        if use_meta is not None:
            lines.append(f"• Use AP info in WLC metadata: {use_meta}")

        nonzero = {k: v for k, v in errors.items()
                   if v and not any(s in k.lower() for s in self._IGNORE)}
        # Split: in an AP chain a non-zero AP counter is the finding, while a
        # non-zero client counter is context. Reported either way, but not as
        # the same thing.
        # Split on word boundaries, not substring: a bare `in` would also
        # pick up "capwap" and "mapping". The device writes the word with a
        # colon attached ("Add AP: idb NOT found"), so the colon is stripped
        # before comparing rather than being part of the token.
        ap_errs = {k: v for k, v in nonzero.items()
                   if any(w.strip(":").lower() == self._AP_MARKER
                          for w in k.split())}
        other_errs = {k: v for k, v in nonzero.items() if k not in ap_errs}
        data["errors"] = nonzero
        data["ap_errors"] = ap_errs
        if ap_errs:
            findings.append(
                "  ⚠ Non-zero AP error counters:\n"
                + "\n".join(f"      {k}: {v}" for k, v in ap_errs.items()))
        if other_errs:
            findings.append(
                "  ℹ Non-zero L2LISP counters not specific to AP handling:\n"
                + "\n".join(f"      {k}: {v}" for k, v in other_errs.items()))

        body = "\n".join(lines) if lines else "(no control-message counters)"
        if findings:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname}'s L2LISP counters, with findings:\n\n"
                + body + "\n\n" + "\n".join(findings), data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{hostname} accepted every WLC notification it received and its "
            f"L2LISP error counters are clean:\n\n" + body, data=data)


class ApAccessTunnelIdb(Check):
    """The AP's access tunnel as the interface descriptor block table sees it.

    `show access-tunnel statistics` says the tunnel exists; this says what IOS
    has actually built for it. An interface has two IDB rows -- a HWIDB and a
    SWIDB -- and it is the SWIDB that matters here: on Edge2 the HWIDB row
    carries `MFIB_IPv4(15)` alone while the SWIDB row carries the feature list
    the tunnel actually runs on, `ACCESS TUNNEL SB(52)` among them.

    The two rows have DIFFERENT indices (65 and 77 for AccessTunnel0), and the
    `ifid` the tunnel check already read is the SWIDB's: `0x0000004D` is 77.
    So the lookup is by that ifid where it is available, falling back to the
    interface name.
    """

    name = "AP Access Tunnel IDB"
    target_node_id = "xtr"

    #: The subblock that makes an access tunnel an access tunnel. Its absence
    #: on a tunnel IOS has otherwise built is the finding this check exists
    #: for -- the interface is there but the feature is not attached to it.
    _REQUIRED_SB = "ACCESS TUNNEL SB"

    def run(self, ctx: RunContext) -> CheckResult:
        tunnel = ctx.state.get("ap_access_tunnel") or {}
        if not tunnel:
            return CheckResult(
                CheckStatus.SKIP,
                "No access tunnel was found for this AP, so there is no "
                "interface to look up in the IDB table.")

        hostname = ctx.state.get("xtr_hostname")
        try:
            from radkit_cli import get_any_single_output
            raw = get_any_single_output(hostname, "show idb all", ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, "show idb all")

        from switchingmodules.idb import parse_show_idb_all
        parsed = parse_show_idb_all(raw)
        return self._grade(ctx, hostname, tunnel, parsed)

    def _grade(self, ctx, hostname, tunnel, parsed):
        from switchingmodules.idb import _same_if
        name = tunnel.get("name")
        # `0x0000004D` -> 77. The tunnel check carries the ifid as the device
        # printed it; the IDB table prints the same number in decimal.
        want_idx = None
        ifid = tunnel.get("ifid")
        if ifid:
            try:
                want_idx = int(str(ifid), 16)
            except (TypeError, ValueError):
                want_idx = None

        rows = parsed.get("interfaces") or []
        sw = next((r for r in rows
                   if r["type"] == "S" and want_idx is not None
                   and r["idx"] == want_idx), None)
        matched_on = "ifid"
        if sw is None:
            # The ifid was unreadable, or the table disagrees with it. Fall
            # back to the name, and say which way the row was found -- a name
            # match where the ifid did not line up is itself worth seeing.
            sw = next((r for r in rows
                       if r["type"] == "S" and _same_if(r["name"], name)), None)
            matched_on = "name"
        # The HWIDB is joined on the SWIDB's SIdx, not on the name. `name`
        # comes from `show access-tunnel statistics`, which abbreviates it
        # ("Ac0"), while the IDB table spells it out ("AccessTunnel0"), so a
        # name match never fires. SIdx is the hardware block's own index and
        # is what ties a software block to its hardware one: both rows for
        # the access tunnel carry 54 even though their if_numbers differ
        # (H 65, S 77). Without a SWIDB there is nothing to join on, so fall
        # back to the name -- loosely -- rather than reporting no HWIDB.
        if sw is not None:
            hw = next((r for r in rows
                       if r["type"] == "H" and r["sidx"] == sw["sidx"]), None)
        else:
            hw = next((r for r in rows
                       if r["type"] == "H" and _same_if(r["name"], name)), None)

        data = {"edge": hostname, "interface": name, "ifid": ifid,
                "expected_idx": want_idx, "matched_on": matched_on,
                "swidb": dict(sw) if sw else None,
                "hwidb": dict(hw) if hw else None,
                "sw_idb_max": parsed.get("sw_idb_max"),
                "sw_idb_in_use": parsed.get("sw_idb_in_use")}

        lines = [f"• Interface: {name}"]
        findings = []

        if sw is None:
            findings.append(
                f"  ⚠ {hostname} lists {name} as an active access tunnel but "
                f"has no software IDB for it. The tunnel is in the "
                f"access-tunnel table without an interface structure behind "
                f"it.")
        else:
            lines.append(f"• SWIDB: if_number {sw['idx']} (SIdx {sw['sidx']}),"
                         f" state {sw['state']}")
            if matched_on == "name" and want_idx is not None:
                findings.append(
                    f"  ⚠ The access-tunnel table gives ifid {ifid} "
                    f"({want_idx}), but the software IDB for {name} is "
                    f"if_number {sw['idx']}. The two disagree about which "
                    f"interface this tunnel is.")
            if sw["state"] != "up":
                findings.append(
                    f"  ⚠ The software IDB for {name} is {sw['state']}, not "
                    f"up.")
            if sw["hw_deleted"]:
                findings.append(
                    f"  ⚠ {name} is flagged deleted in the IDB table while "
                    f"still being listed as an active access tunnel.")

            subs = sw.get("subblocks") or ""
            data["subblocks"] = subs
            if subs:
                lines.append("• SWIDB features: " + subs)
            if self._REQUIRED_SB not in subs:
                findings.append(
                    f"  ⚠ The software IDB for {name} does not carry "
                    f"`{self._REQUIRED_SB}`. The interface exists but the "
                    f"access-tunnel feature is not attached to it.")

        if hw is not None:
            lines.append(
                f"• HWIDB: hw_if_index {hw['idx']}, state {hw['state']}"
                + (f" (old {hw['old_state']}, shadow {hw['shadow_state']})"
                   if hw["old_state"] else ""))
            if hw["state"] != "up":
                findings.append(
                    f"  ⚠ The hardware IDB for {name} is {hw['state']}, not "
                    f"up.")
        else:
            findings.append(
                f"  ⚠ {hostname} has no hardware IDB for {name}.")

        # The platform ceiling, in the same spirit as the access-tunnel
        # maximum: a switch out of software IDBs cannot build another
        # interface, so a tunnel that never appeared may have had nowhere to
        # go. Reported whenever it is close, not only when this AP is hurt.
        mx, used = parsed.get("sw_idb_max"), parsed.get("sw_idb_in_use")
        if mx and used is not None:
            lines.append(f"• Software IDBs in use: {used} of {mx}")
            if used >= mx:
                findings.append(
                    f"  ⚠ {hostname} is at its software IDB ceiling "
                    f"({used} of {mx}). It cannot build another interface.")

        body = "\n".join(lines)
        if findings:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname}'s IDB entry for {name}, with findings:\n\n"
                f"{body}\n\n" + "\n".join(findings), data)
        return CheckResult(
            CheckStatus.OK,
            f"{hostname} has both IDBs for {name}, up, with the access-tunnel "
            f"subblock attached.\n\n{body}", data)


class ApEdgeCollection(Check):
    """Context the edge carries that is read but deliberately not graded.

    Two commands, collected for the report and for whoever reads it after the
    run, neither of them a verification:

    `show switch` -- the stack. An access tunnel is built on one specific
    member, so which members exist and what state they are in is worth having
    in the record even though nothing here judges it.

    `show logging` -- the AP-relevant slice of the log buffer. The user
    settled that this is collection only: flapping is a time-series question
    and belongs to the dedicated flapping module, not to a point-in-time
    check that would have to guess a threshold from one buffer.

    This check therefore never WARNs on content. It reports OK with what it
    found, or FAIL only if the device could not be read at all.
    """

    name = "AP Edge Context"
    target_node_id = "xtr"

    #: Log lines worth keeping out of a buffer that is mostly SSH logins.
    #: Matched case-insensitively against the whole line.
    _LOG_PATTERNS = (
        "accesstunnel", "capwap", "lisp", "%dot1x", "%authmgr", "%mab",
        "%sisf", "%dhcp", "%ilpower", "%poe",
    )

    #: How many matching lines to keep. The buffer runs to hundreds of lines;
    #: the report wants the recent ones, not all of them.
    _LOG_KEEP = 40

    def run(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        from radkit_cli import get_any_single_output, get_single_output_genie
        from checks.ap_onboarding import _as_mapping

        data = {"edge": hostname}
        lines = []

        # The stack. Genie parses this one (ShowSwitch, which lives in
        # show_platform.py rather than show_switch.py).
        try:
            sw = _as_mapping(get_single_output_genie(
                hostname, "show switch", ctx.service)) or {}
        except BaseException:
            # Collection only -- a box that does not answer this is not a
            # finding, and must not stop the run.
            sw = {}
        members = ((sw.get("switch") or {}).get("stack") or {})
        if members:
            data["stack"] = {k: dict(v) for k, v in members.items()}
            data["stack_mac"] = (sw.get("switch") or {}).get("mac_address")
            lines.append(f"• Stack members: {len(members)}")
            for num in sorted(members, key=lambda n: str(n)):
                m = members[num]
                lines.append(
                    f"    {num}: {m.get('role')}, {m.get('state')}, "
                    f"priority {m.get('priority')}, H/W {m.get('hw_ver')}")
            if data.get("stack_mac"):
                lines.append(f"• Stack MAC: {data['stack_mac']}")
        else:
            lines.append("• Stack: not reported by this device.")

        # The log buffer, filtered to what bears on an AP.
        try:
            raw = get_any_single_output(hostname, "show logging", ctx.service)
        except BaseException:
            raw = ""
        hits = []
        for line in str(raw or "").splitlines():
            low = line.lower()
            if any(p in low for p in self._LOG_PATTERNS):
                hits.append(line.strip())
        data["log_matches"] = len(hits)
        kept = hits[-self._LOG_KEEP:]
        data["log"] = kept
        lines.append("")
        if hits:
            lines.append(
                f"• Log: {len(hits)} AP-relevant line"
                f"{'' if len(hits) == 1 else 's'} in the buffer"
                + (f", showing the last {len(kept)}" if len(kept) < len(hits)
                   else ""))
            lines.extend(f"    {h}" for h in kept)
        else:
            lines.append("• Log: nothing AP-relevant in the buffer.")

        return CheckResult(
            CheckStatus.OK,
            f"Context collected from {hostname}. Nothing here is graded.\n\n"
            + "\n".join(lines), data)
