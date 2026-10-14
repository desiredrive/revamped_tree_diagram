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


def decode_wlc_metadata(hex_text):
    """The AP address, L3 VNID and SGT out of the `WLC data length` payload.

    The payload is TLV-structured. The outer entry wraps inner ones, and the
    first inner value carries the three fields in fixed positions:

        AC 13 05 0A   00 00 10 01   00 02 00 06
        AP address    L3 VNID       (unused here)

    followed, after that value, by the SGT as a four-byte field.

    NOT `extract_ip_and_sgt_fixed_positions`, which reads the SGT as two
    bytes at offset 20 -- the high half of that four-byte field, so it
    returns 0 for every SGT below 65536. Its IP offset is right and agrees
    with this. Left alone because the CLI wireless flow depends on it; see
    the note in the module this is read from.

    Returns a dict, with None for anything the payload is too short to hold.
    """
    out = {"ap_ip": None, "l3_vnid": None, "sgt": None, "all_zero": None}
    tok = re.findall(r"\b[0-9A-Fa-f]{2}\b", hex_text or "")
    if not tok:
        return out

    # "Must not be all zeros": a payload the controller sent with nothing in
    # it, which is a different fault from one it never sent.
    out["all_zero"] = all(t == "00" for t in tok)

    def num(lo, hi):
        return int("".join(tok[lo:hi]), 16) if len(tok) >= hi else None

    # Past the outer TLV header (4 bytes) and the inner one (4 more).
    if len(tok) >= 20:
        try:
            out["ap_ip"] = ".".join(str(int(t, 16)) for t in tok[8:12])
        except ValueError:
            out["ap_ip"] = None
    out["l3_vnid"] = num(12, 16)
    out["sgt"] = num(20, 24)
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
        meta = decode_wlc_metadata(rec.get("wlc_data_hex"))

        lines = [
            f"• EID {rec.get('eid_prefix') or self.radio_mac} in instance "
            f"{self.iid}, state {rec.get('state') or '—'}",
            f"• ETR: {', '.join(etrs) if etrs else '—'}",
            f"• Locators up: {', '.join(up) if up else 'none'}",
        ]
        if meta.get("ap_ip"):
            lines.append(
                f"• WLC metadata: AP {meta['ap_ip']}, SGT "
                f"{meta['sgt'] if meta['sgt'] is not None else '—'}, L3 VNID "
                f"{meta['l3_vnid'] if meta['l3_vnid'] is not None else '—'}")

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

        bit = (rec.get("wlc_ap_bit") or "").strip().lower()
        if bit != "set":
            faults.append(
                f"  ⚠ The WLC AP bit is "
                f"{rec.get('wlc_ap_bit') or 'absent'}, not Set. The control "
                f"plane does not see this registration as an AP's, so it is "
                f"not treated as a fabric AP.")

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
                "so the WLC metadata (AP address, SGT and L3 VNID) could not "
                "be read and was not checked.")
        else:
            faults.extend(self._grade_metadata(rec, meta))
        return faults

    def _grade_metadata(self, rec, meta):
        faults = []
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
