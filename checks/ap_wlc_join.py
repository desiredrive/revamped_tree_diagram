"""AP Onboarding step 5 — the AP's own state on its controller.

Everything before this step reasons about the path: the port the AP sits on,
the VLAN it onboards in, the ACLs and SGACLs between it and the controller,
the LISP registration that carries it. None of that answers the question the
operator actually has, which is whether the AP joined.

These checks read that answer off the controller itself, over NETCONF rather
than by scraping `show` output, for three reasons set out in
`netconf_client`: the lists are keyed so one AP is fetched directly, a single
`ap-join-stats` record carries all three join phases where the CLI needs three
commands, and there is no parser to go stale.

NETCONF is opt-in (see `netconf_client.credentials`). With nothing configured
every check here SKIPs with that reason rather than failing, so an operator
who has not set it up sees the chain behave as it did before.

Ordering inside the step follows the join sequence itself:

    ApWlcNetconfGate      can we talk to a controller at all
    ApWlcApRegistration   is the AP joined, and to which controller
    ApWlcApJoinPhases     if not -- or not cleanly -- which phase broke
    ApWlcApTags           the tags it resolved, which decide its config
    ApWlcApJoinHistory    has it been stable, or is it flapping
"""

from checks.ap_onboarding import _ApCheck
from checks.base import CheckResult, CheckStatus, RunContext


def _wlcs(ctx) -> list:
    """The controllers step 2 discovered, as (display name, mgmt ip) pairs."""
    out = []
    for entry in (ctx.state.get("ap_wlc_candidates") or []):
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            out.append((entry[0], entry[1]))
    return out


def _skip_no_netconf() -> CheckResult:
    """The one reason every check here shares, phrased once.

    Not a failure: NETCONF is an alternative to the CLI path, not a
    requirement, and an operator who has not configured it has not done
    anything wrong.
    """
    return CheckResult(
        CheckStatus.SKIP,
        "Skipped — NETCONF is not configured. Set NETCONF_USERNAME and "
        "NETCONF_PASSWORD (and NETCONF_PORT if the controllers do not "
        "listen on 830) to read the AP's state from its controller.",
    )


class ApWlcNetconfGate(_ApCheck):
    """Open a NETCONF session to each controller, and resolve the AP's radio MAC.

    Runs first so the rest of the step has one place to fail. Two things are
    established here:

    The session itself -- opening it costs an SSH handshake and a capability
    exchange, and the checks after this issue a dozen gets between them, so it
    is opened once per controller and cached on the run.

    The AP's radio MAC -- the chain knows the AP by its Ethernet MAC, because
    that is what the edge switch sees on the wire, while almost every list on
    the controller is keyed on the radio MAC. The controller itself maps one
    to the other, and which controller answers that lookup is the first real
    evidence of where the AP is joined.
    """

    name = "WLC NETCONF Session"
    target_node_id = "xtr"
    running_note = "Opening NETCONF to the wireless controllers…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import (
            NetconfError, credentials, dotted_mac, radio_mac_for_ethernet,
            session_for_wlc,
        )

        if not credentials():
            return _skip_no_netconf()

        eth_mac = (ctx.payload.get("mac") or "").strip()
        if not eth_mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — no AP MAC was supplied.")

        wlcs = _wlcs(ctx)
        if not wlcs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no wireless controller was discovered (see WLC "
                "Discovery).")

        reachable, errors, found_on = [], [], []
        radio = ""
        for label, mgmt_ip in wlcs:
            session = session_for_wlc(mgmt_ip)
            if session is None:
                continue
            try:
                mac = radio_mac_for_ethernet(session, eth_mac)
            except NetconfError as e:
                errors.append((label, mgmt_ip, str(e)))
                continue
            reachable.append((label, mgmt_ip))
            if mac:
                found_on.append((label, mgmt_ip))
                radio = radio or mac

        if not reachable:
            detail = "\n".join(f"  • {l} ({ip}) — {e}" for l, ip, e in errors)
            # WARN, deliberately, even though this step can do nothing more.
            #
            # A FAIL from an _ApCheck sets `ap_stop`, which skips every check
            # after it -- and this step runs early, before all the edge-side
            # validations. Failing here because a controller does not answer
            # NETCONF would discard the ACL, SGACL, VACL and LISP findings the
            # rest of the chain produces over RADKit, none of which depend on
            # NETCONF at all. The step marks itself unavailable through its
            # own key and the four checks below SKIP on it; the chain carries
            # on.
            ctx.state["ap_netconf_stop"] = (
                "no controller answered over NETCONF")
            return CheckResult(
                CheckStatus.WARN,
                f"No controller answered over NETCONF, so the AP's state on "
                f"its controller could not be read. Every other check in this "
                f"run is unaffected.\n\n{detail}")

        ctx.state["ap_netconf_wlcs"] = reachable
        ctx.state["ap_radio_mac"] = radio
        ctx.state["ap_netconf_joined_on"] = found_on

        lines = [f"NETCONF session open to {len(reachable)} of "
                 f"{len(wlcs)} controller(s)."]
        if errors:
            lines.append("")
            lines.append("  Not reachable")
            lines += [f"    • {l} ({ip}) — {e}" for l, ip, e in errors]
        lines.append("")
        if radio:
            where = ", ".join(f"{l} ({ip})" for l, ip in found_on)
            lines.append(
                f"  AP {dotted_mac(eth_mac)} is known to {where} as radio MAC "
                f"{dotted_mac(radio)}.")
        else:
            lines.append(
                f"  AP {dotted_mac(eth_mac)} is not known to any controller "
                f"reached — no radio MAC is mapped to its Ethernet MAC.")

        # Not knowing the AP is a finding, but the checks after this one say
        # what it means with far more evidence. WARN here and let them.
        status = CheckStatus.OK if radio else CheckStatus.WARN
        return CheckResult(status, "\n".join(lines),
                           data={"radio_mac": radio,
                                 "reachable": len(reachable)})


#: `ap-operation-state` values that mean the AP is serving. Anything else is
#: reported verbatim rather than mapped, so a state this list has not seen
#: reaches the operator intact instead of being flattened to "not registered".
_REGISTERED = {"registered"}


class ApWlcApRegistration(_ApCheck):
    """Is the AP registered, and with what identity?

    The question the whole chain exists to answer. One keyed read of
    `capwap-data` carries what `show ap summary`, `show ap uptime` and the
    tag half of `show ap config general` print between them: name, address,
    model, serial, software, admin and operational state, mode, fabric flag,
    country and the time it joined.

    Graded on the operational state. A missing record is the loudest possible
    answer -- the controller has no CAPWAP state for this AP at all -- and is
    a fabric fault rather than a tool fault, so it is a WARN that lets the
    phase check below run and say which phase it died in.
    """

    name = "AP Registration on the WLC"
    target_node_id = "xtr"
    running_note = "Reading the AP's CAPWAP state from the controller…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import (
            NetconfError, ap_capwap_data, credentials, dig, dotted_mac,
            session_for_wlc,
        )

        if not credentials():
            return _skip_no_netconf()
        stop = ctx.state.get("ap_netconf_stop")
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}.")

        radio = ctx.state.get("ap_radio_mac")
        wlcs = ctx.state.get("ap_netconf_wlcs") or []
        if not wlcs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no controller was reached (see WLC NETCONF "
                "Session).")
        if not radio:
            return CheckResult(
                CheckStatus.WARN,
                "The AP's Ethernet MAC maps to no radio MAC on any "
                "controller reached, so it has no CAPWAP record to read. "
                "The join-phase check below says how far it got.")

        records, errors = [], []
        for label, mgmt_ip in wlcs:
            session = session_for_wlc(mgmt_ip)
            if session is None:
                continue
            try:
                record = ap_capwap_data(session, radio)
            except NetconfError as e:
                errors.append((label, mgmt_ip, str(e)))
                continue
            if record:
                records.append((label, mgmt_ip, record))

        if not records:
            detail = ""
            if errors:
                detail = "\n\n  Not read\n" + "\n".join(
                    f"    • {l} ({ip}) — {e}" for l, ip, e in errors)
            return CheckResult(
                CheckStatus.WARN,
                f"No controller reached holds a CAPWAP record for radio MAC "
                f"{dotted_mac(radio)}. The AP is not joined to any of "
                f"them.{detail}")

        label, mgmt_ip, rec = records[0]
        state = dig(rec, "ap-state", "ap-operation-state", default="") or ""
        admin = dig(rec, "ap-state", "ap-admin-state", default="") or ""
        name = dig(rec, "name", default="") or "(unnamed)"
        ap_ip = dig(rec, "ip-addr", default="") or ""

        ctx.state["ap_wlc_name"] = name
        ctx.state["ap_wlc_record"] = rec
        ctx.state["ap_wlc_controller"] = (label, mgmt_ip)

        lines = [f"AP {name} is {state or 'in an unreported state'} on "
                 f"{label} ({mgmt_ip})."]
        lines.append("")
        lines.append(f"  Address         {ap_ip}")
        lines.append(f"  Ethernet MAC    "
                     f"{dotted_mac(dig(rec, 'device-detail', 'static-info', 'board-data', 'wtp-enet-mac', default=''))}")
        lines.append(f"  Radio MAC       {dotted_mac(radio)}")
        lines.append(f"  Model           "
                     f"{dig(rec, 'device-detail', 'static-info', 'ap-models', 'model', default='—')}")
        lines.append(f"  Serial          "
                     f"{dig(rec, 'device-detail', 'static-info', 'board-data', 'wtp-serial-num', default='—')}")
        lines.append(f"  Software        "
                     f"{dig(rec, 'device-detail', 'wtp-version', 'sw-version', default='—')}")
        lines.append(f"  Admin state     {admin or '—'}")
        lines.append(f"  Mode            "
                     f"{dig(rec, 'ap-mode-data', 'wtp-mode', default='—')}")
        lines.append(f"  Fabric AP       "
                     f"{dig(rec, 'ap-mode-data', 'ap-fabric-data', 'is-fabric-ap', default='—')}")
        lines.append(f"  Country         "
                     f"{(dig(rec, 'country-code', default='') or '—').strip()}")
        lines.append(f"  Joined at       "
                     f"{dig(rec, 'ap-time-info', 'join-time', default='—')}")
        lines.append(f"  Join took       "
                     f"{dig(rec, 'ap-time-info', 'join-time-taken', default='—')} s")

        warnings = []

        # An AP holding a CAPWAP record on two controllers at once is not a
        # normal steady state: it means one of them has not yet aged out a
        # session the AP has already left, and the stale one can still answer
        # for it. Worth saying even though the AP is up.
        if len(records) > 1:
            where = ", ".join(f"{l} ({ip})" for l, ip, _ in records)
            warnings.append(
                f"the AP holds a CAPWAP record on more than one controller "
                f"({where}); one of them is stale")

        # The controller's idea of the AP's address against the edge's. A
        # disagreement means one of them is working from a lease the other
        # has already replaced, and every address-based check upstream was
        # evaluated against the edge's answer.
        edge_ip = (ctx.state.get("ap_ip") or "").strip()
        if edge_ip and ap_ip and edge_ip != ap_ip:
            warnings.append(
                f"the controller reports {ap_ip} but the edge resolved "
                f"{edge_ip} for this AP")

        # A crash file is per radio slot and survives the rejoin, so an AP
        # that is up right now can still be telling us why it last was not.
        crash = dig(rec, "device-detail", "dynamic-info", "ap-crash-data",
                    default={})
        crashed = [k for k, v in (crash or {}).items() if v]
        if crashed:
            warnings.append(
                "the AP is holding crash files (" + ", ".join(sorted(crashed))
                + ")")

        if errors:
            lines.append("")
            lines.append("  Not read")
            lines += [f"    • {l} ({ip}) — {e}" for l, ip, e in errors]

        if warnings:
            lines.append("")
            lines.append("  Noted")
            lines += [f"    • {w}" for w in warnings]

        if state not in _REGISTERED:
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines) + f"\n\n  The AP is not registered: its "
                f"operational state is {state or 'not reported'}.",
                data={"state": state, "name": name})

        return CheckResult(
            CheckStatus.WARN if warnings else CheckStatus.OK,
            "\n".join(lines), data={"state": state, "name": name})


#: Values of the per-phase failure leaves that mean "nothing went wrong".
#: The 9800 reports a clean phase with a sentinel rather than an empty leaf,
#: and reading those as failures would flag every healthy AP.
_CLEAN = {
    "", "none", "disc-fail-none", "cf-none", "jf-none",
    "dtls-hs-success", "ap-con-failure-none",
}


def _clean(value) -> bool:
    return (value or "").strip().lower() in _CLEAN


class ApWlcApJoinPhases(_ApCheck):
    """Which phase of the join did the AP last fail in?

    An AP joins in three phases -- discovery, then the DTLS handshake, then
    the join/configure exchange -- and each fails for its own reasons. A
    discovery failure means the AP never found the controller, which is a
    path or a DHCP option-43 problem. A DTLS failure means it found it and
    they could not agree, which is certificates, clock or cipher. A join
    failure means both succeeded and the controller refused it, which is tags,
    country or capacity.

    `ap-join-stats` carries all three with their counters, so this says not
    just what failed but how often, and whether the AP is retrying. The CLI
    needs `show wireless stats ap discovery`,
    `show wireless dtls connections` and `show wireless stats ap join
    summary` to assemble the same picture, each showing only its latest event.

    Graded as a fabric observation: a failure here is a WARN, because the
    checks around it still have something to say about why.
    """

    name = "AP Join Phases"
    target_node_id = "xtr"
    running_note = "Reading discovery, DTLS and join counters…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import (
            NetconfError, ap_join_stats, credentials, dig, dotted_mac,
            session_for_wlc,
        )

        if not credentials():
            return _skip_no_netconf()
        stop = ctx.state.get("ap_netconf_stop")
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}.")

        radio = ctx.state.get("ap_radio_mac")
        wlcs = ctx.state.get("ap_netconf_wlcs") or []
        if not (radio and wlcs):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's radio MAC is not known to any controller "
                "reached, so it has no join counters to read.")

        stats, errors = [], []
        for label, mgmt_ip in wlcs:
            session = session_for_wlc(mgmt_ip)
            if session is None:
                continue
            try:
                record = ap_join_stats(session, radio)
            except NetconfError as e:
                errors.append((label, mgmt_ip, str(e)))
                continue
            if record:
                stats.append((label, mgmt_ip, record))

        if not stats:
            detail = ""
            if errors:
                detail = "\n\n  Not read\n" + "\n".join(
                    f"    • {l} ({ip}) — {e}" for l, ip, e in errors)
            return CheckResult(
                CheckStatus.WARN,
                f"No controller reached holds join counters for radio MAC "
                f"{dotted_mac(radio)}.{detail}")

        label, mgmt_ip, rec = stats[0]
        joined = (dig(rec, "ap-join-info", "is-joined", default="") == "true")

        disc_ok = dig(rec, "ap-discovery-info", "num-succ-disc-resp-sent", default="0")
        disc_req = dig(rec, "ap-discovery-info", "num-discovery-req-recvd", default="0")
        disc_err = dig(rec, "ap-discovery-info", "num-err-disc-req", default="0")
        disc_fail = dig(rec, "ap-discovery-info", "last-disc-failure-type", default="")

        dtls_req = dig(rec, "dtls-sess-info", "ctrl-dtls-setup-req", default="0")
        dtls_ok = dig(rec, "dtls-sess-info", "ctrl-dtls-success", default="0")
        dtls_bad = dig(rec, "dtls-sess-info", "ctrl-dtls-failure", default="0")
        dtls_type = dig(rec, "dtls-sess-info", "ctrl-dtls-failure-type", default="")

        join_req = dig(rec, "ap-join-info", "num-join-req-recvd", default="0")
        join_ok = dig(rec, "ap-join-info", "num-succ-join-resp-sent", default="0")
        join_bad = dig(rec, "ap-join-info", "num-unsucc-join-req-procn", default="0")
        join_fail = dig(rec, "ap-join-info", "last-join-failure-type", default="")
        cfg_fail = dig(rec, "ap-join-info", "last-config-failure-type", default="")
        err_type = dig(rec, "ap-join-info", "last-error-type", default="")

        lines = [f"Join phases for {dotted_mac(radio)} on {label} "
                 f"({mgmt_ip}) — currently "
                 f"{'joined' if joined else 'not joined'}."]
        lines.append("")
        lines.append(f"  Discovery   {disc_ok} of {disc_req} answered"
                     + (f", {disc_err} in error" if disc_err not in ("0", "") else ""))
        lines.append(f"  DTLS        {dtls_ok} of {dtls_req} established"
                     + (f", {dtls_bad} failed" if dtls_bad not in ("0", "") else ""))
        lines.append(f"  Join        {join_ok} of {join_req} accepted"
                     + (f", {join_bad} rejected" if join_bad not in ("0", "") else ""))

        # Each phase's last failure, reported only when it is a real one.
        # These leaves are sticky: they hold the last failure whether or not
        # the AP has since recovered, so on a joined AP they are history, not
        # a current fault. Said plainly rather than graded, because an AP that
        # is up now and failed an hour ago is not broken -- but the reason it
        # failed is often exactly what the operator came to find.
        last = []
        if not _clean(disc_fail):
            last.append(("Discovery", disc_fail))
        if not _clean(dtls_type):
            last.append(("DTLS", dtls_type))
        if not _clean(join_fail):
            last.append(("Join", join_fail))
        if not _clean(cfg_fail):
            last.append(("Configure", cfg_fail))
        if not _clean(err_type):
            last.append(("Last error", err_type))

        if last:
            lines.append("")
            lines.append("  Last failure recorded"
                         + (" (the AP has since joined)" if joined else ""))
            lines += [f"    • {phase} — {why}" for phase, why in last]

        disconnect = dig(rec, "ap-disconnect-reason", default="")
        if disconnect:
            lines.append("")
            lines.append(f"  Last disconnect reason: {disconnect}")

        if errors:
            lines.append("")
            lines.append("  Not read")
            lines += [f"    • {l} ({ip}) — {e}" for l, ip, e in errors]

        if not joined:
            # Name the phase the join is actually stuck in, which is the
            # earliest one that is failing -- a DTLS failure downstream of a
            # discovery that never completed says nothing.
            if not _clean(disc_fail) or disc_req in ("0", ""):
                stuck = "discovery — the AP is not reaching this controller"
            elif not _clean(dtls_type):
                stuck = ("DTLS — the AP reaches the controller but the "
                         "handshake fails (certificate, clock or cipher)")
            elif not _clean(join_fail) or not _clean(cfg_fail):
                stuck = ("join/configure — the controller is refusing or "
                         "failing to configure the AP")
            else:
                stuck = "no phase reports a failure, yet the AP is not joined"
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines) + f"\n\n  The join is stuck in {stuck}.",
                data={"joined": False})

        return CheckResult(CheckStatus.OK, "\n".join(lines),
                           data={"joined": True})


class ApWlcApTags(_ApCheck):
    """The tags the AP resolved, which decide everything it is configured with.

    An AP that joins still does nothing useful if it lands on the wrong tags:
    the policy tag selects its WLANs, the site tag its AP profile and the
    flex profile, the RF tag its radio settings. A fabric AP that resolves
    the default site tag has joined and is still not serving the fabric.

    Read from the same `capwap-data` record the registration check fetched,
    so this costs no extra query -- it is reported separately because it is a
    different question with a different answer.
    """

    name = "AP Tags"
    target_node_id = "xtr"
    running_note = "Reading the AP's resolved tags…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import credentials, dig

        if not credentials():
            return _skip_no_netconf()
        stop = ctx.state.get("ap_netconf_stop")
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}.")

        rec = ctx.state.get("ap_wlc_record")
        if not rec:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP has no CAPWAP record on any controller "
                "reached (see AP Registration on the WLC).")

        name = ctx.state.get("ap_wlc_name") or "the AP"
        resolved = dig(rec, "tag-info", "resolved-tag-info", default={}) or {}
        policy = dig(resolved, "resolved-policy-tag", default="") or ""
        site = dig(resolved, "resolved-site-tag", default="") or ""
        rf = dig(resolved, "resolved-rf-tag", default="") or ""
        source = dig(rec, "tag-info", "tag-source", default="") or "—"
        misconfigured = dig(rec, "tag-info", "is-ap-misconfigured",
                            default="") == "true"
        misconfig = dig(rec, "tag-info", "ap-misconfig", default="") or ""

        lines = [f"Tags resolved for {name}:"]
        lines.append("")
        lines.append(f"  Policy tag      {policy or '—'}")
        lines.append(f"  Site tag        {site or '—'}")
        lines.append(f"  RF tag          {rf or '—'}")
        lines.append(f"  AP profile      "
                     f"{dig(rec, 'tag-info', 'site-tag', 'ap-profile', default='—')}")
        lines.append(f"  Flex profile    "
                     f"{dig(rec, 'tag-info', 'site-tag', 'flex-profile', default='—')}")
        lines.append(f"  Tag source      {source}")

        problems = []
        if misconfigured:
            problems.append(
                f"the controller reports the AP as misconfigured"
                + (f" ({misconfig})" if misconfig else ""))
        missing = [n for n, v in
                   (("policy", policy), ("site", site), ("RF", rf)) if not v]
        if missing:
            problems.append(
                f"no {', '.join(missing)} tag resolved")
        # A fabric AP on the default site tag has joined and is still not
        # serving the fabric: the default tag carries no fabric AP profile,
        # so none of the fabric configuration reaches it.
        if dig(rec, "ap-mode-data", "ap-fabric-data", "is-fabric-ap",
               default="") == "true" and site.startswith("default-"):
            problems.append(
                f"this is a fabric AP but it resolved the default site tag "
                f"({site}), which carries no fabric AP profile")

        if problems:
            lines.append("")
            lines.append("  Noted")
            lines += [f"    • {p}" for p in problems]
            return CheckResult(CheckStatus.WARN, "\n".join(lines))

        return CheckResult(CheckStatus.OK, "\n".join(lines),
                           data={"policy": policy, "site": site, "rf": rf})


#: How many of the most recent join/disjoin events to print. The controller
#: keeps far more than an operator reads; the recent ones carry the story.
_HISTORY_SHOWN = 10


class ApWlcApJoinHistory(_ApCheck):
    """Has the AP been stable, or is it rejoining?

    An AP that is joined right now may have joined thirty times today, and a
    point-in-time check cannot tell the difference. `ap-history` keeps the
    join and disjoin events with the reason each disconnect was attributed
    to, which is the only place in this step where a flap is visible.

    Keyed on the *Ethernet* MAC -- the one list in these models that is, which
    is why it takes the MAC the chain already holds rather than the radio MAC
    the rest of the step uses.

    Graded on the disconnect reasons rather than the count: an AP that
    rejoined twice for an image upgrade is behaving correctly, while one that
    rejoined twice on heartbeat expiry has an intermittent data path.
    """

    name = "AP Join History"
    target_node_id = "xtr"
    running_note = "Reading the AP's join and disjoin history…"

    #: Disconnect reasons that are a normal part of operation rather than a
    #: fault. Matched case-insensitively as substrings, because the
    #: controller phrases these as free text.
    BENIGN = ("image download success", "wtp reset config",
              "admin", "reset config cmd")

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import (
            NetconfError, ap_history, as_list, credentials, dig,
            session_for_wlc,
        )

        if not credentials():
            return _skip_no_netconf()
        stop = ctx.state.get("ap_netconf_stop")
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}.")

        eth_mac = (ctx.payload.get("mac") or "").strip()
        wlcs = ctx.state.get("ap_netconf_wlcs") or []
        if not (eth_mac and wlcs):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no controller was reached (see WLC NETCONF "
                "Session).")

        record, errors = {}, []
        for label, mgmt_ip in wlcs:
            session = session_for_wlc(mgmt_ip)
            if session is None:
                continue
            try:
                found = ap_history(session, eth_mac)
            except NetconfError as e:
                errors.append((label, mgmt_ip, str(e)))
                continue
            if found:
                record = found
                break

        if not record:
            detail = ""
            if errors:
                detail = "\n\n  Not read\n" + "\n".join(
                    f"    • {l} ({ip}) — {e}" for l, ip, e in errors)
            return CheckResult(
                CheckStatus.WARN,
                f"No controller reached holds join history for this AP's "
                f"Ethernet MAC.{detail}")

        events = as_list(dig(record, "ewlc-ap-state-ptr"))
        if not events:
            return CheckResult(
                CheckStatus.OK,
                "The controller holds no join or disjoin events for this AP.")

        name = dig(record, "ap-name", default="") or "the AP"
        lines = [f"Join history for {name} — {len(events)} event(s) recorded."]
        lines.append("")
        for event in events[:_HISTORY_SHOWN]:
            when = (dig(event, "timestamp", default="") or "")[:19].replace("T", " ")
            up = dig(event, "is-ap-joined", default="") == "true"
            why = dig(event, "ap-disconnect-reason-str", default="") or ""
            state = "joined" if up else "disjoined"
            row = f"    {when:20} {state:10}" + (f" {why}" if why else "")
            lines.append(row.rstrip())
        if len(events) > _HISTORY_SHOWN:
            lines.append(f"    … {len(events) - _HISTORY_SHOWN} older "
                         f"event(s) not shown")

        # Count only the disjoins that were not a normal part of operation.
        concerning = []
        for event in events:
            if dig(event, "is-ap-joined", default="") == "true":
                continue
            why = (dig(event, "ap-disconnect-reason-str", default="") or "").strip()
            if not why:
                continue
            if any(b in why.lower() for b in self.BENIGN):
                continue
            concerning.append(why)

        if concerning:
            # Grouped by reason: six heartbeat expiries are one finding with a
            # count, not six findings.
            counts: dict = {}
            for why in concerning:
                counts[why] = counts.get(why, 0) + 1
            lines.append("")
            lines.append("  Disconnects not attributable to normal operation")
            for why, count in sorted(counts.items(), key=lambda kv: -kv[1]):
                lines.append(f"    • {why}"
                             + (f" ×{count}" if count > 1 else ""))
            return CheckResult(
                CheckStatus.WARN, "\n".join(lines),
                data={"disconnects": len(concerning)})

        return CheckResult(CheckStatus.OK, "\n".join(lines),
                           data={"events": len(events)})
