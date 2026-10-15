"""`show access-tunnel statistics` on the fabric edge.

Two questions in one command: has the platform room to build tunnels at all,
and what does THIS AP's tunnel look like. The fixture is Edge2's real output,
captured 2026-10-14 -- including the `*` the device puts on an AP whose IP
and MAC have changed during this switch's uptime.
"""
from checks.base import CheckStatus
from checks.ap_radio_registration import ApAccessTunnelStatistics
from wirelessmodules.accesstunnels import parse_access_tunnel_statistics

LIVE = """
Statistics:
\tNumber of Created Access Tunnels (max 200): 1
\tNumber of Deleted Access Tunnels: 0
\tNumber of Active Access Tunnels (max 200): 1

Active Access Tunnels:
\t* denotes AP IP and MAC change
\tMAC represents AP Radio MAC

Name    IfId        AP IP(Destination)                              VRF ID  MAC               Uptime (Times)
------  ----------  ----------------------------------------------  ------  ----------------  ------------------------
Ac0     0x0000004D *172.19.5.10                                     0        3891.b70f.2600    0 day,  07:04:34 (1)

Last AP IP and MAC Changes:

Name    IfId        AP IP(Destination)                              VRF ID  MAC               Uptime (Times)
------  ----------  ----------------------------------------------  ------  ----------------  ------------------------
Ac0     0x0000004D *172.19.5.10                                     0        3891.b70f.2600    0 day,  07:04:34 (1)

Deleted Access Tunnels:

Name    IfId        AP IP(Destination)                              VRF ID  MAC               Downtime (Times)
------  ----------  ----------------------------------------------  ------  ----------------  ------------------------
"""


class _Ctx:
    def __init__(self, mac="3891.b70f.2600"):
        self.service = object()
        self.state = {"xtr_hostname": "Edge2", "ap_wlc_radio_mac": mac}


#: Edge2's real `show access-tunnel summary`, as Genie parses it. The check
#: reads the summary through Genie (ShowAccessTunnelSummary covers it) and
#: the statistics by hand (Genie has no parser for that one).
SUMMARY = {
    "data_tunnels_count": 1,
    "name": {"Ac0": {"rloc_ip": "172.19.1.68", "ap_ip": "172.19.5.10",
                     "vrf_id": "0", "src_port": "N/A", "dst_port": "4789",
                     "ifid": "0x0000004D", "up_time": "0 day,  07:23:51"}},
}


def _run(raw, mac="3891.b70f.2600", summary=None):
    import radkit_cli
    chk, ctx = ApAccessTunnelStatistics(), _Ctx(mac)
    real_any = radkit_cli.get_any_single_output
    real_genie = radkit_cli.get_single_output_genie
    radkit_cli.get_any_single_output = lambda *a, **k: raw
    radkit_cli.get_single_output_genie = lambda *a, **k: (
        SUMMARY if summary is None else summary)
    try:
        return chk.run(ctx), ctx
    finally:
        radkit_cli.get_any_single_output = real_any
        radkit_cli.get_single_output_genie = real_genie


def test_the_parser_reads_the_counters_and_the_max_from_the_label():
    """The max is carried inside the counter's own label -- `(max 200)` --
    not on a line of its own."""
    s = parse_access_tunnel_statistics(LIVE)
    assert (s["created"], s["deleted"], s["active"], s["max"]) == (1, 0, 1, 200)


def test_only_the_active_table_is_read():
    """The same row is repeated under "Last AP IP and MAC Changes". Folding
    the tables together would report this one AP's tunnel twice."""
    s = parse_access_tunnel_statistics(LIVE)
    assert len(s["tunnels"]) == 1


def test_the_star_is_read_as_an_ip_change():
    """The device's own legend: `* denotes AP IP and MAC change`. It is
    attached to the address with no space, so the address must still parse."""
    t = parse_access_tunnel_statistics(LIVE)["tunnels"][0]
    assert t["ip_changed"] is True
    assert t["ap_ip"] == "172.19.5.10"


def test_an_unstarred_address_is_not_flagged():
    s = parse_access_tunnel_statistics(LIVE.replace("*172.19.5.10", " 172.19.5.10"))
    assert s["tunnels"][0]["ip_changed"] is False
    assert s["tunnels"][0]["ap_ip"] == "172.19.5.10"


def test_the_healthy_edge_passes_and_prints_the_counts():
    """1 of 200 is healthy. The user asked for the deleted and active counts
    to be printed either way."""
    r, _ = _run(LIVE)
    # The `*` used to make this a WARN. The user settled it: a past AP
    # address change is history, not a fault, and the tunnel in front of it
    # is up. Nothing else on this edge is wrong, so the check passes.
    assert r.status is CheckStatus.OK
    assert r.data["active"] == 1 and r.data["max"] == 200
    assert "Active tunnels     1 of 200" in r.message
    assert "Deleted            0" in r.message


def test_the_ap_tunnel_is_found_by_radio_mac():
    r, ctx = _run(LIVE)
    t = r.data["ap_tunnel"]
    assert t["name"] == "Ac0"
    assert t["ap_ip"] == "172.19.5.10"
    assert t["uptime"].startswith("0 day")
    assert ctx.state["ap_access_tunnel"]["ifid"] == "0x0000004D"


def test_the_star_is_reported_but_never_graded():
    """Reported as a detail, not as a finding.

    The device's legend defines `*` as an AP IP and MAC change, which is a
    historical marker: it says the address changed at some point in this
    switch's uptime, not that anything is wrong now.
    """
    r, _ = _run(LIVE)
    assert r.data["ap_tunnel"]["ip_changed"] is True
    assert "AP IP/MAC changed  yes" in r.message
    assert r.status is CheckStatus.OK
    assert "⚠" not in r.message


def test_at_the_ceiling_is_a_failure():
    """The user's rule: actives equal to the maximum is a failure -- the
    platform cannot build another tunnel."""
    r, _ = _run(LIVE.replace("Number of Active Access Tunnels (max 200): 1",
                             "Number of Active Access Tunnels (max 200): 200"))
    assert r.status is CheckStatus.FAIL
    assert r.data["at_capacity"] is True
    assert "ceiling" in r.message


def test_below_the_ceiling_is_not_a_failure():
    """199 of 200 is not yet at capacity, however close."""
    r, _ = _run(LIVE.replace("Number of Active Access Tunnels (max 200): 1",
                             "Number of Active Access Tunnels (max 200): 199"))
    assert r.status is not CheckStatus.FAIL
    assert r.data["at_capacity"] is False


def test_a_mac_with_no_tunnel_says_so():
    r, _ = _run(LIVE, mac="dead.beef.0000")
    assert r.data["ap_tunnel"] is None
    assert "No active access tunnel" in r.message


def test_it_is_queued_after_the_wlc_database_entry():
    """The entry is what asks for the tunnel, so a missing tunnel reads
    differently depending on whether the edge was ever signalled."""
    import inspect
    import checks.ap_wlc as m
    src = inspect.getsource(m)
    assert "ApAccessTunnelStatistics()" in src, "the check is never queued"
    assert (src.index("ApFabricEdgeWlcDatabase()")
            < src.index("ApAccessTunnelStatistics()"))


# --------------------------------------------------------------------------
# Verified against `show access-tunnel summary`. Neither command answers on
# its own: statistics has the `*` and the MAC, summary has the RLOC and the
# ports. They are joined on the tunnel name, the only field both carry.
# --------------------------------------------------------------------------


def test_the_summary_fills_in_what_statistics_does_not():
    r, _ = _run(LIVE)
    assert r.data["summary_tunnel"]["rloc_ip"] == "172.19.1.68"
    assert "RLOC (source)      172.19.1.68" in r.message
    assert "Destination port   4789" in r.message


def test_a_tunnel_missing_from_the_summary_is_a_finding():
    """Listed as active by one command and absent from the other: the two
    views of the same tunnel disagree."""
    r, _ = _run(LIVE, summary={"data_tunnels_count": 0, "name": {}})
    assert r.status is CheckStatus.WARN
    assert "not in its summary" in r.message


def test_disagreeing_ap_addresses_are_a_finding():
    other = {"data_tunnels_count": 1,
             "name": {"Ac0": dict(SUMMARY["name"]["Ac0"], ap_ip="172.19.5.99")}}
    r, _ = _run(LIVE, summary=other)
    assert r.status is CheckStatus.WARN
    assert "disagree on this tunnel's AP address" in r.message


def test_a_tunnel_not_sourced_from_the_edge_loopback_is_a_finding():
    """The access tunnel is sourced from the edge's own RLOC. Anything else
    means it is built from an address the fabric does not resolve to it."""
    import radkit_cli
    chk, ctx = ApAccessTunnelStatistics(), _Ctx()
    ctx.state["xtr_loopback"] = "172.19.1.68"
    real_any, real_g = (radkit_cli.get_any_single_output,
                        radkit_cli.get_single_output_genie)
    other = {"data_tunnels_count": 1,
             "name": {"Ac0": dict(SUMMARY["name"]["Ac0"], rloc_ip="10.0.0.1")}}
    radkit_cli.get_any_single_output = lambda *a, **k: LIVE
    radkit_cli.get_single_output_genie = lambda *a, **k: other
    try:
        r = chk.run(ctx)
    finally:
        radkit_cli.get_any_single_output = real_any
        radkit_cli.get_single_output_genie = real_g
    assert r.status is CheckStatus.WARN
    assert "not the edge's Loopback0" in r.message


def test_the_matching_loopback_is_not_flagged():
    import radkit_cli
    chk, ctx = ApAccessTunnelStatistics(), _Ctx()
    ctx.state["xtr_loopback"] = "172.19.1.68"
    real_any, real_g = (radkit_cli.get_any_single_output,
                        radkit_cli.get_single_output_genie)
    radkit_cli.get_any_single_output = lambda *a, **k: LIVE
    radkit_cli.get_single_output_genie = lambda *a, **k: SUMMARY
    try:
        r = chk.run(ctx)
    finally:
        radkit_cli.get_any_single_output = real_any
        radkit_cli.get_single_output_genie = real_g
    assert "not the edge's Loopback0" not in r.message


# --------------------------------------------------------------------------
# User rules, 2026-10-14: an absent tunnel still prints whatever rows carry
# this AP's MAC or address; a live tunnel is drawn on the canvas and recorded
# for the PD pass.
# --------------------------------------------------------------------------


def test_rows_referencing_the_ap_are_printed_when_no_tunnel_matches():
    """`not found` on its own hides the difference between no row at all and
    a row with the right address under the wrong MAC."""
    import radkit_cli
    raw = LIVE.replace("3891.b70f.2600", "dead.beef.0001")
    chk, ctx = ApAccessTunnelStatistics(), _Ctx()
    # The AP's address as the metadata decode left it, so the row can still
    # be matched on address after the MAC no longer matches.
    ctx.state["ap_ip_metadata"] = "172.19.5.10"
    real_any, real_genie = (radkit_cli.get_any_single_output,
                            radkit_cli.get_single_output_genie)
    radkit_cli.get_any_single_output = lambda *a, **k: raw
    radkit_cli.get_single_output_genie = lambda *a, **k: SUMMARY
    try:
        r = chk.run(ctx)
    finally:
        radkit_cli.get_any_single_output = real_any
        radkit_cli.get_single_output_genie = real_genie
    assert r.status is CheckStatus.WARN
    assert r.data["partial_tunnel_matches"]
    assert "AP address" in r.message
    assert "dead.beef.0001" in r.message


def test_a_live_tunnel_is_drawn_between_the_edge_and_the_ap():
    r, _ = _run(LIVE)
    edge = r.data["add_edges"][0]
    assert edge["source"] == "xtr" and edge["target"] == "ap"
    assert edge["access_tunnel"] is True
    assert edge["label"] == "Ac0 - VXLAN"


def test_no_edge_is_drawn_when_there_is_no_tunnel():
    """The device lists a tunnel under `Active` only while it is up, so an
    absent row means there is nothing to draw."""
    r, _ = _run(LIVE, mac="dead.beef.0001")
    assert "add_edges" not in r.data


def test_the_tunnel_interface_is_recorded_for_the_pd_pass():
    _, ctx = _run(LIVE)
    ifms = [o for o in ctx.state["pd_objects"]
            if o["kind"] == "IFM" and o.get("interface") == "Ac0"]
    assert len(ifms) == 1
    assert ifms[0]["radkit_hostname"] == "Edge2"


def test_the_summary_tunnel_count_is_recorded_as_an_interface_list():
    _, ctx = _run(LIVE)
    lists = [o for o in ctx.state["pd_objects"]
             if o["kind"] == "interface_list"]
    assert len(lists) == 1
    assert lists[0]["interface_type"] == "access-tunnel"
    assert lists[0]["count"] == 1


# --------------------------------------------------------------------------
# A second platform. Verbatim from a C9200 (PEN_SDA3), supplied by the user
# 2026-10-14. Two things differ from the Edge2 sample everything else here is
# built on: the ceiling is 25 rather than 200, and with no tunnels the device
# prints the counters alone -- none of the three tables appear at all.
# --------------------------------------------------------------------------

C9200 = """PEN_SDA3#show access-tunnel statistics

Statistics:
        Number of Created Access Tunnels (max 25): 0
        Number of Deleted Access Tunnels: 0
        Number of Active Access Tunnels (max 25): 0
"""


def test_the_platform_ceiling_is_read_not_assumed():
    """25 on a C9200, 200 on the Edge2 box. The limit is only ever taken from
    the counter's own label, so a third platform needs no code change."""
    s = parse_access_tunnel_statistics(C9200)
    assert s["max"] == 25
    assert (s["created"], s["deleted"], s["active"]) == (0, 0, 0)


def test_counters_alone_with_no_tables_parse_cleanly():
    """With nothing active the device omits all three tables. The active-table
    search must come back empty rather than failing or matching the counter
    block it sits below."""
    assert parse_access_tunnel_statistics(C9200)["tunnels"] == []


def test_an_empty_switch_is_not_reported_as_at_capacity():
    """0 of 25 is as far from the ceiling as it gets. The `>=` comparison
    would read 0 >= 0 as full if the max ever went missing, so this pins the
    healthy-but-empty case."""
    r, _ = _run(C9200, mac="3891.b70f.2600")
    assert r.data["at_capacity"] is False
    assert r.status is not CheckStatus.FAIL
