"""The AP's access tunnel in the IDB table.

The S row is the one that matters: on Edge2 the HWIDB row for AccessTunnel0
carries `MFIB_IPv4(15)` alone, while the SWIDB row carries the feature list
the tunnel runs on. The two rows have different indices -- 65 and 77 -- and
the `ifid` from `show access-tunnel statistics` is the SWIDB's: 0x0000004D
is 77. Both samples are verbatim from Edge2, pulled 2026-10-14.
"""

from checks.base import CheckStatus
from checks.ap_radio_registration import ApAccessTunnelIdb

IDB = """show idb all

Maximum number of Software IDBs 131072.  In use 78.

                       HWIDBs     SWIDBs          uHWIDBs    uSWIDBs
Active                     59         70                0          0
Total IDBs                 67         78                0          0

Type SIdx     Idx St,O,Sh HDel Interface Name (subblocks)
-----------------------------------------------------------
 H    54      65   U,U,R    .  AccessTunnel0 (MFIB_IPv4(15))
 H    57      53   U,R,U    .  L2LISP0 (MFIB_IPv4(15))

 S    54      77   U        .  AccessTunnel0 (DTP(40), MFIB_IPv4(43), CTS PLATFORM SB(6), ACCESS TUNNEL SB(52), KEEPALIVE(1))
 S    65      53   U        .  LISP0 (UDLD(5), KEEPALIVE(1))
"""

#: As `ApAccessTunnelStatistics` leaves it in state.
TUNNEL = {"name": "AccessTunnel0", "ifid": "0x0000004D",
          "ap_ip": "172.19.5.10", "mac": "3891.b70f.2600"}


class _Ctx:
    def __init__(self, tunnel=TUNNEL):
        self.service = object()
        self.state = {"xtr_hostname": "Edge2"}
        if tunnel is not None:
            self.state["ap_access_tunnel"] = dict(tunnel)


def _run(raw=IDB, tunnel=TUNNEL):
    # The check imports this inside the function, as every other check in
    # this module does, so the patch has to land on radkit_cli itself.
    import radkit_cli
    chk, ctx = ApAccessTunnelIdb(), _Ctx(tunnel)
    real = radkit_cli.get_any_single_output
    radkit_cli.get_any_single_output = lambda *a, **k: raw
    try:
        return chk.run(ctx), ctx
    finally:
        radkit_cli.get_any_single_output = real


def test_the_healthy_tunnel_passes_and_prints_both_rows():
    r, _ = _run()
    assert r.status is CheckStatus.OK
    assert r.data["swidb"]["idx"] == 77
    assert r.data["hwidb"]["idx"] == 65
    assert "if_number 77" in r.message
    assert "hw_if_index 65" in r.message


def test_the_swidb_is_found_by_the_ifid_not_the_name():
    """0x0000004D is 77, which is the SWIDB index. Matching on the ifid is
    what makes this robust if two interfaces ever share a name shape."""
    r, _ = _run()
    assert r.data["matched_on"] == "ifid"
    assert r.data["expected_idx"] == 77


def test_the_s_row_is_the_one_read_for_features():
    """The whole point. The H row carries MFIB_IPv4 alone; the feature list
    lives on the S row, and reading the H row would report no subblocks."""
    r, _ = _run()
    assert "ACCESS TUNNEL SB(52)" in r.data["subblocks"]
    assert "DTP(40)" in r.data["subblocks"]
    assert r.data["hwidb"]["subblocks"] == "MFIB_IPv4(15)"


def test_a_tunnel_with_no_software_idb_warns():
    """Listed as an active access tunnel with no interface structure behind
    it."""
    raw = IDB.replace(
        " S    54      77   U        .  AccessTunnel0 (DTP(40), MFIB_IPv4(43),"
        " CTS PLATFORM SB(6), ACCESS TUNNEL SB(52), KEEPALIVE(1))\n", "")
    r, _ = _run(raw)
    assert r.status is CheckStatus.WARN
    assert r.data["swidb"] is None
    assert "no software IDB" in r.message


def test_a_missing_access_tunnel_subblock_warns():
    """The interface exists but the feature is not attached to it -- the
    failure this check exists to separate from "no interface at all"."""
    raw = IDB.replace("ACCESS TUNNEL SB(52), ", "")
    r, _ = _run(raw)
    assert r.status is CheckStatus.WARN
    assert "does not carry `ACCESS TUNNEL SB`" in r.message


def test_a_down_swidb_warns():
    raw = IDB.replace(" S    54      77   U        .",
                      " S    54      77   D        .")
    r, _ = _run(raw)
    assert r.status is CheckStatus.WARN
    assert "software IDB for AccessTunnel0 is down" in r.message


def test_a_deleted_row_warns_while_the_tunnel_is_still_active():
    raw = IDB.replace(" S    54      77   U        .",
                      " S    54      77   U        X")
    r, _ = _run(raw)
    assert r.status is CheckStatus.WARN
    assert "flagged deleted" in r.message


def test_an_ifid_that_disagrees_with_the_table_is_reported():
    """Falls back to the name so the row is still printed, but says the two
    sources disagree about which interface this tunnel is."""
    r, _ = _run(tunnel={**TUNNEL, "ifid": "0x000000FF"})
    assert r.status is CheckStatus.WARN
    assert r.data["matched_on"] == "name"
    assert "disagree about which interface" in r.message
    assert r.data["swidb"]["idx"] == 77


def test_an_unreadable_ifid_falls_back_to_the_name_without_complaint():
    """No ifid is not a disagreement -- there is nothing to disagree with."""
    r, _ = _run(tunnel={**TUNNEL, "ifid": None})
    assert r.status is CheckStatus.OK
    assert r.data["matched_on"] == "name"
    assert r.data["swidb"]["idx"] == 77


def test_the_software_idb_ceiling_is_reported():
    r, _ = _run()
    assert r.data["sw_idb_max"] == 131072
    assert "78 of 131072" in r.message


def test_being_at_the_idb_ceiling_warns():
    """A switch out of software IDBs cannot build another interface."""
    raw = IDB.replace("Maximum number of Software IDBs 131072.  In use 78.",
                      "Maximum number of Software IDBs 78.  In use 78.")
    r, _ = _run(raw)
    assert r.status is CheckStatus.WARN
    assert "software IDB ceiling" in r.message


def test_it_skips_when_no_tunnel_was_found():
    """Nothing to look up. A SKIP, not a finding -- the absent tunnel is
    already reported by the check that looked for it."""
    r, _ = _run(tunnel=None)
    assert r.status is CheckStatus.SKIP


def test_it_is_queued_after_the_tunnel_check_that_feeds_it():
    """It reads `ap_access_tunnel` from state, so it must run after the
    check that puts it there or it would always skip."""
    import inspect
    import checks.ap_wlc as m
    src = inspect.getsource(m)
    assert src.index("ApAccessTunnelStatistics()") \
        < src.index("ApAccessTunnelIdb()")


def test_the_abbreviated_tunnel_name_still_finds_the_hardware_idb():
    """`show access-tunnel statistics` abbreviates the name; the IDB table
    spells it out.

    Edge2 reports the tunnel as `Ac0` and lists it in the IDB as
    `AccessTunnel0`. Joining the HWIDB on the name therefore never matched
    and the check reported a missing hardware IDB on a device that plainly
    had one. The join is on the SWIDB's SIdx, which both rows share.
    """
    r, _ = _run(tunnel=dict(TUNNEL, name="Ac0"))
    assert r.data["hwidb"] is not None
    assert r.data["hwidb"]["idx"] == 65
    assert r.data["swidb"]["idx"] == 77
    assert "no hardware IDB" not in r.message


def test_the_hardware_idb_is_joined_on_sidx_not_on_the_index():
    """The two rows carry different if_numbers -- 65 and 77 -- so the join
    cannot be on the index. It is on SIdx, which both carry as 54."""
    r, _ = _run(tunnel=dict(TUNNEL, name="Ac0"))
    assert r.data["hwidb"]["sidx"] == r.data["swidb"]["sidx"] == 54


def test_a_missing_hardware_row_is_still_reported():
    """The fix must not silence the real finding."""
    raw = IDB.replace(" H    54      65   U,U,R    .  AccessTunnel0"
                      " (MFIB_IPv4(15))\n", "")
    r, _ = _run(raw, tunnel=dict(TUNNEL, name="Ac0"))
    assert r.data["hwidb"] is None
    assert "no hardware IDB" in r.message
    assert r.status is CheckStatus.WARN
