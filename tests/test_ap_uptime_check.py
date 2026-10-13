"""The "AP Uptime" check: a soft reading, and the flap it can expose.

The finding this check exists for is the gap between the two durations. An
AP up for days but associated for minutes did not reload -- it dropped its
CAPWAP session and came back, and `show ap summary` reports it as Registered
exactly like an AP that has been stable for a month.
"""

import types

import pytest

from checks.base import CheckStatus

WLC = "wlc-jalejand-cisco-com"
HDR = ("AP Name                          Ethernet MAC    Radio MAC       "
       "AP Up Time                                          "
       "Association Up Time")
SEP = "-" * 147


def _output(ap_up, assoc_up, mac="b811.4b0e.2630", name="AP-002"):
    return "\n".join([
        "Number of APs: 1", HDR, SEP,
        f"{name}   {mac}  3891.b70f.2600  {ap_up}   {assoc_up}",
    ])


def _ctx(mac="b811.4b0e.2630", cdp="AP-002.cisco.com"):
    return types.SimpleNamespace(
        service=object(), payload={"mac": mac},
        state={"ap_cdp_neighbor": {"device_id": cdp}})


@pytest.fixture
def served(monkeypatch):
    """Serve a chosen `show ap uptime` body to the check."""
    import radkit_cli

    def serve(text):
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s: text)
    return serve


def test_stable_ap_reports_both_durations(served):
    from checks.ap_wlc import ApWlcApUptime

    served(_output("11 hours 33 minutes 37 seconds",
                   "11 hours 31 minutes 43 seconds"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert "AP-002" in r.message
    assert "b811.4b0e.2630" in r.message
    assert "3891.b70f.2600" in r.message
    assert "11 hours 33 minutes 37 seconds" in r.message
    assert "11 hours 31 minutes 43 seconds" in r.message


def test_recent_association_with_long_uptime_is_a_flap(served):
    """Up for days, associated for minutes: it flapped, it did not reload."""
    from checks.ap_wlc import ApWlcApUptime

    served(_output("5 days 2 hours 1 minutes", "4 minutes 12 seconds"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "flapped recently but did not reload" in r.message


def test_recent_association_with_recent_uptime_is_a_reload(served):
    """Both durations short: the AP rebooted, which is not a flap.

    Reporting a reload as a flap would send someone looking for a link fault
    that is not there.
    """
    from checks.ap_wlc import ApWlcApUptime

    served(_output("3 minutes 5 seconds", "2 minutes 1 seconds"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "reloaded rather than flapped" in r.message


def test_ten_minute_boundary(served):
    """Just under warns, just over does not."""
    from checks.ap_wlc import ApWlcApUptime

    served(_output("5 days 0 hours 0 minutes", "9 minutes 59 seconds"))
    assert ApWlcApUptime(WLC, "wlc0").run_ap(_ctx()).status is CheckStatus.WARN

    served(_output("5 days 0 hours 0 minutes", "10 minutes 1 seconds"))
    assert ApWlcApUptime(WLC, "wlc0").run_ap(_ctx()).status is CheckStatus.OK


def test_absent_ap_is_a_soft_warn_naming_cdp_name_and_mac(served):
    from checks.ap_wlc import ApWlcApUptime

    served(_output("1 hours 0 minutes", "1 hours 0 minutes"))
    ctx = _ctx(mac="dead.beef.0001")
    r = ApWlcApUptime(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "AP-002.cisco.com" in r.message
    assert "dead.beef.0001" in r.message
    assert "show ap uptime" in r.message
    # Soft: it must never stop the chain.
    assert not ctx.state.get("ap_stop")


def test_absent_ap_without_a_cdp_name_still_reads(served):
    from checks.ap_wlc import ApWlcApUptime

    served(_output("1 hours 0 minutes", "1 hours 0 minutes"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx(mac="dead.beef.0001", cdp=""))
    assert r.status is CheckStatus.WARN
    assert "dead.beef.0001" in r.message


def test_unreadable_rows_are_surfaced_when_the_ap_is_missing(served):
    """The AP may be in a row the parser refused, and that must be said."""
    from checks.ap_wlc import ApWlcApUptime

    served("\n".join(["Number of APs: 2", HDR, SEP,
                      "AP-002   b811.4b0e.2630  3891.b70f.2600  1 hours 0 minutes   1 hours 0 minutes",
                      "AP-003   mangled row that will not match"]))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx(mac="aaaa.bbbb.cccc"))
    assert r.status is CheckStatus.WARN
    assert "could not be read" in r.message


def test_an_ungradeable_association_is_passed_over_silently(served):
    """A duration we cannot read produces no verdict and no note.

    The durations themselves are still reported. Guessing the number would
    either warn about a stable AP or stay silent about a flapping one.
    """
    from checks.ap_wlc import ApWlcApUptime

    served(_output("5 days 0 hours 0 minutes", "2 fortnights"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert "2 fortnights" in r.message
    assert "⚠" not in r.message


def test_no_mac_supplied_skips(served):
    from checks.ap_wlc import ApWlcApUptime

    served(_output("1 hours 0 minutes", "1 hours 0 minutes"))
    r = ApWlcApUptime(WLC, "wlc0").run_ap(_ctx(mac=""))
    assert r.status is CheckStatus.SKIP
