"""The AP's country, graded against the controller it joined.

The fault this exists for is quiet: an AP whose country is not configured on
its controller joins and registers normally, and then every radio stays
down. Every registration check passes, so it reads as an RF problem.
"""

import types

import pytest

from checks.base import CheckStatus
from wirelessmodules.accesspointinfo import parse_wireless_country

WLC = "wlc-jalejand-cisco-com"

# Verbatim from the lab WLC.
REAL = """WLCv#show wireless country configured
 
Configured Country..........................   MX - Mexico                    
Configured Country Codes
        MX  - Mexico                              802.11a Indoor,Outdoor/ 802.11b Indoor,Outdoor/ 802.11g Indoor,Outdoor/ 802.11 6GHz Indoor 
 
WLCv#"""

TWO = """Configured Country..........................   MX - Mexico
Configured Country Codes
        MX  - Mexico                              802.11a Indoor,Outdoor
        US  - United States                       802.11a Indoor,Outdoor
"""


def _ctx(ap_country="MX"):
    state = {}
    if ap_country:
        state["ap_wlc_country"] = {WLC: ap_country}
    return types.SimpleNamespace(service=object(), payload={}, state=state)


@pytest.fixture
def served(monkeypatch):
    import radkit_cli

    def serve(text):
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s: text)
    return serve


def test_parser_reads_the_real_output():
    countries, unreadable = parse_wireless_country(REAL)
    assert unreadable == 0
    assert list(countries) == ["MX"]
    assert countries["MX"]["name"] == "Mexico"
    assert "802.11a Indoor,Outdoor" in countries["MX"]["bands"]


def test_parser_reads_several_countries():
    countries, unreadable = parse_wireless_country(TWO)
    assert unreadable == 0
    assert sorted(countries) == ["MX", "US"]
    assert countries["US"]["name"] == "United States"


def test_parser_never_raises():
    assert parse_wireless_country("") == ({}, 0)
    assert parse_wireless_country(None) == ({}, 0)


def test_parser_ignores_the_summary_line():
    """The "Configured Country" line duplicates a table row.

    Counting it would report one more country than is configured.
    """
    countries, _ = parse_wireless_country(REAL)
    assert len(countries) == 1


def test_matching_country_passes(served):
    from checks.ap_wlc import ApWlcApCountry

    served(REAL)
    r = ApWlcApCountry(WLC, "wlc0").run_ap(_ctx("MX"))
    assert r.status is CheckStatus.OK
    assert "MX  Mexico" in r.message


def test_country_not_configured_warns(served):
    """The AP joins and registers; only the radios never come up."""
    from checks.ap_wlc import ApWlcApCountry

    served(REAL)
    ctx = _ctx("US")
    r = ApWlcApCountry(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "every radio stays down" in r.message
    assert not ctx.state.get("ap_stop")


def test_controller_with_no_country_warns(served):
    from checks.ap_wlc import ApWlcApCountry

    served("Configured Country Codes\n")
    r = ApWlcApCountry(WLC, "wlc0").run_ap(_ctx("MX"))
    assert r.status is CheckStatus.WARN
    assert "no configured regulatory country" in r.message


def test_without_the_aps_country_the_list_still_shows(served):
    """Nothing to grade against is not a reason to withhold the list."""
    from checks.ap_wlc import ApWlcApCountry

    served(REAL)
    r = ApWlcApCountry(WLC, "wlc0").run_ap(_ctx(ap_country=""))
    assert r.status is CheckStatus.OK
    assert "MX  Mexico" in r.message
    assert "not graded" in r.message


def test_country_grades_even_when_it_runs_before_ap_state(served, monkeypatch):
    """This check is ordered ahead of the one that publishes the country.

    It therefore resolves the AP itself rather than grading nothing. Without
    this it would silently degrade to listing the controller's countries.
    """
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApCountry

    served(REAL)
    monkeypatch.setattr(mod, "_ap_summary_rows",
                        lambda p: {"AP-002": {"ethernet_mac": "b811.4b0e.2630"}})
    monkeypatch.setattr(mod, "_ap_config_general",
                        lambda h, n, s: ({"country_code": "MX"}, None))
    import radkit_cli
    monkeypatch.setattr(radkit_cli, "get_single_output_genie",
                        lambda h, c, s, **k: {"ap_name": {}})

    # No ap_wlc_country in state: ApWlcApState has not run yet.
    ctx = types.SimpleNamespace(
        service=object(), payload={"mac": "b811.4b0e.2630"}, state={})
    r = ApWlcApCountry(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    assert "AP country  MX" in r.message
    assert "not graded" not in r.message


def test_country_without_a_resolvable_ap_lists_but_does_not_grade(served,
                                                                  monkeypatch):
    """A MAC that matches no AP must not silently grade as present."""
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApCountry

    served(REAL)
    monkeypatch.setattr(mod, "_ap_summary_rows", lambda p: {})
    import radkit_cli
    monkeypatch.setattr(radkit_cli, "get_single_output_genie",
                        lambda h, c, s, **k: {"ap_name": {}})

    ctx = types.SimpleNamespace(
        service=object(), payload={"mac": "dead.beef.0001"}, state={})
    r = ApWlcApCountry(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    assert "not graded" in r.message
