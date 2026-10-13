"""`show wireless stats ap discovery` — the parser and the check on it."""

import types

import pytest

from checks.base import CheckStatus
from wirelessmodules.accesspointinfo import parse_ap_discovery_stats

WLC = "wlc-jalejand-cisco-com"
AP_MAC = "b811.4b0e.2630"

LIVE = """WLCv#show wireless stats ap discovery
 
Discovery requests received from total number of APs : 2
 
AP Radio MAC    AP Ethernet MAC  IP Address                               Last Success time          Last failure type             Last failure time
----------------------------------------------------------------------------------------------------------------------------------------------------
3891.b70f.2600  b811.4b0e.2630   172.19.5.10                              10/13/26 07:27:17          None                          NA
687d.b461.dc10  687d.b45c.526c   172.19.10.11                             10/13/26 20:15:14          None                          NA
 
WLCv#"""

FAILED = LIVE.replace(
    "172.19.5.10                              10/13/26 07:27:17          None                          NA",
    "172.19.5.9                               10/13/26 07:27:17          DTLS handshake failure        10/13/26 06:58:02")


def test_parses_rows_keyed_on_the_ethernet_mac():
    """The rest of the AP chain keys on the Ethernet MAC, so this does too."""
    rows, unreadable, expected = parse_ap_discovery_stats(LIVE)
    assert unreadable == 0
    assert expected == 2
    entry = rows[AP_MAC]
    assert entry["radio_mac"] == "3891.b70f.2600"
    assert entry["ip_address"] == "172.19.5.10"
    assert entry["last_success_time"] == "10/13/26 07:27:17"
    assert entry["last_failure_type"] == "None"
    assert entry["last_failure_time"] == "NA"


def test_a_multi_word_failure_type_is_kept_whole():
    """The column boundary is two spaces, not one."""
    rows, _u, _e = parse_ap_discovery_stats(FAILED)
    assert rows[AP_MAC]["last_failure_type"] == "DTLS handshake failure"
    assert rows[AP_MAC]["last_failure_time"] == "10/13/26 06:58:02"


@pytest.mark.parametrize("bad", [None, "", "\x00 garbage", "no table"])
def test_parser_never_raises(bad):
    rows, _u, _e = parse_ap_discovery_stats(bad)
    assert rows == {}


@pytest.fixture
def served(monkeypatch):
    def _serve(text):
        import radkit_cli
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s, **k: text)
    return _serve


def _ctx():
    return types.SimpleNamespace(service=object(), payload={"mac": AP_MAC},
                                 state={})


def test_no_failure_is_not_reported(served):
    """A successful discovery is already evident from the AP being joined."""
    from checks.ap_wlc import ApWlcApDiscovery

    served(LIVE)
    r = ApWlcApDiscovery(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK


def test_a_failure_reports_type_time_and_the_address_at_the_time(served):
    from checks.ap_wlc import ApWlcApDiscovery

    served(FAILED)
    r = ApWlcApDiscovery(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "DTLS handshake failure" in r.message
    assert "10/13/26 06:58:02" in r.message
    # The address it held then, which is what makes the failure actionable.
    assert "172.19.5.9" in r.message


def test_an_ap_absent_from_the_table_is_not_a_finding(served):
    """Whether it should have discovered is ApWlcApState's question."""
    from checks.ap_wlc import ApWlcApDiscovery

    served(LIVE)
    ctx = types.SimpleNamespace(service=object(),
                                payload={"mac": "dead.beef.0001"}, state={})
    r = ApWlcApDiscovery(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
