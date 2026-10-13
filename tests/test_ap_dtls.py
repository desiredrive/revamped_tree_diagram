"""`show wireless dtls connections` — the parser and the check on it."""

import types

import pytest

from checks.base import CheckStatus
from wirelessmodules.accesspointinfo import (
    parse_dtls_connections, control_session_for,
)

WLC = "wlc-jalejand-cisco-com"
NAME = "AP-002"

HEADER = ("AP Name                          Local Port     Peer IP       "
          "Peer Port  Version     Ciphersuite\n" + "-" * 96 + "\n")

LIVE = HEADER + (
    "AP-002                           Capwap_Ctrl   172.19.5.10    5272  "
    "     DTLSv1.2   TLS_NUM_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n")

EMPTY = HEADER + " \nWLCv#"


def test_parses_the_session_fields():
    rows, unreadable = parse_dtls_connections(LIVE)
    assert unreadable == 0
    assert len(rows) == 1
    row = rows[0]
    assert row["ap_name"] == NAME
    assert row["local_port"] == "Capwap_Ctrl"
    assert row["peer_ip"] == "172.19.5.10"
    assert row["peer_port"] == "5272"
    assert row["version"] == "DTLSv1.2"
    assert row["ciphersuite"] == "TLS_NUM_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_the_control_session_is_picked_out_of_several():
    """An AP tunnelling client traffic also holds a data session."""
    both = LIVE + (
        "AP-002                           Capwap_Data   172.19.5.10    5272  "
        "     DTLSv1.2   TLS_NUM_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n")
    rows, _u = parse_dtls_connections(both)
    assert len(rows) == 2
    assert control_session_for(rows, NAME)["local_port"] == "Capwap_Ctrl"


def test_a_data_session_alone_is_not_a_control_session():
    data_only = HEADER + (
        "AP-002                           Capwap_Data   172.19.5.10    5272  "
        "     DTLSv1.2   TLS_NUM_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n")
    rows, _u = parse_dtls_connections(data_only)
    assert control_session_for(rows, NAME) is None


def test_another_aps_session_is_not_this_aps():
    rows, _u = parse_dtls_connections(LIVE)
    assert control_session_for(rows, "AP-999") is None


@pytest.mark.parametrize("bad", [None, "", "\x00 garbage", "no table"])
def test_parser_never_raises(bad):
    rows, _u = parse_dtls_connections(bad)
    assert rows == []


@pytest.fixture
def served(monkeypatch):
    def _serve(text):
        import radkit_cli
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s, **k: text)
    return _serve


def _ctx(ap_ip=None):
    state = {"ap_wlc_ap_name": NAME}
    if ap_ip:
        state["ap_ip"] = ap_ip
        state["ap_ip_source"] = "device-tracking + DHCP snooping"
    return types.SimpleNamespace(service=object(),
                                 payload={"mac": "b811.4b0e.2630"},
                                 state=state)


def test_an_established_session_reports_its_parameters(served):
    from checks.ap_wlc import ApWlcApDtls

    served(LIVE)
    r = ApWlcApDtls(WLC, "wlc0").run_ap(_ctx("172.19.5.10"))
    assert r.status is CheckStatus.OK
    assert "DTLSv1.2" in r.message
    assert "5272" in r.message
    assert "TLS_NUM_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in r.message


def test_no_session_is_a_warning_that_does_not_stop_the_run(served):
    """A fabric fault does not stop the run: the checks around this one still
    explain the path the AP was trying to use."""
    from checks.ap_wlc import ApWlcApDtls

    served(EMPTY)
    ctx = _ctx()
    r = ApWlcApDtls(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "no DTLS session" in r.message
    assert "ap_stop" not in ctx.state


def test_a_session_to_another_address_than_sisf_saw_is_flagged(served):
    """One of the two is stale."""
    from checks.ap_wlc import ApWlcApDtls

    served(LIVE)
    r = ApWlcApDtls(WLC, "wlc0").run_ap(_ctx("172.19.5.99"))
    assert r.status is CheckStatus.WARN
    assert "172.19.5.10" in r.message and "172.19.5.99" in r.message


def test_without_a_sisf_address_the_peer_is_not_graded(served):
    """Nothing to compare against is not a disagreement."""
    from checks.ap_wlc import ApWlcApDtls

    served(LIVE)
    r = ApWlcApDtls(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK


def test_an_ap_on_another_controller_is_skipped(served, monkeypatch):
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApDtls

    served(LIVE)
    monkeypatch.setattr(mod, "_resolve_ap_name", lambda c, h, s: "")
    r = ApWlcApDtls(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.SKIP
