"""Offline tests for the NETCONF client and the WLC join checks.

The fixtures in tests/fixtures are verbatim `rpc-reply` bodies captured from a
9800 running 17.15.5, so these exercise the real shapes the parser meets --
including the ones that are easy to get wrong offline: a YANG list that
arrives as a single entry, empty leaves, and the stub record `ap-history`
returns for a MAC it does not know.

No device is touched. The session is replaced with a stub that answers from
the fixture matching the filter.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURES = Path(__file__).parent / "fixtures"

EMPTY = ('<?xml version="1.0" encoding="UTF-8"?>'
         '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
         '<data></data></rpc-reply>')


class StubSession:
    """Answers a subtree filter from a fixture, the way the 9800 would.

    Matches on the list element in the filter rather than on the whole
    string, so a test can assert the *key* was sent correctly without the
    stub having to reproduce the device's key matching.
    """

    def __init__(self, mapping, record=None):
        self._mapping = mapping
        self.filters = record if record is not None else []

    def get_subtree(self, xml_filter):
        import xml.etree.ElementTree as ET
        from netconf_client import to_dict
        self.filters.append(xml_filter)
        for marker, fixture in self._mapping.items():
            if marker in xml_filter:
                text = (FIXTURES / fixture).read_text() if fixture else EMPTY
                return to_dict(ET.fromstring(text))
        return to_dict(ET.fromstring(EMPTY))


ALL = {
    "ethernet-mac-wtp-mac-map": "wlc_eth_mac_map.xml",
    "capwap-data": "wlc_capwap_data.xml",
    "ap-join-stats": "wlc_ap_join_stats.xml",
    "ap-history": "wlc_ap_history.xml",
}


def test_netconf_mac_conversion():
    """Every MAC form the app holds converts to the colon form the 9800 keys on.

    The single most load-bearing conversion here: a dotted MAC in a filter is
    not rejected by the device, it simply matches nothing -- which reads as
    "this AP is not joined".
    """
    from netconf_client import dotted_mac, netconf_mac
    assert netconf_mac("3891.b70f.2600") == "38:91:b7:0f:26:00"
    assert netconf_mac("38:91:B7:0F:26:00") == "38:91:b7:0f:26:00"
    assert netconf_mac("3891-B70F-2600") == "38:91:b7:0f:26:00"
    assert dotted_mac("38:91:b7:0f:26:00") == "3891.b70f.2600"
    # Not twelve hex digits: returned as given, so it fails visibly on the
    # device rather than being silently mangled into a valid-looking MAC.
    assert netconf_mac("bogus") == "bogus"
    assert netconf_mac("") == ""


def test_keyed_filter_uses_colon_mac():
    """The filter the client sends carries the colon form, not the dotted one."""
    from netconf_client import ap_capwap_data
    sent = []
    ap_capwap_data(StubSession(ALL, sent), "3891.b70f.2600")
    assert "<wtp-mac>38:91:b7:0f:26:00</wtp-mac>" in sent[0]
    assert "3891.b70f.2600" not in sent[0]


def test_history_is_keyed_on_ethernet_mac():
    """`ap-history` is keyed on the Ethernet MAC -- the one list that is.

    Sending the radio MAC here returns empty, which would read as an AP that
    has never joined.
    """
    from netconf_client import ap_history
    sent = []
    ap_history(StubSession(ALL, sent), "b811.4b0e.2630")
    assert "<ethernet-mac>b8:11:4b:0e:26:30</ethernet-mac>" in sent[0]


def test_capwap_record_fields():
    """The fields the registration check reports all resolve from real XML."""
    from netconf_client import ap_capwap_data, dig
    rec = ap_capwap_data(StubSession(ALL), "3891.b70f.2600")
    assert dig(rec, "name") == "AP-002"
    assert dig(rec, "ip-addr") == "172.19.5.10"
    assert dig(rec, "ap-state", "ap-operation-state") == "registered"
    assert dig(rec, "ap-mode-data", "ap-fabric-data", "is-fabric-ap") == "true"
    assert dig(rec, "device-detail", "wtp-version", "sw-version") == "17.15.5.36"
    assert dig(rec, "tag-info", "resolved-tag-info",
               "resolved-site-tag") == "ST_jalej_Insurgen_35a54_0"
    # Four levels down and absent on an AP that never joined: must not raise.
    assert dig(rec, "no", "such", "path", default="fallback") == "fallback"


def test_single_entry_list_reads_as_a_list():
    """A YANG list with one entry must not be iterated as a dict.

    ElementTree cannot tell a one-entry list from a container, so without
    `as_list` a single join event would iterate its own leaf names.
    """
    from netconf_client import ap_history, as_list, dig
    rec = ap_history(StubSession(ALL), "b811.4b0e.2630")
    events = as_list(dig(rec, "ewlc-ap-state-ptr"))
    assert len(events) == 20
    assert all(isinstance(e, dict) for e in events)
    assert as_list(None) == [] and as_list("") == []
    assert as_list({"a": 1}) == [{"a": 1}]


def test_absent_ap_returns_empty_not_error():
    """An AP the controller does not know is {} -- an answer, not a failure."""
    from netconf_client import (ap_capwap_data, ap_join_stats,
                                radio_mac_for_ethernet)
    none = StubSession({})
    assert ap_capwap_data(none, "dead.beef.0001") == {}
    assert ap_join_stats(none, "dead.beef.0001") == {}
    assert radio_mac_for_ethernet(none, "dead.beef.0001") == ""


def test_history_stub_for_unknown_mac_is_discarded():
    """`ap-history` answers an unknown MAC with a stub, which must not count.

    The device echoes the MAC back with an empty name and an all-zero radio
    MAC. Taken at face value that is an AP with a clean history.
    """
    from netconf_client import ap_history
    stub = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><data>'
            '<ap-global-oper-data xmlns="http://cisco.com/ns/yang/'
            'Cisco-IOS-XE-wireless-ap-global-oper"><ap-history>'
            '<ethernet-mac>de:ad:be:ef:00:01</ethernet-mac><ap-name></ap-name>'
            '<wtp-mac>00:00:00:00:00:00</wtp-mac>'
            '</ap-history></ap-global-oper-data></data></rpc-reply>')

    class Stub:
        def get_subtree(self, _f):
            import xml.etree.ElementTree as ET
            from netconf_client import to_dict
            return to_dict(ET.fromstring(stub))

    assert ap_history(Stub(), "dead.beef.0001") == {}


def _ctx(**state):
    """A RunContext stand-in carrying what the WLC checks read."""
    from types import SimpleNamespace
    ctx = SimpleNamespace()
    ctx.service = None
    ctx.payload = {"mac": "b811.4b0e.2630"}
    ctx.state = {"edge": True, "ap_ip": "172.19.5.10",
                 "ap_wlc_candidates": [("wlc", "10.0.0.1", "w0")]}
    ctx.state.update(state)
    return ctx


def _checks():
    from checks.ap_wlc_join import (
        ApWlcApJoinHistory, ApWlcApJoinPhases, ApWlcApRegistration,
        ApWlcApTags, ApWlcNetconfGate)
    return [ApWlcNetconfGate(), ApWlcApRegistration(), ApWlcApJoinPhases(),
            ApWlcApTags(), ApWlcApJoinHistory()]


def test_every_check_skips_when_netconf_unconfigured(monkeypatch):
    """With no credentials the step disappears, rather than failing.

    This is the guarantee that adding NETCONF changed nothing for an operator
    who has not configured it.
    """
    from checks.base import CheckStatus
    monkeypatch.delenv("NETCONF_USERNAME", raising=False)
    monkeypatch.delenv("NETCONF_PASSWORD", raising=False)
    for check in _checks():
        result = check.run(_ctx())
        assert result.status == CheckStatus.SKIP, check.name
        assert "NETCONF is not configured" in result.message


def test_unreachable_controller_does_not_stop_the_chain(monkeypatch):
    """A controller that will not answer must not skip the other 36 checks.

    These checks run at position 9 of 46. A FAIL from an _ApCheck sets
    `ap_stop`, which skips everything after it -- so failing here because of
    NETCONF would discard every edge-side ACL, SGACL and LISP finding, none
    of which depend on NETCONF at all.
    """
    import netconf_client
    from checks.ap_wlc_join import ApWlcNetconfGate
    from checks.base import CheckStatus

    monkeypatch.setenv("NETCONF_USERNAME", "u")
    monkeypatch.setenv("NETCONF_PASSWORD", "p")

    def refuse(_host, _user, _pw, _port=830):
        class Dead:
            def get_subtree(self, _f):
                raise netconf_client.NetconfError("connection refused")
        return Dead()

    monkeypatch.setattr(netconf_client, "session_for", refuse)
    ctx = _ctx()
    result = ApWlcNetconfGate().run(ctx)
    assert result.status == CheckStatus.WARN
    assert ctx.state.get("ap_stop") is None
    assert ctx.state.get("ap_netconf_stop")


def _wire(monkeypatch, mapping):
    """Point the checks at fixture-backed sessions instead of a device."""
    import netconf_client
    monkeypatch.setenv("NETCONF_USERNAME", "u")
    monkeypatch.setenv("NETCONF_PASSWORD", "p")
    monkeypatch.setattr(netconf_client, "session_for",
                        lambda *a, **k: StubSession(mapping))


def test_joined_ap_reports_registered(monkeypatch):
    """The happy path, end to end, off the captured record."""
    from checks.ap_wlc_join import ApWlcApRegistration, ApWlcNetconfGate
    from checks.base import CheckStatus
    _wire(monkeypatch, ALL)
    ctx = _ctx()
    assert ApWlcNetconfGate().run(ctx).status == CheckStatus.OK
    assert ctx.state["ap_radio_mac"] == "38:91:b7:0f:26:00"
    result = ApWlcApRegistration().run(ctx)
    assert result.status == CheckStatus.OK
    assert "AP-002 is registered" in result.message
    assert "C9130AXI-A" in result.message


def test_address_disagreement_is_reported(monkeypatch):
    """The controller's address for the AP against the edge's.

    A disagreement means every address-based check upstream was evaluated
    against a different address than the controller is using.
    """
    from checks.ap_wlc_join import ApWlcApRegistration, ApWlcNetconfGate
    from checks.base import CheckStatus
    _wire(monkeypatch, ALL)
    ctx = _ctx(ap_ip="172.19.5.99")
    ApWlcNetconfGate().run(ctx)
    result = ApWlcApRegistration().run(ctx)
    assert result.status == CheckStatus.WARN
    assert "172.19.5.99" in result.message and "172.19.5.10" in result.message


def test_join_phases_separate_history_from_current_state(monkeypatch):
    """A sticky failure leaf on a joined AP is history, not a fault.

    The captured AP is joined and still carries `jf-dtls-alert-from-peer`
    from an earlier image upgrade. Grading on that leaf alone would flag a
    healthy AP.
    """
    from checks.ap_wlc_join import ApWlcApJoinPhases, ApWlcNetconfGate
    from checks.base import CheckStatus
    _wire(monkeypatch, ALL)
    ctx = _ctx()
    ApWlcNetconfGate().run(ctx)
    result = ApWlcApJoinPhases().run(ctx)
    assert result.status == CheckStatus.OK
    assert "currently joined" in result.message
    assert "the AP has since joined" in result.message


def test_history_separates_benign_rejoins_from_faults(monkeypatch):
    """Image-upgrade rejoins are normal; heartbeat expiry is not.

    The captured history holds both. Counting every disjoin would call a
    healthy upgrade a fault; counting none would hide the flap.
    """
    from checks.ap_wlc_join import ApWlcApJoinHistory, ApWlcNetconfGate
    from checks.base import CheckStatus
    _wire(monkeypatch, ALL)
    ctx = _ctx()
    ApWlcNetconfGate().run(ctx)
    result = ApWlcApJoinHistory().run(ctx)
    assert result.status == CheckStatus.WARN
    assert "Heart beat timer expiry ×6" in result.message
    assert "Image Download Success" not in result.message.split("Disconnects")[1]


def test_unjoined_ap_names_the_phase_it_is_stuck_in(monkeypatch):
    """An AP that discovers but never completes DTLS is stuck in DTLS.

    The earliest failing phase is the one that matters: a join failure
    downstream of a DTLS that never succeeded says nothing.
    """
    from checks.ap_wlc_join import ApWlcApJoinPhases
    from checks.base import CheckStatus
    import netconf_client

    stuck = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><data>'
             '<ap-global-oper-data xmlns="http://cisco.com/ns/yang/'
             'Cisco-IOS-XE-wireless-ap-global-oper"><ap-join-stats>'
             '<wtp-mac>38:91:b7:0f:26:00</wtp-mac>'
             '<ap-join-info><is-joined>false</is-joined>'
             '<num-join-req-recvd>0</num-join-req-recvd>'
             '<last-join-failure-type>jf-none</last-join-failure-type>'
             '<last-config-failure-type>cf-none</last-config-failure-type>'
             '</ap-join-info>'
             '<ap-discovery-info><num-discovery-req-recvd>9'
             '</num-discovery-req-recvd><num-succ-disc-resp-sent>9'
             '</num-succ-disc-resp-sent>'
             '<last-disc-failure-type>disc-fail-none</last-disc-failure-type>'
             '</ap-discovery-info>'
             '<dtls-sess-info><ctrl-dtls-setup-req>9</ctrl-dtls-setup-req>'
             '<ctrl-dtls-success>0</ctrl-dtls-success>'
             '<ctrl-dtls-failure>9</ctrl-dtls-failure>'
             '<ctrl-dtls-failure-type>dtls-cert-verify-fail'
             '</ctrl-dtls-failure-type></dtls-sess-info>'
             '</ap-join-stats></ap-global-oper-data></data></rpc-reply>')

    class Stub:
        def get_subtree(self, _f):
            import xml.etree.ElementTree as ET
            from netconf_client import to_dict
            return to_dict(ET.fromstring(stuck))

    monkeypatch.setenv("NETCONF_USERNAME", "u")
    monkeypatch.setenv("NETCONF_PASSWORD", "p")
    monkeypatch.setattr(netconf_client, "session_for", lambda *a, **k: Stub())

    ctx = _ctx(ap_radio_mac="38:91:b7:0f:26:00",
               ap_netconf_wlcs=[("wlc", "10.0.0.1")])
    result = ApWlcApJoinPhases().run(ctx)
    assert result.status == CheckStatus.WARN
    assert "not joined" in result.message
    assert "stuck in DTLS" in result.message
    assert "dtls-cert-verify-fail" in result.message
