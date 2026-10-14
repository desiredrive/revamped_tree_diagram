"""Is the AP's radio MAC registered on each reachable control plane?

The controller registers it into the INFRA_VN L2 instance to every control
plane it holds a session with, so a control plane with no record holds no
record of the AP at all. Read from each control plane, not the controller.

Every sample below is the live output from Border1 and Border2 in the lab.
"""

import types

from checks.base import CheckStatus
from checks.ap_radio_registration import (
    ApRadioMacRegistration, ApRadioMacRegistrationVerdict,
    decode_wlc_metadata)


MAC = "3891.b70f.2600"

# Border1, `... ethernet server 3891.b70f.2600 internal`. The `WLC data
# length` block and its payload are the ONLY difference from the plain form.
REGISTERED = """
LISP Site Registration Information

Site name: site_uci
  EID-prefix: 3891.b70f.2600/48 instance-id 8188
    First registered:     03:39:12
    Last registered:      03:39:12
    State:                complete
    Registration errors:
      Authentication failures:   0
      Allowed locators mismatch: 0
    ETR 10.31.136.74:59703
      last registered 03:39:12, no proxy-reply, no map-notify
      state complete, no security-capability
      sourced by reliable transport
      WLC AP bit: Set
      WLC data length: 34
        00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01
        00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00
        00 00
      Locator      Local  State      Pri/Wgt  Scope       RDP
      172.19.1.68  yes    up           0/0    IPv4 none   [-]
"""

# Border2, which holds no session to the controller and so no registration.
NOT_FOUND = (
    "% Could not find instance-id 8188 EID 3891.b70f.2600 in site database.")


def _check(monkeypatch, outputs, edge_loopback="172.19.1.68"):
    """The check with the CLI read stubbed. `outputs` maps command substring
    to the device's answer, so the internal/plain fallback can be exercised."""
    import checks.ap_radio_registration as m

    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(hostname=h)))

    def fake(host, cmd, _svc):
        for frag, out in outputs.items():
            if frag in cmd:
                return out
        return None
    monkeypatch.setattr("radkit_cli.get_any_single_output", fake)

    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    chk = ApRadioMacRegistration("border1", "10.31.136.64", MAC, 8188,
                                 "catc", "cp-1", edge_loopback)
    return chk.run(ctx), ctx


def test_a_healthy_registration_passes(monkeypatch):
    """Border1's actual state: complete, reliable transport, AP bit Set,
    ETR matching the edge's Loopback0, locator up, metadata populated."""
    r, ctx = _check(monkeypatch, {"internal": REGISTERED})
    assert r.status is CheckStatus.OK
    assert r.data["state"] == "complete"
    assert r.data["etrs"] == ["10.31.136.74"]
    assert r.data["locators_up"] == ["172.19.1.68"]
    assert ctx.state["ap_radio_reg"]["border1"] is True


def test_the_metadata_carries_the_ap_address_sgt_and_vnid(monkeypatch):
    """The three fields the `internal` form exists to provide."""
    r, _ = _check(monkeypatch, {"internal": REGISTERED})
    assert r.data["metadata"]["ap_ip"] == "172.19.5.10"
    assert r.data["metadata"]["sgt"] == 3
    assert r.data["metadata"]["l3_vnid"] == 4097
    assert "172.19.5.10" in r.message and "SGT 3" in r.message


def test_a_control_plane_with_no_record_is_reported(monkeypatch):
    """Border2's actual state. The device ANSWERED -- it holds nothing --
    which is a different thing from the read having failed."""
    r, ctx = _check(monkeypatch, {"3891.b70f.2600": NOT_FOUND})
    assert r.status is CheckStatus.WARN
    assert "holds no registration" in r.message
    assert r.data["registered"] is False
    assert ctx.state["ap_radio_reg"]["border1"] is False


def test_the_locator_is_graded_against_the_edge_not_the_etr(monkeypatch):
    """On a radio-MAC registration the ETR is the CONTROLLER's WMI -- the
    controller is what registers it -- and the edge's Loopback0 appears in
    the locator table. Grading the ETR against the edge's Lo0 failed the
    healthy record Border1 actually holds."""
    r, _ = _check(monkeypatch, {"internal": REGISTERED},
                  edge_loopback="172.19.1.99")
    assert r.status is CheckStatus.WARN
    assert "not the edge's Loopback0 172.19.1.99" in r.message
    # The ETR is still the WMI, and that is not itself a fault.
    assert r.data["etrs"] == ["10.31.136.74"]


def test_an_incomplete_state_is_a_fault(monkeypatch):
    r, _ = _check(monkeypatch,
                  {"internal": REGISTERED.replace("State:                complete",
                                                  "State:                incomplete")})
    assert r.status is CheckStatus.WARN
    assert "not complete" in r.message


def test_auth_failures_only_count_while_the_state_is_not_complete(monkeypatch):
    """A complete registration with historic failures is a key that WAS
    wrong and has since been fixed. Reporting it every run is noise."""
    withfails = REGISTERED.replace("Authentication failures:   0",
                                   "Authentication failures:   7")
    r, _ = _check(monkeypatch, {"internal": withfails})
    assert r.status is CheckStatus.OK
    assert r.data["auth_failures"] == 7

    both = withfails.replace("State:                complete",
                             "State:                incomplete")
    r2, _ = _check(monkeypatch, {"internal": both})
    assert r2.status is CheckStatus.WARN
    assert "7 authentication failure" in r2.message


def test_a_cleared_wlc_ap_bit_is_a_fault(monkeypatch):
    r, _ = _check(monkeypatch,
                  {"internal": REGISTERED.replace("WLC AP bit: Set",
                                                  "WLC AP bit: Clear")})
    assert r.status is CheckStatus.WARN
    assert "WLC AP bit is Clear" in r.message


def test_a_registration_not_over_reliable_transport_is_a_fault(monkeypatch):
    r, _ = _check(monkeypatch,
                  {"internal": REGISTERED.replace(
                      "      sourced by reliable transport\n", "")})
    assert r.status is CheckStatus.WARN
    assert "not sourced by reliable transport" in r.message


def test_all_zero_metadata_is_a_fault(monkeypatch):
    """The controller sent the field but filled none of it -- a different
    fault from never having sent it."""
    zeros = REGISTERED
    for ln in ("00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01",
               "00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00"):
        zeros = zeros.replace(ln, " ".join(["00"] * 16))
    r, _ = _check(monkeypatch, {"internal": zeros})
    assert r.status is CheckStatus.WARN
    assert "bytes of zeros" in r.message


def test_the_plain_form_is_the_fallback_and_skips_the_metadata(monkeypatch):
    """Some versions do not support `internal`. Its fields are then unread,
    which is reported rather than graded as absent metadata."""
    plain = REGISTERED
    for frag in ("      WLC data length: 34\n",
                 "        00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01\n",
                 "        00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00\n",
                 "        00 00\n"):
        plain = plain.replace(frag, "")
    r, _ = _check(monkeypatch, {"internal": "% Invalid input detected",
                                "3891.b70f.2600": plain})
    assert r.data["command_form"] == "plain"
    assert "does not support the `internal` form" in r.message
    # The metadata is NOT reported as missing -- it was never asked for.
    assert "carries no WLC metadata" not in r.message


def _verdict(reg):
    ctx = types.SimpleNamespace(service=object(), payload={},
                                state={"ap_radio_reg": reg})
    return ApRadioMacRegistrationVerdict(MAC, 8188).run(ctx), ctx


def test_registered_nowhere_is_a_total_failure():
    """The one state that stops the run: no control plane can answer a
    map-request for the radio MAC, so nothing downstream can succeed."""
    r, ctx = _verdict({"border1": False, "border2": False})
    assert r.status is CheckStatus.FAIL
    assert "registered on none" in r.message
    assert ctx.state["ap_stop"]


def test_registered_on_some_warns_and_does_not_stop_the_run():
    """The lab's actual state: Border1 holds it, Border2 does not. The
    fabric still resolves the AP, so this is a fault and not an outage."""
    r, ctx = _verdict({"border1": True, "border2": False})
    assert r.status is CheckStatus.WARN
    assert "border1" in r.message and "border2" in r.message
    assert "ap_stop" not in ctx.state


def test_registered_everywhere_passes():
    r, _ = _verdict({"border1": True, "border2": True})
    assert r.status is CheckStatus.OK


def test_no_control_plane_asked_skips():
    r, _ = _verdict({})
    assert r.status is CheckStatus.SKIP


def test_the_metadata_decoder_reads_the_live_payload():
    """Bytes 20-23 are the SGT as a four-byte field. The existing
    extract_ip_and_sgt_fixed_positions reads two bytes at offset 20 -- the
    high half -- and so returns 0 for every SGT below 65536. Its IP offset
    is right and agrees with this one."""
    hx = ("00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01 "
          "00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00  00 00")
    assert decode_wlc_metadata(hx) == {
        "ap_ip": "172.19.5.10", "l3_vnid": 4097, "sgt": 3, "all_zero": False}


def test_the_decoder_survives_an_absent_payload():
    assert decode_wlc_metadata(None)["ap_ip"] is None
    assert decode_wlc_metadata("")["all_zero"] is None


# --------------------------------------------------------------------------
# Queuing. One registration check per resolved control plane, then the
# verdict -- and all of it before the LISP session trigger, which is what
# explains a control plane that holds no registration.
# --------------------------------------------------------------------------


def _trigger_ctx(**over):
    state = {
        "ap_wlc_radio_mac": MAC,
        "ap_wlc_l2_vnid": "8188",
        "ap_wlc_cp_planes": [("172.19.1.64", "border1", "10.31.136.64"),
                             ("172.19.1.65", "border2", "10.31.136.65")],
        "ap_wlc_cp_nodes": {"172.19.1.64": "apcp-1", "border1": "apcp-1",
                            "172.19.1.65": "apcp-2", "border2": "apcp-2"},
        "xtr_loopback": "172.19.1.68",
        "catc_name": "mxc-dnac5",
    }
    state.update(over)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


def _trigger(ctx):
    from checks.ap_radio_registration import ApRadioMacRegistrationTrigger
    return ApRadioMacRegistrationTrigger("wlc-1", "wlc").run(ctx)


def test_one_registration_check_per_control_plane_then_the_verdict():
    r = _trigger(_trigger_ctx())
    q = r.data["queue_checks"]
    assert [type(c).__name__ for c in q] == [
        "ApRadioMacRegistration", "ApRadioMacRegistration",
        "ApRadioMacRegistrationVerdict"]
    # Each lands on the node the edge already drew for that control plane.
    assert [c.target_node_id for c in q[:2]] == ["apcp-1", "apcp-2"]


def test_the_edge_loopback_is_passed_through_for_the_locator_check():
    q = _trigger(_trigger_ctx()).data["queue_checks"]
    assert all(c.edge_loopback == "172.19.1.68" for c in q[:2])


def test_the_management_ip_is_used_not_the_rloc():
    """Profiling goes through Catalyst Center by management address; no
    device is managed at the RLOC."""
    q = _trigger(_trigger_ctx()).data["queue_checks"]
    assert [c.cp_mgmt for c in q[:2]] == ["10.31.136.64", "10.31.136.65"]


def test_an_unknown_radio_mac_skips():
    assert _trigger(_trigger_ctx(ap_wlc_radio_mac="")).status is \
        CheckStatus.SKIP


def test_no_l2_instance_skips():
    assert _trigger(_trigger_ctx(ap_wlc_l2_vnid=None)).status is \
        CheckStatus.SKIP


def test_no_resolved_control_plane_skips():
    assert _trigger(_trigger_ctx(ap_wlc_cp_planes=[])).status is \
        CheckStatus.SKIP


def test_the_registration_is_read_before_the_session_trigger():
    """A control plane holding no registration is what the session flow
    exists to explain, so reading it afterwards inverts the causality."""
    import inspect
    from checks import ap_wlc
    src = inspect.getsource(ap_wlc.ApWlcApStateProfile)
    assert src.index("ApRadioMacRegistrationTrigger(hostname, node)") < \
        src.index("ApWlcCpLispSessionTrigger(hostname, node)")
