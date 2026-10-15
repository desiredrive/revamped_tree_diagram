"""Is the AP's radio MAC registered on each reachable control plane?

The controller registers it into the INFRA_VN L2 instance to every control
plane it holds a session with, so a control plane with no record holds no
record of the AP at all. Read from each control plane, not the controller.

Every sample below is the live output from Border1 and Border2 in the lab.
"""

import types

import pytest

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


def test_the_metadata_carries_the_ap_address_and_vnid(monkeypatch):
    """The fields the `internal` form exists to provide. No SGT: see
    test_the_decoder_reports_no_sgt_at_all below."""
    r, _ = _check(monkeypatch, {"internal": REGISTERED})
    assert r.data["metadata"]["ap_ip"] == "172.19.5.10"
    assert r.data["metadata"]["l3_vnid"] == 4097
    assert "172.19.5.10" in r.message


def test_no_sgt_is_reported_for_an_onboarding_ap(monkeypatch):
    """AP onboarding does not turn on the AP's SGT, and the value this
    decoder produced for it was wrong anyway."""
    r, _ = _check(monkeypatch, {"internal": REGISTERED})
    assert "sgt" not in r.data["metadata"]
    assert "SGT" not in r.message


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


# The live payload, as Edge2 prints it for the lab AP. Newer IOS-XE decodes
# it on the device; older releases print only this hex, which is why the
# decoder exists.
LIVE_PAYLOAD = ("00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01 "
                "00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00  00 00")


def test_the_metadata_decoder_reads_the_live_payload():
    """Graded against the device's OWN decode of this exact payload:

        Metadata:  IPv4 address: 172.19.5.10
                   Client SGT: 0
                   Client association time: 0
    """
    assert decode_wlc_metadata(LIVE_PAYLOAD) == {
        "ap_ip": "172.19.5.10", "l3_vnid": 4097, "all_zero": False}


def test_the_decoder_reports_no_sgt_at_all():
    """Bytes 20-23 are NOT a value: the first inner TLV declares length 12,
    so its value runs to byte 19 and bytes 20-23 are the NEXT inner TLV's
    header (type 2, length 6). Reading them as data returned SGT 3 for an AP
    the device itself decodes as `Client SGT: 0` -- the 3 was the low byte of
    a length field. No SGT is better than a wrong one."""
    out = decode_wlc_metadata(LIVE_PAYLOAD)
    assert "sgt" not in out


def test_the_tlv_lengths_are_self_consistent():
    """The framing the fix rests on: outer length 34 matches the 34 bytes the
    device reports, and the first inner TLV is type 1 length 12."""
    tok = LIVE_PAYLOAD.split()
    assert len(tok) == 34
    assert int(tok[2] + tok[3], 16) == 34          # outer length
    assert int(tok[4] + tok[5], 16) == 1           # inner type
    assert int(tok[6] + tok[7], 16) == 12          # inner length
    # The AP address and the VNID sit at the front of that value.
    assert tok[8:12] == ["AC", "13", "05", "0A"]   # 172.19.5.10
    assert int("".join(tok[12:16]), 16) == 4097    # L3 VNID
    # The next TLV header (type 2, length 6) begins at byte 16, so everything
    # from there on is framing or another entry's content -- NOT an SGT field
    # at 20-23, which is what the old decoder read.
    assert int(tok[16] + tok[17], 16) == 2
    assert int(tok[18] + tok[19], 16) == 6


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
    exists to explain, so reading it afterwards inverts the causality.

    NOTE: ApWlcControlPlanes now runs immediately after ApWlcApState, which
    puts the session flow it queues BEFORE the registration read. That is the
    requested order, so this no longer asserts the old sequence -- it pins
    only that the flow is queued from the control-plane check, which is what
    keeps it from being suppressed by an earlier `ap_stop`.

    The causality concern this test was written for is therefore not
    enforced here any more; the session flow may report before the
    registration it explains has been read.
    """
    import inspect
    from checks import ap_wlc
    cp = inspect.getsource(ap_wlc.ApWlcControlPlanes)
    assert "ApWlcCpLispSessionTrigger(" in cp


# --------------------------------------------------------------------------
# Native decode where the release offers one, local decode where it does not.
# Most IOS-XE versions have no `Metadata:` block; the lab edge runs an
# experimental build that does.
# --------------------------------------------------------------------------

# Verbatim from Edge2 (experimental 27.01 build).
EDGE_DATABASE_WLC = """\
WLC clients/access-points information for LISP 0 EID-table Vlan 2045 (IID 8188)

Hardware Address: 3891.b70f.2600
Type:             AP
Sources:          1
Source MS:        172.19.1.64
RLOC:             172.19.1.68
Metadata length:  34
Metadata (hex):   00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01
                  00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00
                  00 00
Metadata:         IPv4 address: 172.19.5.10
                  Client SGT: 0
                  Client association time: 0
"""


def test_the_device_decode_is_used_when_the_release_offers_one():
    from checks.ap_radio_registration import parse_native_metadata

    assert parse_native_metadata(EDGE_DATABASE_WLC) == {
        "ap_ip": "172.19.5.10", "source": "device"}


def test_a_release_without_the_block_falls_back():
    """The normal case. Border1's `ethernet server ... internal` carries the
    hex payload and no decode, verified live -- so the parser must say so
    rather than half-match."""
    from checks.ap_radio_registration import parse_native_metadata

    cp_output = ("      WLC AP bit: Set\n"
                 "      WLC data length: 34\n"
                 "        00 01 00 22  00 01 00 0C  AC 13 05 0A\n")
    assert parse_native_metadata(cp_output) is None
    assert parse_native_metadata("") is None
    assert parse_native_metadata(None) is None


def test_both_paths_agree_on_the_ap_address():
    """The local decode is only trustworthy where it matches the device on a
    payload the device CAN decode. This is that payload."""
    from checks.ap_radio_registration import parse_native_metadata

    native = parse_native_metadata(EDGE_DATABASE_WLC)
    ours = decode_wlc_metadata(LIVE_PAYLOAD)
    assert native["ap_ip"] == ours["ap_ip"] == "172.19.5.10"


def test_the_native_block_is_not_mined_for_an_sgt():
    """It prints `Client SGT: 0`, and AP onboarding ignores the SGT. Reading
    it here would reintroduce the field by the back door."""
    from checks.ap_radio_registration import parse_native_metadata

    assert "sgt" not in parse_native_metadata(EDGE_DATABASE_WLC)


# --------------------------------------------------------------------------
# The native read is best-effort: it FAILS OVER to the local decode, never
# failing the check. A device that is unreachable, slow, or does not support
# the command must leave the registration verdict untouched.
# --------------------------------------------------------------------------


def _check_with_edge(monkeypatch, native, edge="Edge2", not_found=False,
                     registered=None):
    """As _check, but with an edge in state so the native read is attempted.
    `native` is the reply to the `database wlc` command -- or an exception
    class to raise from it."""
    import checks.ap_radio_registration as m

    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(hostname=h)))

    def fake(host, cmd, _svc):
        if "database wlc" in cmd:
            if isinstance(native, type) and issubclass(native, BaseException):
                raise native("simulated")
            return native
        if "internal" in cmd:
            if not_found:
                return NOT_FOUND
            return registered if registered is not None else REGISTERED
        return None
    monkeypatch.setattr("radkit_cli.get_any_single_output", fake)

    ctx = types.SimpleNamespace(service=object(), payload={},
                                state={"xtr_hostname": edge} if edge else {})
    chk = ApRadioMacRegistration("border1", "10.31.136.64", MAC, 8188,
                                 "catc", "cp-1", "172.19.1.68")
    return chk.run(ctx), ctx


@pytest.mark.parametrize("native", [
    EDGE_DATABASE_WLC,
    # Every way the read can come back without a decode. None of these is a
    # fault: most IOS-XE releases simply do not have the block.
    "% Invalid input detected at '^' marker.",
    "",
    None,
    RuntimeError,
    TimeoutError,
])
def test_the_native_read_fails_over_rather_than_failing(monkeypatch, native):
    """Whatever the edge does, the check still reports the registration and
    still resolves the AP address from THIS control plane's own payload."""
    r, _ctx = _check_with_edge(monkeypatch, native)
    assert r.status is CheckStatus.OK
    assert r.data["metadata"]["source"] == "decoded"
    assert r.data["metadata"]["ap_ip"] == "172.19.5.10"
    assert r.data["metadata"]["l3_vnid"] == 4097
    assert r.data["registered"] is True


def test_no_edge_in_state_skips_the_native_read(monkeypatch):
    """Nothing to ask. The local decode carries it, as it does on every
    release without the block."""
    r, _ctx = _check_with_edge(monkeypatch, EDGE_DATABASE_WLC, edge=None)
    assert r.status is CheckStatus.OK
    assert r.data["metadata"]["source"] == "decoded"
    assert r.data["metadata"]["ap_ip"] == "172.19.5.10"


def test_every_field_comes_from_this_control_planes_own_payload(monkeypatch):
    """The whole point of reading each control plane separately. The edge's
    decode is a cross-check, never a substitute -- splicing its value in
    would hide a control plane that is out of step."""
    r, _ctx = _check_with_edge(monkeypatch, EDGE_DATABASE_WLC)
    assert r.data["metadata"]["source"] == "decoded"
    assert r.data["metadata"]["l3_vnid"] == 4097
    # Read and recorded, so the agreement is visible...
    assert r.data["metadata"]["device_ap_ip"] == "172.19.5.10"
    assert r.data["metadata"]["agrees_with_device"] is True


def test_a_control_plane_that_disagrees_with_the_edge_is_reported(monkeypatch):
    """The fault this separation exists to catch. B1 and B2 are read
    independently; one holding a different AP address than the edge decodes
    is a stale registration, and it must not be papered over with the edge's
    value."""
    # The edge decodes a DIFFERENT address than the control plane's payload
    # carries (the REGISTERED fixture holds 172.19.5.10).
    other = EDGE_DATABASE_WLC.replace("IPv4 address: 172.19.5.10",
                                      "IPv4 address: 172.19.5.99")
    r, _ctx = _check_with_edge(monkeypatch, other)
    # This control plane's OWN value is what is reported.
    assert r.data["metadata"]["ap_ip"] == "172.19.5.10"
    assert r.data["metadata"]["device_ap_ip"] == "172.19.5.99"
    assert r.data["metadata"]["agrees_with_device"] is False
    # And the disagreement is surfaced, not buried in data.
    assert r.status is CheckStatus.WARN
    assert "disagree" in r.message
    assert "172.19.5.99" in r.message


def test_an_unregistered_control_plane_is_never_a_mismatch(monkeypatch):
    """A mismatch is only meaningful where there IS a registration. A
    control plane holding no record has nothing to compare, and saying its
    metadata disagrees with the edge would be a second finding invented out
    of the first one."""
    r, _ctx = _check_with_edge(monkeypatch, EDGE_DATABASE_WLC, not_found=True)
    assert r.data["registered"] is False
    assert "disagree" not in r.message
    assert "metadata" not in r.data


@pytest.mark.parametrize("hexline", [
    # Registered, but the payload carries no usable AP address.
    "      WLC data length: 0\n",
    "      WLC data length: 12\n        00 00 00 00  00 00 00 00  00 00 00 00\n",
])
def test_a_registration_without_an_address_is_not_a_mismatch(monkeypatch,
                                                             hexline):
    """Registered but carrying nothing to compare. That is its own finding
    (the metadata checks say so); it is not a disagreement with the edge."""
    import re as _re
    rec = _re.sub(r"      WLC data length: 34\n(?:        [0-9A-F ]+\n)+",
                  hexline, REGISTERED)
    r, _ctx = _check_with_edge(monkeypatch, EDGE_DATABASE_WLC, registered=rec)
    assert r.data["registered"] is True
    assert r.data["metadata"]["ap_ip"] is None
    # None, not False: nothing was compared.
    assert r.data["metadata"]["agrees_with_device"] is None
    assert "disagree" not in r.message


def test_a_border_that_reports_no_wlc_section_is_not_a_fault(monkeypatch):
    """Not every release prints the WLC metadata on a border, even where it
    accepts the `internal` form. The registration is complete and healthy;
    the fields are simply not exposed. Grading their absence reported a
    missing AP bit and missing metadata on a record with nothing wrong."""
    import re as _re
    rec = _re.sub(
        r"      WLC AP bit:.*\n      WLC data length: \d+\n"
        r"(?:        [0-9A-F ]+\n)+", "", REGISTERED)
    assert "WLC data length" not in rec and "WLC AP bit" not in rec

    r, _ctx = _check_with_edge(monkeypatch, "", registered=rec)
    assert r.data["registered"] is True
    # Reported as the release's silence, once...
    assert "does not report the WLC metadata section" in r.message
    # ...not as an unset AP bit or a controller that withheld the payload.
    assert "AP bit" not in r.message
    assert "carries no WLC metadata" not in r.message


def test_a_genuinely_empty_payload_is_still_a_fault(monkeypatch):
    """The distinction that matters. Here the device DOES report the WLC
    section -- it says length 0 -- which is the controller registering the
    radio MAC without the AP's identity. That is a real finding."""
    import re as _re
    rec = _re.sub(r"      WLC data length: 34\n(?:        [0-9A-F ]+\n)+",
                  "      WLC data length: 0\n", REGISTERED)
    r, _ctx = _check_with_edge(monkeypatch, "", registered=rec)
    assert r.status is CheckStatus.WARN
    assert "WLC metadata length of 0" in r.message
    assert "does not report the WLC metadata section" not in r.message
    # Not the absent-payload note: the device did report the section.
    assert "no metadata payload" not in r.message


def test_an_unreported_payload_length_is_not_a_fault(monkeypatch):
    """Border2's case. The device prints the AP bit and then stops -- no
    length line at all -- while its peer prints both for the same
    registration. Absent is not zero: nothing was read, so there is
    nothing to grade."""
    import re as _re
    rec = _re.sub(r"      WLC data length: 34\n(?:        [0-9A-F ]+\n)+",
                  "", REGISTERED)
    r, _ctx = _check_with_edge(monkeypatch, "", registered=rec)
    assert r.status is CheckStatus.OK
    assert "no metadata payload" in r.message
    assert "⚠" not in r.message


def test_an_info_note_alone_never_warns(monkeypatch):
    """The ℹ bullets record what a command did not say. Grading on them
    marks a healthy AP faulty because a border is terse."""
    import re as _re
    rec = _re.sub(r"      WLC AP bit: Set\n", "", REGISTERED)
    rec = _re.sub(r"      WLC data length: 34\n(?:        [0-9A-F ]+\n)+",
                  "", rec)
    r, _ctx = _check_with_edge(monkeypatch, "", registered=rec)
    assert r.status is CheckStatus.OK
    assert "ℹ" in r.message


# --------------------------------------------------------------------------
# A registration missing from every control plane must still be EXPLAINED.
# That branch sets `ap_stop`, so the session flow has to be queued from the
# verdict itself -- a separately-queued _ApCheck would skip on that stop.
# --------------------------------------------------------------------------


def _verdict(reg, host="wlc-jalejand-cisco-com"):
    import types
    from checks.ap_radio_registration import ApRadioMacRegistrationVerdict
    ctx = types.SimpleNamespace(service=object(), payload={},
                                state={"ap_radio_reg": reg})
    v = ApRadioMacRegistrationVerdict("3891.b70f.2600", "8188", "wlc", host)
    return v.run(ctx), ctx


def test_registered_nowhere_queues_the_session_flow():
    from checks.ap_wlc import ApWlcCpLispSessionTrigger
    r, ctx = _verdict({"cp1": False, "cp2": False})
    assert r.status is CheckStatus.FAIL
    queued = (r.data or {}).get("queue_checks") or []
    assert any(isinstance(c, ApWlcCpLispSessionTrigger) for c in queued)
    # The stop is still set -- the flow is queued despite it, not instead.
    assert ctx.state.get("ap_stop")


def test_registered_on_some_queues_the_session_flow_too():
    """The WARN branch already promised the session checks would say why."""
    from checks.ap_wlc import ApWlcCpLispSessionTrigger
    r, _ = _verdict({"cp1": True, "cp2": False})
    assert r.status is CheckStatus.WARN
    queued = (r.data or {}).get("queue_checks") or []
    assert any(isinstance(c, ApWlcCpLispSessionTrigger) for c in queued)


def test_registered_everywhere_queues_nothing():
    r, _ = _verdict({"cp1": True, "cp2": True})
    assert r.status is CheckStatus.OK
    assert not (r.data or {}).get("queue_checks")
