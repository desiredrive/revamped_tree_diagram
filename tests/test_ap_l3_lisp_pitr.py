"""`ApL3LispPitr` — the switch's proxy-ITR RLOC must be its own Loopback0.

Written against the live fabric that exposed the gap: edge-2 advertises
172.19.1.67 as its PITR while its own Loopback0 is 172.19.1.68, and nothing
in the AP flow said so. Every registration this flow checks is written with
172.19.1.68, so proxied traffic is steered at a different box.

The check reads `show lisp service ipv4`, NOT `show lisp instance-id <id>
ipv4`. Both carry proxy_itr_rloc, but Genie's schema for the instance form
requires `itr.proxy_itr_router` and its parser does not set that key when
the PITR line carries an "RLOCs: ... (not local)" suffix -- one missing key
makes Genie discard the whole parse. The service form was verified to parse
cleanly on the same device. `test_the_service_command_is_what_gets_read`
pins that choice, because switching to the instance form would make this
check silently unreadable on exactly the devices it is for.
"""

import types

import pytest

from checks.base import CheckStatus
from checks import ap_onboarding
from checks.ap_onboarding import ApL3LispPitr


HOST = "edge-2-jalejand-cisco-com"
LO0 = "172.19.1.68"
OTHER = "172.19.1.67"


def _parsed(pitr):
    return {"lisp_id": {0: {"itr": {"proxy_itr_rloc": pitr}}}}


def _ctx(loopback=LO0):
    state = {"xtr_hostname": HOST}
    if loopback:
        state["xtr_loopback"] = loopback
    return types.SimpleNamespace(service=object(), payload={}, state=state)


@pytest.fixture
def genie(monkeypatch):
    """Capture the command issued and control what Genie returns."""
    calls = []

    def _set(result):
        def _fake(hostname, cmd, service):
            calls.append((hostname, cmd))
            if isinstance(result, BaseException):
                raise result
            return result
        monkeypatch.setattr("radkit_cli.get_single_output_genie", _fake)

    _set.calls = calls
    return _set


def test_a_mismatched_pitr_warns_and_names_both_addresses(genie):
    """The live case. Both numbers must appear: one alone is unactionable."""
    genie(_parsed(OTHER))
    r = ApL3LispPitr().run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert OTHER in r.message and LO0 in r.message
    assert r.data["match"] is False


def test_a_matching_pitr_passes(genie):
    genie(_parsed(LO0))
    r = ApL3LispPitr().run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert r.data["match"] is True


def test_the_service_command_is_what_gets_read(genie):
    """Not `show lisp instance-id <id> ipv4`, whose Genie schema discards it."""
    genie(_parsed(LO0))
    ApL3LispPitr().run_ap(_ctx())
    assert genie.calls == [(HOST, "show lisp service ipv4")]


def test_an_unreadable_pitr_warns_rather_than_failing(genie):
    """Manifest rule: FAIL is for the tool being unable to continue."""
    genie(RuntimeError("no such command"))
    r = ApL3LispPitr().run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert r.data["pitr_unread"] is True
    # The cause is reported: an errored command and an empty one are
    # different next steps for the reader.
    assert "RuntimeError" in r.message


def test_an_empty_parse_is_unread_not_a_match(genie):
    """A missing key must never read as agreement with the loopback."""
    genie({"lisp_id": {0: {"itr": {}}}})
    r = ApL3LispPitr().run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert r.data["pitr_unread"] is True


def test_an_unresolvable_loopback_is_reported_as_uncompared(genie,
                                                            monkeypatch):
    """Tri-state: no Loopback0 means no comparison, never a pass."""
    genie(_parsed(OTHER))
    monkeypatch.setattr("checks.lisp._query_loopback0",
                        lambda ctx: (None, None, "unresolved"))
    r = ApL3LispPitr().run_ap(_ctx(loopback=None))
    assert r.status is CheckStatus.WARN
    assert r.data["comparable"] is False
    assert "could not be compared" in r.message


def test_the_loopback_is_resolved_when_state_lacks_it(genie, monkeypatch):
    """The AP chain runs neither CpLoopback nor RlocDefinition, so the
    check resolves Loopback0 itself instead of skipping."""
    genie(_parsed(LO0))
    monkeypatch.setattr("checks.lisp._query_loopback0",
                        lambda ctx: (LO0, "255.255.255.255", None))
    ctx = _ctx(loopback=None)
    r = ApL3LispPitr().run_ap(ctx)
    assert r.status is CheckStatus.OK
    # Published for whatever runs next, not just used locally.
    assert ctx.state["xtr_loopback"] == LO0
