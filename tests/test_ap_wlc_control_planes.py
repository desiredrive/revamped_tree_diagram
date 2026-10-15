"""`ApWlcControlPlanes` — how the WLC's LISP control planes are graded.

The grading rule is not "down is bad". Only the site-local control planes can
register a client joining at this site, so they alone decide the verdict; a
Multi-Site control plane serves a remote site and is reported without
affecting it. That asymmetry is the thing most worth pinning: a change that
starts counting the Multi-Site CPs would pass every other test in the suite.

All-CPs-down is WARN rather than FAIL by the manifest rule -- a fabric fault,
not the tool failing to continue. The deferral is real: `ApCpDiscovery` runs
later in the AP flow, resolves the site's CPs from Catalyst Center and queries
each directly for the AP's registration. The two FAIL branches below have no
such deferral, because a CP that is not defined at all is a provisioning fault
with nothing downstream to re-verify.
"""

import types

import pytest

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcControlPlanes


WLC = "wlc-jalejand-cisco-com"


def _fabric(rows):
    """`show wireless fabric summary` with the given control-plane rows.

    Verbatim shape, including the Fabric VNID Mapping banner below: the parser
    stops at it, and a fixture without it would not exercise that boundary.
    """
    body = "\n".join(rows)
    return (
        "Fabric Status      : Enabled\n"
        "\n"
        "Control-plane:\n"
        "Name                             IP-address        Key          Status\n"
        "--------------------------------------------------------------------\n"
        f"{body}\n"
        "\n"
        "Fabric VNID Mapping:\n"
        "  Name              L2-VNID   L3-VNID  IP Address       Subnet\n"
        "  172_19_5_0-INFRA_VN  8188    4097    172.19.5.0   255.255.255.0\n"
    )


UP = "default-control-plane           172.19.1.64       key1         Up"
DOWN_64 = "default-control-plane           172.19.1.64       key1         Down"
DOWN_65 = "default-control-plane           172.19.1.65       key1         Down"
# Multi-Site names routinely contain a space -- the reason the check reads raw
# output instead of Genie's parsed dict, which drops them.
MSRB = "jalejand_San Ange_e9143         172.19.1.100      key2         Down"


def _ctx(raw):
    return types.SimpleNamespace(
        service=object(),
        payload={},
        state={
            "ap_wlc_collected": {WLC: types.SimpleNamespace(hostname=WLC)},
            "ap_wlc_raw_fabric": {WLC: raw},
        },
    )


def _run(raw):
    return ApWlcControlPlanes(WLC, "wlc").run_ap(_ctx(raw))


def test_no_control_planes_at_all_fails():
    """Nothing is defined: a provisioning fault, with nothing to defer to."""
    r = _run(_fabric([]))
    assert r.status is CheckStatus.FAIL
    assert "No LISP control planes are defined" in r.message


def test_only_multisite_control_planes_fails():
    """A client joining HERE has no control plane, however healthy the MSRB."""
    r = _run(_fabric([MSRB.replace("Down", "Up")]))
    assert r.status is CheckStatus.FAIL
    assert "No site control plane is defined" in r.message


def test_every_site_control_plane_down_warns_not_fails():
    """The reported case: two site CPs down, one Multi-Site down.

    WARN, not FAIL -- `ApCpDiscovery` grades the CP nodes later in the flow.
    """
    r = _run(_fabric([DOWN_64, DOWN_65, MSRB]))
    assert r.status is CheckStatus.WARN
    assert "None of the 2 site control plane(s) is Up" in r.message


def test_the_multisite_control_plane_is_not_counted_in_the_verdict():
    """Three CPs are listed but the count says 2: only site-local ones grade.

    Asserted on the rendered count rather than on an internal, because the
    count is what a reader acts on -- and an MSRB silently folded into it
    would make a remote site's outage look like a local one.
    """
    r = _run(_fabric([DOWN_64, DOWN_65, MSRB]))
    assert "the 2 site control" in r.message
    # Listed, though: reported without affecting the result.
    assert "172.19.1.100" in r.message
    assert "Multi-Site Control Planes" in r.message


def test_a_down_multisite_does_not_drag_down_a_healthy_site_cp():
    """The remote site is broken; this one is not. Nothing to warn about."""
    r = _run(_fabric([UP, MSRB]))
    assert r.status is CheckStatus.OK


def test_one_of_two_site_control_planes_down_warns_about_redundancy():
    r = _run(_fabric([UP, DOWN_65]))
    assert r.status is CheckStatus.WARN
    assert "redundancy" in r.message
    assert "172.19.1.65" in r.message


def test_the_control_planes_are_published_for_later_checks():
    ctx = _ctx(_fabric([UP, DOWN_65, MSRB]))
    ApWlcControlPlanes(WLC, "wlc").run_ap(ctx)
    stored = ctx.state["ap_wlc_control_planes"][WLC]
    assert [c["ip_address"] for c in stored["local"]] == ["172.19.1.64",
                                                          "172.19.1.65"]
    assert [c["ip_address"] for c in stored["multisite"]] == ["172.19.1.100"]


def test_uncollected_controller_skips():
    ctx = types.SimpleNamespace(service=object(), payload={},
                                state={"ap_wlc_collected": {}})
    r = ApWlcControlPlanes(WLC, "wlc").run_ap(ctx)
    assert r.status is CheckStatus.SKIP
