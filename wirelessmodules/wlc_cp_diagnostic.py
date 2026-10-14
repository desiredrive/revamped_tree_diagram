"""Inputs for the FEW LISP session troubleshooting, read from a Fabric WLC.

The troubleshooting itself is `singleETRLISPSessionOnlyFEW` in
traffic_flows.lispsessiontroubleshooting, called directly by the check the same
way WirelessCpSession calls `fabricEnabledWirelessSession`. Nothing here
reimplements any of it.

This module only answers the two questions that function cannot ask a wireless
controller for itself:

  * which instance ID an AP registers with -- the INFRA_VN L2 VNID, which
    `fabricEnabledWirelessSession` takes from a client's fabric attributes and
    which step 2 has no endpoint to read
  * which address to register from -- the wireless management interface
"""


def infra_vn_vnid(info):
    """The INFRA_VN L2 VNID -- the instance ID an AP's registration uses.

    This is the one value `fabricEnabledWirelessSession` takes from a client's
    fabric attributes. An AP onboards in the INFRA_VN, so for step 2 it comes
    from the controller's own VNID mapping instead and no endpoint is needed.
    """
    mapping = (getattr(info, "fabric_state", None) or {}).get("fabric_vnid_mapping") or {}
    for vnid, attrs in (mapping.get("l2_vnid") or {}).items():
        if "INFRA_VN" in ((attrs or {}).get("name") or ""):
            return vnid
    return None


def wmi_ip(info):
    """The single wireless management IP, or None.

    Refuses to guess with zero or several management interfaces, mirroring
    lispsessiontroubleshooting.py:1839. The WMI is the source RLOC for the
    registration, so picking the wrong one would misdirect every check below it.
    """
    interfaces = ((getattr(info, "wmi_information", None) or {}).get("interfaces") or [])
    if len(interfaces) != 1:
        return None
    return interfaces[0].get("ipaddress")


def ap_endpoint_attributes(info, radio_mac, control_plane_name):
    """An AP posing as the endpoint `fabricEnabledWirelessSession` expects.

    That function reads a wireless CLIENT's fabric attributes -- the ones
    `show wireless client mac-address <mac> detail` reports. An AP is not a
    client and has no such record, but it registers through the controller the
    same way, so the flow applies unchanged once the four attributes it reads
    are supplied from the controller's own fabric state instead.

    `rloc` is the WMI: the controller registers from its wireless management
    interface, and that address is the source of the TCP socket every per-
    control-plane check measures. None when the WMI is ambiguous, which the
    caller must treat as "do not run" rather than substituting a guess.

    `sgt` is not carried: an AP's registration has no client SGT, and the flow
    only logs it.
    """
    from types import SimpleNamespace

    vnid = infra_vn_vnid(info)
    return SimpleNamespace(
        mac=radio_mac,
        endpointinfo={"fabric": {
            "status": "Enabled",
            "rloc": wmi_ip(info),
            "vnid": vnid,
            "sgt": None,
            "control_plane_name": control_plane_name,
        }},
    )
