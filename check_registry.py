"""Chain assembly for each scenario.

Check classes live in:
  - checks_common.py   — scenario-agnostic checks
  - checks_profile.py  — Catalyst Center / device-profiling / fabric-role
  - checks_lisp.py     — CP-loopback, RLOC, PITR/PETR, LISP/SISF params
  - checks_dhcp.py     — DHCP pool/parameters/snooping/relay/SVI/ACLs
  - checks_underlay.py — CEF forwarding, underlay reachability/CDP
  - checks_border.py   — border discovery, control-plane, per-border chain

This module just imports them and orders them per scenario.
"""

from checks import Check
from checks.common import (
    ValidateVrfParam,
    DetectInfraVn,
    ProfileXtrHostname,
)
from checks.profile import (
    ResolveCatcName,
    ProfileXtrNetworkDevice,
    ProfileXtrFabricDevice,
    FabricSiteLookup,
    XtrRoleClassification,
    MacLearning,
    CdpNeighborCheck,
    AuthenticationSessionCheck,
    LocalSgt,
)
from checks.lisp import (
    CpLoopback,
    RlocDefinition,
    PitrValidation,
    PetrValidation,
    LispParameters,
    SisfDeviceTracking,
)
from checks.dhcp import (
    PoolIdentification,
    DhcpParameters,
    DhcpSnoopingValidation,
    DhcpRelayValidation,
    SviValidation,
    SviInterfaceCounters,
    DhcpSnoopingClientStats,
    LocalPolicies,
)
from checks.underlay import (
    EdgeForwarding,
    UnderlayReachability,
    UnderlayCdpDiscovery,
)
from checks.border import BorderDiscovery
from checks.wireless import (
    WirelessWlcDiscovery,
    WirelessEndpointProfile,
    WirelessEndpointSsid,
    WirelessEndpointRadio,
    WirelessEndpointMobility,
    WirelessEndpointSessionManager,
    WirelessEndpointFabric,
    WirelessEndpointStats,
    WirelessWlcEndpointValidation,
    WirelessApTags,
    WirelessWlanProfile,
    WirelessPolicyProfile,
    WirelessFlexProfile,
    WirelessSiteTag,
    WirelessCpSession,
    WirelessCpEidQuery,
    WirelessFabricEdgeResolve,
    WirelessFabricEdgeRedirect,
    WirelessAccessTunnel,
    WirelessFabricEdgeMac,
    WirelessRoamingHistory,
    WirelessL2LispStats,
)
from checks.ew_flow import EwSourceEndpointOnboarding, EwFlowElection, EwSourceSisf
from checks.ew_l2lisp import (
    EwSourceL2LispParameters,
    EwSourceEtrRegistration,
    EwL2LispAclEvaluation,
    EwSourceArResolution,
    EwDestArResolution,
    EwIntraVsInter,
)
from checks.ew_destination import (
    EwDestXtrLookup,
    EwDestXtrProfiling,
    EwFabricSiteComparison,
    EwRemoteMapCache,
    EwDestEndpointOnboarding,
    EwDestSisf,
    EwDestAuthenticationSession,
)
from checks.ew_underlay import (
    EwUnderlayRibLookup,
    EwUnderlayCef,
    EwUnderlayPhysical,
    EwUnderlayMtu,
    EwUnderlayPingNoMtu,
    EwUnderlayPingMtu,
)
from checks.ew_security import EwSourceCts, EwDestCts, EwCtsRules
from checks.ew_acl import EwSourcePacl, EwSourceVacl, EwDestPacl, EwDestVacl


def _normalize_payload(payload: dict) -> None:
    """Mutate-in-place: copy east-west input field names to the names the shared
    profile / fabric / role checks already read (mgmt_ip, vrf).

    Lets us reuse ProfileXtrHostname / ProfileXtrNetworkDevice / FabricSiteLookup
    / XtrRoleClassification as-is for the source XTR without scenario-specific
    branches inside those checks.
    """
    if payload.get("scenario") == "east_west":
        if not payload.get("mgmt_ip") and payload.get("device_source_ip"):
            payload["mgmt_ip"] = payload["device_source_ip"]
        # East-west form doesn't ask for VRF; ValidateVrfParam requires one.
        # Default to "default" (INFRA_VN) unless caller specifies — most L2
        # east-west flows live in a user VRF; honor the form value when present.
        if not (payload.get("vrf") or "").strip():
            payload["vrf"] = payload.get("vrf_name") or "default"
    if payload.get("scenario") == "underlay_multicast":
        if not payload.get("mgmt_ip") and payload.get("umcast_source_ip"):
            payload["mgmt_ip"] = payload["umcast_source_ip"]
        if not (payload.get("vrf") or "").strip():
            payload["vrf"] = "default"


def build_check_chain(payload: dict) -> list[Check]:
    """Return the ordered list of checks for one run, given the scenario payload."""
    _normalize_payload(payload)
    scenario = payload.get("scenario")
    if scenario == "dhcp":
        return [
            ValidateVrfParam(),
            DetectInfraVn(),
            ProfileXtrHostname(),
            ResolveCatcName(),
            ProfileXtrNetworkDevice(),
            ProfileXtrFabricDevice(),
            FabricSiteLookup(),
            XtrRoleClassification(),
            WirelessWlcDiscovery(),
            WirelessEndpointProfile(),
            WirelessEndpointSsid(),
            WirelessEndpointRadio(),
            WirelessEndpointMobility(),
            WirelessEndpointSessionManager(),
            WirelessEndpointFabric(),
            WirelessEndpointStats(),
            WirelessWlcEndpointValidation(),
            WirelessApTags(),
            WirelessWlanProfile(),
            WirelessPolicyProfile(),
            WirelessFlexProfile(),
            WirelessSiteTag(),
            WirelessCpSession(),
            WirelessCpEidQuery(),
            WirelessFabricEdgeResolve(),
            WirelessFabricEdgeRedirect(),
            WirelessAccessTunnel(),
            WirelessFabricEdgeMac(),
            WirelessRoamingHistory(),
            WirelessL2LispStats(),
            CpLoopback(),
            RlocDefinition(),
            PitrValidation(),
            PetrValidation(),
            MacLearning(),
            CdpNeighborCheck(),
            AuthenticationSessionCheck(),
            LocalSgt(),
            PoolIdentification(),
            DhcpParameters(),
            DhcpSnoopingValidation(),
            DhcpRelayValidation(),
            SviValidation(),
            SviInterfaceCounters(),
            DhcpSnoopingClientStats(),
            LocalPolicies(),
            LispParameters(),
            SisfDeviceTracking(),
            EdgeForwarding(),
            UnderlayReachability(),
            UnderlayCdpDiscovery(),
            BorderDiscovery(),
        ]
    # East-West chain.
    if scenario == "east_west":
        return [
            ValidateVrfParam(),
            ProfileXtrHostname(),
            ResolveCatcName(),
            ProfileXtrNetworkDevice(),
            ProfileXtrFabricDevice(),
            FabricSiteLookup(),
            XtrRoleClassification(),
            # Source endpoint + flow election
            EwSourceEndpointOnboarding(),
            # Fabric-Enabled Wireless (only if payload.is_few=True; otherwise SKIP).
            # Runs AFTER onboarding so the discovered MAC/VLAN are available.
            # Note: WirelessFabricEdgeRedirect may redirect xtr_hostname when the
            # wireless endpoint has roamed off the user-supplied XTR.
            WirelessWlcDiscovery(),
            WirelessEndpointProfile(),
            WirelessEndpointSsid(),
            WirelessEndpointRadio(),
            WirelessEndpointMobility(),
            WirelessEndpointSessionManager(),
            WirelessEndpointFabric(),
            WirelessEndpointStats(),
            WirelessWlcEndpointValidation(),
            WirelessApTags(),
            WirelessWlanProfile(),
            WirelessPolicyProfile(),
            WirelessFlexProfile(),
            WirelessSiteTag(),
            WirelessCpSession(),
            WirelessCpEidQuery(),
            WirelessFabricEdgeResolve(),
            WirelessFabricEdgeRedirect(),
            WirelessAccessTunnel(),
            WirelessFabricEdgeMac(),
            WirelessRoamingHistory(),
            WirelessL2LispStats(),
            EwFlowElection(),
            # Source-side local endpoint validations — depend only on the
            # source XTR + onboarded MAC/VLAN, so run them right after
            # onboarding (not bolted onto the end of the chain).
            MacLearning(),
            CdpNeighborCheck(),
            AuthenticationSessionCheck(),
            LocalSgt(),
            EwSourceSisf(),
            # L2 LISP state + AR/MAC + ACL
            EwSourceL2LispParameters(),
            EwSourceEtrRegistration(),
            EwL2LispAclEvaluation(),
            EwSourceArResolution(),
            EwDestArResolution(),
            EwIntraVsInter(),
            # Destination XTR + endpoint
            EwDestXtrLookup(),
            EwDestXtrProfiling(),
            EwFabricSiteComparison(),
            EwRemoteMapCache(),
            EwDestEndpointOnboarding(),
            EwDestSisf(),
            EwDestAuthenticationSession(),
            # PACL / VACL bidirectional evaluation on both XTRs
            EwSourcePacl(),
            EwSourceVacl(),
            EwDestPacl(),
            EwDestVacl(),
            # Underlay (inter-XTR only)
            EwUnderlayRibLookup(),
            EwUnderlayCef(),
            EwUnderlayPhysical(),
            EwUnderlayMtu(),
            EwUnderlayPingNoMtu(),
            EwUnderlayPingMtu(),
            UnderlayCdpDiscovery(),
            # CTS / RBACL
            EwSourceCts(),
            EwDestCts(),
            EwCtsRules(),
        ]
    if scenario == "underlay_multicast":
        from checks.underlay_multicast_seed import UmcastSeed, UmcastDstXtrProfile
        from checks.underlay_multicast import build_underlay_multicast_chain
        from checks.underlay_multicast_correlation import (
            build_underlay_multicast_correlation_chain,
        )
        from checks.underlay_multicast_rp import (
            build_underlay_multicast_rp_chain,
        )
        from checks.underlay_multicast_sg import build_underlay_multicast_sg_chain
        from checks.underlay_multicast_path import build_underlay_multicast_path_chain
        chain = [
            ValidateVrfParam(),
            ProfileXtrHostname(),
            ResolveCatcName(),
            ProfileXtrNetworkDevice(),
            ProfileXtrFabricDevice(),
            FabricSiteLookup(),
            UmcastSeed(),
            UmcastDstXtrProfile(),
        ]
        chain.extend(build_underlay_multicast_chain("fhr"))
        chain.extend(build_underlay_multicast_chain("lhr"))
        chain.extend(build_underlay_multicast_correlation_chain())
        chain.extend(build_underlay_multicast_rp_chain())
        chain.extend(build_underlay_multicast_sg_chain())
        chain.extend(build_underlay_multicast_path_chain())
        return chain
    return []
