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
from checks.shared import normalize_mac
from checks.common import (
    ValidateVrfParam,
    DetectInfraVn,
    ProfileXtrHostname,
)
from checks.ap_onboarding import (
    ApEdgeGate,
    ApInfraVnVlan,
    ApMacLearning,
    ApCdpNeighbor,
    ApAccountingAttributes,
    ApSwitchportState,
    ApInterfaceStatus,
    ApRouteToWlc,
    ApCefToWlc,
    ApPhysicalPathToWlc,
    ApCapwapAccessLists,
    ApDhcpAccessLists,
    ApAuthTemplate,
    ApDeviceClassifier,
    ApAuthenticationSession,
    ApDataSessionCount,
    ApSviState,
    ApL2LispInstance,
    ApL2LispDynamicEid,
    ApL2LispDatabase,
    ApL2LispRegistration,
    ApIpAddress,
    ApL3LispInstance,
    ApL3LispDynamicEid,
    ApL3LispDatabase,
    ApL3LispRegistration,
    ApCpDiscovery,
)
from checks.ap_wlc import ApWlcDiscovery, ApWlcProfile
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
    if payload.get("scenario") == "ap_onboarding":
        # The AP form asks for `ap_mac`; every shared check reads `mac`. Without
        # this the AP MAC is collected, validated, sent -- and silently dropped.
        if not payload.get("mac") and payload.get("ap_mac"):
            payload["mac"] = payload["ap_mac"]
        # An AP onboards in the INFRA_VN.
        if not (payload.get("vrf") or "").strip():
            payload["vrf"] = "default"
    if payload.get("scenario") == "underlay_multicast":
        if not payload.get("mgmt_ip") and payload.get("umcast_source_ip"):
            payload["mgmt_ip"] = payload["umcast_source_ip"]
        if not (payload.get("vrf") or "").strip():
            payload["vrf"] = "default"

    # Every check keys device lookups on this MAC, and Genie keys its parsed
    # results the way IOS prints them (b811.4b0e.2630). Normalising once here --
    # the single point all of them read from -- means a MAC typed with colons,
    # hyphens or in upper case finds the endpoint instead of being reported as
    # unknown to a switch that had profiled it correctly.
    for key in ("mac", "ap_mac", "client_mac", "destination_mac"):
        if payload.get(key):
            payload[key] = normalize_mac(payload[key])


def build_check_chain(payload: dict) -> list[Check]:
    """Return the ordered list of checks for one run, given the scenario payload."""
    _normalize_payload(payload)
    scenario = payload.get("scenario")
    if scenario == "ap_onboarding":
        # Step 1 -- identify the AP and profile the switch it lands on. Reuses
        # the profiling chain verbatim; ApEdgeGate then stops the flow unless
        # the XTR is an Edge node, since an AP onboards through a fabric edge.
        return [
            ProfileXtrHostname(),
            ResolveCatcName(),
            ProfileXtrNetworkDevice(),
            ProfileXtrFabricDevice(),
            FabricSiteLookup(),
            XtrRoleClassification(),
            ApEdgeGate(),
            # Step 2 -- the wireless controllers themselves. Standalone: every
            # Fabric WLC at the site is profiled, with no AP-specific lookup.
            ApWlcDiscovery(),
            ApWlcProfile(),
            # Step 3 -- the AP's current state on the edge. Starts by deriving
            # the VLAN it onboards in from the INFRA_VN L2 instance step 2 read
            # off the controllers; every later edge check hangs off that VLAN.
            ApInfraVnVlan(),
            ApMacLearning(),
            # CDP before the authentication session: the auth validator reads
            # the is_ap / cdpneighborhost that this check produces.
            ApCdpNeighbor(),
            # Divergence path only: the MAC was learned outside the INFRA_VN
            # VLAN, and authentication is what assigned the VLAN it is in -- so
            # it runs BEFORE the interface checks here, to put the reason on the
            # canvas ahead of the consequence. On the normal path this instance
            # does not appear and the late one below runs instead.
            ApAuthenticationSession(early=True),
            # The port's own L2 state, before anything that runs on top of it.
            ApSwitchportState(),
            # Right after the port's L2 config: same port, its physical health.
            ApInterfaceStatus(),
            # Path to the controller, in order: RIB, then CEF, then the
            # physical interfaces the path resolves onto.
            ApRouteToWlc(),
            ApCefToWlc(),
            ApPhysicalPathToWlc(),
            # ACLs on that same CEF-derived path, for the AP's
            # CAPWAP join to the controller.
            ApCapwapAccessLists(),
            # What the switch reports to AAA about the AP, which is what
            # profiling policy matches on.
            ApAccountingAttributes(),
            # The switch's own opinion of the endpoint, independent of CDP.
            ApDeviceClassifier(),
            # Template before the session: what the port is configured to do,
            # before what actually happened to it.
            ApAuthTemplate(),
            # Authentication last of the port checks: it grades the assigned
            # VLAN against the INFRA_VN VLAN, so it needs ApInfraVnVlan, and
            # its port comes from ApMacLearning.
            ApAuthenticationSession(early=False),
            # After the session grading: it counts sessions on the same
            # collected output, and needs ApCdpNeighbor's is_ap to know whether
            # more than one is a fault or just what a downstream switch looks
            # like.
            ApDataSessionCount(),
            # Spec 3b.1. The AP's gateway, and the first check that leaves the
            # access port to look at routing. Needs ApInfraVnVlan's VLAN; runs
            # after the port-level checks because a port that never came up
            # makes the gateway's state beside the point.
            ApSviState(),
            ApDhcpAccessLists(),
            # Spec 3b.3. Graded as a sequence in the order the fabric builds
            # it: instance, then dynamic EID, then database, then registration
            # to each control plane. Split into four checks so the canvas says
            # which link broke rather than failing one node four ways.
            ApL2LispInstance(),
            ApL2LispDynamicEid(),
            ApL2LispDatabase(),
            ApL2LispRegistration(),
            ApIpAddress(),
            ApL3LispInstance(),
            ApL3LispDynamicEid(),
            ApL3LispDatabase(),
            ApL3LispRegistration(),
            ApCpDiscovery(),
        ]
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
