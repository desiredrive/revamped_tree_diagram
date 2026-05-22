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
from checks_common import (
    ValidateVrfParam,
    DetectInfraVn,
    ProfileXtrHostname,
)
from checks_profile import (
    ResolveCatcName,
    ProfileXtrNetworkDevice,
    ProfileXtrFabricDevice,
    FabricSiteLookup,
    XtrRoleClassification,
    FewRedirectReal,
    MacLearning,
    CdpNeighborCheck,
    AuthenticationSessionCheck,
    LocalSgt,
)
from checks_lisp import (
    CpLoopback,
    RlocDefinition,
    PitrValidation,
    PetrValidation,
    LispParameters,
    SisfDeviceTracking,
)
from checks_dhcp import (
    PoolIdentification,
    DhcpParameters,
    DhcpSnoopingValidation,
    DhcpRelayValidation,
    SviValidation,
    DhcpSnoopingClientStats,
    LocalPolicies,
)
from checks_underlay import (
    EdgeForwarding,
    UnderlayReachability,
    UnderlayCdpDiscovery,
)
from checks_border import BorderDiscovery


def build_check_chain(payload: dict) -> list[Check]:
    """Return the ordered list of checks for one run, given the scenario payload."""
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
            CpLoopback(),
            RlocDefinition(),
            PitrValidation(),
            PetrValidation(),
            FewRedirectReal(),
            MacLearning(),
            CdpNeighborCheck(),
            AuthenticationSessionCheck(),
            LocalSgt(),
            PoolIdentification(),
            DhcpParameters(),
            DhcpSnoopingValidation(),
            DhcpRelayValidation(),
            SviValidation(),
            DhcpSnoopingClientStats(),
            LocalPolicies(),
            LispParameters(),
            SisfDeviceTracking(),
            EdgeForwarding(),
            UnderlayReachability(),
            UnderlayCdpDiscovery(),
            BorderDiscovery(),
        ]
    # East-West chain comes later.
    return []
