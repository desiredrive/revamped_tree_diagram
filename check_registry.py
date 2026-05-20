"""Chain assembly for each scenario.

The actual Check classes live in:
  - checks_common.py — scenario-agnostic checks (param validation, profiling)
  - checks_dhcp.py   — DHCP-specific checks

This module just imports them and orders them per scenario.
"""

from checks import Check
from checks_common import (
    ValidateVrfParam,
    DetectInfraVn,
    ProfileXtrHostname,
)
from checks_dhcp import (
    ResolveCatcName,
    ProfileXtrNetworkDevice,
    ProfileXtrFabricDevice,
    FabricSiteLookup,
    XtrRoleClassification,
    CpLoopback,
    RlocDefinition,
    PitrValidation,
    PetrValidation,
    FewRedirectReal,
    MacLearning,
    AuthSessionAndCdp,
    LocalSgt,
    PoolIdentification,
    DhcpParameters,
    DhcpSnoopingValidation,
    DhcpRelayValidation,
    SviValidation,
    DhcpSnoopingClientStats,
    LocalPolicies,
    LispParameters,
    EdgeForwarding,
    UnderlayReachability,
    UnderlayCdpDiscovery,
    BorderDiscovery,
)


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
            AuthSessionAndCdp(),
            LocalSgt(),
            PoolIdentification(),
            DhcpParameters(),
            DhcpSnoopingValidation(),
            DhcpRelayValidation(),
            SviValidation(),
            DhcpSnoopingClientStats(),
            LocalPolicies(),
            LispParameters(),
            EdgeForwarding(),
            UnderlayReachability(),
            UnderlayCdpDiscovery(),
            BorderDiscovery(),
        ]
    # East-West chain comes later.
    return []
