"""Check chain framework — base classes + domain modules.

External callers should import the framework primitives from this package:

    from checks import Check, CheckResult, CheckStatus, RunContext

Domain modules live alongside (e.g. ``checks.dhcp``, ``checks.ew_flow``,
``checks.underlay_multicast``) and are wired into ordered chains by
``check_registry.build_check_chain``.
"""

from checks.base import Check, CheckResult, CheckStatus, RunContext

__all__ = ["Check", "CheckResult", "CheckStatus", "RunContext"]
