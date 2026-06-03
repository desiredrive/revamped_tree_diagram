"""Reusable hardware/control-plane programming validators.

Each module here exposes a small, self-contained primitive that any check
module (DHCP, east-west, wireless, border, ...) can call without dragging
in RunContext or scenario-specific state. The validators take plain inputs
(hostname, identifiers, expectations) and return structured results that
the caller converts into a CheckResult.
"""
