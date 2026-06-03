"""Standalone runner for programming/* primitives.

Usage:
    python -m programming.test_runner mac --hostname HOST --mac MAC --vlan VLAN \\
                                           [--expected-interface I] \\
                                           [--rsa-serial SERIAL] \\
                                           [--email EMAIL] [--domain DOMAIN]

The runner bootstraps a radkit Service (with SSO login if needed) the same way
the webserver does, then calls the primitive directly and prints the structured
result. It does not import the check chain, the webserver, or
programming/inventory.py — the goal is to exercise parsers in isolation
against real devices.

Add subcommands as new primitives land (`route`, `interface`, `mroute`, ...).
"""

from __future__ import annotations

import argparse
import sys
from pprint import pprint
from typing import Optional

import getpass
import os

from radkit_client.sync import Client

from programming.mac import (
    MacProgrammingInput,
    validate_mac_programming,
    validate_fed_mac_programming,
    compare_mac_programming,
    _is_cp_learned_iface,
)
from programming.cef import (
    CefProgrammingInput,
    validate_cef_programming,
    validate_fed_cef_programming,
    compare_cef_programming,
)
from programming.adjacency import (
    AdjacencyInput,
    validate_adjacency_programming,
    validate_fed_adjacency_programming,
    compare_adjacency_programming,
)
from programming.lisp_adjacency import (
    LispAdjacencyInput,
    validate_lisp_adjacency_programming,
    validate_fed_lisp_adjacency_programming,
    compare_lisp_adjacency_programming,
)
from programming.lisp_l3_iface import (
    LispL3IfaceInput,
    validate_lisp_l3_iface_programming,
    validate_fed_lisp_l3_iface_programming,
    compare_lisp_l3_iface_programming,
)
from programming.route_adjacency import validate_route_with_adjacencies


_DEFAULT_RSA_SERIAL = "7an6-bxvq-tkcs"
_DEFAULT_EMAIL = "jalejand@cisco.com"
_DEFAULT_DOMAIN = "PROD"


def _login_certificate(client, email: str, domain: str, passphrase: str) -> None:
    """Certificate-based login. Requires a private key already enrolled with RSA."""
    from radkit_client.sync import PromptInterrupted
    result = client.certificate_login(
        identity=email,
        domain=domain,
        private_key_password=passphrase,
    )
    if isinstance(result, PromptInterrupted):
        raise RuntimeError(
            "Certificate login was interrupted — RSA prompted for input "
            "(likely a missing or wrong private-key password)."
        )
    print("Certificate login complete.")


def _login_sso(client, email: str, domain: str) -> None:
    """SSO login if no cached connection. Prints URL for the user to open."""
    resp = client.oauth_connect_only(identity=email, domain=domain)
    if resp is None:
        raise RuntimeError("RSA returned no OAuth response.")
    print("=" * 70)
    print("Open this URL in a browser to complete SSO:")
    print(str(resp.sso_url))
    print("(Waiting for completion...)")
    print("=" * 70)
    client.sso_login(
        identity=email,
        domain=domain,
        oauth_connect_response=resp,
        open_browser=False,
    )
    print("SSO login complete.")


def _resolve_passphrase(args) -> str:
    if args.passphrase is not None:
        return args.passphrase
    env = os.environ.get("RADKIT_KEY_PASSWORD")
    if env is not None:
        return env
    return getpass.getpass("Private key passphrase (empty if none): ")


def _open_service(client, args):
    try:
        return client.service_cloud(args.rsa_serial).wait()
    except Exception:
        # Most likely "Not yet connected" — log in then retry.
        if args.auth == "certificate":
            _login_certificate(client, args.email, args.domain,
                               _resolve_passphrase(args))
        else:
            _login_sso(client, args.email, args.domain)
        return client.service_cloud(args.rsa_serial).wait()


def _run_mac(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = MacProgrammingInput(
            hostname=args.hostname,
            mac=args.mac,
            vlan=args.vlan,
        )
        result = validate_mac_programming(inp, service)

    print("=" * 70)
    print(f"hostname:           {args.hostname}")
    print(f"mac (input):        {args.mac}")
    print(f"vlan:               {args.vlan}")
    print("-" * 70)
    print(f"programmed:         {result.programmed}")
    print(f"mac_type:           {result.mac_type}")
    print(f"interface:          {result.interface}")
    print(f"rloc_ip:            {result.rloc_ip}")
    print(f"access_tunnel:      {result.access_tunnel}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    print("-" * 70)
    print("raw_parsed:")
    pprint(result.raw_parsed)
    return 0 if result.programmed else 2


def _run_fed(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = MacProgrammingInput(
            hostname=args.hostname,
            mac=args.mac,
            vlan=args.vlan,
            switch_member=args.switch_member,
            sup_role=args.sup_role,
        )
        result = validate_fed_mac_programming(inp, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"mac (input):     {args.mac}")
    print(f"vlan:            {args.vlan}")
    print(f"switch_member:   {args.switch_member}")
    print(f"sup_role:        {args.sup_role}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"interface:       {result.interface}")
    print(f"rloc_ip:         {result.rloc_ip}")
    print(f"type:            {result.type}")
    print(f"flags:           {result.flags}")
    print(f"seq:             {result.seq}")
    print(f"ec_bi:           {result.ec_bi}")
    print(f"machandle:       {result.machandle}")
    print(f"si_handle:       {result.si_handle}")
    print(f"ri_handle:       {result.ri_handle}")
    print(f"di_handle:       {result.di_handle}")
    print(f"a_time:          {result.a_time}")
    print(f"e_time:          {result.e_time}")
    print(f"con:             {result.con}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    print("-" * 70)
    print("raw_fields:")
    pprint(result.raw_fields)
    return 0 if result.programmed else 2


def _run_compare(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        ios_inp = MacProgrammingInput(
            hostname=args.hostname,
            mac=args.mac,
            vlan=args.vlan,
            switch_member=args.switch_member,
            sup_role=args.sup_role,
        )
        ios = validate_mac_programming(ios_inp, service)

        # CP-learned MACs (L2LISP / Tu / RLOC / AccessTunnel / LISP) live on
        # the active sup — force `switch active` for the FED query regardless
        # of what the caller passed.
        forced_active = (
            ios.programmed
            and (ios.mac_type == "cp_learn" or _is_cp_learned_iface(ios.interface))
        )
        fed_inp = MacProgrammingInput(
            hostname=args.hostname,
            mac=args.mac,
            vlan=args.vlan,
            switch_member=None if forced_active else args.switch_member,
            sup_role=None if forced_active else args.sup_role,
        )
        fed = validate_fed_mac_programming(fed_inp, service)
        cmp_ = compare_mac_programming(
            ios, fed,
            queried_switch_member=None if forced_active else args.switch_member,
        )

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"mac:             {args.mac}")
    print(f"vlan:            {args.vlan}")
    print(f"switch_member:   {args.switch_member}"
          + ("  (overridden → active for CP-learned MAC)" if forced_active else ""))
    print("-" * 70)
    print(f"IOS programmed:  {ios.programmed}  type={ios.mac_type}  intf={ios.interface}")
    print(f"FED programmed:  {fed.programmed}  intf={fed.interface}"
          + (f"  rloc_ip={fed.rloc_ip}" if fed.rloc_ip else ""))
    print("-" * 70)
    print(f"status:          {cmp_.status}")
    print(f"ios_interface:   {cmp_.ios_interface}")
    print(f"fed_interface:   {cmp_.fed_interface}")
    print(f"queried_member:  {cmp_.queried_switch_member}")
    print(f"iface_member:    {cmp_.interface_switch_member}")
    print(f"detail:          {cmp_.detail}")
    return 0 if cmp_.status == "match" else 2


def _run_adj(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = AdjacencyInput(
            hostname=args.hostname,
            address=args.address,
            vrf=_norm_vrf(args.vrf),
            vlan=args.vlan,
        )
        result = validate_adjacency_programming(inp, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"address:         {args.address}")
    print(f"vrf:             {args.vrf or '(default)'}")
    print(f"vlan:            {args.vlan}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"interface:       {result.interface}")
    print(f"dst_mac:         {result.dst_mac}")
    print(f"src_mac:         {result.src_mac}")
    print(f"ethertype:       {result.ethertype}")
    print(f"encap_length:    {result.encap_length}")
    print(f"source:          {result.source}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_fedadj(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        result = validate_fed_adjacency_programming(args.address, args.hostname, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"address:         {args.address}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"interface:       {result.interface}")
    print(f"dst_mac:         {result.dst_mac}")
    print(f"adj_id:          {result.adj_id}")
    print(f"si_hdl:          {result.si_hdl}")
    print(f"ri_hdl:          {result.ri_hdl}")
    print(f"pd_flags:        {result.pd_flags}")
    print(f"pmap_intfs:      {result.pmap_interfaces}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_adj_compare(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = AdjacencyInput(
            hostname=args.hostname,
            address=args.address,
            vrf=_norm_vrf(args.vrf),
            vlan=args.vlan,
        )
        ios = validate_adjacency_programming(inp, service)
        fed = validate_fed_adjacency_programming(args.address, args.hostname, service)
        cmp_ = compare_adjacency_programming(ios, fed)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"address:         {args.address}")
    print(f"vrf:             {args.vrf or '(default)'}")
    print(f"vlan:            {args.vlan}")
    print("-" * 70)
    print(f"IOS programmed:  {ios.programmed}  intf={ios.interface}  dst_mac={ios.dst_mac}  src={ios.source}")
    print(f"FED programmed:  {fed.programmed}  intf={fed.interface}  dst_mac={fed.dst_mac}  pmap={fed.pmap_interfaces}")
    print("-" * 70)
    print(f"status:          {cmp_.status}")
    print(f"detail:          {cmp_.detail}")
    return 0 if cmp_.status == "match" else 2


def _split_prefix_mask(text: str) -> tuple[str, int]:
    if "/" not in text:
        raise SystemExit("--prefix must be in x.x.x.x/yy form (e.g. 10.0.0.0/24).")
    p, m = text.rsplit("/", 1)
    return p.strip(), int(m)


def _split_prefix_optional_mask(text: str) -> tuple[str, Optional[int]]:
    """Accept either a host IP or a prefix/length — CEF lookups are relaxed."""
    if "/" not in text:
        return text.strip(), None
    p, m = text.rsplit("/", 1)
    return p.strip(), int(m)


def _norm_vrf(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    t = text.strip()
    return None if t == "" else t


def _run_cef(args) -> int:
    prefix, mask = _split_prefix_optional_mask(args.prefix)
    with Client.create() as client:
        service = _open_service(client, args)
        inp = CefProgrammingInput(
            hostname=args.hostname, prefix=prefix, mask=mask,
            vrf=_norm_vrf(args.vrf),
        )
        result = validate_cef_programming(inp, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"queried prefix:  {prefix}" + (f"/{mask}" if mask is not None else "  (no mask)"))
    print(f"vrf:             {args.vrf or '(default RIB)'}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"matched prefix:  {result.matched_prefix}/{result.matched_mask}")
    print(f"nexthops:        {result.nexthops}")
    print(f"interfaces:      {result.interfaces}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_fedroute(args) -> int:
    prefix, mask = _split_prefix_mask(args.prefix)
    with Client.create() as client:
        service = _open_service(client, args)
        result = validate_fed_cef_programming(
            args.hostname, prefix, mask, _norm_vrf(args.vrf), service,
        )

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"prefix:          {prefix}/{mask}")
    print(f"vrf:             {args.vrf or '(default RIB)'}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"nexthops:        {result.nexthops}")
    print(f"interfaces:      {result.interfaces}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_cef_compare(args) -> int:
    prefix, mask = _split_prefix_optional_mask(args.prefix)
    vrf = _norm_vrf(args.vrf)
    with Client.create() as client:
        service = _open_service(client, args)
        ios = validate_cef_programming(
            CefProgrammingInput(hostname=args.hostname, prefix=prefix, mask=mask, vrf=vrf),
            service,
        )
        if ios.programmed and ios.matched_prefix and ios.matched_mask is not None:
            fed = validate_fed_cef_programming(
                args.hostname, ios.matched_prefix, ios.matched_mask, vrf, service,
            )
        elif mask is not None:
            fed = validate_fed_cef_programming(
                args.hostname, prefix, mask, vrf, service,
            )
        else:
            from programming.cef import CefFedResult
            fed = CefFedResult(programmed=False, raw_cli="(skipped — no matched prefix and no input mask)")
        cmp_ = compare_cef_programming(ios, fed)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"queried prefix:  {prefix}" + (f"/{mask}" if mask is not None else "  (no mask)"))
    print(f"vrf:             {args.vrf or '(default RIB)'}")
    print("-" * 70)
    print(f"CEF programmed:  {ios.programmed}  matched={ios.matched_prefix}/{ios.matched_mask}"
          + ("  [receive]" if ios.is_receive else ""))
    print(f"  nexthops:      {ios.nexthops}")
    print(f"  interfaces:    {ios.interfaces}")
    print(f"FED programmed:  {fed.programmed}"
          + ("  [receive]" if fed.is_receive else ""))
    print(f"  nexthops:      {fed.nexthops}")
    print(f"  interfaces:    {fed.interfaces}")
    print("-" * 70)
    print(f"status:          {cmp_.status}")
    print(f"detail:          {cmp_.detail}")
    return 0 if cmp_.status == "match" else 2


def _run_lispadj(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = LispAdjacencyInput(
            hostname=args.hostname,
            rloc=args.rloc,
            instance_id=args.iid,
        )
        result = validate_lisp_adjacency_programming(inp, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"rloc:            {args.rloc}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"lisp_interface:  {result.lisp_interface}")
    print(f"rloc (parsed):   {result.rloc}")
    print(f"iid (parsed):    {result.instance_id}")
    print(f"encap_length:    {result.encap_length}")
    print(f"next_chain:      {result.next_chain_interface} -> {result.next_chain_address}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_fedlispadj(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        result = validate_fed_lisp_adjacency_programming(
            args.rloc, args.hostname, service, instance_id=args.iid,
        )

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"rloc:            {args.rloc}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"rloc (parsed):   {result.rloc}")
    print(f"if_name:         {result.if_name}")
    print(f"iid (parsed):    {result.instance_id}")
    print(f"si_hdl:          {result.si_hdl}")
    print(f"ri_hdl:          {result.ri_hdl}")
    print(f"pd_flags:        {result.pd_flags}")
    print(f"adj_id:          {result.adj_id}")
    print(f"adj_handle:      {result.adj_handle}")
    print(f"encap_iid:       {result.encap_iid}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_lispadj_compare(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = LispAdjacencyInput(
            hostname=args.hostname,
            rloc=args.rloc,
            instance_id=args.iid,
        )
        ios = validate_lisp_adjacency_programming(inp, service)
        fed = validate_fed_lisp_adjacency_programming(
            args.rloc, args.hostname, service, instance_id=args.iid,
        )
        cmp_ = compare_lisp_adjacency_programming(ios, fed)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"rloc:            {args.rloc}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"IOS programmed:  {ios.programmed}  intf={ios.lisp_interface}  "
          f"iid={ios.instance_id}  next={ios.next_chain_interface}->{ios.next_chain_address}")
    print(f"FED programmed:  {fed.programmed}  if_name={fed.if_name}  "
          f"iid={fed.instance_id}  adj_id={fed.adj_id}  pd={fed.pd_flags}")
    print("-" * 70)
    print(f"status:          {cmp_.status}")
    print(f"detail:          {cmp_.detail}")
    return 0 if cmp_.status == "match" else 2


def _run_lispl3if(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = LispL3IfaceInput(hostname=args.hostname, instance_id=args.iid)
        result = validate_lisp_l3_iface_programming(inp, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"interface_name:  {result.interface_name}")
    print(f"line_state:      {result.line_state}")
    print(f"protocol_state:  {result.protocol_state}")
    print(f"vrf:             {result.vrf}")
    print("-" * 70)
    print("raw_cli:")
    print(result.raw_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_fedlispl3if(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        result = validate_fed_lisp_l3_iface_programming(args.iid, args.hostname, service)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"programmed:      {result.programmed}")
    print(f"if_id:           {result.if_id}")
    print(f"interface_name:  {result.interface_name}")
    print(f"block_state:     {result.block_state}")
    print(f"iface_state:     {result.iface_state}")
    print(f"iface_status:    {result.iface_status}")
    print(f"instance_id:     {result.instance_id}")
    print(f"udp_dest_port:   {result.udp_dest_port}")
    print(f"ipv4_sgt_enable: {result.ipv4_sgt_enable}")
    print("-" * 70)
    print("raw_mappings_cli:")
    print(result.raw_mappings_cli or "(empty)")
    print("-" * 70)
    print("raw_detail_cli:")
    print(result.raw_detail_cli or "(empty)")
    return 0 if result.programmed else 2


def _run_lispl3if_compare(args) -> int:
    with Client.create() as client:
        service = _open_service(client, args)
        inp = LispL3IfaceInput(hostname=args.hostname, instance_id=args.iid)
        ios = validate_lisp_l3_iface_programming(inp, service)
        fed = validate_fed_lisp_l3_iface_programming(args.iid, args.hostname, service)
        cmp_ = compare_lisp_l3_iface_programming(args.iid, ios, fed)

    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"instance_id:     {args.iid}")
    print("-" * 70)
    print(f"IOS programmed:  {ios.programmed}  intf={ios.interface_name}  "
          f"{ios.line_state}/{ios.protocol_state}  vrf={ios.vrf}")
    print(f"FED programmed:  {fed.programmed}  if_id={fed.if_id}  "
          f"block={fed.block_state}  state={fed.iface_state}  "
          f"status={fed.iface_status}")
    print(f"                 iid={fed.instance_id}  udp={fed.udp_dest_port}  "
          f"sgt={fed.ipv4_sgt_enable}")
    print("-" * 70)
    print(f"status:          {cmp_.status}")
    print(f"detail:          {cmp_.detail}")
    if cmp_.issues:
        print("issues:")
        for issue in cmp_.issues:
            print(f"  - {issue}")
    return 0 if cmp_.status == "match" else 2


def _run_route_full_compare(args) -> int:
    prefix, mask = _split_prefix_optional_mask(args.prefix)
    vrf = _norm_vrf(args.vrf)
    with Client.create() as client:
        service = _open_service(client, args)
        result = validate_route_with_adjacencies(
            args.hostname, prefix, mask, vrf, service,
        )

    cmp_ = result.cef_compare
    print("=" * 70)
    print(f"hostname:        {args.hostname}")
    print(f"prefix:          {prefix}" + (f"/{mask}" if mask is not None else "  (no mask)"))
    print(f"vrf:             {args.vrf or '(default RIB)'}")
    print("-" * 70)
    print(f"CEF status:      {cmp_.status}")
    print(f"  matched:       {cmp_.matched_prefix}/{cmp_.matched_mask}")
    print(f"  ios_nexthops:  {cmp_.ios_nexthops}")
    print(f"  fed_nexthops:  {cmp_.fed_nexthops}")
    print(f"  ios_ifaces:    {cmp_.ios_interfaces}")
    print("-" * 70)
    if not result.nexthop_results:
        print("nexthops:        (none — receive route or no nexthops)")
    for r in result.nexthop_results:
        print(f"nexthop {r.nexthop}:")
        print(f"  cef_intf:    {r.expected_interface}")
        print(f"  ios_adj:     programmed={r.ios.programmed}  "
              f"intf={r.ios.interface}  dst_mac={r.ios.dst_mac}  src={r.ios.source}")
        print(f"  fed_adj:     programmed={r.fed.programmed}  "
              f"intf={r.fed.interface}  dst_mac={r.fed.dst_mac}  pmap={r.fed.pmap_interfaces}")
        print(f"  adj_status:  {r.adj_compare.status}")
        print(f"  addr_match:  {r.address_match}    iface_match: {r.interface_match}")
        print(f"  detail:      {r.adj_compare.detail}")
    print("-" * 70)
    print(f"OVERALL status:  {result.status}")
    print(f"detail:          {result.detail}")
    if result.issues:
        print("issues:")
        for issue in result.issues:
            print(f"  - {issue}")
    return 0 if result.status == "match" else 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="programming.test_runner")
    p.add_argument("--rsa-serial", default=_DEFAULT_RSA_SERIAL,
                   help="RADKit service serial (defaults to main.py's value).")
    p.add_argument("--email", default=_DEFAULT_EMAIL,
                   help="Email identity for SSO login (used if not cached).")
    p.add_argument("--domain", default=_DEFAULT_DOMAIN,
                   help="RSA domain (PROD, STAGE).")
    p.add_argument("--auth", choices=("certificate", "sso"), default="certificate",
                   help="Login method (default: certificate).")
    p.add_argument("--passphrase", default=None,
                   help="Private-key passphrase. If omitted, read from "
                        "RADKIT_KEY_PASSWORD env var or prompt interactively.")

    sub = p.add_subparsers(dest="primitive", required=True)

    pm = sub.add_parser("mac", help="Validate MAC address programming.")
    pm.add_argument("--hostname", required=True)
    pm.add_argument("--mac", required=True, help="Any common MAC format.")
    pm.add_argument("--vlan", required=True, type=int)
    pm.set_defaults(func=_run_mac)

    pf = sub.add_parser("fed", help="Validate FED MATM (hardware) MAC programming.")
    pf.add_argument("--hostname", required=True)
    pf.add_argument("--mac", required=True, help="Any common MAC format.")
    pf.add_argument("--vlan", required=True, type=int)
    pf.add_argument("--switch-member", type=int, default=None,
                    help="Stack member (e.g. 1). Default: switch active.")
    pf.add_argument("--sup-role", choices=("active", "standby"), default=None,
                    help="Sup role; ignored if --switch-member is given.")
    pf.set_defaults(func=_run_fed)

    pc = sub.add_parser("compare", help="Compare IOS MAC table vs FED MATM.")
    pc.add_argument("--hostname", required=True)
    pc.add_argument("--mac", required=True)
    pc.add_argument("--vlan", required=True, type=int)
    pc.add_argument("--switch-member", type=int, default=None,
                    help="Stack member to query in FED. Default: switch active.")
    pc.add_argument("--sup-role", choices=("active", "standby"), default=None)
    pc.set_defaults(func=_run_compare)

    pr = sub.add_parser("cef", help="Validate CEF (software) prefix programming.")
    pr.add_argument("--hostname", required=True)
    pr.add_argument("--prefix", required=True, help="x.x.x.x or x.x.x.x/yy")
    pr.add_argument("--vrf", default=None, help="VRF name; omit for default RIB.")
    pr.set_defaults(func=_run_cef)

    prf = sub.add_parser("fedroute", help="Validate FED hardware route programming.")
    prf.add_argument("--hostname", required=True)
    prf.add_argument("--prefix", required=True, help="x.x.x.x/yy (mask required for FED).")
    prf.add_argument("--vrf", default=None, help="VRF name; omit for default RIB.")
    prf.set_defaults(func=_run_fedroute)

    prc = sub.add_parser("cef-compare", help="Compare CEF vs FED for a prefix.")
    prc.add_argument("--hostname", required=True)
    prc.add_argument("--prefix", required=True, help="x.x.x.x or x.x.x.x/yy")
    prc.add_argument("--vrf", default=None, help="VRF name; omit for default RIB.")
    prc.set_defaults(func=_run_cef_compare)

    pa = sub.add_parser("adj", help="Validate IOS adjacency entry.")
    pa.add_argument("--hostname", required=True)
    pa.add_argument("--address", required=True, help="Next-hop IP (e.g. 172.19.10.10).")
    pa.add_argument("--vrf", default=None, help="VRF name; omit for default.")
    pa.add_argument("--vlan", type=int, default=None, help="Optional VLAN scope.")
    pa.set_defaults(func=_run_adj)

    pfa = sub.add_parser("fedadj", help="Validate FED hardware adjacency entry.")
    pfa.add_argument("--hostname", required=True)
    pfa.add_argument("--address", required=True)
    pfa.set_defaults(func=_run_fedadj)

    pac = sub.add_parser("adj-compare", help="Compare IOS adjacency vs FED adjacency.")
    pac.add_argument("--hostname", required=True)
    pac.add_argument("--address", required=True)
    pac.add_argument("--vrf", default=None)
    pac.add_argument("--vlan", type=int, default=None)
    pac.set_defaults(func=_run_adj_compare)

    pla = sub.add_parser("lispadj", help="Validate IOS LISP adjacency entry.")
    pla.add_argument("--hostname", required=True)
    pla.add_argument("--rloc", required=True, help="Underlay RLOC IP (e.g. 172.19.1.64).")
    pla.add_argument("--iid", required=True, type=int, help="LISP instance ID (e.g. 4099).")
    pla.set_defaults(func=_run_lispadj)

    pfla = sub.add_parser("fedlispadj", help="Validate FED LISP hardware adjacency entry.")
    pfla.add_argument("--hostname", required=True)
    pfla.add_argument("--rloc", required=True)
    pfla.add_argument("--iid", required=True, type=int,
                      help="LISP instance ID — disambiguates the FED row.")
    pfla.set_defaults(func=_run_fedlispadj)

    plac = sub.add_parser("lispadj-compare", help="Compare IOS LISP adj vs FED LISP adj.")
    plac.add_argument("--hostname", required=True)
    plac.add_argument("--rloc", required=True)
    plac.add_argument("--iid", required=True, type=int)
    plac.set_defaults(func=_run_lispadj_compare)

    pli = sub.add_parser("lispl3if", help="Validate IOS L3 LISP interface (sw view).")
    pli.add_argument("--hostname", required=True)
    pli.add_argument("--iid", required=True, type=int, help="LISP instance ID (e.g. 4099).")
    pli.set_defaults(func=_run_lispl3if)

    pfli = sub.add_parser("fedlispl3if", help="Validate FED L3 LISP interface block.")
    pfli.add_argument("--hostname", required=True)
    pfli.add_argument("--iid", required=True, type=int)
    pfli.set_defaults(func=_run_fedlispl3if)

    plic = sub.add_parser("lispl3if-compare", help="Compare IOS vs FED for L3 LISP iface.")
    plic.add_argument("--hostname", required=True)
    plic.add_argument("--iid", required=True, type=int)
    plic.set_defaults(func=_run_lispl3if_compare)

    pfull = sub.add_parser(
        "route-full-compare",
        help="End-to-end: CEF vs FED route + per-nexthop adjacency programming.",
    )
    pfull.add_argument("--hostname", required=True)
    pfull.add_argument("--prefix", required=True, help="x.x.x.x or x.x.x.x/yy")
    pfull.add_argument("--vrf", default=None, help="VRF name; omit for default RIB.")
    pfull.set_defaults(func=_run_route_full_compare)

    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
