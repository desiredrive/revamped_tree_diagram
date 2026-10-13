import re

from radkit_cli import get_any_single_output


def get_vacl_drop_acls(hostname, vlan_id, service):
    """
    Identifies VACLs that result in a 'drop' action, including the implicit deny.
    Returns a unique list of ACL names and a special marker if an implicit drop is active.
    """
    drop_acls = []
    has_catch_all_forward = False

    # 1. Find the VACL map name applied to the specific VLAN
    cmd_filter = f"show vlan filter vlan {vlan_id}"
    output_filter = get_any_single_output(hostname, cmd_filter, service)

    if not output_filter:
        return []

    # IOS-XE answers a per-VLAN query with "Vlan 1021 has filter NAME." and
    # only uses the "VLAN Map NAME is filtering VLANs:" form when asked for
    # every filter at once. Matching the second form alone meant a VLAN that
    # genuinely had a VACL always parsed as having none -- the check could
    # not report a drop it was looking straight at. Both forms are read.
    map_match = (re.search(r"has filter\s+(\S+?)\.?\s*$",
                           output_filter, re.MULTILINE)
                 or re.search(r"VLAN Map (\S+) is filtering", output_filter))
    if not map_match:
        return []

    map_name = map_match.group(1)

    # 2. Get the details of the access-map
    cmd_map = f"show vlan access-map {map_name}"
    output_map = get_any_single_output(hostname, cmd_map, service)

    if not output_map:
        return []

    # 3. Parse sequences for explicit drops and the catch-all forward
    # We split by the start of a new sequence definition
    sequences = re.split(r'Vlan access-map\s+"?\S+"?\s+\d+', output_map)

    for seq in sequences:
        if not seq.strip():
            continue

        # The device prints the action on the line AFTER the "Action:"
        # header, not as "action: drop" on one line, so both spellings are
        # accepted. Without this every sequence read as having no action and
        # no drop was ever reported.
        low = seq.lower()
        is_drop = bool(re.search(r"action:\s*(?:\n\s*)?drop", low))
        is_forward = bool(re.search(r"action:\s*(?:\n\s*)?forward", low))

        # Check for explicit drops
        if is_drop:
            # Match clauses print as "ip   address: NAME" under a "Match
            # clauses:" header. The v4 and v6 clauses are separate lines and
            # only the v4 one is collected: callers evaluate IPv4 flows, and
            # feeding them an IPv6 access list raised KeyError('ipv4') once
            # per flow -- four unreadable results for a list that was never
            # relevant. "ip" is matched without "ipv6" via the negative
            # lookahead.
            for acl in re.findall(
                    r"\bip(?!v6)\s+address:\s*(\S+)", seq, re.IGNORECASE):
                drop_acls.append(acl)

        # Check for a catch-all forward
        # In IOS, a sequence with 'action: forward' and NO 'match' line is a 'permit any'
        if is_forward:
            if "address:" not in low:
                has_catch_all_forward = True
            else:
                # Also check if it matches an ACL that is effectively 'permit any'
                # (This is harder to parse without looking at the ACL itself,
                # but we can flag the ACL for the next stage of your script)
                pass

    # 4. Handle the Implicit Deny
    # If the last sequence (or any sequence) isn't a catch-all forward,
    # then anything not explicitly matched is dropped.
    if not has_catch_all_forward:
        # We add a virtual marker so your main logic knows to warn about the implicit deny
        drop_acls.append("VACL_IMPLICIT_DENY_ACTIVE")

    return list(dict.fromkeys(drop_acls))