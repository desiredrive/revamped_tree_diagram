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

    if not output_filter or "is filtering" not in output_filter:
        return []

    map_match = re.search(r"VLAN Map (\S+) is filtering", output_filter)
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

        # Check for explicit drops
        if "action: drop" in seq.lower():
            acl_match = re.search(r"match: (?:ip|ipv6) address (\S+)", seq, re.IGNORECASE)
            if acl_match:
                drop_acls.append(acl_match.group(1))

        # Check for a catch-all forward
        # In IOS, a sequence with 'action: forward' and NO 'match' line is a 'permit any'
        if "action: forward" in seq.lower():
            if "match:" not in seq.lower():
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