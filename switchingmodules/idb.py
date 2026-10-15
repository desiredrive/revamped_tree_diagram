"""`show idb all` -- the interface descriptor block table.

An IDB is the data structure IOS keeps per interface. Every interface has a
HWIDB (the hardware block) and one or more SWIDBs (the software blocks); a
subinterface has its own SWIDB hanging off the parent's HWIDB, which is why
`LISP0.4097` appears in the S section and not in the H section.

Two things make this worth reading in an AP flow. The counters at the top are
a platform ceiling the same way the access-tunnel maximum is -- a switch out
of software IDBs cannot build another interface, so an access tunnel that
never appeared may have had nowhere to go. And the AP's access tunnel has its
own pair of rows here, which is the IOS-side half of the PD comparison: what
IOS thinks it has programmed, against what the hardware actually holds.

The command is not parsed by Genie (checked against the full 5504-command
parser index), so it is parsed here by hand.
"""

import re

#: The device's own legend, printed at the foot of the output. Decoded rather
#: than passed through: `U,R,U` on its own is unreadable in a report.
STATE_CODES = {
    "A": "admin-down",
    "D": "down",
    "G": "going-down",
    "I": "init",
    "R": "reset",
    "T": "testing",
    "U": "up",
    "X": "deleted",
}


def _decode_state(field):
    """`U,R,U` -> ("up", "reset", "up"); `U` -> ("up", None, None).

    The two sections print different numbers of state fields: a HWIDB row
    carries current, old and shadow state, a SWIDB row carries current state
    alone. Missing fields come back None rather than being invented.
    """
    parts = [p.strip() for p in str(field or "").split(",")]
    out = []
    for i in range(3):
        code = parts[i] if i < len(parts) and parts[i] else None
        out.append(STATE_CODES.get(code, code) if code else None)
    return tuple(out)


def _counts(output, label):
    """The HWIDBs/SWIDBs/uHWIDBs/uSWIDBs row named `label`."""
    m = re.search(r"^\s*" + label + r"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
                  output, re.M)
    if not m:
        return None
    return {"hwidb": int(m.group(1)), "swidb": int(m.group(2)),
            "uhwidb": int(m.group(3)), "uswidb": int(m.group(4))}


#: One table row. The subblock list in parentheses is captured whole and left
#: as text -- it is a feature inventory, not something this flow grades.
_ROW = re.compile(
    r"^\s*(?P<type>[HS])\s+"
    r"(?P<sidx>\d+)\s+"
    r"(?P<idx>\d+)\s+"
    # HWIDB rows carry "U,U,R", SWIDB rows carry a bare "U".
    r"(?P<state>[A-Z](?:,[A-Z]){0,2})\s+"
    # HDel: "." for live, "X" for a deleted HWIDB, "I" during init.
    r"(?P<hdel>\S)\s+"
    r"(?P<name>\S+)"
    r"(?:\s+\((?P<subblocks>.*)\))?\s*$")


def parse_show_idb_all(output):
    """Parse `show idb all`.

    Returns::

        {"sw_idb_max", "sw_idb_in_use", "micro_idb_max", "micro_idb_in_use",
         "active", "inactive", "dirty", "total",      # each a counts dict
         "interfaces": [ ... ]}

    Each interface row is {"type" ("H"/"S"), "sidx", "idx", "state",
    "old_state", "shadow_state", "hw_deleted", "name", "subblocks"}.

    An interface normally appears TWICE -- once as a HWIDB and once as a
    SWIDB -- with DIFFERENT `idx` values (AccessTunnel0 on Edge2 is hw 65,
    sw 77). Rows are kept flat and separate rather than merged by name for
    that reason: merging would have to discard one of the two indices, and
    `show ifnum list` keys on the if_number, so both are needed.

    `interfaces` is NOT the full IDB population and must never be used as a
    count of it. The table lists the ACTIVE rows plus any row flagged
    deleted; the inactive pool is allocated structures with no table entry.
    On Edge2 that is 59 active + 1 deleted = 60 printed against a reported
    `Total IDBs` of 67, the missing 7 being the inactive ones. Read the
    counters for population, the rows for state.

    Counters are None when absent rather than 0, so a parse failure never
    reads as a switch with no interfaces.
    """
    res = {"sw_idb_max": None, "sw_idb_in_use": None,
           "micro_idb_max": None, "micro_idb_in_use": None,
           "active": None, "inactive": None, "dirty": None, "total": None,
           "interfaces": []}
    if not output or not isinstance(output, str):
        return res

    m = re.search(r"Maximum number of Software IDBs\s+(\d+)\.\s+In use\s+(\d+)",
                  output)
    if m:
        res["sw_idb_max"], res["sw_idb_in_use"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"Maximum number of Micro Software IDBs\s+(\d+)\."
                  r"\s+In use\s+(\d+)", output)
    if m:
        res["micro_idb_max"] = int(m.group(1))
        res["micro_idb_in_use"] = int(m.group(2))

    res["active"] = _counts(output, "Active")
    res["inactive"] = _counts(output, "Inactive")
    res["dirty"] = _counts(output, "Dirty")
    res["total"] = _counts(output, "Total IDBs")

    for line in output.splitlines():
        mm = _ROW.match(line)
        if not mm:
            continue
        # The legend at the foot of the output has lines that can look like a
        # row ("R=Reset, T=Testing, U=Up, X=Deleted"); none of them match the
        # shape above, but the Key: block is skipped explicitly in case a
        # future release reflows it.
        st, old, shadow = _decode_state(mm.group("state"))
        res["interfaces"].append({
            "type": mm.group("type"),
            "sidx": int(mm.group("sidx")),
            "idx": int(mm.group("idx")),
            "state": st,
            "old_state": old,
            "shadow_state": shadow,
            # "." means not deleted; the legend defines X=Deleted, I=Init.
            "hw_deleted": mm.group("hdel") == "X",
            "name": mm.group("name"),
            "subblocks": mm.group("subblocks") or "",
        })
    return res


def _same_if(a, b):
    """True when two interface names denote the same interface.

    `show idb all` spells names out ("AccessTunnel0") while
    `show access-tunnel statistics` abbreviates them ("Ac0"), so the two
    cannot be compared directly. An IOS abbreviation keeps the numeric
    suffix intact and truncates only the alphabetic prefix, so the names
    match when the suffixes are equal and the shorter prefix is a prefix of
    the longer. Comparison is case-insensitive; the two commands do not
    agree on capitalisation either.
    """
    if not a or not b:
        return False
    a, b = a.strip().lower(), b.strip().lower()
    if a == b:
        return True
    m1, m2 = _IF_SPLIT.match(a), _IF_SPLIT.match(b)
    if not m1 or not m2:
        return False
    if m1.group("num") != m2.group("num"):
        return False
    p1, p2 = m1.group("alpha"), m2.group("alpha")
    if not p1 or not p2:
        return False
    return p1.startswith(p2) or p2.startswith(p1)


# The alphabetic prefix may itself contain digits ("l2lisp"), so the split
# is anchored on the trailing numeric run rather than on the leading letters.
_IF_SPLIT = re.compile(r"^(?P<alpha>.*?[a-z])(?P<num>[\d][\d/.:]*)$")
