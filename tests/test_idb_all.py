"""`show idb all` on Edge2 (10.31.136.126:1968), pulled live 2026-10-14.

The sample is trimmed to the shapes that matter -- the counter block, a
physical port, both halves of the AP's access tunnel, a subinterface, and the
one deleted row -- rather than all 131 rows. Genie has no parser for this
command (checked against the full 5504-command index), so it is parsed here.
"""

from switchingmodules.idb import (
    STATE_CODES, _decode_state, parse_show_idb_all,
)

LIVE = """show idb all

Maximum number of Software IDBs 131072.  In use 78.


Maximum number of Micro Software IDBs 49152.  In use 0.

                       HWIDBs     SWIDBs          uHWIDBs    uSWIDBs
Active                     59         70                0          0
Inactive                    8          8                0          0
Dirty                       0          0                0          0
Total IDBs                 67         78                0          0
Size each (bytes)        5000       1976             3904        640
Total bytes            335000     154128                0          0

Type SIdx     Idx St,O,Sh HDel Interface Name (subblocks)
-----------------------------------------------------------
 H     1      50   U,U,R    .  Vlan1 (MFIB_IPv4(15), PF_IDB(6), Ether(1))
 H    10      63   U,U,R    .  Vlan2045 (MFIB_IPv4(15), PF_IDB(6), Ether(1))
 H    11       6   U,R,R    X  LI-Null0
 H    14       9   D,D,R    .  TenGigabitEthernet1/0/2 (HW SB CDP(14), Ether(1))
 H    54      65   U,U,R    .  AccessTunnel0 (MFIB_IPv4(15))
 H    56       5   A,I,R    .  Bluetooth0/4 (HW SB CDP(14), Ether(1))
 H    57      53   U,R,U    .  L2LISP0 (MFIB_IPv4(15))

 S     1      51   U        .  Vlan1 (CRYPTO VPN(50), KEEPALIVE(1))
 S    11       7   U        X  LI-Null0 (IPv6 feature on swidb(16), UDLD(5))
 S    54      77   U        .  AccessTunnel0 (DTP(40), ACCESS TUNNEL SB(52), KEEPALIVE(1))
 S    66      54   U        .  LISP0.4097 (DHCPD Sw subblock(48), IOSXE-RP(2))

Key: SIdx=Sort Index, Idx=hw_if_index or if_number
     St=Current State, O=Old State, Sh=Shadow State
     HDel=HWIDB Deleted State
     A=Admindown, D=Down, G=Going Down, I=Init
     R=Reset, T=Testing, U=Up, X=Deleted
"""


def _by(res, name, typ):
    return next(i for i in res["interfaces"]
                if i["name"] == name and i["type"] == typ)


def test_the_software_idb_ceiling_is_read():
    """A switch out of software IDBs cannot build another interface, so an
    access tunnel that never appeared may have had nowhere to go. This is the
    same kind of platform ceiling as the access-tunnel maximum."""
    r = parse_show_idb_all(LIVE)
    assert r["sw_idb_max"] == 131072
    assert r["sw_idb_in_use"] == 78
    assert r["micro_idb_max"] == 49152
    assert r["micro_idb_in_use"] == 0


def test_the_counter_block_is_read_per_column():
    r = parse_show_idb_all(LIVE)
    assert r["active"] == {"hwidb": 59, "swidb": 70, "uhwidb": 0, "uswidb": 0}
    assert r["inactive"]["hwidb"] == 8
    assert r["dirty"]["hwidb"] == 0
    assert r["total"] == {"hwidb": 67, "swidb": 78, "uhwidb": 0, "uswidb": 0}


def test_the_access_tunnel_has_two_rows_with_different_indices():
    """The whole reason rows are kept flat rather than merged by name. On
    Edge2 AccessTunnel0 is hw_if_index 65 and if_number 77; merging the two
    rows would have to discard one, and `show ifnum list` keys on the
    if_number."""
    r = parse_show_idb_all(LIVE)
    assert _by(r, "AccessTunnel0", "H")["idx"] == 65
    assert _by(r, "AccessTunnel0", "S")["idx"] == 77


def test_a_hwidb_row_carries_three_states_and_a_swidb_row_one():
    """The two sections have different column counts. Absent fields come back
    None rather than being filled in with the current state."""
    r = parse_show_idb_all(LIVE)
    hw = _by(r, "AccessTunnel0", "H")
    assert (hw["state"], hw["old_state"], hw["shadow_state"]) \
        == ("up", "up", "reset")
    sw = _by(r, "AccessTunnel0", "S")
    assert (sw["state"], sw["old_state"], sw["shadow_state"]) \
        == ("up", None, None)


def test_states_are_decoded_using_the_devices_own_legend():
    """`U,R,U` is unreadable in a report. The codes are the ones the device
    prints at the foot of its own output, not a guess."""
    assert _decode_state("A,I,R") == ("admin-down", "init", "reset")
    assert _decode_state("D,D,R") == ("down", "down", "reset")
    assert STATE_CODES["X"] == "deleted"


def test_an_unknown_state_code_is_passed_through_not_dropped():
    """A future release adding a code must not silently become None -- that
    would read as "no state" rather than "a state we do not know"."""
    assert _decode_state("Q")[0] == "Q"


def test_the_deleted_row_is_flagged():
    r = parse_show_idb_all(LIVE)
    assert _by(r, "LI-Null0", "H")["hw_deleted"] is True
    assert _by(r, "AccessTunnel0", "H")["hw_deleted"] is False


def test_a_row_with_no_subblocks_parses():
    """`LI-Null0` has no parenthesised list at all. The group is optional, so
    it must come back as empty text rather than failing the row."""
    row = _by(parse_show_idb_all(LIVE), "LI-Null0", "H")
    # Empty text, not None: callers join and search this field, and None
    # would raise there while reading the same as "no subblocks" in a test
    # that only checked falsiness.
    assert row["subblocks"] == ""
    assert isinstance(row["subblocks"], str)
    # A row that HAS subblocks still carries them.
    assert "ACCESS TUNNEL SB(52)" in _by(
        parse_show_idb_all(LIVE), "AccessTunnel0", "S")["subblocks"]


def test_the_subinterface_appears_only_as_a_swidb():
    """A subinterface hangs off its parent's HWIDB, so it has no H row."""
    r = parse_show_idb_all(LIVE)
    names_h = {i["name"] for i in r["interfaces"] if i["type"] == "H"}
    assert "LISP0.4097" not in names_h
    assert _by(r, "LISP0.4097", "S")["idx"] == 54


def test_the_legend_is_not_mistaken_for_rows():
    """The Key: block at the foot contains lines beginning with state codes
    and digits. None of them may become an interface."""
    names = {i["name"] for i in parse_show_idb_all(LIVE)["interfaces"]}
    assert not any(n.startswith(("A=", "R=", "St=", "HDel=")) for n in names)
    assert len(names) == 8


def test_carriage_returns_do_not_break_the_rows():
    """RADKit returns the device's own CRLF line endings. The row regex is
    anchored with $, which would otherwise trip on the trailing \\r."""
    r = parse_show_idb_all(LIVE.replace("\n", "\r\n"))
    assert _by(r, "AccessTunnel0", "S")["idx"] == 77
    assert r["total"]["swidb"] == 78


def test_rows_are_not_the_idb_population():
    """The table lists active rows plus deleted ones; the inactive pool has
    no entry. Reading len(interfaces) as the IDB count is wrong by exactly
    the inactive figure -- on Edge2, 60 printed against 67 total."""
    r = parse_show_idb_all(LIVE)
    printed_h = [i for i in r["interfaces"] if i["type"] == "H"]
    deleted_h = [i for i in printed_h if i["hw_deleted"]]
    assert len(printed_h) == len(deleted_h) + 6     # trimmed sample
    assert r["total"]["hwidb"] > len(printed_h)


def test_junk_returns_empty_rather_than_failing():
    r = parse_show_idb_all("% Invalid input detected at '^' marker.")
    assert r["interfaces"] == []
    assert r["sw_idb_max"] is None
    assert r["total"] is None
