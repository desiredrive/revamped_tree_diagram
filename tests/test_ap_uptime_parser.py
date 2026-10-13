"""`show ap uptime` has no Genie parser, so the table is read by hand.

The safety property under test is not "it parses the lab's output" -- it is
that a row it cannot read fully is refused and counted rather than
half-recovered. A row in the dict with a blank uptime reads as an AP fault;
a row that was refused reads as a parsing gap, and only the second is true.
"""

from wirelessmodules.accesspointinfo import parse_ap_uptime

HDR = ("AP Name                          Ethernet MAC    Radio MAC       "
       "AP Up Time                                          "
       "Association Up Time")
SEP = "-" * 147

# Verbatim from the lab WLC, trailing padding included.
REAL = """WLCv#show ap uptime
Number of APs: 1
 
 
""" + HDR + "\n" + SEP + """
AP-002                           b811.4b0e.2630  3891.b70f.2600  11 hours 26 minutes 42 seconds                      11 hours 24 minutes 48 seconds               
 
WLCv#"""


def _table(*rows, count=None):
    lines = ([f"Number of APs: {count}"] if count is not None else [])
    return "\n".join(lines + [HDR, SEP] + list(rows))


def test_real_device_output():
    rows, unreadable, expected = parse_ap_uptime(REAL)
    assert unreadable == 0
    assert expected == 1
    assert list(rows) == ["AP-002"]
    ap = rows["AP-002"]
    assert ap["ethernet_mac"] == "b811.4b0e.2630"
    assert ap["radio_mac"] == "3891.b70f.2600"
    # Exactly as the device wrote them, trailing padding stripped.
    assert ap["ap_up_time"] == "11 hours 26 minutes 42 seconds"
    assert ap["association_up_time"] == "11 hours 24 minutes 48 seconds"


def test_structure_lines_are_not_counted_as_unreadable_rows():
    """The echo, header, rule and prompt are structure, not failed rows."""
    _, unreadable, _ = parse_ap_uptime(REAL)
    assert unreadable == 0


def test_two_aps():
    rows, unreadable, expected = parse_ap_uptime(_table(
        "AP-002   b811.4b0e.2630  3891.b70f.2600  11 hours 1 minutes 2 seconds    10 hours 3 minutes 4 seconds",
        "AP-003   b811.4b0e.2631  3891.b70f.2601  5 days 2 hours 1 minutes        5 days 2 hours 0 minutes",
        count=2))
    assert unreadable == 0 and expected == 2 and len(rows) == 2
    assert rows["AP-003"]["ap_up_time"] == "5 days 2 hours 1 minutes"


def test_a_name_wider_than_its_column_still_parses():
    """IOS pads the name column but does not truncate a longer name.

    Anchoring on the MACs rather than on column offsets is what makes this
    work; a fixed-width slice would cut the name and shift every field.
    """
    long_name = "AP-with-a-very-long-name-exceeding-the-column-width"
    rows, unreadable, _ = parse_ap_uptime(_table(
        f"{long_name}  b811.4b0e.2630  3891.b70f.2600  9 hours 0 minutes   8 hours 0 minutes",
        count=1))
    assert unreadable == 0
    assert rows[long_name]["radio_mac"] == "3891.b70f.2600"


def test_an_incomplete_row_is_refused_not_half_read():
    """Missing the second uptime must yield no row at all."""
    rows, unreadable, _ = parse_ap_uptime(
        _table("AP-004   b811.4b0e.2632  3891.b70f.2602  9 hours", count=1))
    assert rows == {}
    assert unreadable == 1


def test_a_row_without_macs_is_refused():
    rows, unreadable, _ = parse_ap_uptime(
        _table("AP-005   some  junk  here  and more", count=1))
    assert rows == {}
    assert unreadable == 1


def test_a_dropped_ap_is_visible_through_the_count():
    """The device promised 2 APs and printed 1.

    The parser does not invent the missing row; it reports both numbers so
    the caller can say an AP went unread instead of silently showing one.
    """
    rows, unreadable, expected = parse_ap_uptime(_table(
        "AP-002  b811.4b0e.2630  3891.b70f.2600  1 hours 0 minutes   1 hours 0 minutes",
        count=2))
    assert len(rows) == 1 and expected == 2 and unreadable == 0


def test_garbage_and_empty_input_never_raise():
    """This runs inside a check; a cosmetic CLI change must not traceback."""
    assert parse_ap_uptime("") == ({}, 0, None)
    assert parse_ap_uptime(None) == ({}, 0, None)
    rows, unreadable, expected = parse_ap_uptime("total nonsense\nmore nonsense")
    assert rows == {} and unreadable == 2 and expected is None
