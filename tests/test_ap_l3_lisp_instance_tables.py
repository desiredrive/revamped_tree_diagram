"""Reading `Locator table:` / `EID table:` when Genie discards the result.

Genie parses `show lisp instance-id <id> ipv4` correctly and then fails its
OWN schema check: the schema requires `itr.proxy_itr_router`, which the
parser only sets when the PITR line reads a bare `enabled`/`disabled`. A
real SD-Access edge prints

    Proxy-ITR Router (PITR):   enabled RLOCs: 172.19.1.67 (not local)

the regex misses, the key is absent, and Genie throws away the WHOLE result
(status FAILURE, data None) although locator table and EID table parsed
fine. Verified against edge-2-jalejand-cisco-com, whose status_message was
"Missing keys: [['lisp_id', 0, 'instance_id', 4097, 'itr',
'proxy_itr_router']]".

So the two fields the check needs are read from the text as a fallback.
"""

from checks.ap_onboarding import _instance_tables_from_text


# Verbatim from the device that exposed this, trimmed to the relevant head.
REAL = """  Instance ID:                              4097
  Router-lisp ID:                           0
  Locator table:                            default
  EID table:                                default
  Ingress Tunnel Router (ITR):              disabled
  Egress Tunnel Router (ETR):               enabled
  Proxy-ITR Router (PITR):                  enabled RLOCs: 172.19.1.67 (not local)
  Proxy-ETR Router (PETR):                  disabled
"""


def test_both_tables_are_read_from_real_device_output():
    assert _instance_tables_from_text(REAL) == {
        "locator_table": "default", "eid_table": "default"}


def test_a_vrf_bound_instance_is_reported_as_such():
    """The fallback must not flatten a VRF binding into `default`."""
    text = REAL.replace("Locator table:                            default",
                        "Locator table:                            CORP")
    assert _instance_tables_from_text(text)["locator_table"] == "CORP"
    assert _instance_tables_from_text(text)["eid_table"] == "default"


def test_the_pitr_line_is_not_mistaken_for_a_table():
    """`EID table:` is matched at the start of the line, not anywhere in it."""
    assert "proxy" not in str(_instance_tables_from_text(REAL)).lower()


def test_missing_fields_are_absent_rather_than_guessed():
    assert _instance_tables_from_text("  Instance ID:  4097\n") == {}


def test_no_output_is_not_an_error():
    assert _instance_tables_from_text("") == {}
    assert _instance_tables_from_text(None) == {}


def test_the_first_occurrence_wins():
    """Two instances in one capture must not blend into each other."""
    two = REAL + REAL.replace("default", "OTHER")
    assert _instance_tables_from_text(two)["locator_table"] == "default"
