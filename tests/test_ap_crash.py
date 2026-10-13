"""`show ap crash-file` — the parser and the check built on it."""

import types

import pytest

from checks.base import CheckStatus
from wirelessmodules.accesspointinfo import parse_ap_crash_files

WLC = "wlc-jalejand-cisco-com"

# Trimmed from a production controller: several APs, Radio Slot columns empty.
REAL = """HYS-MPO-ITR-SDA-WLC-01#show ap crash-file
File Location: BOOTFLASH
AP Name                          Crash File                         Radio Slot 0                       Radio Slot 1
--------------------------------------------------------------------------------------------------------------------
HYS-MPO-05F-SDA-AP-02            HYS-MPO-05F-SDA-AP-02_4800b33aea80.crash
HYS-MPO-13F-SDA-AP-02            HYS-MPO-13F-SDA-AP-02_4800b33aeac0.crash
HYS-MPO-10F-SDA-AP-04            HYS-MPO-10F-SDA-AP-04_4800b33b01e0.crash
HYS-MPO-ITR-SDA-WLC-01#"""

# The healthy case, and the one the lab controller actually returns.
EMPTY = """WLCv#show ap crash-file
File Location: BOOTFLASH
AP Name                          Crash File                         Radio Slot 0
----------------------------------------------------------------------------------
 
WLCv#"""


def test_parses_every_row_and_its_embedded_mac():
    rows, unreadable = parse_ap_crash_files(REAL)
    assert len(rows) == 3
    assert unreadable == 0
    entry = rows["HYS-MPO-05F-SDA-AP-02"]
    assert entry["crash_file"] == "HYS-MPO-05F-SDA-AP-02_4800b33aea80.crash"
    assert entry["mac"] == "4800b33aea80"


def test_empty_table_is_no_crashes_not_a_parse_failure():
    """The healthy answer has to be distinguishable from a broken parse."""
    assert parse_ap_crash_files(EMPTY) == ({}, 0)


def test_structure_lines_are_not_counted_as_unreadable():
    """The echo, File Location, header, rule and prompt are not data."""
    _rows, unreadable = parse_ap_crash_files(REAL)
    assert unreadable == 0


@pytest.mark.parametrize("bad", [None, "", "\x00 garbage", "no table here"])
def test_parser_never_raises(bad):
    """It runs inside a check whose job is to report."""
    rows, _unreadable = parse_ap_crash_files(bad)
    assert rows == {}


def test_a_row_without_a_mac_in_the_filename_still_parses():
    """The MAC is a convenience; the AP name is the key."""
    text = ("AP Name          Crash File\n"
            "---------------------------\n"
            "AP-002           AP-002.crash\n")
    rows, _ = parse_ap_crash_files(text)
    assert rows["AP-002"]["mac"] == ""


def _ctx(state=None):
    return types.SimpleNamespace(
        service=object(), payload={"mac": "b811.4b0e.2630"},
        state=state if state is not None else {"ap_wlc_ap_name": "AP-002"})


@pytest.fixture
def served(monkeypatch):
    def _serve(text):
        import radkit_cli
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s, **k: text)
    return _serve


def test_this_ap_absent_from_a_populated_table_is_ok(served):
    """Other APs crashing is not this AP's finding."""
    from checks.ap_wlc import ApWlcApCrash

    served(REAL)
    r = ApWlcApCrash(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert "no crash file" in r.message


def test_this_ap_present_is_a_warning(served):
    from checks.ap_wlc import ApWlcApCrash

    served(REAL.replace("HYS-MPO-05F-SDA-AP-02 ", "AP-002" + " " * 16, 1))
    r = ApWlcApCrash(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "crashed at some point" in r.message


def test_an_unreadable_row_is_passed_over(served):
    """A malformed line says nothing about whether this AP crashed."""
    from checks.ap_wlc import ApWlcApCrash

    served(REAL + "\n!! corrupt line with no crash file\n")
    r = ApWlcApCrash(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK


def test_an_ap_on_another_controller_is_skipped(served, monkeypatch):
    """Absence from this controller is ApWlcApState's finding, not this one's."""
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApCrash

    served(REAL)
    monkeypatch.setattr(mod, "_resolve_ap_name", lambda c, h, s: "")
    r = ApWlcApCrash(WLC, "wlc0").run_ap(_ctx(state={}))
    assert r.status is CheckStatus.SKIP
