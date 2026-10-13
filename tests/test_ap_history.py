"""`show wireless stats ap history` — the parser and the check on it."""

import types

import pytest

from checks.base import CheckStatus
from wirelessmodules.accesspointinfo import (
    parse_ap_history, disjoins_for, disjoins_by_day,
)

WLC = "wlc-jalejand-cisco-com"
NAME = "AP-002"
RADIO = "3891.b70f.2600"


def _row(event, time, reason="NA", count="NA"):
    return (f"{NAME:32} {RADIO}  {event:9}  {time}  NA"
            f"                       {reason:26} {count} ")


HEADER = ("AP Name                          Radio MAC       Event      Time"
          "               Recent Disconnect Time   Disconnect Reason"
          "          Disconnect Count\n"
          + "-" * 147 + "\n")

LIVE = HEADER + "\n".join([
    _row("Joined", "10/13/26 07:27:21"),
    _row("Disjoined", "10/13/26 07:22:59", "Heart beat timer expiry", "1"),
    _row("Joined", "10/12/26 22:21:28"),
    # A planned upgrade: a disconnect, but not a fault.
    _row("Disjoined", "10/09/26 23:24:30", "Image Download Success", "2"),
    _row("Disjoined", "10/09/26 22:30:47", "Heart beat timer expiry", "1"),
    _row("Disjoined", "10/09/26 11:36:18", "DTLS close alert from peer", "1"),
])


def test_parses_both_event_types():
    rows, unreadable = parse_ap_history(LIVE)
    assert unreadable == 0
    assert len(rows) == 6
    assert rows[0]["event"] == "Joined"
    assert rows[1]["disconnect_reason"] == "Heart beat timer expiry"


def test_a_reason_touching_the_count_column_still_splits():
    """"DTLS close alert from peer 1" has one space, not two."""
    rows, _u = parse_ap_history(LIVE)
    dtls = [r for r in rows if r["disconnect_reason"].startswith("DTLS")][0]
    assert dtls["disconnect_reason"] == "DTLS close alert from peer"
    assert dtls["disconnect_count"] == "1"


def test_image_download_is_not_counted_as_a_disjoin():
    """An AP drops to load new software and comes back. Not a flap."""
    rows, _u = parse_ap_history(LIVE)
    reasons = [d["disconnect_reason"] for d in disjoins_for(rows)]
    assert "Image Download Success" not in reasons
    assert len(reasons) == 3


def test_disjoins_are_capped_and_newest_first():
    rows, _u = parse_ap_history(LIVE)
    out = disjoins_for(rows, limit=2)
    assert len(out) == 2
    assert out[0]["time"] == "10/13/26 07:22:59"


def test_disjoins_filter_to_one_ap():
    other = LIVE + "\n" + _row(
        "Disjoined", "10/13/26 09:00:00", "Heart beat timer expiry",
        "1").replace(NAME, "AP-999").replace(RADIO, "aaaa.bbbb.cccc")
    rows, _u = parse_ap_history(other)
    assert len(disjoins_for(rows, radio_mac=RADIO)) == 3
    assert len(disjoins_for(rows, radio_mac="aaaa.bbbb.cccc")) == 1


def test_days_are_counted_by_calendar_date():
    rows, _u = parse_ap_history(LIVE)
    assert disjoins_by_day(disjoins_for(rows)) == {
        "10/13/26": 1, "10/09/26": 2}


@pytest.mark.parametrize("bad", [None, "", "\x00 garbage", "no table"])
def test_parser_never_raises(bad):
    rows, _u = parse_ap_history(bad)
    assert rows == []


@pytest.fixture
def served(monkeypatch):
    def _serve(text):
        import radkit_cli
        monkeypatch.setattr(radkit_cli, "get_any_single_output",
                            lambda h, c, s, **k: text)
    return _serve


def _ctx():
    return types.SimpleNamespace(
        service=object(), payload={"mac": "b811.4b0e.2630"},
        state={"ap_wlc_ap_name": NAME, "ap_wlc_radio_mac": RADIO})


def test_occasional_disjoins_are_listed_but_not_flagged(served):
    """One or two in a day is ordinary and says nothing on its own."""
    from checks.ap_wlc import ApWlcApHistory

    served(LIVE)
    r = ApWlcApHistory(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert "Heart beat timer expiry" in r.message


def test_more_than_two_in_one_day_is_flapping(served):
    from checks.ap_wlc import ApWlcApHistory

    served(LIVE + "\n" + "\n".join([
        _row("Disjoined", "10/13/26 05:11:02", "Heart beat timer expiry", "1"),
        _row("Disjoined", "10/13/26 03:44:18", "DTLS close alert from peer", "1"),
    ]))
    r = ApWlcApHistory(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "3 on 10/13/26" in r.message


def test_an_upgrade_day_does_not_become_a_flap(served):
    """Three disconnects where two are image downloads is not flapping."""
    from checks.ap_wlc import ApWlcApHistory

    served(HEADER + "\n".join([
        _row("Disjoined", "10/13/26 07:22:59", "Heart beat timer expiry", "1"),
        _row("Disjoined", "10/13/26 05:11:02", "Image Download Success", "1"),
        _row("Disjoined", "10/13/26 03:44:18", "Image Download Success", "1"),
    ]))
    r = ApWlcApHistory(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK


def test_no_disjoins_at_all(served):
    from checks.ap_wlc import ApWlcApHistory

    served(HEADER + _row("Joined", "10/13/26 07:27:21"))
    r = ApWlcApHistory(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.OK
    assert "no recorded disjoins" in r.message
