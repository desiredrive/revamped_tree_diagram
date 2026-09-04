"""Transport seam tests.

Run: python -m pytest tests/ -v   (or: python tests/test_transport.py)

These are the first tests in the repo that exercise the I/O layer without a
fabric. That is the point of the seam: before it, checking any of this needed
live devices.
"""

import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transport import (  # noqa: E402
    LiveTransport, MissingFixture, ReplayTransport,
    get_transport, reset_transport, set_transport,
)


def _fixture(**overrides) -> Path:
    data = {
        "commands": {"EDGE-1||show mac address-table":
                     "Vlan 1021  aaaa.bbbb.cccc  DYNAMIC  Gi1/0/1"},
        "apis": {"catc||/dna/intent/api/v1/network-device/ip-address/10.1.1.1":
                 {"response": {"hostname": "EDGE-1", "platformId": "C9300-48P"}}},
        "inventory": {"host||^10.1.1.1$": ["EDGE-1"],
                      "device_type||CENTER": ["catc"]},
    }
    data.update(overrides)
    path = Path(tempfile.mkdtemp()) / "case.json"
    path.write_text(json.dumps(data))
    return path


def test_live_is_the_default():
    """Nothing that does not opt in may change behaviour."""
    assert isinstance(get_transport(), LiveTransport)
    assert get_transport().requires_service is True


def test_replay_serves_radkit_cli_without_a_service():
    """The whole I/O layer must work with service=None."""
    token = set_transport(ReplayTransport(_fixture()))
    try:
        from radkit_cli import (get_any_single_output, get_catc_api,
                                get_catc_name, get_hostname_from_mgmtip)
        assert get_any_single_output("EDGE-1", "show mac address-table", None) == \
            "Vlan 1021  aaaa.bbbb.cccc  DYNAMIC  Gi1/0/1"
        assert get_catc_api(
            "catc", "/dna/intent/api/v1/network-device/ip-address/10.1.1.1", None
        )["response"]["platformId"] == "C9300-48P"
        assert get_hostname_from_mgmtip("10.1.1.1", None) == "EDGE-1"
        assert get_catc_name(None) == "catc"
        assert get_transport().requires_service is False
    finally:
        reset_transport(token)


def test_missing_fixture_is_loud():
    """A gap must fail visibly, not look like a device that said nothing.

    MissingFixture must NOT subclass KeyError: radkit_cli catches KeyError and
    turns it into sys.exit, which would hide the gap.
    """
    token = set_transport(ReplayTransport(_fixture()))
    try:
        from radkit_cli import get_any_single_output
        try:
            get_any_single_output("EDGE-1", "show version", None)
        except MissingFixture as e:
            assert "show version" in str(e)
        else:
            raise AssertionError("a missing fixture did not raise")
    finally:
        reset_transport(token)


def test_command_list_and_string_key_alike():
    """radkit_cli passes [command] on one path and command on the other; a
    fixture recorded via either must be found by both."""
    token = set_transport(ReplayTransport(_fixture()))
    try:
        t = get_transport()
        assert t.exec("EDGE-1", "show mac address-table").result.data == \
               t.exec("EDGE-1", ["show mac address-table"]).result.data
    finally:
        reset_transport(token)


def test_survives_thread_pool_fan_out():
    """The multi-border case: iptransit fans out to a ThreadPoolExecutor.

    Pool threads start with a fresh context, so a worker would fall back to
    LiveTransport and try to reach real devices. iptransit already snapshots the
    caller's context (for the per-session logfile); this asserts the transport
    rides along with it.
    """
    fx = _fixture(commands={f"BORDER-{i}||show ip route": f"routes on {i}"
                            for i in range(4)})
    token = set_transport(ReplayTransport(fx))
    try:
        from radkit_cli import get_any_single_output

        def worker(i):
            return get_any_single_output(f"BORDER-{i}", "show ip route", None)

        caller_context = copy_context()
        with ThreadPoolExecutor(max_workers=4) as ex:
            got = list(ex.map(lambda i: caller_context.copy().run(worker, i), range(4)))
        assert got == [f"routes on {i}" for i in range(4)]
    finally:
        reset_transport(token)


def test_scenarios_still_assemble():
    """Guard against the seam breaking chain assembly."""
    from check_registry import build_check_chain
    expected = {"dhcp": 52, "east_west": 63, "underlay_multicast": 52,
                "ap_onboarding": 7}
    for scenario, count in expected.items():
        chain = build_check_chain(
            {"scenario": scenario, "mgmt_ip": "1.1.1.1", "vrf": "default"})
        assert len(chain) == count, f"{scenario}: {len(chain)} != {count}"


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as e:
            failed += 1
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{'FAILED' if failed else 'All tests passed'}"
          f"{f' ({failed})' if failed else ''}")
    sys.exit(1 if failed else 0)
