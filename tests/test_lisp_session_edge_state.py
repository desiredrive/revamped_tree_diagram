"""The LISP session edges carry their state once it is known.

The edges are drawn at discovery time, before any session has been read, so
they start as a bare "LISP Session". `LispPerMapServerSession` is what learns the
state, and these pin that it hands the canvas enough to say so.
"""
import inspect
import checks.lisp_session as m


def test_the_state_check_emits_the_node_and_the_state():
    src = inspect.getsource(m.LispPerMapServerSession.run_session)
    assert 'data["lisp_session_state"] = [' in src
    assert '{"node": self.target_node_id, "state": state}' in src


def test_it_is_keyed_by_node_not_by_address():
    """The session peers with the RLOC while the control-plane node carries
    its management IP. Those differ, so an address-keyed payload would match
    no edge at all -- the comment at the AP discovery site says as much."""
    src = inspect.getsource(m.LispPerMapServerSession.run_session)
    i = src.index('data["lisp_session_state"]')
    payload = src[i:i + 200]
    assert "self.target_node_id" in payload
    assert "map_server" not in payload


def test_it_is_guarded_on_having_a_node():
    """`node_for` returns nothing when the control plane was merged into
    another node. Emitting a payload with no node would have the client
    silently skip it, so it is not emitted at all."""
    src = inspect.getsource(m.LispPerMapServerSession.run_session)
    assert "if self.target_node_id:" in src


def test_the_runner_forwards_it():
    import scenario_runner
    src = inspect.getsource(scenario_runner)
    assert '"lisp_session_state"' in src, (
        "the payload is built but never reaches the UI")
