"""Transport seam for device and Catalyst Center I/O.

Every command and API call in the app funnels through five functions in
`radkit_cli`. This module puts one indirection under them so the same check
code can run three ways:

  live      talk to devices through RADKit (what has always happened)
  recording live, and additionally save every response to a fixture file
  replay    serve saved responses; never touch RADKit at all

Replay is the point: 30k lines of check logic currently have no test coverage
because exercising a chain needs a live fabric. With fixtures a full 52-check
DHCP run is a fast, offline, deterministic test.

The seam is deliberately thin. Everything RADKit-specific that is *not* raw
I/O -- the genie parse retry, the CatC rate-limit backoff, the error paths --
stays in `radkit_cli`, because that logic is worth exercising in tests too.
What lives here is only "get bytes for (hostname, command)".

A ContextVar, not a global or a thread-local: `iptransit` fans work out to a
ThreadPoolExecutor, and a thread-local would leave pool threads unset -- they
would silently fall back to live RADKit in exactly the multi-border case a test
is trying to replay. Same reasoning as the per-session logfile.
"""

from __future__ import annotations

import json
import threading
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Optional


class Transport:
    """Raw I/O for one run. Subclasses decide where the bytes come from."""

    #: False for transports that need no RADKit service handle. Lets the UI
    #: decide whether a scenario requires SSO at all.
    requires_service = True

    def exec(self, hostname: str, command: str, service, timeout: int = 0):
        """Run `command` on `hostname`; return RADKit's request object."""
        raise NotImplementedError

    def http_get(self, dnac: str, api_url: str, service):
        """GET a Catalyst Center API path; return the decoded JSON."""
        raise NotImplementedError

    def inventory_filter(self, service, key: str, pattern: str) -> list[str]:
        """Device names matching an inventory filter."""
        raise NotImplementedError


class LiveTransport(Transport):
    """Talk to real devices through RADKit. The historical behaviour."""

    def exec(self, hostname: str, command: str, service, timeout: int = 0):
        device = service.inventory[hostname]
        # exec() takes a bare string for the genie path and a list for the raw
        # path; both are preserved by passing the caller's form straight through.
        if timeout:
            return device.exec(command, timeout=timeout).wait()
        return device.exec(command).wait()

    def http_get(self, dnac: str, api_url: str, service):
        response = service.inventory[dnac].http.get(api_url).wait()
        return json.loads(response.content)

    def inventory_filter(self, service, key: str, pattern: str) -> list[str]:
        return list(service.inventory.filter(key, pattern).keys())


def _command_text(command) -> str:
    """Callers pass either a bare string or a one-element list (both are valid
    RADKit exec forms). Normalise so a fixture keys the same either way."""
    if isinstance(command, (list, tuple)):
        return command[0] if len(command) == 1 else "|".join(map(str, command))
    return str(command)


def _key(hostname: str, command) -> str:
    """Fixture key. Hostname and command together identify a response."""
    return f"{hostname}||{_command_text(command)}"


class RecordingTransport(Transport):
    """Live I/O that also writes every response to a fixture file.

    Wraps rather than replaces LiveTransport, so a recorded run behaves exactly
    like a normal one -- recording must never change what an engineer sees.

    Note this cannot reuse the collection log as a fixture source: that log
    truncates output at 15000 characters (append_to_logging_file), which is fine
    for reading but would silently corrupt a fixture.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._live = LiveTransport()
        self._lock = threading.Lock()   # checks run across a thread pool
        self._data: dict[str, Any] = {"commands": {}, "apis": {}, "inventory": {}}

    def exec(self, hostname: str, command: str, service, timeout: int = 0):
        result = self._live.exec(hostname, command, service, timeout)
        # Store the raw text. The genie parse is deliberately re-run on replay
        # rather than cached, so a parser change is exercised by the tests.
        try:
            text = result.result.data
        except Exception:
            try:
                text = result.result[command].data
            except Exception:
                text = None
        if text is not None:
            with self._lock:
                self._data["commands"][_key(hostname, command)] = text
        return result

    def http_get(self, dnac: str, api_url: str, service):
        payload = self._live.http_get(dnac, api_url, service)
        with self._lock:
            self._data["apis"][_key(dnac, api_url)] = payload
        return payload

    def inventory_filter(self, service, key: str, pattern: str) -> list[str]:
        names = self._live.inventory_filter(service, key, pattern)
        with self._lock:
            self._data["inventory"][_key(key, pattern)] = names
        return names

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.path.write_text(json.dumps(self._data, indent=2))
        return self.path


class MissingFixture(Exception):
    """A replay run asked for something the fixture does not contain.

    Raised rather than returning None so a gap in a fixture is a loud test
    failure, not a check quietly deciding the device said nothing.
    """


class _ReplayResult:
    """Stands in for a RADKit request object, exposing just what callers read.

    `.result.data` and `.result[command].data` are the two shapes radkit_cli
    reads; `.wait()` is a no-op so the genie retry loop works unchanged.
    """

    class _Inner:
        def __init__(self, data): self.data = data
        def __getitem__(self, _key): return self

    def __init__(self, text: str):
        self.result = self._Inner(text)

    def wait(self):
        return self


class ReplayTransport(Transport):
    """Serve saved responses. Never touches RADKit."""

    requires_service = False

    def __init__(self, path: Path | str):
        self._data = json.loads(Path(path).read_text())
        self.path = Path(path)

    def exec(self, hostname: str, command: str, service=None, timeout: int = 0):
        k = _key(hostname, command)
        try:
            return _ReplayResult(self._data["commands"][k])
        except KeyError:
            raise MissingFixture(
                f"No recorded output for {_command_text(command)!r} on "
                f"{hostname!r} in {self.path.name}"
            ) from None

    def http_get(self, dnac: str, api_url: str, service=None):
        k = _key(dnac, api_url)
        try:
            return self._data["apis"][k]
        except KeyError:
            raise MissingFixture(
                f"No recorded response for API {api_url!r} on {dnac!r} "
                f"in {self.path.name}"
            ) from None

    def inventory_filter(self, service, key: str, pattern: str) -> list[str]:
        k = _key(key, pattern)
        try:
            return self._data["inventory"][k]
        except KeyError:
            raise MissingFixture(
                f"No recorded inventory for filter {key}={pattern!r} "
                f"in {self.path.name}"
            ) from None


# Live by default, so nothing that does not opt in changes behaviour.
_current: ContextVar[Transport] = ContextVar("transport", default=LiveTransport())


def get_transport() -> Transport:
    return _current.get()


def set_transport(transport: Transport):
    """Install a transport for this context. Returns the token to reset with."""
    return _current.set(transport)


def reset_transport(token) -> None:
    _current.reset(token)
