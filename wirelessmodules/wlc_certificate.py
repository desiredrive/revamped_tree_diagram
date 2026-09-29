"""Wireless management certificate validity.

`show wireless management trustpoint` reports `Certificate Info: Available`,
which says a certificate is installed -- not that it is currently valid. An
expired certificate is still "Available", so a WLC can pass that check and
still refuse every AP: the DTLS handshake an AP uses to join fails when the
controller presents an expired certificate.

Genie parses the dates that close this gap -- ShowCryptoPkiCertificates yields
`validity_date.start_date` / `end_date` -- but nothing in Genie evaluates them.
Its certificate APIs stop short of this:

  * cat9k/c9800 get_pki_trustpoint_state  -- returns the trustpoint state
    string, no dates
  * cat9k/c9800 verify_pki_trustpoint_state -- polls a live device until a
    state matches; needs a device object, so it cannot run against
    already-collected output
  * sudi verify_crypto_pki_certificate -- SUDI hardware certificates, a
    different trustpoint

So this module does not parse anything: it consumes Genie's parsed structure
and answers the one question Genie does not, which is whether the dates in it
are still good relative to now.

Only the device-facing certificate matters here. That command also returns the
CA certificate(s) in the chain, which have their own (usually much longer)
lifetimes -- reporting the CA's expiry as the controller's would give a
reassuring date while the identity certificate underneath it has expired.
"""

from datetime import datetime, timezone

# `end date: 04:32:19 UTC Mar 2 2026`. The zone abbreviation is whatever the
# device is configured for (UTC, IST, EST...), and abbreviations are ambiguous,
# so it is captured but not used to shift the time -- see _parse_date.
_DATE_FORMAT = "%H:%M:%S %Z %b %d %Y"

# Certificates the controller presents to an AP. The CA / router self-signed
# entries in the same output belong to the chain, not to the controller's
# identity, and their dates must not stand in for it.
_DEVICE_USAGES = {"general purpose", "signature", "encryption"}

# Inside this window the certificate still works but is close enough to expiry
# that it is worth surfacing before it strands every AP at the site.
EXPIRY_WARNING_DAYS = 30


def _parse_date(value: str):
    """A `show crypto` date string as an aware UTC datetime, or None.

    The zone abbreviation is dropped rather than interpreted: %Z accepts only a
    handful of names, abbreviations are genuinely ambiguous (IST is two
    different zones), and the certificate lifetimes involved are months or
    years. Treating the wall-clock time as UTC can therefore be off by at most
    a few hours, which never changes the verdict -- except within hours of the
    boundary, where "expiring" already covers it.
    """
    if not value:
        return None
    parts = value.split()
    if len(parts) != 5:
        return None
    hms, _zone, mon, day, year = parts
    try:
        naive = datetime.strptime(f"{hms} {mon} {day} {year}", "%H:%M:%S %b %d %Y")
    except ValueError:
        return None
    return naive.replace(tzinfo=timezone.utc)


def extract_certificates(parsed: dict, trustpoint: str = None) -> list[dict]:
    """Flatten the parser's nested trustpoint structure into a list.

    Genie nests as trustpoints -> <name> -> associated_trustpoints -> <name>.
    Each entry keeps the trustpoint it was found under so a caller can tell the
    controller's own certificate from others in the same output.
    """
    certs = []
    for outer, body in ((parsed or {}).get("trustpoints") or {}).items():
        for inner, entry in ((body or {}).get("associated_trustpoints") or {}).items():
            if trustpoint and trustpoint not in (outer, inner):
                continue
            # Genie gives this level two shapes, both legitimate. Asking for one
            # trustpoint -- which is what the trustpoint check does -- yields a
            # LIST of certificate dicts under a single "certificate" key, since
            # the device can hold more than one certificate for that trustpoint.
            # The unfiltered command instead yields one dict per role, keyed
            # "certificate" / "ca_certificate". Reading only the second shape
            # crashed on every filtered lookup.
            for cert in (entry if isinstance(entry, list) else [entry]):
                if not isinstance(cert, dict):
                    continue
                validity = cert.get("validity_date") or {}
                certs.append({
                    "trustpoint": inner or outer,
                    "status": cert.get("status"),
                    "usage": (cert.get("usage") or "").strip(),
                    "serial": cert.get("serial_number_in_hex"),
                    "start_date": validity.get("start_date"),
                    "end_date": validity.get("end_date"),
                    "subject": cert.get("subject") or {},
                    "issuer": cert.get("issuer") or {},
                })
    return certs


def _is_device_certificate(cert: dict) -> bool:
    """True for a certificate the controller presents, not a CA in the chain."""
    return (cert.get("usage") or "").strip().lower() in _DEVICE_USAGES


def classify(cert: dict, now: datetime = None) -> tuple[str, str]:
    """(state, detail) for one certificate.

    state is one of: valid, expiring, expired, not_yet_valid, unknown.
    "unknown" means the dates could not be read -- reported as such rather than
    assumed good, since a silent parse failure here would recreate exactly the
    blind spot this module exists to close.
    """
    now = now or datetime.now(timezone.utc)
    end = _parse_date(cert.get("end_date"))
    start = _parse_date(cert.get("start_date"))

    if end is None:
        return "unknown", (
            f"validity dates could not be read (end date: "
            f"{cert.get('end_date') or 'absent'})")

    if end <= now:
        days = (now - end).days
        return "expired", (
            f"expired {days} day(s) ago, on {cert.get('end_date')}")

    if start is not None and start > now:
        return "not_yet_valid", (
            f"not valid until {cert.get('start_date')}; the controller clock "
            "may be wrong")

    days_left = (end - now).days
    if days_left <= EXPIRY_WARNING_DAYS:
        return "expiring", (
            f"expires in {days_left} day(s), on {cert.get('end_date')}")

    return "valid", f"valid until {cert.get('end_date')} ({days_left} days)"


def assess(parsed: dict, trustpoint: str = None, now: datetime = None) -> dict:
    """Verdict for a controller's management certificate.

    Returns {state, detail, certificate, checked, skipped_ca}. `state` is the
    worst state among the controller's own certificates, ordered so a genuine
    problem always outranks a clean one.
    """
    certs = extract_certificates(parsed, trustpoint)
    device_certs = [c for c in certs if _is_device_certificate(c)]
    # Fall back to everything found rather than reporting nothing at all: a
    # release that words the usage differently should still get a verdict.
    considered = device_certs or certs

    if not considered:
        return {"state": "unknown", "certificate": None, "checked": 0,
                "skipped_ca": 0,
                "detail": "no certificate was returned for this trustpoint"}

    order = ["expired", "not_yet_valid", "unknown", "expiring", "valid"]
    graded = [(order.index(s), s, d, c)
              for c, (s, d) in ((c, classify(c, now)) for c in considered)]
    graded.sort(key=lambda g: g[0])
    _, state, detail, cert = graded[0]

    return {
        "state": state,
        "detail": detail,
        "certificate": cert,
        "checked": len(considered),
        "skipped_ca": len(certs) - len(device_certs) if device_certs else 0,
    }
