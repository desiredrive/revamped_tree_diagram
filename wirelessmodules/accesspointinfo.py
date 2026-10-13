from radkit_cli import get_single_output_genie, get_any_single_output
import re
import ipaddress

class AccessPointInfo:
    def __init__(self, wlc):
        self.wlc = wlc
    def apconfiggeneral(self, apname, service):
        wlcname = self.wlc
        apcg_cmd = f"show ap name {apname} config general"
        apcg_op = get_single_output_genie(wlcname,apcg_cmd, service)
        self.apconfiggeneral = apcg_op

    def fabric_status(self,apname,service):
        wlcname = self.wlc
        apfabriccmd = f"show ap name {apname} config general | i Fabric|RLOC"
        apfabricop = get_any_single_output(wlcname,apfabriccmd, service)
        rloc = None
        for line in (apfabricop or "").splitlines():
            m = re.match(r"^\s*RLOC\s*:\s*(\S+)\s*$", line)
            if not m:
                continue
            candidate = m.group(1)
            try:
                rloc =  str(ipaddress.ip_address(candidate))
            except ValueError:
                rloc = None
        self.rloc = rloc


#: Each unit IOS prints in an uptime, and its length in seconds.
_UPTIME_UNITS = {
    "second": 1, "seconds": 1, "sec": 1, "secs": 1,
    "minute": 60, "minutes": 60, "min": 60, "mins": 60,
    "hour": 3600, "hours": 3600, "hr": 3600, "hrs": 3600,
    "day": 86400, "days": 86400,
    "week": 604800, "weeks": 604800,
}

_UPTIME_PART = re.compile(r"(\d+)\s+([A-Za-z]+)")


def uptime_seconds(text):
    """An IOS uptime string as whole seconds, or None if it is not one.

    "11 hours 26 minutes 42 seconds" -> 41202.

    None rather than a guess whenever anything is unrecognised: an unknown
    unit, or no number/unit pair at all. The caller uses this to decide
    whether an AP associated recently enough to call it a flap, and a
    mis-read duration would put that warning on a perfectly stable AP -- or,
    worse, withhold it from one that is flapping. Declining to answer is the
    only safe failure here, and the caller reports the raw string instead.
    """
    if not text:
        return None
    parts = _UPTIME_PART.findall(text)
    if not parts:
        return None
    total = 0
    for value, unit in parts:
        scale = _UPTIME_UNITS.get(unit.lower())
        if scale is None:
            # One unrecognised unit makes the whole duration untrustworthy:
            # dropping it would silently under-count and could turn a stable
            # AP into a reported flap.
            return None
        total += int(value) * scale
    return total


#: One `show ap uptime` row. Anchored on the two MACs rather than on column
#: positions: the AP name column is padded to a fixed width, but a name longer
#: than that width pushes every later column right, and IOS does not truncate
#: it. Anchoring on the MACs -- which have a fixed, unambiguous shape -- means
#: a long name shifts nothing that matters.
#:
#: Both uptimes are left as the device wrote them ("11 hours 26 minutes 42
#: seconds"). Converting to seconds here would mean guessing at unit spellings
#: this lab has not shown us, and a wrong number is worse than a string.
_AP_UPTIME_ROW = re.compile(
    r"^(?P<ap_name>\S.*?)\s+"
    r"(?P<ethernet_mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<radio_mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<ap_up_time>\S.*?)\s{2,}"
    r"(?P<association_up_time>\S.*?)\s*$"
)

#: The count IOS prints above the table, used only as a cross-check.
_AP_COUNT = re.compile(r"^\s*Number of APs:\s*(\d+)\s*$")


def parse_ap_uptime(text):
    """`show ap uptime` as (rows, unreadable, expected).

    There is no Genie parser for this command, so the table is read here.

    `rows` maps AP name -> {ethernet_mac, radio_mac, ap_up_time,
    association_up_time}, with every value exactly as the device printed it.
    `unreadable` counts lines that looked like data but did not match, and
    `expected` is the "Number of APs" IOS prints, or None if it was absent.

    Nothing is inferred. A line that does not match is counted, never
    half-read into a row: a partially-recovered row is indistinguishable from
    a complete one once it is in the dict, and an AP reported with a blank
    uptime reads as a fault that is really a parsing gap. The caller compares
    `len(rows)` against `expected` and says so when they disagree, which is
    the only way a silently-dropped AP becomes visible.

    Safe on anything: unparseable input yields ({}, 0, None) rather than
    raising, because this runs inside a check whose job is to report, and a
    traceback from a cosmetic CLI change would take the whole step down.
    """
    rows = {}
    unreadable = 0
    expected = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        count = _AP_COUNT.match(line)
        if count:
            expected = int(count.group(1))
            continue
        # The echoed command, the column header, the rule under it and the
        # trailing prompt are all structure, not data, and none of them should
        # count as a row we failed to read.
        if (stripped.startswith("AP Name")
                or set(stripped) <= set("- ")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        match = _AP_UPTIME_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        entry = match.groupdict()
        name = entry.pop("ap_name").strip()
        rows[name] = {k: v.strip() for k, v in entry.items()}
    return rows, unreadable, expected


#: A row under "Configured Country Codes": the code, the country name, and
#: the bands with the environments each is approved for.
#:
#: Anchored on the two-letter code followed by a dash, which is the one part
#: of the row with a fixed shape. The band list is free text whose contents
#: vary by regulatory domain, so it is captured whole rather than split into
#: fields this lab cannot show us the full range of.
_COUNTRY_ROW = re.compile(
    r"^\s+(?P<code>[A-Z]{2})\s+-\s+(?P<name>\S[^\s].*?)\s{2,}(?P<bands>\S.*?)\s*$"
)

#: The summary line IOS prints above the table.
_COUNTRY_SUMMARY = re.compile(
    r"^\s*Configured Country\.+\s+(?P<code>[A-Z]{2})\s*-\s*(?P<name>.+?)\s*$"
)


def parse_wireless_country(text):
    """`show wireless country configured` as (countries, unreadable).

    There is no Genie parser for this command.

    `countries` maps the two-letter code -> {name, bands}, with both values
    as the device printed them. `unreadable` counts lines that sat under the
    table heading but did not match.

    An empty dict with no unreadable rows means the controller genuinely has
    no configured country -- a real and serious answer, since no AP can bring
    a radio up without one. That is why a row is never half-recovered: a
    country in the dict with a blank name is indistinguishable from a
    configured one, and the AP's country would then grade as present when it
    was never read.
    """
    countries = {}
    unreadable = 0
    in_table = False
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("#") or "#show " in stripped:
            continue
        summary = _COUNTRY_SUMMARY.match(line)
        if summary:
            # The single "Configured Country" line duplicates one of the rows
            # below; the table is authoritative, so this is not a row.
            continue
        if stripped.startswith("Configured Country Codes"):
            in_table = True
            continue
        if not in_table:
            continue
        match = _COUNTRY_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        entry = match.groupdict()
        countries[entry["code"]] = {
            "name": entry["name"].strip(),
            "bands": entry["bands"].strip(),
        }
    return countries, unreadable


#: One `show ap crash-file` row. The crash filename is the anchor: it always
#: ends in .crash and never contains a space, while the AP name column is
#: padded to a width a longer name overruns. The four Radio Slot columns that
#: follow are usually empty and are not captured -- a radio crash is a
#: separate concern from the AP crashing, and nothing here grades them.
_AP_CRASH_ROW = re.compile(
    r"^(?P<ap_name>\S.*?)\s+(?P<crash_file>\S+\.crash)\b"
)

#: The MAC a crash filename embeds, undotted: NAME_4800b33aea80.crash. It is
#: the only identifier in this table that survives an AP being renamed, which
#: is why the lookup prefers it over the name column.
_CRASH_FILE_MAC = re.compile(r"_([0-9a-fA-F]{12})\.crash$")


def parse_ap_crash_files(text):
    """`show ap crash-file` as (rows, unreadable).

    There is no Genie parser for this command.

    `rows` maps AP name -> {crash_file, mac}, where `mac` is the undotted MAC
    embedded in the filename, or "" when the filename does not carry one.
    `unreadable` counts lines that looked like data but did not match.

    An empty dict with no unreadable rows is the healthy answer: no AP on this
    controller has crashed. That is why a row is never half-recovered -- an
    entry with a blank filename is indistinguishable from a real crash once it
    is in the dict, and this check's whole output is whether an entry exists.

    Safe on anything: unparseable input yields ({}, 0) rather than raising.
    """
    rows = {}
    unreadable = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # The echoed command, the file-location line, the column header, the
        # rule under it and the trailing prompt are structure, not data.
        if (stripped.startswith("AP Name")
                or stripped.startswith("File Location")
                or set(stripped) <= set("- ")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        match = _AP_CRASH_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        name = match.group("ap_name").strip()
        crash_file = match.group("crash_file").strip()
        mac = _CRASH_FILE_MAC.search(crash_file)
        rows[name] = {"crash_file": crash_file,
                      "mac": (mac.group(1).lower() if mac else "")}
    return rows, unreadable
