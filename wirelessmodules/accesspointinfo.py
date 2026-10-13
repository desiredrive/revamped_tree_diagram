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


#: One `show wireless stats ap discovery` row. Anchored on the two MACs, which
#: have a fixed shape, rather than on column positions: the IP column is wide
#: and the timestamp columns are not padded consistently across releases.
#:
#: The last three fields are kept as the device printed them. "None" and "NA"
#: are literal strings the controller writes for an AP that has never failed
#: discovery, not empty columns, and the caller tests for them by name.
_AP_DISCOVERY_ROW = re.compile(
    r"^(?P<radio_mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<ethernet_mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<ip_address>\S+)\s+"
    r"(?P<last_success_time>\S+\s+\S+|\S+)\s+"
    r"(?P<last_failure_type>\S.*?)\s{2,}"
    r"(?P<last_failure_time>\S.*?)\s*$"
)

#: The count the controller prints above the table.
_AP_DISCOVERY_COUNT = re.compile(
    r"^\s*Discovery requests received from total number of APs\s*:\s*(\d+)\s*$"
)

#: What the controller writes when an AP has never failed discovery.
NO_DISCOVERY_FAILURE = "none"


def parse_ap_discovery_stats(text):
    """`show wireless stats ap discovery` as (rows, unreadable, expected).

    There is no Genie parser for this command.

    `rows` maps the Ethernet MAC -> {radio_mac, ip_address, last_success_time,
    last_failure_type, last_failure_time}, every value as the device printed
    it. Keyed on the Ethernet MAC because that is what the rest of the AP
    chain keys on -- it is the MAC the edge switch sees on the wire.

    `expected` is the AP count printed above the table, or None if absent.

    The controller keeps only the LAST failure per AP, not a history. An AP
    that failed discovery ten times shows one row with its most recent
    failure, so nothing here can report a sequence.

    Safe on anything: unparseable input yields ({}, 0, None) rather than
    raising.
    """
    rows = {}
    unreadable = 0
    expected = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        count = _AP_DISCOVERY_COUNT.match(line)
        if count:
            expected = int(count.group(1))
            continue
        if (stripped.startswith("AP Radio MAC")
                or set(stripped) <= set("- ")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        match = _AP_DISCOVERY_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        entry = match.groupdict()
        mac = entry.pop("ethernet_mac").strip().lower()
        rows[mac] = {k: v.strip() for k, v in entry.items()}
    return rows, unreadable, expected


#: One `show wireless stats ap history` row.
#:
#: The Disconnect Reason and Disconnect Count columns are separated by a
#: single space on some rows ("DTLS close alert from peer 1"), so the
#: two-space column boundary used elsewhere in this module does not work
#: here. The count is anchored instead: it is the trailing integer, and the
#: reason is whatever precedes it. On a Joined row both are "NA".
_AP_HISTORY_ROW = re.compile(
    r"^(?P<ap_name>\S.*?)\s+"
    r"(?P<radio_mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<event>Joined|Disjoined)\s+"
    r"(?P<time>\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<recent_disconnect_time>NA|\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<disconnect_reason>\S.*?)\s+"
    r"(?P<disconnect_count>NA|\d+)\s*$"
)

#: A disconnect that is a planned image upgrade rather than a fault. The AP
#: drops to load new software and comes back; counting it as a flap would put
#: a warning on every controller upgrade.
_BENIGN_DISCONNECTS = {"image download success"}


def parse_ap_history(text):
    """`show wireless stats ap history` as (rows, unreadable).

    There is no Genie parser for this command.

    `rows` is a list of dicts in the order the controller printed them, which
    is newest first. Each has ap_name, radio_mac, event ("Joined" or
    "Disjoined"), time, recent_disconnect_time, disconnect_reason and
    disconnect_count, every value as the device printed it.

    Unlike the other tables in this module this one holds many rows per AP --
    it is a log, not a snapshot -- so it is returned as a list rather than
    keyed into a dict. The caller filters it to the AP it cares about.

    Safe on anything: unparseable input yields ([], 0) rather than raising.
    """
    rows = []
    unreadable = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if (stripped.startswith("AP Name")
                or set(stripped) <= set("- ")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        match = _AP_HISTORY_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        entry = {k: v.strip() for k, v in match.groupdict().items()}
        entry["ap_name"] = entry["ap_name"].strip()
        rows.append(entry)
    return rows, unreadable


def disjoins_for(rows, ap_name=None, radio_mac=None, limit=10):
    """The most recent `limit` Disjoined rows, newest first.

    Filtered to one AP when `ap_name` or `radio_mac` is given. Rows whose
    reason is a planned image upgrade are dropped: the AP disconnects to load
    new software and rejoins, and counting that as a flap would put a warning
    on every controller upgrade.
    """
    out = []
    want_mac = (radio_mac or "").strip().lower()
    want_name = (ap_name or "").strip()
    for row in rows:
        if row.get("event") != "Disjoined":
            continue
        if want_name and row.get("ap_name") != want_name:
            continue
        if want_mac and (row.get("radio_mac") or "").lower() != want_mac:
            continue
        if (row.get("disconnect_reason") or "").strip().lower() in _BENIGN_DISCONNECTS:
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return out


def disjoins_by_day(disjoins):
    """Map calendar day (the date as printed) -> number of disjoins on it."""
    counts = {}
    for row in disjoins:
        day = (row.get("time") or "").split()[0] if row.get("time") else ""
        if day:
            counts[day] = counts.get(day, 0) + 1
    return counts


#: One `show wireless dtls connections` row. Anchored on the IP and the
#: numeric peer port, which have fixed shapes; the AP name column is padded to
#: a width a longer name overruns, and the ciphersuite is free text that runs
#: to the end of the line.
#:
#: An AP has one row per DTLS session: Capwap_Ctrl for the control session,
#: and Capwap_Data as well when client traffic is tunnelled to the controller.
_DTLS_ROW = re.compile(
    r"^(?P<ap_name>\S.*?)\s+"
    r"(?P<local_port>\S+)\s+"
    r"(?P<peer_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<peer_port>\d+)\s+"
    r"(?P<version>\S+)\s+"
    r"(?P<ciphersuite>\S.*?)\s*$"
)

#: The local port of the CAPWAP control session -- the one that has to exist
#: for an AP to be joined at all.
CAPWAP_CONTROL_PORT = "capwap_ctrl"


def parse_dtls_connections(text):
    """`show wireless dtls connections` as (rows, unreadable).

    There is no Genie parser for this command.

    `rows` is a list of dicts in the order printed, each with ap_name,
    local_port, peer_ip, peer_port, version and ciphersuite, every value as
    the device printed it. A list rather than a dict keyed on the AP name:
    one AP can hold several sessions, and the caller picks the one it wants.

    Safe on anything: unparseable input yields ([], 0) rather than raising.
    """
    rows = []
    unreadable = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if (stripped.startswith("AP Name")
                or set(stripped) <= set("- ")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        match = _DTLS_ROW.match(line)
        if not match:
            unreadable += 1
            continue
        rows.append({k: v.strip() for k, v in match.groupdict().items()})
    return rows, unreadable


def control_session_for(rows, ap_name):
    """The CAPWAP control session for `ap_name`, or None.

    The control session is the one an AP must hold to be joined. A data
    session may or may not be present alongside it depending on how the AP
    tunnels client traffic, so its absence means nothing on its own.
    """
    want = (ap_name or "").strip()
    for row in rows:
        if want and row.get("ap_name") != want:
            continue
        if (row.get("local_port") or "").strip().lower() == CAPWAP_CONTROL_PORT:
            return row
    return None


_FABRIC_STATUS = re.compile(r"^Fabric Status\s*:\s*(?P<status>\S+)\s*$", re.I)

_CP_ROW = re.compile(
    r"^(?P<name>\S.*?)\s{2,}"
    r"(?P<ip_address>\d{1,3}(?:\.\d{1,3}){3})\s{2,}"
    r"(?P<key>\S+)\s{2,}"
    r"(?P<status>\S+)\s*$"
)

_VNID_ROW = re.compile(
    r"^\s*(?P<name>\S+)\s{2,}"
    r"(?P<l2_vnid>\d+)\s{2,}"
    r"(?P<l3_vnid>\d+)\s{2,}"
    r"(?:(?P<ip_address>\d{1,3}(?:\.\d{1,3}){3})\s{2,})?"
    r"(?P<subnet>\d{1,3}(?:\.\d{1,3}){3})\s{2,}"
    r"(?P<control_plane_name>\S.*?)\s*$"
)

#: The L3 instance an AP onboards in. Fixed by SD-Access, not per-deployment.
INFRA_VN_L3_VNID = "4097"

#: What the control-plane table prints for a session that is established.
CP_STATUS_UP = "up"


def parse_wireless_fabric_summary(text):
    """`show wireless fabric summary` as (summary, unreadable).

    There is no Genie parser for this command.

    `summary` is a dict with:
      fabric_status       the controller-wide status, as printed, or ""
      control_planes      list of {name, ip_address, key, status}
      vnids               list of {name, l2_vnid, l3_vnid, ip_address,
                                   subnet, control_plane_name}

    Both lists are in the order printed. The VNID mapping is emitted as
    several tables, each repeating its header, so rows are accumulated across
    all of them rather than stopping at the end of the first -- the INFRA_VN
    row is in the last table on the lab controller.

    The two tables are told apart by shape, not by which header was last
    seen: a control-plane row ends in a status word, a VNID row carries two
    integer VNIDs. Headers that scroll off or wrap therefore cannot
    misattribute a row.

    Safe on anything: unparseable input yields empty lists rather than
    raising.
    """
    summary = {"fabric_status": "", "control_planes": [], "vnids": []}
    unreadable = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        status = _FABRIC_STATUS.match(stripped)
        if status:
            summary["fabric_status"] = status.group("status").strip()
            continue
        if (set(stripped) <= set("- ")
                or stripped.startswith("Control-plane")
                or stripped.startswith("Fabric VNID Mapping")
                or stripped.startswith("Name")
                or stripped.endswith("#")
                or "#show " in stripped):
            continue
        vnid = _VNID_ROW.match(line)
        if vnid:
            summary["vnids"].append(
                {k: (v or "").strip() for k, v in vnid.groupdict().items()})
            continue
        cp = _CP_ROW.match(line)
        if cp:
            summary["control_planes"].append(
                {k: v.strip() for k, v in cp.groupdict().items()})
            continue
        unreadable += 1
    return summary, unreadable


def control_planes_named(summary, name):
    """Every control-plane row matching `name`, in the order printed.

    One name resolves to several addresses -- a control-plane group is a pair
    on the lab controller -- so the caller gets the list, not a single row.
    An empty list means the name the AP is configured against does not exist
    on this controller.
    """
    want = (name or "").strip()
    if not want:
        return []
    return [row for row in (summary or {}).get("control_planes", [])
            if row.get("name") == want]


def vnid_for_l3(summary, l3_vnid=INFRA_VN_L3_VNID):
    """The VNID-mapping row carrying `l3_vnid`, or None.

    Most rows print an L3-VNID of 0: they are L2-only mappings with no
    subnet. The INFRA_VN row is the one with a real L3 instance, and it is
    the row that says which subnet an AP is expected to hold an address in.
    """
    want = str(l3_vnid).strip()
    for row in (summary or {}).get("vnids", []):
        if (row.get("l3_vnid") or "").strip() == want:
            return row
    return None


def subnet_contains(ip_address, network, netmask):
    """Whether `ip_address` falls inside `network`/`netmask`.

    Returns None when any of the three cannot be read as an address, so a
    caller can tell "outside the subnet" from "could not be compared" -- the
    first is a finding about the AP, the second about the output.
    """
    import ipaddress

    try:
        addr = ipaddress.IPv4Address((ip_address or "").strip())
        net = ipaddress.IPv4Network(
            f"{(network or '').strip()}/{(netmask or '').strip()}",
            strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
            ValueError):
        return None
    return addr in net


#: `Control plane name` prints with one fewer space before its colon than its
#: neighbours, so these match on the label and the colon, never on a column.
_AP_RLOC = re.compile(r"^RLOC\s*:\s*(?P<rloc>\S+)\s*$", re.I)
_AP_CP_NAME = re.compile(r"^Control plane name\s*:\s*(?P<name>\S.*?)\s*$", re.I)
_AP_FABRIC_STATUS = re.compile(
    r"^Fabric status\s*:\s*(?P<status>\S.*?)\s*$", re.I)


def parse_ap_fabric_fields(text):
    """The three fabric lines of `show ap name <ap> config general`.

    Returns {fabric_status, rloc, control_plane_name}, each "" when absent.

    Genie parses this command but captures only `fabric_status` of the three:
    it has no capture for RLOC or the control-plane name, so those have to be
    read from the raw output. Taking all three here keeps them from being
    read two different ways.
    """
    found = {"fabric_status": "", "rloc": "", "control_plane_name": ""}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        status = _AP_FABRIC_STATUS.match(stripped)
        if status:
            found["fabric_status"] = status.group("status").strip()
            continue
        rloc = _AP_RLOC.match(stripped)
        if rloc:
            found["rloc"] = rloc.group("rloc").strip()
            continue
        cp = _AP_CP_NAME.match(stripped)
        if cp:
            found["control_plane_name"] = cp.group("name").strip()
    return found
