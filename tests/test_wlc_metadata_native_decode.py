"""The client flow's WLC metadata: device decode first, hex decode second.

`extract_ip_and_sgt_fixed_positions` reads the SGT at fixed byte offsets
derived by observation from one payload. The only payload available to grade
it against carries SGT 0, so a NON-ZERO SGT has never been verified against
a device -- and that function's own docstring disagrees with its code about
which offset it uses (16..17 in the text, 20..22 in the body).

Newer IOS-XE prints its own decode under `show lisp instance-id <iid>
ethernet database wlc`. Where that block exists it is ground truth and the
offsets do not matter. Where it does not -- most releases -- the fixed-offset
read still runs, unchanged.

The sample is verbatim from Edge2 (experimental 27.01 build).
"""

from routingmodules.lisp import (
    extract_ip_and_sgt_fixed_positions,
    parse_show_lisp_iid_ethernet_database_wlc as parse,
)

NATIVE = """\
WLC clients/access-points information for LISP 0 EID-table Vlan 2045 (IID 8188)

Hardware Address: 3891.b70f.2600
Type:             AP
Sources:          1
Source MS:        172.19.1.64
RLOC:             172.19.1.68
Metadata length:  34
Metadata (hex):   00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01
                  00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00
                  00 00
Metadata:         IPv4 address: 172.19.5.10
                  Client SGT: 0
                  Client association time: 0
"""

# The same entry as a release without the decode block prints it.
HEX_ONLY = NATIVE[:NATIVE.index("Metadata:         IPv4")]


def test_the_device_decode_is_captured_when_present():
    e = parse(NATIVE)["entry"]
    assert e["metadata_native_ip"] == "172.19.5.10"
    assert e["metadata_native_sgt"] == 0
    assert e["metadata_native_assoc_time"] == 0


def test_the_hex_is_still_parsed_alongside_it():
    """Both are kept: the hex is what the fallback decodes, and it is also
    the evidence if the two ever disagree."""
    e = parse(NATIVE)["entry"]
    assert e["metadata_hex"].startswith("00 01 00 22")
    assert e["metadata_length"] == 34


def test_a_release_without_the_block_is_unchanged():
    """The common case. Nothing native is invented, and the hex parsing the
    fixed-offset decode depends on still works exactly as before."""
    e = parse(HEX_ONLY)["entry"]
    assert not any(k.startswith("metadata_native") for k in e)
    assert e["metadata_hex"].startswith("00 01 00 22")
    assert e["hardware_address"] == "3891.b70f.2600"


def test_an_sgt_of_zero_is_captured_not_dropped():
    """0 is a real SGT (Unknown), so `if native_sgt:` would discard it and
    silently fall back to the offsets. The caller tests `is not None`."""
    e = parse(NATIVE)["entry"]
    assert e["metadata_native_sgt"] == 0
    assert e["metadata_native_sgt"] is not None


def test_the_two_decoders_agree_on_the_one_payload_we_can_check():
    """This is the whole basis for trusting the fixed offsets, and it is a
    single sample with SGT 0. It is not evidence that a non-zero SGT decodes
    correctly -- see the module docstring."""
    e = parse(NATIVE)["entry"]
    ip, sgt = extract_ip_and_sgt_fixed_positions(e["metadata_hex"])
    assert ip == e["metadata_native_ip"] == "172.19.5.10"
    assert sgt == e["metadata_native_sgt"] == 0


# --------------------------------------------------------------------------
# The caller's preference. `lispdbwlcentry` needs a device read to reach it,
# so the selection is exercised directly -- it is four lines and they are the
# whole point of the change.
# --------------------------------------------------------------------------


def _select(entry):
    """The selection block of lispdbwlcentry, as it runs there."""
    ip_fixed, sgt_fixed = extract_ip_and_sgt_fixed_positions(
        entry.get("metadata_hex"))
    native_ip = entry.get("metadata_native_ip")
    native_sgt = entry.get("metadata_native_sgt")
    return {
        "ap_ip": native_ip or ip_fixed,
        "sgt": native_sgt if native_sgt is not None else sgt_fixed,
        "source": "device" if native_sgt is not None else "decoded",
        "agrees": (None if native_sgt is None or sgt_fixed is None
                   else native_sgt == sgt_fixed),
    }


def test_the_device_value_wins_where_there_is_one():
    out = _select(parse(NATIVE)["entry"])
    assert out["source"] == "device"
    assert out["ap_ip"] == "172.19.5.10"
    assert out["sgt"] == 0
    assert out["agrees"] is True


def test_the_fixed_offsets_are_used_where_there_is_not():
    """Most releases. The behaviour here is exactly what it was before."""
    out = _select(parse(HEX_ONLY)["entry"])
    assert out["source"] == "decoded"
    assert out["ap_ip"] == "172.19.5.10"
    assert out["sgt"] == 0
    assert out["agrees"] is None


def test_a_device_sgt_of_zero_is_not_mistaken_for_absent():
    """The trap in `native_sgt or sgt_fixed`: SGT 0 is falsy, so a device
    that decoded 0 would be overridden by the offsets -- exactly the value
    this change exists to trust."""
    entry = dict(parse(NATIVE)["entry"])
    # Offsets that would disagree, to make the override visible if it happened.
    entry["metadata_hex"] = ("00 01 00 22  00 01 00 0C  AC 13 05 0A "
                             "00 00 10 01  00 02 00 06  00 07 00 03")
    out = _select(entry)
    assert out["sgt"] == 0
    assert out["source"] == "device"


def test_a_disagreement_is_recorded_rather_than_hidden():
    """If the device and the offsets differ, the offsets are wrong for that
    release. Preferring the device silently would lose the evidence."""
    entry = dict(parse(NATIVE)["entry"])
    entry["metadata_native_sgt"] = 17
    out = _select(entry)
    assert out["sgt"] == 17          # the device wins...
    assert out["agrees"] is False    # ...and the conflict is visible


def test_the_mirror_above_still_matches_the_real_caller():
    """`_select` is a copy of the selection block in `lispdbwlcentry`, which
    needs a live device read to reach. A copy that silently drifts from the
    original tests nothing, so the original's lines are asserted here: break
    the caller and this fails even though `_select` still passes."""
    import inspect
    import routingmodules.lisp as lisp_mod

    src = inspect.getsource(lisp_mod)
    start = src.index("def lispdbwlcentry")
    block = src[start:start + 3000]

    for line in (
        "self.ap_ip_metadata = native_ip or ap_ip_metadata",
        "self.sgt_metadata = native_sgt if native_sgt is not None "
        "else sgt_metadata",
        'self.metadata_source = "device" if native_sgt is not None '
        'else "decoded"',
        "native_sgt is None or sgt_metadata is None",
        "else native_sgt == sgt_metadata",
    ):
        assert line in block, (
            "lispdbwlcentry no longer contains %r -- the mirror in _select "
            "is out of date, so these tests are checking a copy that the "
            "device path no longer runs." % line)
