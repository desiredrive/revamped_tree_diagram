"""Verbatim lab fixtures for the three WLAN checks.

Gated on the access tunnel being up. All samples are verbatim from the lab
WLC and AP-002, pulled 2026-10-14.
"""

from checks.base import CheckStatus

WLAN_SUMMARY = """show wlan summary
Number of WLANs: 5

ID   Profile Name                     SSID                             Status 2.4GHz/5GHz Security
------------------------------------------------------------------------------------------------
17   MX CWA_profile                   MX CWA                           UP     [open],MAC Filtering
19   MX iPSK_profile                  MX iPSK                          UP     [WPA2][PSK][AES]
22   MX Open_profile                  MX Open                          UP     [open]
23   MX Enterprise_profile            MX Enterprise                    UP     [WPA3][AES]
25   MX EWA SDA_profile               MX EWA SDA                       UP     [open],[Web Auth]
"""

AP_WLAN = """show ap wlan summary
BSSID           SSID                              WLAN profile name                 AP WLAN State  AP WLAN Uptime    Client Count  AP Name                           IP Address                                Physical Capabilities  AP Mode          CAPWAP Path MTU  Radio Uptime      TxPwr           Channel                                   AP Up time                                            Association Up time
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
3891.b70f.2600  MX Enterprise                     MX Enterprise_profile             Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2602  MX CWA                            MX CWA_profile                    Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2604  MX Open                           MX Open_profile                   Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2605  MX iPSK                           MX iPSK_profile                   Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2608  MX EWA SDA                        MX EWA SDA_profile                Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2607  MX Enterprise                     MX Enterprise_profile             Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours                                              8 hours
3891.b70f.260f  MX EWA SDA                        MX EWA SDA_profile                Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours                                              8 hours
"""

PTAG = """Policy Tag Name : PT_jalej_Insur_Floor17_f95a9

Number of WLAN-POLICY maps: 5
WLAN Profile Name                 Policy Name
------------------------------------------------------------------------
MX CWA_profile                    MX CWA_profile
MX Open_profile                   MX Open_profile
MX iPSK_profile                   MX iPSK_profile
MX EWA SDA_profile                MX EWA SDA_profile
MX Enterprise_profile             MX Enterprise_profile
"""

SLOT = """Administrative State                            : Enabled
Operation State                                 : Registered
  Radio Type                                    : 802.11ax - 5 GHz
  Radio Role                                    : Sniffer
  Radio Role Op                                 : Manual
  Administrative State                          : Enabled
"""

FABRIC_WLAN = """show fabric wlan summary
Number of Fabric wlan : 5

WLAN Profile Name                     SSID                           Status
----------------------------------------------------------------------------
17   MX CWA_profile                   MX CWA                           UP
19   MX iPSK_profile                  MX iPSK                          UP
22   MX Open_profile                  MX Open                          UP
23   MX Enterprise_profile            MX Enterprise                    UP
25   MX EWA SDA_profile               MX EWA SDA                       UP
"""


PTAG_NAME = "PT_jalej_Insur_Floor17_f95a9"


class _Ctx:
    def __init__(self, tunnel=True, ap_name="AP-002", ptag=PTAG_NAME):
        self.service = object()
        self.state = {}
        if tunnel:
            self.state["ap_access_tunnel"] = {"name": "Ac0"}
        if ap_name:
            self.state["ap_wlc_ap_name"] = ap_name
        if ptag:
            # As ApWlcApState leaves it.
            self.state["ap_wlc_tags"] = {"WLCv": {"policy_tag": ptag}}





def fake_device(summary=WLAN_SUMMARY, ap_wlan=AP_WLAN, fabric=FABRIC_WLAN,
                ptag_detail=PTAG, slot=SLOT):
    """The lab WLC, answering by command substring.

    `fabric=None` stands for a controller that refuses
    `show fabric wlan summary` -- the case the fabric/non-fabric split must
    decline to judge rather than call everything non-fabric.
    """
    def fake(host, cmd, service):
        if "fabric wlan" in cmd:
            if fabric is None:
                raise RuntimeError("unsupported")
            return fabric
        if "tag policy detailed" in cmd:
            return ptag_detail
        if "config slot" in cmd:
            return slot
        if "ap wlan summary" in cmd:
            return ap_wlan
        if "wlan summary" in cmd:
            return summary
        if "config general" in cmd:
            return f"Policy Tag Name  : {PTAG_NAME}\n"
        raise AssertionError(cmd)
    return fake


def run_chain(*checks, ctx=None, **kw):
    """Run checks in queue order against ONE ctx, returning their results.

    The three WLAN checks are coupled through `ctx.state` rather than by
    being one function body, so driving them together is what exercises the
    handoff -- a check tested alone cannot show that the state key its
    neighbour publishes is the one it reads.
    """
    import radkit_cli
    ctx = ctx if ctx is not None else _Ctx(**{
        k: v for k, v in kw.items()
        if k in ("tunnel", "ap_name", "ptag")})
    fake = fake_device(**{k: v for k, v in kw.items()
                          if k not in ("tunnel", "ap_name", "ptag")})
    real = radkit_cli.get_any_single_output
    radkit_cli.get_any_single_output = fake
    try:
        return [c.run_ap(ctx) for c in checks], ctx
    finally:
        radkit_cli.get_any_single_output = real
