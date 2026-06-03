// SDA Pathfinder — frontend.
// Wizard: login → service → scenario → live topology with streamed Checks.

window.addEventListener('error', (e) => console.error('window error:', e.message, e.error));

fetch('/version').then(r => r.ok ? r.json() : null).then(v => {
  if (!v) return;
  const el = document.getElementById('appVersion');
  if (!el) return;
  const sha = v.commit ? ' · ' + v.commit : '';
  el.textContent = 'v' + (v.version || 'dev') + sha;
}).catch(() => {});

let currentSession = null;
let cy = null;
// Maps virtual node ids (e.g. an RPF-walk hop's `upath3`) to the actual
// rendered node id when the spec was IP-deduped into an existing node.
// Lets later `connect_to` / edge specs target the virtual id and still
// resolve to the merged node.
const nodeIdAliases = new Map();
function resolveNodeId(id) {
  return id && nodeIdAliases.has(id) ? nodeIdAliases.get(id) : id;
}
let selectedNodeId = null;
let currentPayload = null;
let currentEventSource = null;
let runInFlight = false;

// ---- Session persistence (survive page reload / network blip) -------------

const STORAGE_KEY = 'sdaTroubleshooterSession';

function saveSession(patch) {
  try {
    const cur = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    localStorage.setItem(STORAGE_KEY, JSON.stringify(Object.assign(cur, patch)));
  } catch (e) { /* localStorage unavailable */ }
}

function clearSession() {
  try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
}

function readSession() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); }
  catch (e) { return {}; }
}

// ---- Login -----------------------------------------------------------------

const loginForm = document.getElementById('loginForm');
const loginStatus = document.getElementById('status');
const methodSelect = document.getElementById('method');
const passphraseRow = document.getElementById('passphraseRow');

function syncPassphraseVisibility() {
  passphraseRow.style.display = (methodSelect.value === 'certificate') ? 'block' : 'none';
}
methodSelect.addEventListener('change', syncPassphraseVisibility);
syncPassphraseVisibility();

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginStatus.className = 'ok';
  loginStatus.textContent = 'Sending...';
  const payload = {
    email: document.getElementById('email').value,
    domain: document.getElementById('domain').value,
    method: document.getElementById('method').value,
    passphrase: document.getElementById('passphrase').value || null,
  };
  try {
    const r = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (!r.ok) {
      loginStatus.className = 'err';
      loginStatus.textContent = data.detail || ('HTTP ' + r.status);
      return;
    }
    loginStatus.className = 'ok';
    loginStatus.textContent = 'Starting login...';
    pollLoginStatus(data.session_id);
  } catch (err) {
    loginStatus.className = 'err';
    loginStatus.textContent = 'Network error: ' + err;
  }
});

async function pollLoginStatus(sid) {
  let urlShown = false;
  while (true) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const r = await fetch('/login/status/' + sid);
      const d = await r.json();
      if (d.status === 'error') {
        loginStatus.className = 'err';
        loginStatus.textContent = 'Login failed: ' + (d.error || 'unknown');
        return;
      }
      if (d.status === 'ready') {
        loginStatus.className = 'ok';
        loginStatus.innerHTML = '<b>Logged in!</b><br>Session: ' + sid;
        showServiceForm(sid);
        return;
      }
      if (!urlShown && d.sso_url) {
        urlShown = true;
        loginStatus.innerHTML =
          'Open this URL to authenticate (waiting...):<br><br>' +
          '<a href="' + d.sso_url + '" target="_blank" rel="noopener" ' +
          'style="color:#93c5fd;word-break:break-all">' + d.sso_url + '</a>';
      }
    } catch (e) {
      // network blip — keep polling
    }
  }
}

// ---- Service selection -----------------------------------------------------

const serviceForm = document.getElementById('serviceForm');
const serviceStatus = document.getElementById('serviceStatus');
const serviceUser = document.getElementById('serviceUser');

function setStatus(el, kind, html) {
  el.style.display = 'block';
  if (kind === 'err') {
    el.style.background = '#7f1d1d';
    el.style.color = '#fee2e2';
  } else {
    el.style.background = '#064e3b';
    el.style.color = '#d1fae5';
  }
  if (html === undefined) return;
  if (html instanceof Node) { el.innerHTML = ''; el.appendChild(html); }
  else el.innerHTML = html;
}

function showServiceForm(sid) {
  currentSession = sid;
  saveSession({ sid });
  loginForm.style.display = 'none';
  serviceUser.textContent = 'Logged in as ' + document.getElementById('email').value;
  serviceForm.style.display = 'block';
}

serviceForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus(serviceStatus, 'ok', 'Connecting...');
  try {
    const r = await fetch('/service', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSession,
        serial: document.getElementById('serial').value,
      }),
    });
    const data = await r.json();
    if (!r.ok) {
      setStatus(serviceStatus, 'err', data.detail || ('HTTP ' + r.status));
      return;
    }
    pollServiceStatus(currentSession);
  } catch (err) {
    setStatus(serviceStatus, 'err', 'Network error: ' + err);
  }
});

async function pollServiceStatus(sid) {
  while (true) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const r = await fetch('/service/status/' + sid);
      const d = await r.json();
      if (d.status === 'error') {
        setStatus(serviceStatus, 'err', 'Connect failed: ' + (d.error || 'unknown'));
        return;
      }
      if (d.status === 'ready') {
        setStatus(serviceStatus, 'ok', '<b>Connected!</b><br>Service: ' + (d.name || d.serial));
        saveSession({ serviceName: d.name || d.serial, serviceSerial: d.serial });
        showScenarioForm(d.name || d.serial);
        return;
      }
    } catch (e) { /* keep polling */ }
  }
}

// ---- Scenario form ---------------------------------------------------------

const scenarioForm = document.getElementById('scenarioForm');
const scenarioSelect = document.getElementById('scenario');
const scenarioService = document.getElementById('scenarioService');
const scenarioStatus = document.getElementById('scenarioStatus');
const dhcpInputs = document.getElementById('dhcpInputs');
const ewInputs = document.getElementById('ewInputs');
const umcastInputs = document.getElementById('umcastInputs');
const ewL2 = document.getElementById('ew_l2only');
const ewL2Inputs = document.getElementById('ewL2Inputs');
const macInput = document.getElementById('dhcp_mac');
const macMsg = document.getElementById('dhcp_mac_msg');

function showScenarioForm(serviceLabel) {
  serviceForm.style.display = 'none';
  scenarioService.textContent = 'Service: ' + serviceLabel;
  scenarioForm.style.display = 'block';
}

scenarioSelect.addEventListener('change', () => {
  const v = scenarioSelect.value;
  dhcpInputs.style.display   = (v === 'dhcp') ? 'block' : 'none';
  ewInputs.style.display     = (v === 'east_west') ? 'block' : 'none';
  umcastInputs.style.display = (v === 'underlay_multicast') ? 'block' : 'none';
});

// Sync visibility on load — the browser may restore a non-default selection
// (east_west) without firing 'change', leaving the DHCP fields visible.
// Run once now (covers fast-paint), again after DOMContentLoaded (covers
// browsers that restore form state asynchronously), and again on pageshow
// (covers bfcache restores via Back/Forward navigation).
function _syncScenarioInputs() {
  scenarioSelect.dispatchEvent(new Event('change'));
}
_syncScenarioInputs();
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _syncScenarioInputs);
}
window.addEventListener('pageshow', _syncScenarioInputs);

ewL2.addEventListener('change', () => {
  ewL2Inputs.style.display = ewL2.checked ? 'block' : 'none';
});

// MAC sanitization: accept aa:bb:..., aa-bb-..., aabb.ccdd.eeff, AABBCCDDEEFF, etc.
// Returns normalized "aaaa.bbbb.cccc" or null if not a valid 12-hex-char MAC.
function normalizeMac(raw) {
  if (!raw) return null;
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.slice(0, 4) + '.' + hex.slice(4, 8) + '.' + hex.slice(8, 12);
}

macInput.addEventListener('blur', () => {
  const raw = macInput.value.trim();
  if (!raw) { macMsg.textContent = ''; macMsg.className = 'field-msg'; return; }
  const norm = normalizeMac(raw);
  if (norm) {
    macInput.value = norm;
    macMsg.textContent = 'Normalized to ' + norm;
    macMsg.className = 'field-msg msg-ok';
  } else {
    macMsg.textContent = 'Invalid MAC — need 12 hex characters.';
    macMsg.className = 'field-msg msg-err';
  }
});

scenarioForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const v = scenarioSelect.value;
  let payload;
  if (v === 'dhcp') {
    const normMac = normalizeMac(macInput.value);
    if (!normMac) {
      macMsg.textContent = 'Invalid MAC — need 12 hex characters.';
      macMsg.className = 'field-msg msg-err';
      macInput.focus();
      return;
    }
    macInput.value = normMac;
    payload = {
      scenario: 'dhcp',
      mgmt_ip: document.getElementById('dhcp_mgmt_ip').value,
      catc_name: document.getElementById('dhcp_catc_name').value,
      vlan: parseInt(document.getElementById('dhcp_vlan').value, 10),
      mac: normMac,
      vrf: document.getElementById('dhcp_vrf').value,
      is_few: document.getElementById('dhcp_is_few').checked,
    };
  } else if (v === 'underlay_multicast') {
    const iid = parseInt(document.getElementById('umcast_l2vni_iid').value, 10);
    const vlan = parseInt(document.getElementById('umcast_vlan').value, 10);
    payload = {
      scenario: 'underlay_multicast',
      umcast_source_ip: document.getElementById('umcast_source_ip').value,
      umcast_l2vni_iid: Number.isFinite(iid) ? iid : null,
      umcast_vlan: Number.isFinite(vlan) ? vlan : null,
      umcast_dest_ip: document.getElementById('umcast_dest_ip').value,
      umcast_vrf: document.getElementById('umcast_vrf').value,
      umcast_group: document.getElementById('umcast_group').value,
    };
  } else {
    payload = {
      scenario: 'east_west',
      device_source_ip: document.getElementById('ew_device_ip').value,
      endpoint_ip: document.getElementById('ew_endpoint_ip').value,
      destination_ip: document.getElementById('ew_destination_ip').value,
      l2_only: ewL2.checked,
      mask: ewL2.checked ? parseInt(document.getElementById('ew_mask').value, 10) : null,
      gateway: ewL2.checked ? document.getElementById('ew_gateway').value : null,
      is_few: document.getElementById('ew_is_few').checked,
    };
  }
  scenarioStatus.style.display = 'none';
  currentPayload = payload;
  showTopology(payload);
  startRun(payload);
});

// ---- Icons -----------------------------------------------------------------

// One icon SVG per status — the badge is drawn directly inside the SVG so the
// position is exact and there are no multi-background-image quirks.
function iconSvg(badgeFill) {
  // Rect is inset on top & right to leave room for the corner badge to peek out.
  const arrow =
    "<line x1='46' y1='54' x2='46' y2='28' stroke='white' stroke-width='2.2' stroke-linecap='round'/>" +
    "<polygon points='46,18 40.5,28 51.5,28' fill='white'/>";
  let arrows = "";
  for (let i = 0; i < 8; i++) {
    arrows += "<g transform='rotate(" + (i * 45) + " 46 54)'>" + arrow + "</g>";
  }
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<rect x='2' y='10' width='88' height='88' rx='12' ry='12' " +
      "fill='#1e40af' stroke='#0f172a' stroke-width='3'/>" +
    arrows +
    "<circle cx='90' cy='10' r='10' fill='" + badgeFill + "' stroke='white' stroke-width='2.5'/>" +
    "</svg>"
  );
}
function iconUrl(fill) {
  return "data:image/svg+xml;utf8," + encodeURIComponent(iconSvg(fill));
}
const ICON_URL = {
  pending: iconUrl('#cbd5e1'),
  running: iconUrl('#eab308'),
  ok:      iconUrl('#22c55e'),
  warn:    iconUrl('#f97316'),
  fail:    iconUrl('#ef4444'),
  skip:    iconUrl('#94a3b8'),
};

// Endpoint (computer) icon — drawn as a separate shape so it visually reads as
// "the client" rather than another fabric device.
function computerIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<rect x='12' y='18' width='76' height='52' rx='4' ry='4' " +
      "fill='#0f172a' stroke='#1e293b' stroke-width='3'/>" +
    "<rect x='18' y='24' width='64' height='40' fill='#38bdf8'/>" +
    "<rect x='34' y='72' width='32' height='6' fill='#1e293b'/>" +
    "<rect x='22' y='78' width='56' height='6' rx='2' ry='2' " +
      "fill='#0f172a' stroke='#1e293b' stroke-width='2'/>" +
    "</svg>"
  );
}
const ENDPOINT_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(computerIconSvg());

// Borders look like routers with a globe behind them.
function borderIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<circle cx='50' cy='50' r='40' fill='#1e3a8a' stroke='#0f172a' stroke-width='3'/>" +
    "<path d='M10 50 H90 M50 10 V90 M20 30 Q50 50 80 30 M20 70 Q50 50 80 70' " +
      "fill='none' stroke='#93c5fd' stroke-width='2'/>" +
    "</svg>"
  );
}
const BORDER_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(borderIconSvg());

// Control plane: a square with a sigma (LISP map-server).
function cpIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<rect x='10' y='10' width='80' height='80' rx='10' ry='10' " +
      "fill='#7c3aed' stroke='#0f172a' stroke-width='3'/>" +
    "<text x='50' y='65' text-anchor='middle' font-family='monospace' " +
      "font-size='44' font-weight='700' fill='white'>Σ</text>" +
    "</svg>"
  );
}
const CP_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(cpIconSvg());

// DHCP server: a stack of disks (server rack).
function dhcpServerIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<rect x='15' y='18' width='70' height='64' rx='4' ry='4' " +
      "fill='#0f172a' stroke='#1e293b' stroke-width='3'/>" +
    "<rect x='22' y='26' width='56' height='12' fill='#475569'/>" +
    "<rect x='22' y='44' width='56' height='12' fill='#475569'/>" +
    "<rect x='22' y='62' width='56' height='12' fill='#475569'/>" +
    "<circle cx='30' cy='32' r='2' fill='#22c55e'/>" +
    "<circle cx='30' cy='50' r='2' fill='#22c55e'/>" +
    "<circle cx='30' cy='68' r='2' fill='#22c55e'/>" +
    "</svg>"
  );
}
const DHCP_SERVER_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(dhcpServerIconSvg());

// Underlay switch (CDP-discovered): a stacked 3550-style chassis.
function underlaySwitchIconSvg(fill) {
  fill = fill || '#1e293b';
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<rect x='10' y='35' width='80' height='30' rx='3' ry='3' " +
      "fill='" + fill + "' stroke='#0f172a' stroke-width='3'/>" +
    "<rect x='18' y='44' width='8' height='4' fill='#22c55e'/>" +
    "<rect x='30' y='44' width='8' height='4' fill='#22c55e'/>" +
    "<rect x='42' y='44' width='8' height='4' fill='#fbbf24'/>" +
    "<rect x='54' y='44' width='8' height='4' fill='#22c55e'/>" +
    "<rect x='66' y='44' width='8' height='4' fill='#94a3b8'/>" +
    "<rect x='18' y='54' width='56' height='3' fill='#475569'/>" +
    "</svg>"
  );
}
const UNDERLAY_SWITCH_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(underlaySwitchIconSvg('#1e293b'));
const UNDERLAY_UNKNOWN_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(underlaySwitchIconSvg('#94a3b8'));

// Fabric cloud — generic underlay placeholder used when next-hops resolve to
// physical interfaces but CDP doesn't return a specific neighbor. All such
// unresolved next-hops collapse into a single shared "Fabric" node so the
// topology stays readable.
function fabricCloudIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    "<path d='M25 65 Q12 65 12 52 Q12 42 23 40 Q23 27 38 27 Q42 18 54 18 " +
    "Q67 18 71 30 Q86 30 86 44 Q86 56 75 58 Q75 68 63 68 L28 68 " +
    "Q25 68 25 65 Z' fill='#cbd5e1' stroke='#475569' stroke-width='2.5' " +
    "stroke-linejoin='round'/>" +
    "</svg>"
  );
}
const FABRIC_CLOUD_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(fabricCloudIconSvg());

// Wireless LAN Controller: Cisco-style blue square — three solid white
// triangles pointing toward the centre on top, chain-link ribbon across the
// bottom, and a status badge in the top-right corner.
function wlcIconSvg(badgeFill) {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    // Rounded blue body inset on top & right so the badge can peek out.
    "<rect x='6' y='14' width='80' height='80' rx='10' ry='10' " +
      "fill='#1d4ed8' stroke='#0c1e5e' stroke-width='3'/>" +
    // Three solid white triangles in a row, all pointing toward the centre
    // (i.e. up toward the top edge of the icon body).
    "<polygon points='28,52 18,52 23,40' fill='#ffffff'/>" +
    "<polygon points='51,52 41,52 46,40' fill='#ffffff'/>" +
    "<polygon points='74,52 64,52 69,40' fill='#ffffff'/>" +
    // Divider line above the ribbon.
    "<line x1='10' y1='62' x2='82' y2='62' stroke='#ffffff' stroke-width='2'/>" +
    // Chain-link ribbon: six interlocking ovals centred on y=74.
    "<g fill='none' stroke='#ffffff' stroke-width='2.4'>" +
      "<ellipse cx='18' cy='74' rx='6' ry='4'/>" +
      "<ellipse cx='30' cy='74' rx='6' ry='4'/>" +
      "<ellipse cx='42' cy='74' rx='6' ry='4'/>" +
      "<ellipse cx='54' cy='74' rx='6' ry='4'/>" +
      "<ellipse cx='66' cy='74' rx='6' ry='4'/>" +
      "<ellipse cx='78' cy='74' rx='6' ry='4'/>" +
    "</g>" +
    // Status badge in the top-right corner.
    "<circle cx='86' cy='14' r='10' fill='" + badgeFill + "' " +
      "stroke='white' stroke-width='2.5'/>" +
    "</svg>"
  );
}
function wlcIconUrl(fill) {
  return "data:image/svg+xml;utf8," + encodeURIComponent(wlcIconSvg(fill));
}
const WLC_ICON_URL = {
  pending: wlcIconUrl('#cbd5e1'),
  running: wlcIconUrl('#eab308'),
  ok:      wlcIconUrl('#22c55e'),
  warn:    wlcIconUrl('#f97316'),
  fail:    wlcIconUrl('#ef4444'),
  skip:    wlcIconUrl('#94a3b8'),
};

// Access Point: Cisco-style rounded blue square with a smaller rounded
// rectangle window and a top LED dot.
function apIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
    // Rounded blue body.
    "<rect x='14' y='14' width='72' height='72' rx='14' ry='14' " +
      "fill='#1d4ed8' stroke='#0c1e5e' stroke-width='3'/>" +
    // Inner rounded white window (the AP's recessed face).
    "<rect x='34' y='30' width='32' height='44' rx='8' ry='8' " +
      "fill='none' stroke='#ffffff' stroke-width='3'/>" +
    // Small LED indicator at the top of the window.
    "<rect x='46' y='36' width='8' height='5' rx='1.5' ry='1.5' " +
      "fill='none' stroke='#ffffff' stroke-width='2'/>" +
    "</svg>"
  );
}
const AP_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(apIconSvg());

const ROLE_ICON = {
  endpoint: ENDPOINT_ICON_URL,
  border: BORDER_ICON_URL,
  'control-plane': CP_ICON_URL,
  'dhcp-server': DHCP_SERVER_ICON_URL,
  'underlay-switch': UNDERLAY_SWITCH_ICON_URL,
  'underlay-unknown': UNDERLAY_UNKNOWN_ICON_URL,
  fabric: FABRIC_CLOUD_ICON_URL,
  wlc: WLC_ICON_URL.pending,
  'access-point': AP_ICON_URL,
};

// ---- Topology --------------------------------------------------------------

function showTopology(payload) {
  document.body.classList.add('topology-active');
  scenarioForm.style.display = 'none';
  document.getElementById('topologyPanel').style.display = 'block';
  const wiredToggle = document.getElementById('topologyWiredToggle');
  const wiredCheckbox = document.getElementById('topologyTreatAsWired');
  if (payload.scenario === 'dhcp') {
    wiredToggle.style.display = 'inline-flex';
    wiredCheckbox.checked = (payload.is_few === false);
  } else {
    wiredToggle.style.display = 'none';
  }
  document.getElementById('topologySub').textContent =
    payload.scenario === 'dhcp'
      ? 'DHCP — XTR ' + payload.mgmt_ip + ' · MAC ' + payload.mac + ' · VLAN ' + payload.vlan
      : payload.scenario === 'underlay_multicast'
        ? 'Underlay Multicast — FHR ' + payload.umcast_source_ip
          + (payload.umcast_dest_ip ? (' → LHR ' + payload.umcast_dest_ip) : '')
          + ' · IID ' + payload.umcast_l2vni_iid + ' · VLAN ' + payload.umcast_vlan
        : 'East-West — ' + payload.device_source_ip + ' → ' + payload.destination_ip;

  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [],
    style: [
      { selector: 'node', style: {
          'background-color': '#ffffff',
          'background-image': ICON_URL.pending,
          'background-fit': 'contain',
          'background-clip': 'none',
          'border-width': 0,
          'label': 'data(label)',
          'text-wrap': 'wrap',
          'text-max-width': '160px',
          'color': '#0f172a',
          'font-size': '12px',
          'font-weight': 600,
          'text-valign': 'bottom',
          'padding': 0,
          'text-margin-y': -40,
          'width': 88,
          'height': 88,
          'shape': 'round-rectangle',
      }},
      { selector: 'node[status = "running"]', style: { 'background-image': ICON_URL.running } },
      { selector: 'node[status = "ok"]',      style: { 'background-image': ICON_URL.ok } },
      { selector: 'node[status = "warn"]',    style: { 'background-image': ICON_URL.warn } },
      { selector: 'node[status = "fail"]',    style: { 'background-image': ICON_URL.fail } },
      { selector: 'node[status = "skip"]',    style: { 'background-image': ICON_URL.skip } },
      { selector: 'node[role = "endpoint"]', style: {
          'background-image': ENDPOINT_ICON_URL,
          'width': 72,
          'height': 72,
          'text-margin-y': -28,
          'font-size': '11px',
      }},
      { selector: 'node[role = "border"]', style: {
          'width': 88,
          'height': 88,
          'text-margin-y': -40,
      }},
      { selector: 'node[role = "control-plane"]', style: {
          'background-image': CP_ICON_URL,
          'width': 76,
          'height': 76,
          'text-margin-y': -30,
      }},
      { selector: 'node[role = "dhcp-server"]', style: {
          'background-image': DHCP_SERVER_ICON_URL,
          'width': 72,
          'height': 72,
          'text-margin-y': -28,
      }},
      { selector: 'node[role = "underlay-switch"]', style: {
          'background-image': UNDERLAY_SWITCH_ICON_URL,
          'width': 70,
          'height': 70,
          'text-margin-y': -28,
          'font-size': '11px',
      }},
      { selector: 'node[role = "underlay-unknown"]', style: {
          'background-image': UNDERLAY_UNKNOWN_ICON_URL,
          'width': 70,
          'height': 70,
          'text-margin-y': -28,
          'font-size': '11px',
          'opacity': 0.75,
      }},
      { selector: 'node[role = "fabric"]', style: {
          'background-image': FABRIC_CLOUD_ICON_URL,
          'width': 110,
          'height': 88,
          'text-margin-y': -36,
          'font-size': '12px',
          'font-weight': 'bold',
      }},
      { selector: 'node[role = "wlc"]', style: {
          'background-image': WLC_ICON_URL.pending,
          'width': 88,
          'height': 88,
          'text-margin-y': -40,
      }},
      { selector: 'node[role = "wlc"][status = "pending"]', style: { 'background-image': WLC_ICON_URL.pending } },
      { selector: 'node[role = "wlc"][status = "running"]', style: { 'background-image': WLC_ICON_URL.running } },
      { selector: 'node[role = "wlc"][status = "ok"]',      style: { 'background-image': WLC_ICON_URL.ok } },
      { selector: 'node[role = "wlc"][status = "warn"]',    style: { 'background-image': WLC_ICON_URL.warn } },
      { selector: 'node[role = "wlc"][status = "fail"]',    style: { 'background-image': WLC_ICON_URL.fail } },
      { selector: 'node[role = "wlc"][status = "skip"]',    style: { 'background-image': WLC_ICON_URL.skip } },
      { selector: 'node[role = "access-point"]', style: {
          'background-image': AP_ICON_URL,
          'width': 88,
          'height': 88,
          'text-margin-y': -40,
          'font-size': '11px',
      }},
      { selector: 'edge', style: {
          'line-color': '#94a3b8',
          'width': 2,
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-size': '11px',
          'color': '#0f172a',
          'text-background-color': '#ffffff',
          'text-background-opacity': 0.9,
          'text-background-padding': '2px',
          'text-background-shape': 'round-rectangle',
          'text-rotation': 'autorotate',
          'text-wrap': 'wrap',
      }},
      { selector: 'edge[wireless = "true"]', style: {
          'line-style': 'dashed',
          'line-dash-pattern': [6, 4],
          'line-color': '#2563eb',
          'width': 2,
      }},
      { selector: 'edge[rfBand = "good"]',   style: { 'color': '#16a34a' } },
      { selector: 'edge[rfBand = "normal"]', style: { 'color': '#0f172a' } },
      { selector: 'edge[rfBand = "bad"]',    style: { 'color': '#dc2626' } },
    ],
    layout: { name: 'preset' },
    wheelSensitivity: 0.2,
  });

  const xtrIp = payload.scenario === 'dhcp'
    ? payload.mgmt_ip
    : payload.scenario === 'underlay_multicast'
      ? payload.umcast_source_ip
      : payload.device_source_ip;
  cy.add({
    group: 'nodes',
    data: { id: 'xtr', label: xtrIp, baseLabel: xtrIp, tags: [], role: 'xtr', status: 'pending', checks: [] },
    position: { x: 200, y: 200 },
  });
  cy.center('#xtr');

  cy.on('tap', 'node', (e) => showChecksPanel(e.target.id()));
  cy.on('tap', (e) => { if (e.target === cy) hideChecksPanel(); });
  document.getElementById('checksPanelClose').addEventListener('click', hideChecksPanel);
  document.getElementById('topologyRefresh').addEventListener('click', refreshTopology);
  const backBtn = document.getElementById('topologyBackMenu');
  if (backBtn) {
    backBtn.addEventListener('click', backToMenu);
  }
  const resetBtn = document.getElementById('topologyResetView');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (!cy) return;
      cy.fit(undefined, 80);
      cy.center();
    });
  }
  document.getElementById('topologyDownloadLog').addEventListener('click', () => {
    // Use a hidden <a download> click instead of navigating window.location
    // — navigation tears down the active EventSource and surfaces as
    // "interrupted" in the network console.
    const a = document.createElement('a');
    a.href = '/logfile';
    a.download = 'collection_logfile.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
  });
  document.getElementById('topologyDownloadTopology').addEventListener('click', () => {
    if (!cy) return;
    // Render the full graph (not just the visible viewport) into a 1920x1080
    // JPEG. cy.jpg() with output:'blob' returns a Blob we can download via a
    // hidden <a download> click — no navigation, EventSource stays alive.
    const blob = cy.jpg({
      output: 'blob',
      full: true,
      bg: '#ffffff',
      maxWidth: 1920,
      maxHeight: 1080,
      quality: 0.92,
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    a.download = 'topology-' + ts + '.jpg';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
  document.getElementById('topologyDownloadChecks').addEventListener('click', () => {
    if (!cy) return;
    downloadChecksPdf();
  });
}

function downloadChecksPdf() {
  const jspdfNs = window.jspdf || {};
  const JsPDF = jspdfNs.jsPDF || window.jsPDF;
  if (!JsPDF) { alert('jsPDF not loaded'); return; }
  const doc = new JsPDF({ unit: 'pt', format: 'letter' });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const marginX = 40;
  const marginTop = 50;
  const marginBottom = 40;
  let y = marginTop;

  const sanitize = (s) => String(s == null ? '' : s)
    .replace(/→/g, '->')
    .replace(/←/g, '<-')
    .replace(/↔/g, '<->')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/…/g, '...')
    .replace(/[^\x00-\xFF]/g, '?');

  const wrap = (text, width, fontSize) => {
    doc.setFontSize(fontSize);
    return doc.splitTextToSize(sanitize(text), width);
  };
  const ensureSpace = (need) => {
    if (y + need > pageH - marginBottom) { doc.addPage(); y = marginTop; }
  };
  const writeLines = (lines, fontSize, lineGap) => {
    doc.setFontSize(fontSize);
    const lh = fontSize * 1.25 + (lineGap || 0);
    for (const ln of lines) {
      ensureSpace(lh);
      doc.text(ln, marginX, y);
      y += lh;
    }
  };

  // Title
  const scenario = (currentPayload && currentPayload.scenario) || 'run';
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('SDA Pathfinder — Checks Report', marginX, y); y += 22;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text('Scenario: ' + scenario, marginX, y); y += 14;
  doc.text('Generated: ' + new Date().toLocaleString(), marginX, y); y += 20;

  // Order: xtr, dxtr, then RPs (urpN), then path hops, then everything else
  const orderRank = (id) => {
    if (id === 'xtr') return 0;
    if (id === 'dxtr') return 1;
    if (/^urp\d+$/.test(id)) return 2 + parseInt(id.slice(3), 10) * 0.001;
    if (/^upath\d+$/.test(id)) return 100 + parseInt(id.slice(5), 10) * 0.001;
    return 1000;
  };
  const nodes = cy.nodes().toArray().slice().sort((a, b) => {
    const ra = orderRank(a.id()), rb = orderRank(b.id());
    if (ra !== rb) return ra - rb;
    return a.id().localeCompare(b.id());
  });

  const STATUS_TAG = { ok: '[OK]', warn: '[WARN]', fail: '[FAIL]', skip: '[SKIP]', running: '[RUN]', pending: '[…]' };

  for (const n of nodes) {
    const checks = n.data('checks') || [];
    if (!checks.length) continue;
    const label = n.data('label') || n.id();
    const role = n.data('role') || '';
    ensureSpace(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    const titleText = sanitize(label.replace(/\n/g, ' ') + (role ? '  (' + role + ')' : '') + '  —  ' + n.id());
    const titleLines = doc.splitTextToSize(titleText, pageW - 2 * marginX);
    const titleLh = 13 * 1.3;
    for (const ln of titleLines) {
      ensureSpace(titleLh);
      doc.text(ln, marginX, y);
      y += titleLh;
    }
    y += 4;
    doc.setFont('helvetica', 'normal');

    // Counters
    const counts = { ok: 0, warn: 0, fail: 0, skip: 0, running: 0, pending: 0 };
    checks.forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1; });
    doc.setFontSize(10);
    const summary = ['ok', 'warn', 'fail', 'skip']
      .filter(k => counts[k]).map(k => counts[k] + ' ' + k).join(' · ') || 'no terminal results';
    doc.text(summary, marginX, y); y += 16;

    for (const c of checks) {
      ensureSpace(30);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      const tag = STATUS_TAG[c.status] || '[?]';
      const STATUS_RGB = {
        ok:      [22, 163, 74],
        warn:    [202, 138, 4],
        fail:    [220, 38, 38],
        skip:    [100, 116, 139],
        running: [37, 99, 235],
        pending: [100, 116, 139],
      };
      const rgb = STATUS_RGB[c.status] || [0, 0, 0];
      const tagWidth = doc.getTextWidth(tag + ' ');
      const nameText = sanitize(c.name || '(unnamed)');
      const nameLines = doc.splitTextToSize(nameText, pageW - 2 * marginX - tagWidth);
      const headLh = 11 * 1.3;
      ensureSpace(headLh);
      doc.setTextColor(rgb[0], rgb[1], rgb[2]);
      doc.text(tag, marginX, y);
      doc.setTextColor(0, 0, 0);
      doc.text(' ' + nameLines[0], marginX + doc.getTextWidth(tag), y);
      y += headLh;
      for (let i = 1; i < nameLines.length; i++) {
        ensureSpace(headLh);
        doc.text(nameLines[i], marginX + tagWidth, y);
        y += headLh;
      }
      doc.setFont('helvetica', 'normal');
      const body = c.message ? wrap(c.message, pageW - 2 * marginX - 10, 9) : ['(no detail)'];
      doc.setFontSize(9);
      const lh = 9 * 1.25;
      for (const ln of body) {
        ensureSpace(lh);
        doc.text(ln, marginX + 10, y);
        y += lh;
      }
      y += 4;
    }
    y += 10;
  }

  doc.save('checks-' + scenario + '-' + ts + '.pdf');
}

function refreshTopology() {
  if (!currentPayload) return;
  if (currentPayload.scenario === 'dhcp') {
    const wired = document.getElementById('topologyTreatAsWired');
    if (wired) currentPayload.is_few = !wired.checked;
  }
  hideChecksPanel();
  cy.elements().remove();
  nodeIdAliases.clear();
  const xtrIp = currentPayload.scenario === 'dhcp'
    ? currentPayload.mgmt_ip
    : currentPayload.device_source_ip;
  cy.add({
    group: 'nodes',
    data: { id: 'xtr', label: xtrIp, baseLabel: xtrIp, tags: [], role: 'xtr', status: 'pending', checks: [] },
    position: { x: 200, y: 200 },
  });
  cy.center('#xtr');
  startRun(currentPayload);
}

function backToMenu() {
  console.log('[backToMenu] click received, currentSession=', currentSession);
  if (currentSession) {
    try {
      fetch('/run/stop/' + currentSession, { method: 'POST', keepalive: true })
        .then(r => console.log('[backToMenu] /run/stop status:', r.status))
        .catch(err => console.warn('[backToMenu] /run/stop failed:', err));
    } catch (e) { console.warn('[backToMenu] fetch threw:', e); }
  }
  if (currentEventSource) {
    try { currentEventSource.close(); } catch (e) {}
    currentEventSource = null;
  }
  if (cy) {
    try { cy.elements().remove(); } catch (e) {}
    nodeIdAliases.clear();
  }
  hideChecksPanel();
  const panel = document.getElementById('topologyPanel');
  if (panel) panel.style.display = 'none';
  document.body.classList.remove('topology-active');
  if (typeof scenarioForm !== 'undefined' && scenarioForm) {
    scenarioForm.style.display = 'block';
  } else {
    const sf = document.getElementById('scenarioForm');
    if (sf) sf.style.display = 'block';
  }
  const status = document.getElementById('status');
  if (status) { status.className = ''; status.style.display = 'none'; status.textContent = ''; }
}

// ---- Checks panel ----------------------------------------------------------

const STATUS_ICON_CHAR = { pending: '·', skip: '—', running: '…', ok: '✓', warn: '!', fail: '✗' };

function showChecksPanel(nodeId) {
  selectedNodeId = nodeId;
  document.getElementById('checksPanel').style.display = 'flex';
  if (cy) cy.resize();
  renderChecksPanel();
}

function hideChecksPanel() {
  selectedNodeId = null;
  document.getElementById('checksPanel').style.display = 'none';
  if (cy) cy.resize();
}

function renderChecksPanel() {
  if (!cy || !selectedNodeId) return;
  const node = cy.getElementById(selectedNodeId);
  if (node.empty()) { hideChecksPanel(); return; }

  const list = document.getElementById('checksList');
  const summary = document.getElementById('checksPanelSummary');
  const title = document.getElementById('checksPanelTitle');
  title.textContent = node.data('label') || selectedNodeId;

  const items = node.data('checks') || [];
  const counts = { ok: 0, warn: 0, fail: 0, running: 0, skip: 0, pending: 0 };
  items.forEach(it => { counts[it.status] = (counts[it.status] || 0) + 1; });
  summary.textContent =
    counts.ok + ' ok · ' +
    (counts.warn || 0) + ' warn · ' +
    (counts.fail || 0) + ' fail' +
    (counts.skip ? ' · ' + counts.skip + ' skipped' : '');

  const expanded = new Set(
    Array.from(list.querySelectorAll('.check-row.expanded')).map(el => el.dataset.key)
  );
  list.innerHTML = '';
  items.forEach(it => {
    const key = selectedNodeId + '|' + it.name;
    const row = document.createElement('div');
    row.className = 'check-row' + (expanded.has(key) ? ' expanded' : '');
    row.dataset.key = key;
    row.innerHTML =
      '<div class="row-head">' +
        '<span class="row-icon s-' + it.status + '">' + (STATUS_ICON_CHAR[it.status] || '?') + '</span>' +
        '<span class="row-name">' + escapeHtml(it.name) + '</span>' +
        '<span class="row-chevron">▶</span>' +
      '</div>' +
      '<div class="row-detail">' + escapeHtml(it.message || '(no detail)') + '</div>';
    // Toggle only when the header is clicked — the detail body stays
    // selectable so users can copy text without collapsing the row.
    row.querySelector('.row-head').addEventListener('click', () => row.classList.toggle('expanded'));
    list.appendChild(row);
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---- Run + SSE wiring ------------------------------------------------------

const STATUS_RANK = { pending: 0, skip: 1, ok: 2, running: 3, warn: 4, fail: 5 };
function escalate(prev, next) {
  return (STATUS_RANK[next] >= STATUS_RANK[prev || 'pending']) ? next : prev;
}

function updateNode(nodeId, partial) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (n.empty()) return;
  Object.entries(partial).forEach(([k, v]) => n.data(k, v));
}

function applyNodeLabel(nodeId) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (n.empty()) return;
  const base = n.data('baseLabel') || n.data('label') || '';
  const rloc = n.data('rloc');
  const tags = n.data('tags') || [];
  let label = base;
  if (rloc) label += '\nRLOC: ' + rloc;
  if (tags.length) label += '\n[' + tags.join(', ') + ']';
  n.data('label', label);
}

function addEndpointNode(info) {
  if (!cy) return;
  const parentId = info.parent_node_id || 'xtr';
  const parent = cy.getElementById(parentId);
  if (parent.empty()) return;

  const macLine = 'MAC: ' + (info.mac || '?');
  const vlanLabel = info.wireless ? 'VNID' : 'VLAN';
  const vlanLine = vlanLabel + ': ' + (info.vlan != null ? info.vlan : '?');
  const sgtLine = 'SGT: ' + (info.sgt != null && info.sgt !== '' ? info.sgt : '0');
  const lines = [];
  if (info.ip) lines.push('IP: ' + info.ip);
  lines.push(macLine, vlanLine, sgtLine);
  const label = lines.join('\n');

  // Build the edge label. Wireless edges show SSID + RSSI/SNR; wired edges
  // show the access port. info.edge_label wins if the backend provided one.
  let edgeLabel = info.edge_label;
  if (!edgeLabel) {
    if (info.wireless) {
      const parts = [];
      if (info.port) parts.push('SSID ' + info.port);
      if (info.rssi != null) parts.push('RSSI ' + info.rssi + ' dBm');
      if (info.snr != null) parts.push('SNR ' + info.snr + ' dB');
      edgeLabel = parts.join('\n');
    } else {
      edgeLabel = info.port || '';
    }
  }
  const wirelessFlag = info.wireless ? 'true' : 'false';
  const rfBand = info.rf_band || '';

  // Find an existing endpoint to merge with: prefer MAC match on any
  // role=endpoint node (covers east-west src-endpoint / dest-endpoint added
  // via add_nodes), fall back to the canonical 'endpoint' id used by the
  // wired DHCP path.
  const normMac = (m) => (m || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  const macKey = normMac(info.mac);
  let existing = null;
  if (macKey) {
    cy.nodes().forEach((n) => {
      if (existing) return;
      if (n.data('role') !== 'endpoint') return;
      if (normMac(n.data('mac')) === macKey) existing = n;
    });
  }
  if (!existing) {
    const canon = cy.getElementById('endpoint');
    if (!canon.empty()) existing = canon;
  }
  console.log('[addEndpointNode] mac=', info.mac, 'macKey=', macKey,
              'merge_into=', existing ? existing.id() : '(none — new node)');
  if (existing) {
    const existingId = existing.id();
    existing.data({ label: label, baseLabel: label, mac: info.mac, vlan: info.vlan, sgt: info.sgt });
    // Edge id naming convention: 'endpoint-edge' for the canonical node,
    // '<nodeId>-edge' or just rely on connectedEdges() for spawned ones.
    let edge = cy.getElementById(existingId + '-edge');
    if (edge.empty()) edge = cy.getElementById('endpoint-edge');
    if (edge.empty()) {
      // No tracked edge — look at any edge with this node as source.
      const candidates = existing.connectedEdges().filter(e => e.data('source') === existingId);
      if (!candidates.empty()) edge = candidates[0];
    }
    if (!edge.empty()) {
      if (edge.data('target') !== parentId) {
        const edgeId = edge.id();
        cy.remove(edge);
        cy.add({
          group: 'edges',
          data: {
            id: edgeId,
            source: existingId,
            target: parentId,
            label: edgeLabel,
            wireless: wirelessFlag,
            rfBand: rfBand,
          },
        });
      } else {
        edge.data('label', edgeLabel);
        edge.data('wireless', wirelessFlag);
        edge.data('rfBand', rfBand);
      }
    } else {
      cy.add({
        group: 'edges',
        data: {
          id: existingId + '-edge',
          source: existingId,
          target: parentId,
          label: edgeLabel,
          wireless: wirelessFlag,
          rfBand: rfBand,
        },
      });
    }
    return;
  }

  const pos = parent.position();
  cy.add({
    group: 'nodes',
    data: {
      id: 'endpoint',
      role: 'endpoint',
      label: label,
      baseLabel: label,
      tags: [],
      mac: info.mac,
      vlan: info.vlan,
      sgt: info.sgt,
      checks: [],
    },
    position: { x: pos.x - 160, y: pos.y + 160 },
  });
  cy.add({
    group: 'edges',
    data: {
      id: 'endpoint-edge',
      source: 'endpoint',
      target: parentId,
      label: edgeLabel,
      wireless: wirelessFlag,
      rfBand: rfBand,
    },
  });
}

// Layout offset, by role, used when no explicit position is given.
const ROLE_OFFSET = {
  endpoint:        { dx: -160, dy:  160 },
  border:          { dx:  220, dy:    0 },
  'control-plane': { dx:  220, dy: -180 },
  'dhcp-server':   { dx:  420, dy:    0 },
  'underlay-switch':  { dx: -260, dy:  -60 },
  'underlay-unknown': { dx: -260, dy:  -60 },
  fabric:          { dx: -340, dy:  140 },
  wlc:             { dx:    0, dy: -260 },
  'access-point':  { dx: -180, dy: -160 },
  // Spawned by WirelessFabricEdgeEtr when the wireless endpoint roamed off
  // the user-supplied XTR — placed to the right of the original.
  xtr:             { dx:  280, dy:    0 },
};

// Human-readable role tag added to a merged node when multiple checks land on
// the same physical device (matched by IP).
const ROLE_TAG = {
  border: 'Border',
  'control-plane': 'CP',
  'underlay-switch': 'Next-Hop',
  'underlay-unknown': 'Next-Hop',
  'dhcp-server': 'DHCP',
  wlc: 'WLC',
  'access-point': 'AP',
};

function addNodes(nodes) {
  if (!Array.isArray(nodes) || !cy) return;
  const occupied = new Set();
  const ipIndex = new Map();  // ip -> existing node id
  cy.nodes().forEach(n => {
    const p = n.position();
    occupied.add(Math.round(p.x) + ',' + Math.round(p.y));
    const ip = n.data('ip');
    if (ip) ipIndex.set(ip, n.id());
  });

  nodes.forEach(spec => {
    if (!spec || !spec.id) return;

    // Exact-id hit: refresh the label, and if connect_to is now provided
    // (e.g. AP was added floating, then wired to XTR after FE discovery),
    // create the parent edge now.
    const existing = cy.getElementById(spec.id);
    if (!existing.empty()) {
      if (spec.label) existing.data({ label: spec.label, baseLabel: spec.label });
      if (spec.ip && !existing.data('ip')) existing.data('ip', spec.ip);
      if (spec.connect_to && !cy.getElementById(spec.connect_to).empty()) {
        const edgeId = spec.id + '-edge';
        if (cy.getElementById(edgeId).empty()) {
          cy.add({
            group: 'edges',
            data: {
              id: edgeId,
              source: spec.id,
              target: spec.connect_to,
              label: spec.edge_label || '',
              wireless: spec.edge_wireless ? 'true' : 'false',
            },
          });
        }
      }
      return;
    }

    // IP-match hit: same physical device under a different role. Tag the
    // existing node with the new role and add a second edge labelled for the
    // new role, rather than drawing a duplicate node.
    if (spec.ip && ipIndex.has(spec.ip)) {
      const targetId = ipIndex.get(spec.ip);
      // Register the alias so subsequent specs that reference spec.id (e.g.
      // the next path-walk hop's connect_to) resolve to the merged node.
      nodeIdAliases.set(spec.id, targetId);
      const target = cy.getElementById(targetId);
      const tag = ROLE_TAG[spec.role];
      if (tag) {
        const tags = (target.data('tags') || []).slice();
        if (!tags.includes(tag)) {
          tags.push(tag);
          target.data('tags', tags);
          applyNodeLabel(targetId);
        }
      }
      const parentId = resolveNodeId(spec.connect_to) || 'xtr';
      // Stable, collision-free edge id; merge-edge suffix so we can recognize
      // these later if we ever want to clean them up on Run Again.
      const edgeId = 'merge-' + spec.id + '-to-' + targetId;
      if (cy.getElementById(edgeId).empty() && !cy.getElementById(parentId).empty()) {
        cy.add({
          group: 'edges',
          data: {
            id: edgeId,
            source: targetId,
            target: parentId,
            label: spec.edge_label || '',
          },
        });
      }
      return;
    }

    const floating = spec.floating === true || !spec.connect_to;
    const parentId = resolveNodeId(spec.connect_to) || 'xtr';
    const parent = cy.getElementById(parentId);
    // Need *some* reference point for positioning; bail if XTR isn't there yet.
    if (parent.empty()) return;
    const role = spec.role || 'unknown';
    const offset = ROLE_OFFSET[role] || { dx: 200, dy: 0 };
    let x = parent.position().x + offset.dx;
    let y = parent.position().y + offset.dy;
    // Stagger if the slot is already occupied.
    while (occupied.has(Math.round(x) + ',' + Math.round(y))) {
      y += 100;
    }
    occupied.add(Math.round(x) + ',' + Math.round(y));

    cy.add({
      group: 'nodes',
      data: {
        id: spec.id,
        role: role,
        label: spec.label || spec.id,
        baseLabel: spec.label || spec.id,
        ip: spec.ip || null,
        mac: spec.mac || null,
        vlan: spec.vlan != null ? spec.vlan : null,
        tags: [],
        checks: [],
      },
      position: { x: x, y: y },
    });
    if (!floating) {
      cy.add({
        group: 'edges',
        data: {
          id: spec.id + '-edge',
          source: spec.id,
          target: parentId,
          label: spec.edge_label || '',
          wireless: spec.edge_wireless ? 'true' : 'false',
        },
      });
    }
    if (spec.ip) ipIndex.set(spec.ip, spec.id);
  });
}

// Draw standalone edges between two existing nodes. Used for peer relationships
// like border-to-border CDP links where neither endpoint is being created by
// this message.
function addEdges(edges) {
  if (!cy || !Array.isArray(edges)) return;
  edges.forEach(spec => {
    if (!spec || !spec.source || !spec.target) return;
    const sourceId = resolveNodeId(spec.source);
    const targetId = resolveNodeId(spec.target);
    const src = cy.getElementById(sourceId);
    const dst = cy.getElementById(targetId);
    if (src.empty() || dst.empty()) return;
    // Stable id, order-independent so we don't double-draw the reciprocal CDP
    // entry (border-1 sees border-2 AND border-2 sees border-1).
    const ids = [sourceId, targetId].sort();
    const edgeId = (spec.id_prefix || 'link') + '-' + ids[0] + '-' + ids[1];
    if (!cy.getElementById(edgeId).empty()) return;
    cy.add({
      group: 'edges',
      data: {
        id: edgeId,
        source: sourceId,
        target: targetId,
        label: spec.label || '',
      },
    });
  });
}

function appendCheck(nodeId, entry) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (n.empty()) return;
  const list = (n.data('checks') || []).slice();
  const idx = list.findIndex(c => c.name === entry.name);
  if (idx >= 0) { list[idx] = Object.assign({}, list[idx], entry); }
  else { list.push(entry); }
  n.data('checks', list);
  // Recompute node status from the full check list. Skip is neutral — only
  // ok/warn/fail count toward the terminal verdict. Running shows while there
  // are still in-flight checks and no failure has surfaced.
  n.data('status', computeNodeStatus(list));
  if (selectedNodeId === nodeId) renderChecksPanel();
}

// Terminal severity. 'skip' is intentionally absent → neutral; a node with
// only OK + SKIP results stays green.
const TERMINAL_RANK = { ok: 1, warn: 2, fail: 3 };
function computeNodeStatus(checks) {
  if (!checks || !checks.length) return 'pending';
  let best = 0, anyTerminal = false, anyRunning = false, anySkip = false;
  for (const c of checks) {
    if (c.status === 'running') { anyRunning = true; continue; }
    if (c.status === 'skip')    { anySkip = true; continue; }
    const r = TERMINAL_RANK[c.status];
    if (r) { anyTerminal = true; if (r > best) best = r; }
  }
  // A fail takes effect immediately even with checks still running.
  if (best === 3) return 'fail';
  if (anyRunning) return 'running';
  if (anyTerminal) return best === 2 ? 'warn' : 'ok';
  return anySkip ? 'skip' : 'pending';
}

let lastEventId = 0;

async function startRun(payload) {
  if (currentEventSource) { try { currentEventSource.close(); } catch (e) {} }
  setRunInFlight(true);
  // Pass `?since=<last>` so the server skips events from any earlier run on
  // this session. EventSource auto-reconnects within the same connection use
  // Last-Event-ID; this only affects fresh EventSource instances.
  const url = '/run/events/' + currentSession + '?since=' + lastEventId;
  const es = new EventSource(url);
  currentEventSource = es;
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (ev.lastEventId) {
      const n = parseInt(ev.lastEventId, 10);
      if (!isNaN(n) && n > lastEventId) { lastEventId = n; saveSession({ lastEventId }); }
    }
    handleEvent(msg);
    if (msg.type === 'run_complete') { es.close(); setRunInFlight(false); }
  };
  es.onerror = () => { /* let the browser auto-reconnect */ };

  try {
    const r = await fetch('/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentSession, payload: payload }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      console.error('Run request failed:', d.detail || r.status);
      es.close();
      setRunInFlight(false);
    }
  } catch (e) {
    console.error('Run request error:', e);
    es.close();
    setRunInFlight(false);
  }
}

function setRunInFlight(active) {
  runInFlight = active;
  const btn = document.getElementById('topologyRefresh');
  if (btn) btn.disabled = active;
}

function mergeNodeInto(srcId, tgtId, edgeLabel) {
  if (!cy || !srcId || !tgtId || srcId === tgtId) return false;
  const src = cy.getElementById(srcId);
  const tgt = cy.getElementById(tgtId);
  if (src.empty() || tgt.empty()) return false;

  // Tags: union, preserving order.
  const tags = (tgt.data('tags') || []).slice();
  (src.data('tags') || []).forEach(t => { if (!tags.includes(t)) tags.push(t); });
  tgt.data('tags', tags);

  // Role promotion: a Border folded into a CDP-discovered underlay node should
  // adopt the Border identity (and the same fabric-device icon as the Edge),
  // not stay rendered as a generic underlay chassis.
  if (src.data('role') === 'border' && tgt.data('role') !== 'border') {
    tgt.data('role', 'border');
  }

  // Checks: append src's checks to tgt (status badges then reflect the union).
  const checks = (tgt.data('checks') || []).slice();
  (src.data('checks') || []).forEach(c => {
    if (!checks.find(x => x.name === c.name)) checks.push(c);
  });
  tgt.data('checks', checks);

  // Recompute merged status from the unioned check list (skip-neutral).
  tgt.data('status', computeNodeStatus(checks));

  // Re-home edges that touched src to touch tgt instead, then drop duplicates.
  // If tgt already has an edge to the same other endpoint, keep the more
  // informative label (interface labels like "Te1/0/3 <-> Twe1/0/4" win over
  // generic role labels like "fabric").
  const edgeBetween = (a, b) => cy.edges().filter(e => {
    const s = e.data('source'), t = e.data('target');
    return (s === a && t === b) || (s === b && t === a);
  });
  src.connectedEdges().forEach(e => {
    const otherEnd = (e.data('source') === srcId) ? e.data('target') : e.data('source');
    if (otherEnd === tgtId) { e.remove(); return; }
    const incomingLabel = e.data('label') || '';
    const existing = edgeBetween(tgtId, otherEnd);
    if (existing.length > 0) {
      const existingLabel = existing[0].data('label') || '';
      if (incomingLabel && incomingLabel.length > existingLabel.length) {
        existing[0].data('label', incomingLabel);
      }
      e.remove();
      return;
    }
    const newId = 'merged-' + srcId + '-' + otherEnd;
    if (!cy.getElementById(newId).empty()) { e.remove(); return; }
    cy.add({
      group: 'edges',
      data: {
        id: newId,
        source: tgtId,
        target: otherEnd,
        label: incomingLabel,
      },
    });
    e.remove();
  });

  // Add the new role edge (e.g. "fabric") between tgt and its parent (xtr by
  // default — borders are always connected through the Edge). Skip if an edge
  // already exists between tgt and the parent (CDP usually added one already).
  if (edgeLabel) {
    const parentId = 'xtr';
    const newEdgeId = 'merge-role-' + srcId + '-' + tgtId;
    if (cy.getElementById(newEdgeId).empty()
        && !cy.getElementById(parentId).empty()
        && edgeBetween(tgtId, parentId).length === 0) {
      cy.add({
        group: 'edges',
        data: {
          id: newEdgeId,
          source: tgtId,
          target: parentId,
          label: edgeLabel,
        },
      });
    }
  }

  src.remove();
  if (selectedNodeId === srcId) selectedNodeId = tgtId;
  return true;
}

function handleEvent(msg) {
  switch (msg.type) {
    case 'run_started':
      break;
    case 'check_started': {
      const nodeId = msg.target_node_id || 'xtr';
      appendCheck(nodeId, { name: msg.name, status: 'running', message: '' });
      break;
    }
    case 'check_finished': {
      let nodeId = msg.target_node_id || 'xtr';
      // Merge first so subsequent relabel/tags/rloc land on the merged node.
      if (msg.merge_into && msg.merge_into.target) {
        const ok = mergeNodeInto(
          msg.merge_into.source || nodeId,
          msg.merge_into.target,
          msg.merge_into.edge_label,
        );
        if (ok) nodeId = msg.merge_into.target;
      }
      appendCheck(nodeId, { name: msg.name, status: msg.status, message: msg.message || '' });
      const n = cy.getElementById(nodeId);
      if (msg.node_relabel) {
        // Treat node_relabel as the NEW base label (e.g. XTR redirected to a
        // different device). Tags belong to the previous device, so clear them.
        updateNode(nodeId, { baseLabel: msg.node_relabel, tags: [] });
        applyNodeLabel(nodeId);
      }
      if (Array.isArray(msg.node_tags)) {
        updateNode(nodeId, { tags: msg.node_tags });
        applyNodeLabel(nodeId);
      }
      if (msg.node_rloc) {
        updateNode(nodeId, { rloc: msg.node_rloc });
        applyNodeLabel(nodeId);
      }
      if (Array.isArray(msg.relabel_nodes)) {
        msg.relabel_nodes.forEach(spec => {
          if (!spec || !spec.id) return;
          const target = cy.getElementById(spec.id);
          if (target.empty()) return;
          if (spec.label != null) {
            updateNode(spec.id, { baseLabel: spec.label });
            applyNodeLabel(spec.id);
          }
        });
      }
      if (Array.isArray(msg.add_nodes)) {
        addNodes(msg.add_nodes);
      }
      if (Array.isArray(msg.add_edges)) {
        addEdges(msg.add_edges);
      }
      if (msg.add_endpoint) {
        addEndpointNode(msg.add_endpoint);
      }
      break;
    }
    case 'run_complete':
      break;
  }
}

// ---- Restore-on-load --------------------------------------------------------
// If a previous session is still alive server-side, skip the login wizard and
// reattach. The browser's EventSource sends Last-Event-ID automatically on
// reconnect, so the server replays anything we missed.

function reattachEventStream() {
  if (!currentSession) return;
  if (currentEventSource) { try { currentEventSource.close(); } catch (e) {} }
  const url = '/run/events/' + currentSession + '?since=' + lastEventId;
  const es = new EventSource(url);
  currentEventSource = es;
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (ev.lastEventId) {
      const n = parseInt(ev.lastEventId, 10);
      if (!isNaN(n) && n > lastEventId) { lastEventId = n; saveSession({ lastEventId }); }
    }
    handleEvent(msg);
    if (msg.type === 'run_complete') { es.close(); setRunInFlight(false); }
  };
  es.onerror = () => { /* let the browser auto-reconnect */ };
  setRunInFlight(true);
}

async function restoreSession() {
  const saved = readSession();
  if (!saved.sid) return;

  try {
    const r = await fetch('/login/status/' + saved.sid);
    if (!r.ok) { clearSession(); return; }
    const d = await r.json();
    if (d.status !== 'ready') { clearSession(); return; }
  } catch (e) { return; }

  currentSession = saved.sid;
  loginForm.style.display = 'none';

  // Probe service state — if it's already connected, jump straight to the
  // scenario form and (best-effort) reconnect the SSE stream so any in-flight
  // run keeps painting.
  try {
    const r = await fetch('/service/status/' + saved.sid);
    const d = await r.json();
    if (d && d.status === 'ready') {
      const label = d.name || d.serial || saved.serviceName || '';
      saveSession({ serviceName: label, serviceSerial: d.serial });
      showScenarioForm(label);
      // Reattach to the event stream so an in-flight run keeps painting and a
      // completed-but-missed run still replays final state.
      if (typeof saved.lastEventId === 'number') lastEventId = saved.lastEventId;
      reattachEventStream();
      return;
    }
  } catch (e) { /* fall through to service form */ }

  // Logged in but no service yet — show the service form.
  serviceUser.textContent = 'Restored session ' + saved.sid;
  serviceForm.style.display = 'block';
}

restoreSession();
