// SDA Fabric Troubleshooter — frontend.
// Wizard: login → service → scenario → live topology with streamed Checks.

window.addEventListener('error', (e) => console.error('window error:', e.message, e.error));

let currentSession = null;
let cy = null;
let selectedNodeId = null;
let currentPayload = null;
let currentEventSource = null;
let runInFlight = false;

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
  dhcpInputs.style.display = (v === 'dhcp') ? 'block' : 'none';
  ewInputs.style.display   = (v === 'east_west') ? 'block' : 'none';
});

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
  } else {
    payload = {
      scenario: 'east_west',
      device_source_ip: document.getElementById('ew_device_ip').value,
      endpoint_ip: document.getElementById('ew_endpoint_ip').value,
      destination_ip: document.getElementById('ew_destination_ip').value,
      l2_only: ewL2.checked,
      mask: ewL2.checked ? parseInt(document.getElementById('ew_mask').value, 10) : null,
      gateway: ewL2.checked ? document.getElementById('ew_gateway').value : null,
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

const ROLE_ICON = {
  endpoint: ENDPOINT_ICON_URL,
  border: BORDER_ICON_URL,
  'control-plane': CP_ICON_URL,
  'dhcp-server': DHCP_SERVER_ICON_URL,
  'underlay-switch': UNDERLAY_SWITCH_ICON_URL,
  'underlay-unknown': UNDERLAY_UNKNOWN_ICON_URL,
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
  document.getElementById('topologySub').textContent = payload.scenario === 'dhcp'
    ? 'DHCP — XTR ' + payload.mgmt_ip + ' · MAC ' + payload.mac + ' · VLAN ' + payload.vlan
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
      }},
    ],
    layout: { name: 'preset' },
    wheelSensitivity: 0.2,
  });

  const xtrIp = payload.scenario === 'dhcp' ? payload.mgmt_ip : payload.device_source_ip;
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
  document.getElementById('topologyDownloadLog').addEventListener('click', () => {
    window.location.href = '/logfile';
  });
}

function refreshTopology() {
  if (!currentPayload) return;
  if (currentPayload.scenario === 'dhcp') {
    const wired = document.getElementById('topologyTreatAsWired');
    if (wired) currentPayload.is_few = !wired.checked;
  }
  hideChecksPanel();
  cy.elements().remove();
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
    row.addEventListener('click', () => row.classList.toggle('expanded'));
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
  const vlanLine = 'VLAN: ' + (info.vlan != null ? info.vlan : '?');
  const sgtLine = 'SGT: ' + (info.sgt != null && info.sgt !== '' ? info.sgt : '0');
  const label = macLine + '\n' + vlanLine + '\n' + sgtLine;

  const existing = cy.getElementById('endpoint');
  if (!existing.empty()) {
    existing.data({ label: label, baseLabel: label, mac: info.mac, vlan: info.vlan, sgt: info.sgt });
    const edge = cy.getElementById('endpoint-edge');
    if (!edge.empty() && info.port) edge.data('label', info.port);
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
      label: info.port || '',
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
};

// Human-readable role tag added to a merged node when multiple checks land on
// the same physical device (matched by IP).
const ROLE_TAG = {
  border: 'Border',
  'control-plane': 'CP',
  'underlay-switch': 'Next-Hop',
  'underlay-unknown': 'Next-Hop',
  'dhcp-server': 'DHCP',
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

    // Exact-id hit: just refresh the label, nothing else to do.
    const existing = cy.getElementById(spec.id);
    if (!existing.empty()) {
      if (spec.label) existing.data({ label: spec.label, baseLabel: spec.label });
      if (spec.ip && !existing.data('ip')) existing.data('ip', spec.ip);
      return;
    }

    // IP-match hit: same physical device under a different role. Tag the
    // existing node with the new role and add a second edge labelled for the
    // new role, rather than drawing a duplicate node.
    if (spec.ip && ipIndex.has(spec.ip)) {
      const targetId = ipIndex.get(spec.ip);
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
      const parentId = spec.connect_to || 'xtr';
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

    const parentId = spec.connect_to || 'xtr';
    const parent = cy.getElementById(parentId);
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
        tags: [],
        checks: [],
      },
      position: { x: x, y: y },
    });
    cy.add({
      group: 'edges',
      data: {
        id: spec.id + '-edge',
        source: spec.id,
        target: parentId,
        label: spec.edge_label || '',
      },
    });
    if (spec.ip) ipIndex.set(spec.ip, spec.id);
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
  if (selectedNodeId === nodeId) renderChecksPanel();
}

async function startRun(payload) {
  if (currentEventSource) { try { currentEventSource.close(); } catch (e) {} }
  setRunInFlight(true);
  const es = new EventSource('/run/events/' + currentSession);
  currentEventSource = es;
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
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

  // Checks: append src's checks to tgt (status badges then reflect the union).
  const checks = (tgt.data('checks') || []).slice();
  (src.data('checks') || []).forEach(c => {
    if (!checks.find(x => x.name === c.name)) checks.push(c);
  });
  tgt.data('checks', checks);

  // Status escalation from src.
  const srcStatus = src.data('status');
  if (srcStatus) tgt.data('status', escalate(tgt.data('status'), srcStatus));

  // Re-home edges that touched src to touch tgt instead, then drop duplicates.
  src.connectedEdges().forEach(e => {
    const otherEnd = (e.data('source') === srcId) ? e.data('target') : e.data('source');
    if (otherEnd === tgtId) { e.remove(); return; }
    const newId = 'merged-' + srcId + '-' + otherEnd;
    if (!cy.getElementById(newId).empty()) { e.remove(); return; }
    cy.add({
      group: 'edges',
      data: {
        id: newId,
        source: tgtId,
        target: otherEnd,
        label: e.data('label') || '',
      },
    });
    e.remove();
  });

  // Add the new role edge (e.g. "fabric") between tgt and its parent (xtr by
  // default — borders are always connected through the Edge).
  if (edgeLabel) {
    const parentId = 'xtr';
    const newEdgeId = 'merge-role-' + srcId + '-' + tgtId;
    if (cy.getElementById(newEdgeId).empty() && !cy.getElementById(parentId).empty()) {
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
      const n = cy.getElementById(nodeId);
      if (!n.empty()) n.data('status', escalate(n.data('status'), 'running'));
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
      if (!n.empty()) n.data('status', escalate(n.data('status'), msg.status));
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
      if (msg.add_endpoint) {
        addEndpointNode(msg.add_endpoint);
      }
      if (Array.isArray(msg.add_nodes)) {
        addNodes(msg.add_nodes);
      }
      break;
    }
    case 'run_complete':
      break;
  }
}
