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
// Whether an RSA service is connected. The picker uses it to decide whether a
// chosen scenario resumes at login, at the service form, or straight at its inputs.
let serviceReady = false;

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

// Session-level notice: the server went away, or replay was lossy. Both mean
// what is on screen can no longer be trusted to be complete, so they get a
// persistent banner rather than a line in the log.
function showBanner(text) {
  const el = document.getElementById('banner');
  if (!el) return;
  el.textContent = text + ' ';
  const btn = document.createElement('button');
  btn.textContent = 'Reload';
  btn.onclick = () => location.reload();
  el.appendChild(btn);
  el.classList.add('show');
}

// ---- Login -----------------------------------------------------------------

const loginForm = document.getElementById('loginForm');
const loginStatus = document.getElementById('status');
const methodSelect = document.getElementById('method');
const passphraseRow = document.getElementById('passphraseRow');
const methodRow = methodSelect ? methodSelect.closest('label, div') || methodSelect : null;

// Certificate login needs a key on disk and prompts on stdin, so the cloud
// server does not offer it. It advertises that via /version; the server also
// rejects the method outright, this just keeps the UI honest.
fetch('/version').then(r => r.ok ? r.json() : null).then(v => {
  if (v && v.cert_login_enabled === false) {
    const opt = methodSelect && methodSelect.querySelector('option[value="certificate"]');
    if (opt) opt.remove();
    if (methodSelect) methodSelect.value = 'sso';
    if (methodRow && methodRow !== methodSelect) methodRow.style.display = 'none';
    syncPassphraseVisibility();
  }
}).catch(() => {});

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

// RADKit's client setup and forwarder connect each take tens of seconds, and we
// get no progress out of them -- only the result. A static "Connecting..." is
// then indistinguishable from a hang, so show elapsed time: it does not make
// the wait shorter, but it makes it legible as waiting rather than broken.
function waitingHtml(what, startedAt, extra) {
  const secs = Math.round((Date.now() - startedAt) / 1000);
  return what + ' <b>' + secs + 's</b><br>' +
    '<span style="opacity:0.75;font-size:0.9em">' +
    (extra || 'RADKit calls can take 30-60s.') + '</span>';
}

async function pollLoginStatus(sid) {
  let urlShown = false;
  const startedAt = Date.now();
  while (true) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const r = await fetch('/login/status/' + sid);
      // 404 means the session is gone -- almost always a server restart, which
      // ends every session (a RADKit client cannot outlive its process). Say so
      // and stop; without this the tab polls a dead session forever.
      if (r.status === 404) {
        clearSession();
        loginStatus.className = 'err';
        loginStatus.innerHTML =
          '<b>Session ended.</b><br>The server restarted, so this session is ' +
          'gone. Reload the page and log in again.';
        return;
      }
      if (!r.ok) continue;  // 5xx or a blip -- keep polling
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
      } else if (!urlShown) {
        // Still inside RADKit client setup -- no SSO URL to show yet.
        loginStatus.className = 'ok';
        loginStatus.innerHTML = waitingHtml(
          'Starting RADKit client...', startedAt,
          'Validating certificates with the RADKit cloud. Usually 30-60s.');
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


// ---- RADKit connection badge ---------------------------------------------
// Always-on indicator. A login that has quietly gone stale is otherwise
// invisible until a run fails half a minute in, so the state gets its own
// corner of the screen rather than a line buried in a form.
const radkitBadge = document.getElementById('radkitBadge');

function setRadkitStatus(state, label, detail) {
  if (!radkitBadge) return;
  radkitBadge.hidden = false;
  radkitBadge.classList.remove('is-ready', 'is-partial', 'is-dead');
  if (state) radkitBadge.classList.add('is-' + state);
  const s = radkitBadge.querySelector('.radkit-state');
  const d = radkitBadge.querySelector('.radkit-detail');
  if (s) s.textContent = label;
  if (d) d.textContent = detail || '';
}

function showServiceForm(sid) {
  currentSession = sid;
  saveSession({ sid });
  pickerPane.style.display = 'none';
  loginForm.style.display = 'none';
  serviceUser.textContent = 'Logged in as ' + document.getElementById('email').value;
  setRadkitStatus('partial', 'Logged in \u2014 no service',
                  document.getElementById('email').value);
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
  const startedAt = Date.now();
  while (true) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const r = await fetch('/service/status/' + sid);
      if (r.status === 404) {
        clearSession();
        setStatus(serviceStatus, 'err',
          '<b>Session ended.</b><br>The server restarted. Reload and log in again.');
        return;
      }
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
      setStatus(serviceStatus, 'ok', waitingHtml(
        'Connecting to service...', startedAt,
        'Establishing the RADKit forwarder tunnel. Usually 30-60s.'));
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
  serviceReady = true;
  serviceForm.style.display = 'none';
  pickerPane.style.display = 'none';
  scenarioService.textContent = 'Service: ' + serviceLabel;
  setRadkitStatus('ready', 'RADKit connected', serviceLabel);
  if (scenarioTitle) scenarioTitle.textContent = scenarioLabel(scenarioSelect.value);
  scenarioForm.style.display = 'block';
}

scenarioSelect.addEventListener('change', () => {
  const v = scenarioSelect.value;
  dhcpInputs.style.display   = (v === 'dhcp') ? 'block' : 'none';
  ewInputs.style.display     = (v === 'east_west') ? 'block' : 'none';
  umcastInputs.style.display = (v === 'underlay_multicast') ? 'block' : 'none';
  const apInputs = document.getElementById('apInputs');
  if (apInputs) apInputs.style.display = (v === 'ap_onboarding') ? 'block' : 'none';
  // Keep the cards in step with the select, whichever drove the change.
  document.querySelectorAll('.scenario-card[data-scenario]').forEach(btn => {
    btn.setAttribute('aria-pressed', String(btn.dataset.scenario === v));
  });
});

// The cards are the UI; the <select> stays the value holder so every existing
// reader (and the visibility logic above) keeps working unchanged.
//
// Picking a card is also step 1 of the wizard: it advances to login (or
// straight to the scenario form if this session is already logged in and
// connected). Choosing the scenario first needs no RSA service, and it makes
// the login step read as part of the task rather than a gate in front of it.
const pickerPane = document.getElementById('pickerPane');
// The masthead belongs to the landing step only -- once a run is underway the
// topology needs the vertical space more than branding does.
const masthead = document.querySelector('.masthead');
function setHeroVisible(on) {
  if (masthead) masthead.style.display = on ? 'block' : 'none';
}
const loginForScenario = document.getElementById('loginForScenario');
const scenarioTitle = document.getElementById('scenarioTitle');

function scenarioLabel(value) {
  const opt = scenarioSelect.querySelector(`option[value="${value}"]`);
  return opt ? opt.textContent : value;
}

// Where a scenario resumes once its card is picked, given how far this session
// has already got. Kept in one place so the picker and restoreSession agree.
function advanceFromPicker() {
  const label = scenarioLabel(scenarioSelect.value);
  if (scenarioTitle) scenarioTitle.textContent = label;
  pickerPane.style.display = 'none';
  setHeroVisible(false);

  if (currentSession && serviceReady) {
    scenarioForm.style.display = 'block';
    return;
  }
  if (currentSession) {
    serviceForm.style.display = 'block';
    return;
  }
  if (loginForScenario) loginForScenario.textContent = 'To run: ' + label;
  loginForm.style.display = 'block';
}

document.querySelectorAll('.scenario-card[data-scenario]').forEach(btn => {
  btn.addEventListener('click', () => {
    scenarioSelect.value = btn.dataset.scenario;
    scenarioSelect.dispatchEvent(new Event('change'));
    saveSession({ scenario: btn.dataset.scenario });
    advanceFromPicker();
  });
});

// Back to the picker. Only the scenario changes -- the session and the
// connected service are untouched, so there is nothing to re-do.
const changeScenarioBtn = document.getElementById('changeScenario');
if (changeScenarioBtn) {
  changeScenarioBtn.addEventListener('click', () => {
    scenarioForm.style.display = 'none';
    pickerPane.style.display = 'block';
    setHeroVisible(true);
    // Forget the choice too -- otherwise a reload from the picker restores the
    // scenario the user just backed out of.
    saveSession({ scenario: null, runStarted: false });
  });
}

// Back from login / service. Both only rewind the *view* -- a login already in
// flight keeps going, and a connected service stays connected, so coming
// forward again costs nothing. Anything else would throw away a 30-60s RADKit
// call because someone wanted to re-read the cards.
['backFromLogin', 'backFromService'].forEach(id => {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.addEventListener('click', () => {
    loginForm.style.display = 'none';
    serviceForm.style.display = 'none';
    pickerPane.style.display = 'block';
    setHeroVisible(true);
  });
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
  } else if (v === 'ap_onboarding') {
    const apMacInput = document.getElementById('ap_mac');
    const apMacMsg = document.getElementById('ap_mac_msg');
    const normMac = normalizeMac(apMacInput.value);
    if (!normMac) {
      apMacMsg.textContent = 'Invalid MAC — need 12 hex characters.';
      apMacMsg.className = 'field-msg msg-err';
      apMacInput.focus();
      return;
    }
    apMacInput.value = normMac;
    payload = {
      scenario: 'ap_onboarding',
      mgmt_ip: document.getElementById('ap_mgmt_ip').value,
      catc_name: document.getElementById('ap_catc_name').value,
      ap_mac: normMac,
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

// Fabric roles (Fabric Edge, Border, Control Plane) render in Cisco light blue
// with a circled role letter, so the fabric path reads at a glance. Everything
// else keeps the darker blue.
const FABRIC_ROLE_FILL = '#29B5E5';
const DEFAULT_NODE_FILL = '#1e40af';

// One icon SVG per status — the badge is drawn directly inside the SVG so the
// position is exact and there are no multi-background-image quirks.
// `bodyFill` tints the chassis; `roleLabel` is the role marker on the top-left,
// opposite the status badge. A device can hold several fabric roles at once
// (a Border that is also a CP), so the marker widens into a pill to fit them
// all -- "B", "C", "B+C" -- rather than dropping any.
function iconSvg(badgeFill, bodyFill, roleLabel) {
  // Rect is inset on top & right to leave room for the corner badge to peek out.
  const arrow =
    "<line x1='46' y1='54' x2='46' y2='28' stroke='white' stroke-width='2.2' stroke-linecap='round'/>" +
    "<polygon points='46,18 40.5,28 51.5,28' fill='white'/>";
  let arrows = "";
  for (let i = 0; i < 8; i++) {
    arrows += "<g transform='rotate(" + (i * 45) + " 46 54)'>" + arrow + "</g>";
  }
  let roleBadge = "";
  if (roleLabel) {
    const stroke = bodyFill || DEFAULT_NODE_FILL;
    // One character stays a circle; anything longer grows into a pill so the
    // text never spills outside the marker.
    const w = roleLabel.length <= 1 ? 22 : 16 + 9 * roleLabel.length;
    const cx = Math.max(15, w / 2 + 3);  // keep the marker inside the viewBox
    roleBadge =
      "<rect x='" + (cx - w / 2) + "' y='10' width='" + w + "' height='22' " +
        "rx='11' ry='11' fill='white' stroke='" + stroke + "' stroke-width='2.5'/>" +
      "<text x='" + cx + "' y='21' text-anchor='middle' dominant-baseline='central' " +
        "font-family='Helvetica,Arial,sans-serif' font-size='" +
        (roleLabel.length > 1 ? 12 : 13) + "' font-weight='bold' " +
        "fill='" + stroke + "'>" + roleLabel + "</text>";
  }
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
    "<rect x='2' y='10' width='88' height='88' rx='12' ry='12' " +
      "fill='" + (bodyFill || DEFAULT_NODE_FILL) + "' stroke='#0f172a' stroke-width='3'/>" +
    arrows +
    "<circle cx='90' cy='10' r='10' fill='" + badgeFill + "' stroke='white' stroke-width='2.5'/>" +
    roleBadge +
    "</svg>"
  );
}
function iconUrl(fill, bodyFill, roleLabel) {
  return "data:image/svg+xml;utf8," + encodeURIComponent(iconSvg(fill, bodyFill, roleLabel));
}

const STATUS_BADGE = {
  pending: '#cbd5e1',
  running: '#eab308',
  ok:      '#22c55e',
  warn:    '#f97316',
  fail:    '#ef4444',
  skip:    '#94a3b8',
};

const ICON_URL = {
  pending: iconUrl(STATUS_BADGE.pending),
  running: iconUrl(STATUS_BADGE.running),
  ok:      iconUrl(STATUS_BADGE.ok),
  warn:    iconUrl(STATUS_BADGE.warn),
  fail:    iconUrl(STATUS_BADGE.fail),
  skip:    iconUrl(STATUS_BADGE.skip),
};

// Fabric-role icons: light blue body + role marker, one per (role combo,
// status) pair so the status badge still shows pass/warn/fail on top of the
// role colour. Combos are pre-built because a device is often several things
// at once -- a Border that is also a CP shows "B+C".
const FABRIC_ROLE_COMBOS = ['E', 'B', 'C', 'B+C', 'E+B', 'E+C', 'E+B+C'];
const FABRIC_ROLE_ICON_URL = {};
for (const combo of FABRIC_ROLE_COMBOS) {
  FABRIC_ROLE_ICON_URL[combo] = {};
  for (const [status, badge] of Object.entries(STATUS_BADGE)) {
    FABRIC_ROLE_ICON_URL[combo][status] = iconUrl(badge, FABRIC_ROLE_FILL, combo);
  }
}

// Endpoint (computer) icon — drawn as a separate shape so it visually reads as
// "the client" rather than another fabric device.
function computerIconSvg() {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
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
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
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
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
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
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
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
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
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
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
    "<path d='M25 65 Q12 65 12 52 Q12 42 23 40 Q23 27 38 27 Q42 18 54 18 " +
    "Q67 18 71 30 Q86 30 86 44 Q86 56 75 58 Q75 68 63 68 L28 68 " +
    "Q25 68 25 65 Z' fill='#cbd5e1' stroke='#475569' stroke-width='2.5' " +
    "stroke-linejoin='round'/>" +
    "</svg>"
  );
}
const FABRIC_CLOUD_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(fabricCloudIconSvg());

// Wireless LAN Controller. Same chassis geometry as the fabric-role icons --
// identical rect, stroke and badge placement -- so the two read as the same
// family of device. Only the glyph differs: three arrows converging upward
// over a chain-link ribbon, per the Cisco WLC symbol.
//
// `bodyFill` follows the same rule as the edges: dark blue by default, and
// fabric light-blue once the WLC is determined to be a fabric WLC.
function wlcIconSvg(badgeFill, bodyFill) {
  const white = "#ffffff";
  // Three arrows radiating from a common centre to the points of a triangle:
  // tails meet in the middle, heads at the vertices. Built from ONE arrow drawn
  // straight up from the centre and rotated 0/120/240 degrees, so all three are
  // identical by construction -- drawing them separately let their origins and
  // head sizes drift apart.
  const CX = 46, CY = 48, R = 27, HL = 13, HW = 8;
  const tipY = CY - R;            // arrowhead tip, at the triangle vertex
  const baseY = CY - (R - HL);    // arrowhead base
  const arrow =
    "<line x1='" + CX + "' y1='" + CY + "' x2='" + CX + "' y2='" + baseY + "' " +
      "stroke='" + white + "' stroke-width='4' stroke-linecap='round'/>" +
    "<polygon points='" + CX + "," + tipY + " " +
      (CX - HW) + "," + baseY + " " + (CX + HW) + "," + baseY + "' fill='" + white + "'/>";
  let glyph = "";
  for (let k = 0; k < 3; k++) {
    glyph += "<g transform='rotate(" + (k * 120) + " " + CX + " " + CY + ")'>" + arrow + "</g>";
  }
  // Chain-link ribbon across the bottom.
  let ribbon = "<g fill='none' stroke='" + white + "' stroke-width='2.6'>";
  for (let i = 0; i < 6; i++) {
    ribbon += "<ellipse cx='" + (18 + i * 11) + "' cy='82' rx='6' ry='4.5'/>";
  }
  ribbon += "</g>";
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
    "<rect x='2' y='10' width='88' height='88' rx='12' ry='12' " +
      "fill='" + (bodyFill || DEFAULT_NODE_FILL) + "' stroke='#0f172a' stroke-width='3'/>" +
    glyph +
    ribbon +
    "<circle cx='90' cy='10' r='10' fill='" + badgeFill + "' stroke='white' stroke-width='2.5'/>" +
    "</svg>"
  );
}
function wlcIconUrl(fill, bodyFill) {
  return "data:image/svg+xml;utf8," + encodeURIComponent(wlcIconSvg(fill, bodyFill));
}
// Two sets: the default dark-blue chassis, and the fabric light-blue one used
// once the WLC is confirmed to be a fabric WLC (node gets fabric = 'yes').
const WLC_ICON_URL = {};
const WLC_FABRIC_ICON_URL = {};
for (const [status, badge] of Object.entries(STATUS_BADGE)) {
  WLC_ICON_URL[status]        = wlcIconUrl(badge, DEFAULT_NODE_FILL);
  WLC_FABRIC_ICON_URL[status] = wlcIconUrl(badge, FABRIC_ROLE_FILL);
}

// Access Point: Cisco-style rounded blue square with a smaller rounded
// rectangle window and a top LED dot.
// `bodyFill` so a fabric AP can wear the same light blue every other fabric
// node does, the way wlcIconSvg already takes one.
function apIconSvg(bodyFill) {
  return (
    "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
    // Rounded body.
    "<rect x='14' y='14' width='72' height='72' rx='14' ry='14' " +
      "fill='" + (bodyFill || '#1d4ed8') + "' stroke='#0c1e5e' stroke-width='3'/>" +
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
// Used once `show ap name <ap> config general` reports Fabric Status:
// Enabled -- the same FABRIC_ROLE_FILL the fabric WLC and the fabric role
// icons use, so "this device is in the fabric" reads identically everywhere.
const AP_FABRIC_ICON_URL =
  "data:image/svg+xml;utf8," + encodeURIComponent(apIconSvg(FABRIC_ROLE_FILL));

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
  document.getElementById('topologyPanel').style.display = 'flex';
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
        : payload.scenario === 'ap_onboarding'
          ? 'AP Onboarding — Edge ' + payload.mgmt_ip + ' · AP MAC ' + payload.ap_mac
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
          // Push the label clear of the icon. background-clip:none lets the
          // icon overflow the node box, so the label has to clear the icon's
          // real extent, not the box -- a negative margin drags it back on top
          // of the artwork. Labels also grow at runtime (RLOC / [tags] lines),
          // so this offset is what keeps multi-line labels below the icon.
          'text-margin-y': 6,
          // A halo keeps text legible where it passes near an edge or icon.
          'text-background-color': '#ffffff',
          'text-background-opacity': 0.85,
          'text-background-padding': '3px',
          'text-background-shape': 'round-rectangle',
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
          'text-margin-y': 8,
          'font-size': '11px',
      }},
      { selector: 'node[role = "border"]', style: {
          'width': 88,
          'height': 88,
          'text-margin-y': 10,
      }},
      { selector: 'node[role = "control-plane"]', style: {
          // No dedicated icon: a CP is a fabric device like an Edge or Border,
          // so it uses the same light-blue switch, marked with a "C" badge by
          // applyFabricRoleIcon.
          'width': 88,
          'height': 88,
          'text-margin-y': 10,
      }},
      { selector: 'node[role = "dhcp-server"]', style: {
          'background-image': DHCP_SERVER_ICON_URL,
          'width': 72,
          'height': 72,
          'text-margin-y': 8,
      }},
      { selector: 'node[role = "underlay-switch"]', style: {
          'background-image': UNDERLAY_SWITCH_ICON_URL,
          'width': 70,
          'height': 70,
          'text-margin-y': 8,
          'font-size': '11px',
      }},
      { selector: 'node[role = "underlay-unknown"]', style: {
          'background-image': UNDERLAY_UNKNOWN_ICON_URL,
          'width': 70,
          'height': 70,
          'text-margin-y': 8,
          'font-size': '11px',
          'opacity': 0.75,
      }},
      { selector: 'node[role = "fabric"]', style: {
          'background-image': FABRIC_CLOUD_ICON_URL,
          'width': 110,
          'height': 88,
          'text-margin-y': 10,
          'font-size': '12px',
          'font-weight': 'bold',
      }},
      { selector: 'node[role = "wlc"]', style: {
          'background-image': WLC_ICON_URL.pending,
          'width': 88,
          'height': 88,
          'text-margin-y': 10,
      }},
      { selector: 'node[role = "wlc"][status = "pending"]', style: { 'background-image': WLC_ICON_URL.pending } },
      { selector: 'node[role = "wlc"][status = "running"]', style: { 'background-image': WLC_ICON_URL.running } },
      { selector: 'node[role = "wlc"][status = "ok"]',      style: { 'background-image': WLC_ICON_URL.ok } },
      { selector: 'node[role = "wlc"][status = "warn"]',    style: { 'background-image': WLC_ICON_URL.warn } },
      { selector: 'node[role = "wlc"][status = "fail"]',    style: { 'background-image': WLC_ICON_URL.fail } },
      { selector: 'node[role = "wlc"][status = "skip"]',    style: { 'background-image': WLC_ICON_URL.skip } },
      // No status yet (node just created): still honour the fabric chassis.
      { selector: 'node[role = "wlc"][fabric = "yes"]', style: { 'background-image': WLC_FABRIC_ICON_URL.pending } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "pending"]', style: { 'background-image': WLC_FABRIC_ICON_URL.pending } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "running"]', style: { 'background-image': WLC_FABRIC_ICON_URL.running } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "ok"]',      style: { 'background-image': WLC_FABRIC_ICON_URL.ok } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "warn"]',    style: { 'background-image': WLC_FABRIC_ICON_URL.warn } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "fail"]',    style: { 'background-image': WLC_FABRIC_ICON_URL.fail } },
      { selector: 'node[role = "wlc"][fabric = "yes"][status = "skip"]',    style: { 'background-image': WLC_FABRIC_ICON_URL.skip } },
      { selector: 'node[role = "access-point"]', style: {
          'background-image': AP_ICON_URL,
          'width': 88,
          'height': 88,
          'text-margin-y': 10,
          'font-size': '11px',
      }},
      { selector: 'node[role = "access-point"][fabric = "yes"]', style: {
          'background-image': AP_FABRIC_ICON_URL } },
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
      // The routed path between fabric nodes. Dotted like the sessions above
      // it for the same reason: the hops between two fabric nodes are not a
      // cable, and the ones this run looked at are drawn as their own edges.
      { selector: 'edge[label = "IP Underlay"]', style: {
          // Straight, unlike the two session edges: the base `edge` rule is
          // bezier, so this has to say so rather than leave it out.
          'curve-style': 'straight',
          'line-style': 'dotted',
          'line-color': '#708aba',
          'width': 3,
          'color': '#3d4f7a',
          'font-size': '10px',
      }},
      // The LISP control-plane session, like CAPWAP, is a relationship
      // between two nodes rather than a cable between them -- the underlay
      // hops it crosses are drawn as their own edges. Matched on the label
      // because these edges are built from a node's `connect_to` rather than
      // an `add_edges` spec, so there is no flag to carry.
      { selector: 'edge[label ^= "LISP Session"]', style: {
          // Bowed like the CAPWAP tunnel, but in the opposite direction: both
          // can hang off the same node, and two curves bowed the same way
          // would sit on top of each other.
          'curve-style': 'unbundled-bezier',
          'control-point-distances': [110],
          'control-point-weights': [0.5],
          'line-style': 'dotted',
          'line-color': '#7095ba',
          'width': 3,
          'color': '#3d5a7a',
          'font-size': '10px',
          // Upright, like the CAPWAP label: autorotate from the base rule
          // would tilt it to the steepest part of the bow.
          'text-rotation': 'none',
      }},
      // A session that is not Up, in a darker blue than the live one. The
      // state rides on its own data flag rather than the label text so the
      // match does not depend on how the label happens to be worded.
      { selector: 'edge[sessionState = "down"]', style: {
          'line-color': '#1e3a5f',
          'color': '#15293f',
      }},
      // The VXLAN access tunnel, drawn only when it is up. Cyan, to match
      // the fabric-node colouring. Drawn as a straight line running
      // parallel to the physical Edge-to-AP port and offset below it, not
      // as a curve: the tunnel follows that cable, so the two belong
      // alongside each other. `segments` with both bend points at the same
      // distance gives a straight run displaced from the direct path --
      // a bezier would bow away from the port it is meant to parallel.
      { selector: 'edge[accessTunnel = "true"]', style: {
          'curve-style': 'segments',
          'segment-distances': [26, 26],
          'segment-weights': [0.08, 0.92],
          'line-style': 'dashed',
          'line-dash-pattern': [8, 4],
          'line-color': '#06b6d4',
          'width': 3,
          'color': '#0e7490',
          'font-size': '10px',
          'text-rotation': 'none',
          'text-margin-y': 12,
      }},
      { selector: 'edge[capwap = "true"]', style: {
          // Bowed away from the physical path so the tunnel reads as going
          // over the topology rather than through it.
          'curve-style': 'unbundled-bezier',
          'control-point-distances': [-110],
          'control-point-weights': [0.5],
          'line-style': 'dashed',
          'line-dash-pattern': [8, 4],
          'line-color': '#70ba8f',
          'width': 3,
          'color': '#3d7a5a',
          'font-size': '10px',
          'text-rotation': 'none',
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
  document.getElementById('checksPanelFilter').addEventListener('click', () => {
    if (!selectedNodeId) return;
    if (findingsOnly.has(selectedNodeId)) findingsOnly.delete(selectedNodeId);
    else findingsOnly.add(selectedNodeId);
    renderChecksPanel();
  });
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
  document.getElementById('topologyDownloadLog').addEventListener('click', async () => {
    // Fetch first rather than clicking a plain <a download>: that gives the
    // browser no way to report a failure, so a 404 shows up as "Check internet
    // connection" -- which is both wrong and unactionable, and just makes
    // people retry. Fetching lets us say what actually happened.
    const url = currentSession ? '/logfile/' + currentSession : '/logfile';
    try {
      const r = await fetch(url);
      if (!r.ok) {
        showBanner(r.status === 404
          // 404 covers both "no such session" and "not yours" -- deliberately,
          // so the endpoint cannot be used to probe for valid session ids.
          ? 'That log is not available. It belongs to another session, or your ' +
            'session ended when the server restarted.'
          : 'Could not download the log (HTTP ' + r.status + ').');
        return;
      }
      const blob = await r.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = 'collection_logfile.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(href);
    } catch (e) {
      showBanner('Could not download the log: ' + e);
    }
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

// A refresh or tab close abandons the run but the server worker keeps going.
// Because that worker is single-threaded, the next run enqueues *behind* the
// abandoned one, and the reconnecting page replays the old run's events onto a
// fresh canvas -- which is why the XTR node came back empty. Beacon a stop on
// the way out so the run dies with the page.
//
// 'pagehide' rather than 'beforeunload': it fires on mobile/bfcache paths where
// beforeunload does not. sendBeacon survives teardown; fetch may not.
window.addEventListener('pagehide', function () {
  if (!currentSession) return;
  try {
    navigator.sendBeacon('/run/stop/' + currentSession, new Blob([], { type: 'text/plain' }));
  } catch (e) { /* nothing useful to do while unloading */ }
});

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

// Statuses the "Findings" filter keeps. `running` and `pending` are kept
// deliberately: a check still in flight has no verdict yet, and dropping it
// would make rows vanish mid-run and reappear as they land -- the filter is
// for hiding settled good news, not for hiding work in progress.
const FINDING_STATUSES = new Set(['warn', 'fail', 'running', 'pending']);

// Per node, not global: a reader narrows the one device they are reading and
// expects the next device to open showing everything. Keyed by node id and
// held across re-renders, which SSE triggers on every check result.
const findingsOnly = new Set();

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

  // The toggle reflects THIS node, and is disabled when there is nothing to
  // filter down to -- an enabled control that visibly does nothing reads as
  // a bug. Counts come from the full list, so the summary keeps telling the
  // truth about the device while the list below shows a subset.
  const btn = document.getElementById('checksPanelFilter');
  const findings = (counts.warn || 0) + (counts.fail || 0);
  const only = findingsOnly.has(selectedNodeId);
  if (btn) {
    btn.setAttribute('aria-pressed', only ? 'true' : 'false');
    btn.disabled = !findings && !only;
    btn.textContent = findings ? 'Findings (' + findings + ')' : 'Findings';
  }

  const expanded = new Set(
    Array.from(list.querySelectorAll('.check-row.expanded')).map(el => el.dataset.key)
  );
  list.innerHTML = '';
  const shown = only ? items.filter(it => FINDING_STATUSES.has(it.status)) : items;
  if (only && !shown.length) {
    const empty = document.createElement('div');
    empty.id = 'checksPanelEmpty';
    empty.textContent = 'No warnings or failures on this device.';
    list.appendChild(empty);
  }
  shown.forEach(it => {
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
  if ('tags' in partial || 'role' in partial || 'status' in partial) {
    applyFabricRoleIcon(nodeId);
  }
}

function applyNodeLabel(nodeId) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (n.empty()) return;
  const base = n.data('baseLabel') || n.data('label') || '';
  const rloc = n.data('rloc');
  // Tags carry the roles merged in later; the role the node was CREATED with
  // is in data('role') and was never shown. A device that is both a Border
  // and a CP therefore read as whichever one happened to arrive second --
  // the badge said "B+C" while the text underneath said just "[CP]".
  const tags = (n.data('tags') || []).slice();
  const ownTag = ROLE_TAG[n.data('role')];
  if (ownTag && !tags.includes(ownTag)) tags.unshift(ownTag);
  let label = base;
  if (rloc) label += '\nRLOC: ' + rloc;
  if (tags.length) label += '\n[' + tags.join(', ') + ']';
  n.data('label', label);
}

// Promote a WLC node to a fabric WLC: cyan chassis (see the
// node[role="wlc"][fabric="yes"] selectors) and a role tag that says so. Called
// when the WLC's `show wireless fabric summary` reports Fabric Status: Enabled.
function markWlcFabric(nodeId) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (n.empty()) return;
  n.data('fabric', 'yes');
  const tags = (n.data('tags') || []).filter(t => t !== 'WLC' && t !== 'Fabric WLC');
  tags.push('Fabric WLC');
  n.data('tags', tags);
  applyNodeLabel(nodeId);
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
// Offsets are generous on purpose: nodes carry multi-line labels (hostname +
// RLOC + role tags) drawn *below* the icon, so the visual footprint of a node
// is considerably taller and wider than its 88px box.
const ROLE_OFFSET = {
  endpoint:        { dx: -200, dy:  240 },
  border:          { dx:  300, dy:    0 },
  'control-plane': { dx:  300, dy: -240 },
  'dhcp-server':   { dx:  580, dy:    0 },
  'underlay-switch':  { dx: -340, dy:  -80 },
  'underlay-unknown': { dx: -340, dy:  -80 },
  fabric:          { dx: -440, dy:  200 },
  // Mirrored across the border arc from the Edge: the Edge sits one gap to
  // the LEFT of the borders, the controller the same gap to the RIGHT. The
  // borders' own horizontal reach is BORDER_ARC_RADIUS * cos(30 deg) ~= 329,
  // so clearing the arc by that same distance again puts the controller at
  // ~710. Its LISP-session links then come back to the control planes over
  // the short side, instead of crossing the fabric as they did when it was
  // parked above the arc.
  wlc:             { dx:  710, dy:    0 },
  // The AP hangs straight off the Edge on the horizontal, so the link that
  // matters most in this scenario reads as one clean line rather than a
  // diagonal competing with the fabric nodes above and below it.
  'access-point':  { dx: -360, dy:    0 },
  // Spawned by WirelessFabricEdgeEtr when the wireless endpoint roamed off
  // the user-supplied XTR — placed to the right of the original.
  xtr:             { dx:  360, dy:    0 },
};

// Borders are placed on an arc to the RIGHT of the Edge, spread evenly rather
// than stacked: they are peers of one another, and stacking them vertically
// implied a hierarchy between them that does not exist. Right also matches the
// direction traffic leaves the fabric, with the AP on the left where it
// enters. The arc is centred on the horizontal, so a single border sits level
// with the Edge and two straddle it symmetrically.
const BORDER_ARC_RADIUS = 380;
const BORDER_ARC_SPREAD = 60;   // total degrees the fan occupies

function borderArcPosition(parent, index, total) {
  const span = total > 1 ? BORDER_ARC_SPREAD : 0;
  const step = total > 1 ? span / (total - 1) : 0;
  // Centred on 0 degrees (straight right).
  const deg = -span / 2 + step * index;
  const rad = deg * Math.PI / 180;
  const p = parent.position();
  return {
    x: p.x + BORDER_ARC_RADIUS * Math.cos(rad),
    y: p.y - BORDER_ARC_RADIUS * Math.sin(rad),
  };
}

// Vertical step used when two nodes would land on the same spot. Must exceed a
// node's icon plus its label block, or staggered nodes still overlap.
const STAGGER_Y = 200;

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

// Which fabric-role marker a node should carry. A device is often several
// things at once (a Border that is also a CP), and the roles arrive at
// different times -- 'xtr' is set when the node is created, Border/CP are
// merged in later as tags when a check lands on the same IP. Every role the
// node holds is shown, joined with '+', in a stable E/B/C order.
function fabricRoleOf(n) {
  const tags = n.data('tags') || [];
  const role = n.data('role');
  const parts = [];
  if (role === 'xtr') parts.push('E');
  if (tags.includes('Border') || role === 'border') parts.push('B');
  if (tags.includes('CP') || role === 'control-plane') parts.push('C');
  return parts.length ? parts.join('+') : null;
}

// Re-point a node at the right icon for its fabric role + current status.
// Status still drives the badge, so a failed Border is light blue with a red
// badge rather than losing its pass/fail signal.
function applyFabricRoleIcon(nodeId) {
  if (!cy) return;
  const n = cy.getElementById(nodeId);
  if (!n || n.empty()) return;
  const fr = fabricRoleOf(n);
  if (!fr) { n.removeStyle('background-image'); return; }
  const status = n.data('status') || 'pending';
  // Fall back to building the icon on the fly for any combination not
  // pre-generated, so a new role never silently loses its marker.
  const url = (FABRIC_ROLE_ICON_URL[fr] || {})[status]
           || iconUrl(STATUS_BADGE[status] || STATUS_BADGE.pending, FABRIC_ROLE_FILL, fr);
  if (url) n.style('background-image', url);
}

function addNodes(nodes) {
  if (!Array.isArray(nodes) || !cy) return;
  // [x, y] pairs of every taken slot, compared by proximity below rather than
  // by exact equality.
  const occupied = new Set();
  const ipIndex = new Map();  // ip -> existing node id
  // Borders are laid out as a set, so the fan needs to know how many there
  // are before placing the first one. Counted across this batch, which is how
  // Border Discovery delivers them.
  const borderTotal = nodes.filter(
    n => n && n.role === 'border' && n.id && cy.getElementById(n.id).empty()
  ).length;
  let borderSeen = 0;
  cy.nodes().forEach(n => {
    const p = n.position();
    occupied.add([p.x, p.y]);
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
          applyFabricRoleIcon(targetId);
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
    let x, y;
    if (role === 'border' && borderTotal > 0) {
      const p = borderArcPosition(parent, borderSeen++, borderTotal);
      x = p.x; y = p.y;
    } else {
      const offset = ROLE_OFFSET[role] || { dx: 200, dy: 0 };
      x = parent.position().x + offset.dx;
      y = parent.position().y + offset.dy;
    }
    // Stagger if something is already near this slot. Exact-coordinate matching
    // is not enough -- two nodes a few px apart still overlap once their labels
    // are drawn -- so treat anything within the stagger box as a collision.
    // Arc-placed borders are already spread so they cannot overlap each
    // other; letting the stagger push them down would undo the even spacing
    // that is the whole point of the fan.
    // The controller is likewise placed deliberately: mirrored across the arc
    // from the Edge. A DHCP server sits at dx 580 to its 710, inside the
    // 200px collision box, so without this the controller gets walked down
    // out of the symmetry it was placed in.
    const onArc = (role === 'border' && borderTotal > 0) || role === 'wlc';
    let guard = 0;
    while (!onArc && guard++ < 40 && [...occupied].some(([ox, oy]) =>
             Math.abs(ox - x) < 200 && Math.abs(oy - y) < STAGGER_Y)) {
      y += STAGGER_Y;
    }
    occupied.add([x, y]);

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
        // 'yes' switches a WLC to the fabric (light-blue) chassis, matching how
        // the edges signal fabric membership.
        fabric: spec.fabric ? 'yes' : 'no',
        tags: Array.isArray(spec.tags) ? spec.tags.slice() : [],
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
    // Tags supplied at creation (e.g. 'Fabric WLC') must be rendered into the
    // label; the node was added with the bare base label.
    if (Array.isArray(spec.tags) && spec.tags.length) applyNodeLabel(spec.id);
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
        // The CAPWAP tunnel is drawn differently from a wired link: it is an
        // overlay between the AP and its controller, not a cable, and the
        // hops it crosses are already on the canvas as their own edges.
        capwap: spec.capwap ? 'true' : undefined,
        // The VXLAN access tunnel between the edge and the AP. Like CAPWAP
        // it is an overlay, not a cable, so it is drawn alongside the wired
        // link rather than replacing it -- both exist at once between the
        // same two nodes, which is why it bows the other way.
        accessTunnel: spec.access_tunnel ? 'true' : undefined,
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
  // Keep the fabric-role icon in step with the new status (status drives the
  // badge; the light-blue body stays).
  applyFabricRoleIcon(nodeId);
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
  // Belt and braces for the refresh case: the pagehide beacon usually kills the
  // abandoned run, but a dropped beacon would leave it running and this new run
  // would queue behind it. Await the stop so the old run is cancelled and any
  // queued run is drained before we enqueue ours.
  if (currentSession) {
    try {
      await fetch('/run/stop/' + currentSession, { method: 'POST' });
    } catch (e) { /* proceed regardless; worst case is the old behaviour */ }
  }
  setRunInFlight(true);
  // A reload only resumes into a scenario form if a run actually started --
  // otherwise an idle refresh traps the user in whatever they last picked.
  saveSession({ runStarted: true });
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
  es.onerror = () => {
    // A blip is normal -- EventSource reconnects itself. But if the session is
    // gone (server restarted), reconnecting just 404s forever, so check once
    // and tell the user instead of spinning silently.
    if (!currentSession) return;
    fetch('/login/status/' + currentSession).then(r => {
      if (r.status === 404) {
        es.close();
        clearSession();
        setRunInFlight(false);
        setRadkitStatus('dead', 'Session expired', 'log in again');
        showBanner('Session ended — the server restarted. Log in again.');
      }
    }).catch(() => {});
  };

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
  applyFabricRoleIcon(tgt.id());

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
    case 'server_shutdown':
      // The server is going away and taking every session with it. Say so --
      // otherwise EventSource just reconnects into a 404 and the run appears
      // to hang.
      clearSession();
      setRunInFlight(false);
      showBanner(msg.message || 'Server is restarting — please log in again.');
      break;
    case 'replay_gap':
      // We reconnected past the end of the buffer, so some checks were never
      // delivered. Better to say the view is incomplete than to paint a
      // partial run as if it were whole.
      showBanner(msg.message || 'Some earlier events were missed; reload to resync.');
      break;
    case 'run_started':
      break;
    case 'check_started': {
      // Through the alias map: a node merged into another (same device
      // discovered a second time under a new role) keeps answering to the id
      // the backend knew it by. Without this the check is filed against an id
      // no node has, and disappears from the report.
      const nodeId = resolveNodeId(msg.target_node_id) || 'xtr';
      appendCheck(nodeId, { name: msg.name, status: 'running', message: msg.note || '' });
      break;
    }
    case 'check_finished': {
      let nodeId = resolveNodeId(msg.target_node_id) || 'xtr';
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
      // A WLC that reports Fabric Status: Enabled becomes a Fabric WLC --
      // cyan chassis and a role tag saying so.
      if (Array.isArray(msg.mark_fabric_wlc)) {
        msg.mark_fabric_wlc.forEach(id => markWlcFabric(id));
      }
      // An AP whose `config general` reports Fabric Status: Enabled wears the
      // same fabric blue. Separate from mark_fabric_wlc because that one also
      // rewrites the WLC role tag, which does not apply to an AP.
      if (Array.isArray(msg.mark_fabric_ap)) {
        msg.mark_fabric_ap.forEach(id => {
          const n = cy && cy.getElementById(id);
          if (n && !n.empty()) n.data('fabric', 'yes');
        });
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
      // The LISP session edges are drawn at discovery time, before any
      // session has been read, so they start as a bare "LISP Session". Once
      // the session check knows the state, say so on the edge and darken the
      // ones that are not Up. Matched by the control-plane node the edge
      // hangs off rather than by address: the session peers with the RLOC
      // while the node carries its management IP, and those differ.
      if (Array.isArray(msg.lisp_session_state)) {
        msg.lisp_session_state.forEach(spec => {
          if (!spec || !spec.node || !cy) return;
          const node = cy.getElementById(spec.node);
          if (!node || node.empty()) return;
          const up = String(spec.state || '').toLowerCase() === 'up';
          node.connectedEdges().forEach(e => {
            if (!String(e.data('label') || '').startsWith('LISP Session')) return;
            e.data('label', 'LISP Session - ' + (up ? 'UP' : 'DOWN'));
            e.data('sessionState', up ? 'up' : 'down');
          });
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
  es.onerror = () => {
    // A blip is normal -- EventSource reconnects itself. But if the session is
    // gone (server restarted), reconnecting just 404s forever, so check once
    // and tell the user instead of spinning silently.
    if (!currentSession) return;
    fetch('/login/status/' + currentSession).then(r => {
      if (r.status === 404) {
        es.close();
        clearSession();
        setRunInFlight(false);
        setRadkitStatus('dead', 'Session expired', 'log in again');
        showBanner('Session ended — the server restarted. Log in again.');
      }
    }).catch(() => {});
  };
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
  setHeroVisible(false);
  if (saved.scenario) {
    scenarioSelect.value = saved.scenario;
    scenarioSelect.dispatchEvent(new Event('change'));
  }

  // Probe service state — if it's already connected, jump straight to the
  // scenario form and (best-effort) reconnect the SSE stream so any in-flight
  // run keeps painting.
  try {
    const r = await fetch('/service/status/' + saved.sid);
    const d = await r.json();
    if (d && d.status === 'ready') {
      const label = d.name || d.serial || saved.serviceName || '';
      saveSession({ serviceName: label, serviceSerial: d.serial });
      serviceReady = true;
      if (!saved.scenario || !saved.runStarted) {
        // Nothing chosen, or chosen but never run -- start at the picker. Only
        // a run in progress (or just finished) is worth resuming into.
        scenarioService.textContent = 'Service: ' + label;
        setRadkitStatus('ready', 'RADKit connected', label);
        pickerPane.style.display = 'block';
        setHeroVisible(true);
        return;
      }
      showScenarioForm(label);
      // Reattach to the event stream so an in-flight run keeps painting and a
      // completed-but-missed run still replays final state.
      if (typeof saved.lastEventId === 'number') lastEventId = saved.lastEventId;
      reattachEventStream();
      return;
    }
  } catch (e) { /* fall through to service form */ }

  // Logged in but no service yet. With a scenario already chosen, resume at the
  // service form; without one there is nothing to resume to, so show the picker.
  serviceUser.textContent = 'Restored session ' + saved.sid;
  setRadkitStatus('partial', 'Logged in \u2014 no service', saved.sid);
  if (saved.scenario && saved.runStarted) {
    pickerPane.style.display = 'none';
    serviceForm.style.display = 'block';
  } else {
    pickerPane.style.display = 'block';
    setHeroVisible(true);
  }
}

restoreSession();
