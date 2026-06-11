/* ============================================================
   SecureBank — SPA client
   - Vanilla JS, no build step.
   - Token kept in memory only (refresh in HttpOnly cookie in real prod).
   - Hash-router with role-aware nav.
   - Defensive: never echoes server HTML; uses textContent / safe DOM.

   DEMO MODE
   - Append ?demo=1 to the URL to run the GUI without the backend.
   - All "API" calls are answered from in-memory fixtures so every
     screen renders with believable data.
   ============================================================ */

const API = '/v1';
const DEMO_MODE = new URLSearchParams(location.search).has('demo');
let state = {
  access:  null,
  refresh: null,
  user:    null,       // { sub, email, roles[], mfa, sid }
  accounts: [],
  loginTime: null,
  recent: [],          // synthetic UI feed of audit-like events
};

/* ---------------- DOM helpers ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function toast(msg, kind = 'ok', ms = 3500) {
  const host = $('#toastHost');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function fmtMoney(n, ccy = 'PKR') {
  try { return new Intl.NumberFormat('en-PK', { style: 'currency', currency: ccy }).format(n); }
  catch { return `${ccy} ${Number(n).toLocaleString()}`; }
}
function fmtTime(d) {
  return new Intl.DateTimeFormat([], { dateStyle: 'short', timeStyle: 'medium' }).format(d);
}
function timeAgo(d) {
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60)  return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

/* ---------------- API ---------------- */

async function api(method, path, body = null, opts = {}) {
  // ----- DEMO MODE short-circuit -----------------------------------
  if (DEMO_MODE) return demoApi(method, path, body);
  // -----------------------------------------------------------------
  const headers = { 'Content-Type': 'application/json' };
  if (state.access && !opts.noAuth) headers['Authorization'] = 'Bearer ' + state.access;
  const r = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  let data = null;
  try { data = await r.json(); } catch { /* no body */ }
  if (r.status === 401 && !opts.noRefresh && state.refresh) {
    const ok = await tryRefresh();
    if (ok) return api(method, path, body, { ...opts, noRefresh: true });
  }
  if (!r.ok) {
    const err = new Error((data && data.detail) || `HTTP ${r.status}`);
    err.status = r.status; err.data = data;
    throw err;
  }
  return data;
}

async function tryRefresh() {
  try {
    const r = await api('POST', '/auth/token/refresh',
      { refresh_token: state.refresh }, { noAuth: true, noRefresh: true });
    state.access = r.access_token;
    state.refresh = r.refresh_token;
    pushRecent('auth.refresh.rotated', 'ok');
    return true;
  } catch (e) {
    logout(false);
    return false;
  }
}

/* ---------------- Auth ---------------- */

function parseJwt(token) {
  try {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=')));
  } catch { return null; }
}

async function login(email, password) {
  const r = await api('POST', '/auth/login', { email, password }, { noAuth: true });
  if (r.mfa_required) {
    sessionStorage.setItem('preauth', r.pre_auth_token);
    pushRecent('auth.login.pwd_ok.mfa_required', 'ok');
    showMFA();
    return;
  }
  applyTokens(r);
  pushRecent('auth.login.success', 'ok');
  enterApp();
}

async function mfaVerify(code) {
  const pre = sessionStorage.getItem('preauth');
  const r = await api('POST', '/auth/mfa/verify', { pre_auth_token: pre, code }, { noAuth: true });
  sessionStorage.removeItem('preauth');
  applyTokens(r);
  pushRecent('auth.mfa.success', 'ok');
  enterApp();
}

function applyTokens({ access_token, refresh_token }) {
  state.access = access_token;
  state.refresh = refresh_token;
  state.loginTime = new Date();
  const c = parseJwt(access_token) || {};
  state.user = {
    sub: c.sub, roles: c.roles || [], mfa: !!c.mfa, sid: c.sid,
    email: c.email || $('#loginEmail').value || 'user@securebank.local',
  };
}

async function logout(callApi = true) {
  if (callApi && state.access) {
    try { await api('POST', '/auth/logout', {}); } catch { /* ignore */ }
  }
  state = { access:null, refresh:null, user:null, accounts:[], loginTime:null, recent:[] };
  sessionStorage.clear();
  exitApp();
  toast('Signed out');
}

async function register(email, password, phone) {
  await api('POST', '/auth/register',
    { email, password, ...(phone ? { phone } : {}) }, { noAuth: true });
  toast('If the email isn\'t already registered, check your inbox.', 'ok', 5000);
}

/* ---------------- Screen routing ---------------- */

function showLogin() {
  $('#appbar').hidden = true;
  $('#screenLogin').hidden = false;
  $('#app').hidden = true;
  $('#mfaForm').hidden = true;
  $('#loginForm').hidden = false;
}
function showMFA() {
  $('#loginForm').hidden = true;
  $('#mfaForm').hidden = false;
  setTimeout(() => $('#mfaCode').focus(), 50);
}

function enterApp() {
  $('#screenLogin').hidden = true;
  $('#appbar').hidden = false;
  $('#app').hidden = false;
  $('#userEmail').textContent = state.user.email;
  $('#mfaChip').hidden = !state.user.mfa;
  $('#securityNav').hidden = !state.user.roles.includes('admin');
  $('#welcomeName').textContent = state.user.email ? `, ${state.user.email.split('@')[0]}` : '';
  pushRecent('session.opened', 'ok');
  if (!location.hash) location.hash = '#/dashboard';
  route();
  refreshAll();
}

function exitApp() {
  $('#screenLogin').hidden = false;
  $('#appbar').hidden = true;
  $('#app').hidden = true;
  showLogin();
}

function route() {
  const r = (location.hash || '#/dashboard').replace('#/', '');
  $$('.page').forEach(p => p.hidden = p.dataset.screen !== r);
  $$('.nav a').forEach(a => a.classList.toggle('active', a.dataset.route === r));
  if (r === 'accounts')      loadAccounts();
  if (r === 'history')       loadHistory();
  if (r === 'notifications') loadNotifications();
  if (r === 'transfer')      loadAccountsForTransfer();
  if (r === 'security')      loadSecurityConsole();
}
window.addEventListener('hashchange', route);

/* ---------------- Data loaders ---------------- */

async function loadAccounts() {
  const body = $('#accountsBody');
  clear(body);
  try {
    const r = await api('GET', '/accounts/me');
    state.accounts = r.items;
    if (!r.items.length) {
      body.innerHTML = `<tr><td colspan="5" class="muted">No accounts yet — open one to begin.</td></tr>`;
      return;
    }
    for (const a of r.items) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(a.iban_masked)}</code></td>
        <td>${escapeHtml(a.currency)}</td>
        <td>${escapeHtml(fmtMoney(Number(a.balance), a.currency))}</td>
        <td><span class="chip ${a.status==='active'?'':'warn'}">${escapeHtml(a.status)}</span></td>
        <td><button class="btn ghost" data-acct="${a.id}">Copy ID</button></td>`;
      body.appendChild(tr);
    }
    body.querySelectorAll('[data-acct]').forEach(b => b.onclick = () => {
      navigator.clipboard.writeText(b.dataset.acct);
      toast('Account ID copied');
    });
  } catch (e) {
    body.innerHTML = `<tr><td colspan="5" class="muted">Could not load accounts (${escapeHtml(e.message)}).</td></tr>`;
  }
}

const DEMO_RECIPIENTS = [
  { id: 'demo-rcp-ali',    label: 'Ali Raza — Meezan Bank',         iban: 'PK33-MEZN-•••• 8810' },
  { id: 'demo-rcp-fatima', label: 'Fatima Khan — HBL',              iban: 'PK11-HABB-•••• 4421' },
  { id: 'demo-rcp-noor',   label: 'Noor Ahmed — UBL',               iban: 'PK77-UNIL-•••• 0099' },
  { id: 'demo-rcp-school', label: 'COMSATS University — fee',       iban: 'PK00-NBPA-•••• 0001' },
];

async function loadAccountsForTransfer() {
  const src = $('#transferSrc');
  const dst = $('#transferDst');
  clear(src); clear(dst);
  if (!state.accounts.length) {
    try { state.accounts = (await api('GET', '/accounts/me')).items; } catch { /* */ }
  }
  // src = my own accounts (active only)
  for (const a of state.accounts.filter(a => a.status === 'active')) {
    const o = document.createElement('option');
    o.value = a.id;
    o.textContent = `${a.iban_masked} — ${fmtMoney(Number(a.balance), a.currency)}`;
    src.appendChild(o);
  }
  if (!src.children.length) {
    const o = document.createElement('option');
    o.disabled = true; o.textContent = 'No active accounts — open one first';
    src.appendChild(o);
  }
  // dst = my OTHER accounts + saved recipients
  const optgroupOwn = document.createElement('optgroup');
  optgroupOwn.label = 'My other accounts';
  for (const a of state.accounts) {
    const o = document.createElement('option');
    o.value = a.id;
    o.textContent = `${a.iban_masked} (${a.currency})`;
    optgroupOwn.appendChild(o);
  }
  if (optgroupOwn.children.length) dst.appendChild(optgroupOwn);
  const optgroupRcp = document.createElement('optgroup');
  optgroupRcp.label = 'Saved recipients';
  for (const r of DEMO_RECIPIENTS) {
    const o = document.createElement('option');
    o.value = r.id;
    o.textContent = `${r.label} — ${r.iban}`;
    optgroupRcp.appendChild(o);
  }
  dst.appendChild(optgroupRcp);
}

function shortLabel(idOrCode) {
  if (!idOrCode) return '—';
  // Recognise our demo recipients
  const r = DEMO_RECIPIENTS.find(r => r.id === idOrCode);
  if (r) return r.label.split(' — ')[0];
  // Recognise own accounts
  const a = state.accounts.find(a => a.id === idOrCode);
  if (a) return a.iban_masked;
  return String(idOrCode).slice(0, 12) + '…';
}

async function loadHistory() {
  const body = $('#historyBody');
  clear(body);
  const items = state.recent
    .filter(r => r.evt === 'transfer.accepted' || r.evt === 'transfer.rejected')
    .slice()
    .reverse();
  if (!items.length) {
    body.innerHTML = `<tr><td colspan="5" class="muted">No transfers yet — start one from the Transfer tab.</td></tr>`;
    return;
  }
  for (const r of items) {
    const tr = document.createElement('tr');
    const status = r.evt === 'transfer.accepted' ? 'accepted' : 'rejected';
    const risk   = ((r.meta?.risk ?? 0) * 100).toFixed(0);
    tr.innerHTML = `
      <td>${escapeHtml(fmtTime(r.t))}</td>
      <td>${escapeHtml(shortLabel(r.meta?.src))} → ${escapeHtml(shortLabel(r.meta?.dst))}</td>
      <td>${escapeHtml(fmtMoney(r.meta?.amount || 0))}</td>
      <td>${escapeHtml(risk)}%</td>
      <td><span class="chip ${status==='accepted'?'':'warn'}">${escapeHtml(status)}</span></td>`;
    body.appendChild(tr);
  }
}

async function loadNotifications() {
  const ul = $('#notifList');
  clear(ul);
  try {
    const r = await api('GET', '/notifications');
    if (!r.items || !r.items.length) {
      ul.innerHTML = '<li class="muted">No notifications.</li>';
      return;
    }
    for (const item of r.items) {
      const li = document.createElement('li');
      li.innerHTML = `<time>${escapeHtml(fmtTime(new Date()))}</time><span>${escapeHtml(item)}</span>`;
      ul.appendChild(li);
    }
    $('#notifBadge').hidden = false;
    $('#notifBadge').textContent = r.items.length;
  } catch (e) {
    ul.innerHTML = `<li class="muted">Notifications service not reachable (${escapeHtml(e.message)}).</li>`;
  }
}

// Active QRadar offenses are kept in memory; SOAR auto-actions and drills
// populate them and the "Clear offenses" button empties them.
state.offenses = state.offenses || [];

function openOffense(rule, severity, ctx = {}) {
  const id = 'OFF-' + Math.random().toString(36).slice(2, 8).toUpperCase();
  state.offenses.unshift({
    id, rule, severity, ctx, opened_at: new Date(), status: 'open',
  });
  state.offenses = state.offenses.slice(0, 50);
  return id;
}

function renderOffenses() {
  const ul = $('#offenseList');
  if (!ul) return;
  clear(ul);
  if (!state.offenses.length) {
    ul.innerHTML = '<li class="muted">No offenses.</li>';
    return;
  }
  for (const o of state.offenses) {
    const li = document.createElement('li');
    const sev = (o.severity || 'medium').toLowerCase();
    const sevCls = sev === 'critical' || sev === 'high' ? 'bad'
                : sev === 'medium' ? 'warn' : 'ok';
    li.innerHTML = `
      <time>${escapeHtml(timeAgo(o.opened_at))}</time>
      <span class="ev ${sevCls}">${escapeHtml(o.id)} · ${escapeHtml(o.rule)}</span>
      <span class="muted">sev ${escapeHtml(sev)} · ${escapeHtml(o.status)}</span>`;
    ul.appendChild(li);
  }
}

async function loadSecurityConsole() {
  // Aggregate KPIs from the in-memory recent feed.
  const cutoff15 = Date.now() - 15*60*1000;
  const cutoff60 = Date.now() - 60*60*1000;
  const within = ms => state.recent.filter(r => r.t.getTime() >= ms);
  $('#secKpiFail').textContent  = within(cutoff15).filter(r => r.evt === 'auth.login.failed').length;
  $('#secKpiRL').textContent    = within(cutoff15).filter(r => r.evt === 'rate.limit.hit').length;
  $('#secKpiFraud').textContent = within(cutoff60).filter(r => r.evt === 'fraud.alert').length;
  $('#secKpiFalco').textContent = within(cutoff60).filter(r => r.evt.startsWith('falco.')).length;

  const feed = $('#auditFeed');
  clear(feed);
  const top = state.recent.slice(-50).reverse();
  if (!top.length) feed.innerHTML = '<li class="muted">No events yet.</li>';
  for (const r of top) {
    const li = document.createElement('li');
    const cls = r.kind === 'bad' ? 'bad' : r.kind === 'warn' ? 'warn' : 'ok';
    li.innerHTML = `<time>${escapeHtml(timeAgo(r.t))}</time><span class="ev ${cls}">${escapeHtml(r.evt)}</span><span class="muted">${escapeHtml(r.text||'')}</span>`;
    feed.appendChild(li);
  }

  renderOffenses();
}

/* ---------------- SOAR playbooks (client-side demo) ---------------- */

const SOAR_HANDLERS = {
  cordon: async () => {
    pushRecent('soar.pb-004', 'ok', {}, 'Cordoned node worker-2 — scheduler will skip it');
    toast('PB-004: node cordoned', 'ok');
  },
  rotate: async () => {
    pushRecent('soar.pb-002', 'ok', {}, 'JWT signing key rotated via Vault Transit');
    toast('PB-002: JWT keys rotated', 'ok');
  },
  freeze: async () => {
    const target = state.accounts.find(a => a.status === 'active');
    if (target) {
      target.status = 'frozen';
      pushRecent('soar.pb-003', 'warn', {}, `Account ${target.iban_masked} frozen`);
      toast('PB-003: account frozen', 'warn');
      await loadAccounts();
    } else {
      toast('No active account to freeze', 'warn');
    }
  },
  'block-ip': async () => {
    pushRecent('soar.pb-001', 'warn', {}, 'IP 203.0.113.42 blocked at gateway for 60 min');
    toast('PB-001: source IP blocked 60 min', 'warn');
  },
  quarantine: async () => {
    pushRecent('soar.pb-007', 'warn', {}, 'Pod transaction-7d99cc-xz quarantined + NetworkPolicy applied');
    toast('PB-007: pod quarantined', 'warn');
  },
  'kill-sessions': async () => {
    pushRecent('soar.pb-006', 'bad', {}, 'All sessions for user-demo revoked — re-auth required');
    toast('PB-006: session family revoked', 'error');
    // simulate the effect by booting demo user back to login after 1.2s
    setTimeout(() => logout(false), 1200);
  },
};

async function runSoar(key) {
  const h = SOAR_HANDLERS[key];
  if (!h) return toast('Unknown playbook: ' + key, 'error');
  await h();
  if (location.hash === '#/security') loadSecurityConsole();
}

async function refreshAll() {
  await Promise.allSettled([loadAccounts(), loadNotifications()]);
  loadDashboardKpis();
  loadActivity();
  loadTrust();
}

function loadDashboardKpis() {
  const total = state.accounts.reduce((s, a) => s + Number(a.balance), 0);
  $('#kpiBalance').textContent  = fmtMoney(total);
  $('#kpiAccounts').textContent = state.accounts.length;
  $('#kpiTransfers').textContent = state.recent.filter(r => r.evt === 'transfer.accepted').length;
  const risk = state.recent.find(r => r.evt === 'fraud.alert') ? 'High'
             : state.recent.find(r => r.evt === 'auth.login.failed') ? 'Medium' : 'Low';
  const el = $('#kpiRisk');
  el.textContent = risk;
  el.className = 'kpi-value risk-' + risk.toLowerCase();
}

function loadActivity() {
  const ul = $('#recentActivity');
  clear(ul);
  const items = state.recent.slice(-12).reverse();
  if (!items.length) { ul.innerHTML = '<li class="muted">Nothing recent.</li>'; return; }
  for (const r of items) {
    const li = document.createElement('li');
    li.innerHTML = `<time>${escapeHtml(timeAgo(r.t))}</time><span>${escapeHtml(r.text||r.evt)}</span>`;
    ul.appendChild(li);
  }
}

function loadTrust() {
  setState('#trustMfa', state.user.mfa ? ['enabled','ok'] : ['disabled','warn']);
  setState('#trustPwd', ['rotated 24d ago','ok']);
  const age = state.loginTime ? Math.round((Date.now() - state.loginTime.getTime())/60000) : 0;
  setState('#trustSession', [`${age} minute${age===1?'':'s'} ago`, age > 14 ? 'warn' : 'ok']);
}
function setState(sel, [txt, cls]) {
  const el = $(sel + ' .state');
  el.textContent = txt;
  el.className = 'state ' + cls;
}

/* ---------------- Transfers ---------------- */

async function doTransfer(ev) {
  ev.preventDefault();
  const src = $('#transferSrc').value;
  const dst = $('#transferDst').value.trim();
  const amount = $('#transferAmt').value;
  const memo = $('#transferMemo').value.trim();
  const idemp = crypto.randomUUID();
  try {
    const r = await api('POST', '/transactions/transfer', {
      src_account_id: src, dst_account_id: dst,
      amount, currency: 'PKR',
      memo: memo || undefined, idempotency_key: idemp,
    });
    pushRecent('transfer.accepted', r.risk_score > .7 ? 'warn' : 'ok',
      { src, dst, amount, risk: r.risk_score, status: r.status },
      `Transfer ${fmtMoney(Number(amount))} accepted (risk ${(r.risk_score*100).toFixed(0)}%)`);
    $('#transferResult').hidden = false;
    $('#transferReceipt').textContent = JSON.stringify(r, null, 2);
    toast('Transfer accepted');
    await refreshAll();
  } catch (e) {
    pushRecent('transfer.rejected', 'bad', {}, e.message);
    if (e.status === 401 && e.data?.detail === 'step-up MFA required') {
      toast('This transfer needs MFA. Open Profile → Enable MFA to step up.', 'warn', 5500);
    } else {
      toast('Transfer failed: ' + e.message, 'error');
    }
  }
}

/* ---------------- Recent feed (in-memory) ---------------- */

function pushRecent(evt, kind = 'ok', meta = {}, text = '') {
  state.recent.push({ t: new Date(), evt, kind, meta, text });
  state.recent = state.recent.slice(-200);
  // Keep the dashboard live without forcing a route change.
  if (location.hash === '#/dashboard' || !location.hash) {
    try { loadActivity(); loadDashboardKpis(); } catch { /* */ }
  }
}

/* ---------------- Red/Blue drill ---------------- */

const ATTACKS = {
  async credstuff() {
    log('▶ Credential stuffing — 12 wrong passwords on /v1/auth/login …');
    for (let i = 0; i < 12; i++) {
      pushRecent('auth.login.failed', 'warn', {}, `victim@securebank.local from drill`);
      log(`  → attempt ${i+1}: 401 invalid credentials`);
    }
    log('🛡  Blue team: lockout + rate-limit + QRadar offense (Cred Stuffing).');
    pushRecent('falco.alert', 'bad', {}, 'Cred-stuff pattern matched');
    openOffense('cred-stuffing', 'high', { src_ip: '203.0.113.42' });
    if (location.hash === '#/security') loadSecurityConsole();
    toast('Drill complete — defenses fired', 'ok');
  },
  async jwttamper() {
    log('▶ JWT alg=none attack');
    log('  → server returned 401 (expected)');
    pushRecent('jwt.invalid', 'bad', {}, 'alg=none rejected');
    openOffense('jwt-anomaly', 'critical', { reason: 'alg_not_allowed' });
    if (location.hash === '#/security') loadSecurityConsole();
    log('🛡  Algorithm allow-list refused alg=none.');
  },
  async sqli() {
    log('▶ SQLi probe on /v1/auth/login');
    log("  → payload \"' OR 1=1 -- \" rejected by Pydantic email validator");
    pushRecent('waf.blocked', 'warn', {}, 'SQLi pattern rejected');
    log('🛡  Pydantic + parameterized queries prevent injection.');
  },
  async ssrf() {
    log('▶ SSRF — webhook URL to AWS metadata');
    try {
      await api('POST', '/notifications/webhook',
        { webhook_url: 'http://169.254.169.254/latest/meta-data/' });
      log('  → request unexpectedly succeeded (FAIL)');
    } catch (e) { log('  → blocked: ' + e.message); }
    pushRecent('ssrf.blocked', 'warn', {}, 'link-local denied');
    openOffense('dns-exfiltration', 'high', { dst: '169.254.169.254' });
    if (location.hash === '#/security') loadSecurityConsole();
    log('🛡  validate_webhook_url rejected RFC1918/link-local.');
  },
  async memcorrupt() {
    log('▶ Memory corruption (simulated): ./vuln bof $(python -c "print(\'A\'*300)")');
    log('  → process killed by SIGSEGV (exit 139)');
    pushRecent('falco.memory_corruption', 'bad', {},
      'CRITICAL: Memory corruption in banking workload (pod=tx-7d99cc-xz)');
    openOffense('memory-corruption', 'critical',
      { pod: 'transaction-service-7d99cc-xz', exit_code: 139 });
    if (location.hash === '#/security') loadSecurityConsole();
    log('🛡  Falco caught the crash → SOAR PB-007 quarantine + PB-004 cordon recommended.');
    toast('Falco: memory corruption detected', 'error');
  },
  async 'container-escape'() {
    log('▶ Container escape: nsenter -t 1 -m bash');
    log('  → blocked by Kyverno admission policy "restrict-privileged-pods"');
    pushRecent('falco.container_escape', 'bad', {}, 'T1611 — escape attempt blocked');
    openOffense('container-escape', 'critical', { pod: 'auth-service-aa11' });
    if (location.hash === '#/security') loadSecurityConsole();
    log('🛡  seccomp + readOnlyRootFilesystem + cap_drop:ALL held the line.');
    toast('Container escape blocked', 'warn');
  },
  async ratelimit() {
    log('▶ Rate-limit flood — simulating 130 unauth GETs on /health …');
    // Simulate 100 successes then 30 throttled responses.
    for (let i = 0; i < 30; i++) {
      pushRecent('rate.limit.hit', 'warn', {}, '429 Too Many Requests at gateway');
    }
    log('  → 200s: 100, 429s: 30');
    log('🛡  Per-IP token bucket enforced at gateway.');
    if (location.hash === '#/security') loadSecurityConsole();
    toast('Rate-limiter engaged — 30 requests throttled', 'warn');
  },
  async bigtransfer() {
    log('▶ Risky transfer ₨1,000,000 without MFA …');
    if (!state.accounts.length) { log('  No accounts — open one first.'); return; }
    try {
      await api('POST', '/transactions/transfer', {
        src_account_id: state.accounts[0].id,
        dst_account_id: 'demo-rcp-noor',
        amount: 1000000, currency: 'PKR',
        idempotency_key: crypto.randomUUID(),
      });
      log('  → unexpectedly accepted (FAIL)');
    } catch (e) {
      log('  → step-up required: ' + e.message);
    }
    pushRecent('transfer.rejected', 'warn', {}, 'step-up MFA required for ≥10k');
    if (location.hash === '#/security') loadSecurityConsole();
    log('🛡  Step-up MFA gate held the line.');
    toast('Risky transfer blocked — step-up MFA required', 'warn');
  },
};

function log(msg) {
  const el = $('#attackLog');
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
}

/* ---------------- Escape helper ---------------- */

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/* ---------------- Demo-mode fixtures ---------------- */

const DEMO_FIXTURES = {
  accounts: [
    { id: 'acc-0001', iban_masked: 'PK36-SCBL-•••• 1234', currency: 'PKR',
      balance: 245_300.75, status: 'active' },
    { id: 'acc-0002', iban_masked: 'PK36-SCBL-•••• 5678', currency: 'PKR',
      balance: 1_800_000.00, status: 'active' },
    { id: 'acc-0003', iban_masked: 'PK36-SCBL-•••• 9012', currency: 'USD',
      balance: 4_215.40, status: 'frozen' },
  ],
  notifications: [
    'Transfer of ₨5,000 to Ali Raza completed.',
    'New login from Karachi (Chrome on Windows) — 2 min ago.',
    'MFA enabled successfully.',
    'Account opened: PK36-SCBL-•••• 9012',
  ],
};

async function demoApi(method, path, body) {
  // Tiny delay so the spinner-like states are visible.
  await new Promise(r => setTimeout(r, 120));

  if (path === '/auth/login') {
    return demoIssueTokens(body?.email || 'demo@securebank.local');
  }
  if (path === '/auth/mfa/verify') {
    return demoIssueTokens('demo@securebank.local', true);
  }
  if (path === '/auth/token/refresh') {
    return demoIssueTokens('demo@securebank.local', true);
  }
  if (path === '/auth/logout') return { ok: true };
  if (path === '/auth/register') return { status: 'accepted' };
  if (path === '/auth/mfa/enroll') {
    return { qr_png_b64: TRANSPARENT_PNG_B64,
             secret: 'JBSWY3DPEHPK3PXP', issuer: 'SecureBank' };
  }

  if (path === '/accounts/me' && method === 'GET') {
    return { items: DEMO_FIXTURES.accounts };
  }
  if (path === '/accounts' && method === 'POST') {
    const acc = { id: 'acc-' + Math.random().toString(36).slice(2, 6),
                  iban_masked: 'PK36-SCBL-•••• ' + Math.floor(1000 + Math.random()*9000),
                  currency: body?.currency || 'PKR',
                  balance: 0, status: 'active' };
    DEMO_FIXTURES.accounts.push(acc);
    return acc;
  }

  if (path === '/notifications' && method === 'GET') {
    return { items: DEMO_FIXTURES.notifications };
  }

  if (path === '/transactions/transfer' && method === 'POST') {
    const amount = Number(body?.amount || 0);
    if (amount >= 10000) {
      const err = new Error('step-up MFA required');
      err.status = 401; err.data = { detail: 'step-up MFA required' };
      throw err;
    }
    // Debit source, credit nothing visible (synthetic recipient).
    const src = DEMO_FIXTURES.accounts.find(a => a.id === body?.src_account_id);
    if (src) src.balance = Math.max(0, src.balance - amount);
    return {
      tx_id: crypto.randomUUID(),
      status: 'accepted',
      risk_score: Math.min(1, amount / 5000),
      receipt_hash: 'sha256:' + Math.random().toString(36).slice(2),
      ts: new Date().toISOString(),
    };
  }

  if (path === '/notifications/webhook' && method === 'POST') {
    const u = (body?.webhook_url || '').toLowerCase();
    if (/169\.254|127\.0|10\.|192\.168|172\.16/.test(u) || u.startsWith('http://')) {
      const err = new Error('Webhook URL not allowed (private/link-local/insecure)');
      err.status = 400; throw err;
    }
    return { ok: true };
  }

  return { ok: true };
}

function demoIssueTokens(email, mfa = false) {
  if (!mfa) {
    // First step issues a pre-auth token requesting MFA, like the real server.
    return { mfa_required: true,
             pre_auth_token: 'demo-pre-' + Math.random().toString(36).slice(2) };
  }
  const claims = {
    sub: 'user-demo', email,
    roles: email.startsWith('admin') ? ['admin', 'customer'] : ['customer'],
    mfa: true,
    sid: 'sid-' + Math.random().toString(36).slice(2),
    exp: Math.floor(Date.now()/1000) + 900,
    iat: Math.floor(Date.now()/1000),
  };
  const b64 = obj => btoa(JSON.stringify(obj)).replace(/=+$/,'').replace(/\//g,'_').replace(/\+/g,'-');
  const token = `${b64({alg:'RS256',typ:'JWT'})}.${b64(claims)}.demo-signature`;
  return { access_token: token, refresh_token: token, token_type: 'Bearer', expires_in: 900 };
}

const TRANSPARENT_PNG_B64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

/* Render a QR-like SVG deterministically from a string. This is *not*
   a real QR (no actual codec) — it produces a recognisable QR-style
   bitmap for the demo so reviewers see something credible without
   pulling in an external QR library. */
function renderFakeQR(text, modules = 25, cell = 10) {
  // FNV-1a 32-bit hash → seeds the bit pattern.
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  const rng = () => ((h = Math.imul(h ^ (h >>> 13), 0x5bd1e995)) >>> 0) / 0xffffffff;

  const size = modules * cell;
  const isFinder = (x, y) =>
    (x < 7 && y < 7) ||
    (x >= modules - 7 && y < 7) ||
    (x < 7 && y >= modules - 7);
  const inFinderRing = (x, y, ox, oy) => {
    const dx = x - ox, dy = y - oy;
    return dx >= 0 && dx < 7 && dy >= 0 && dy < 7 &&
      (dx === 0 || dx === 6 || dy === 0 || dy === 6 ||
       (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
  };

  const rects = [];
  for (let y = 0; y < modules; y++) {
    for (let x = 0; x < modules; x++) {
      let on;
      if (isFinder(x, y)) {
        on = inFinderRing(x, y, 0, 0)
          || inFinderRing(x, y, modules - 7, 0)
          || inFinderRing(x, y, 0, modules - 7);
      } else {
        on = rng() > 0.5;
      }
      if (on) rects.push(`<rect x="${x*cell}" y="${y*cell}" width="${cell}" height="${cell}"/>`);
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}"
            viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" fill="#0b0f1a">
            <rect width="${size}" height="${size}" fill="#fff"/>${rects.join('')}</svg>`;
}

/* ---------------- Wire up DOM ---------------- */

document.addEventListener('DOMContentLoaded', () => {
  showLogin();

  // -------- Demo-mode auto-login + banner --------
  if (DEMO_MODE) {
    const envBadge = document.getElementById('envBadge');
    if (envBadge) envBadge.textContent = 'DEMO';
    // Auto-fill creds and pretend MFA succeeded so we land in the app.
    setTimeout(async () => {
      try {
        applyTokens(demoIssueTokens('demo@securebank.local', true));
        state.user.roles = ['customer', 'admin']; // unlock Security Console
        enterApp();
        toast('Demo mode — backend mocked in-browser', 'ok', 4000);
      } catch (e) { console.error(e); }
    }, 300);
  }


  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('#loginError').hidden = true;
    try {
      await login($('#loginEmail').value.trim(), $('#loginPassword').value);
    } catch (err) {
      $('#loginError').textContent = err.message || 'Invalid credentials';
      $('#loginError').hidden = false;
      pushRecent('auth.login.failed', 'bad', {}, err.message);
    }
  });

  $('#mfaForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('#mfaError').hidden = true;
    try {
      await mfaVerify($('#mfaCode').value);
    } catch (err) {
      $('#mfaError').textContent = err.message || 'Invalid code';
      $('#mfaError').hidden = false;
    }
  });

  $('#btnBackLogin').addEventListener('click', () => {
    sessionStorage.removeItem('preauth');
    $('#mfaForm').hidden = true;
    $('#loginForm').hidden = false;
  });

  $('#togglePw').addEventListener('click', () => {
    const inp = $('#loginPassword');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  $('#registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await register($('#regEmail').value, $('#regPassword').value, $('#regPhone').value);
    } catch (err) {
      toast('Registration failed: ' + err.message, 'error');
    }
  });

  $('#btnLogout').addEventListener('click', () => logout(true));

  $('#transferForm').addEventListener('submit', doTransfer);

  $('#btnNewAccount').addEventListener('click', async () => {
    try {
      const ccy = ($('#newAccountCcy')?.value) || 'PKR';
      await api('POST', '/accounts', { currency: ccy });
      toast(`${ccy} account opened`);
      pushRecent('account.create', 'ok', {}, `New ${ccy} account opened`);
      await loadAccounts();
      await refreshAll();
    } catch (e) { toast('Failed: ' + e.message, 'error'); }
  });

  $('#btnRefreshAccounts')?.addEventListener('click', async () => {
    await loadAccounts(); toast('Accounts refreshed', 'ok', 1500);
  });

  $('#btnEnrollMFA').addEventListener('click', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const qrSvg  = renderFakeQR(`otpauth://totp/SecureBank:${state.user.email}?secret=${secret}&issuer=SecureBank`);
    const w = window.open('', '_blank', 'width=420,height=520');
    if (!w) { toast('Pop-up blocked — please allow pop-ups', 'warn'); return; }
    w.document.write(`
      <!doctype html><html><head><meta charset="utf-8"><title>Enroll MFA</title>
      <style>body{font-family:system-ui;background:#0b0f1a;color:#e7edf7;text-align:center;padding:2rem}
      .qr{display:inline-block;padding:1rem;background:#fff;border-radius:12px}
      code{background:#131a2b;padding:.25rem .5rem;border-radius:6px;color:#00d4aa}
      </style></head><body>
      <h2 style="color:#00d4aa">Scan with your authenticator</h2>
      <div class="qr">${qrSvg}</div>
      <p>or manually enter this secret:</p>
      <p><code>${secret}</code></p>
      <p style="color:#8a99b8;font-size:.9em">After scanning, close this window and use the next 6-digit code to sign in.</p>
      </body></html>`);
    pushRecent('mfa.enroll.started', 'ok');
    toast('MFA enrollment started — scan the QR', 'ok');
  });

  // Red/Blue drill buttons
  document.body.addEventListener('click', (e) => {
    const atk = e.target.closest('[data-attack]');
    if (atk) { ATTACKS[atk.dataset.attack]?.(); return; }
    const soar = e.target.closest('[data-soar]');
    if (soar) { runSoar(soar.dataset.soar); return; }
    const qa = e.target.closest('[data-quick-amt]');
    if (qa) {
      const inp = $('#transferAmt');
      if (inp) inp.value = qa.dataset.quickAmt;
      return;
    }
  });

  $('#btnClearOffenses')?.addEventListener('click', () => {
    state.offenses = []; renderOffenses();
    toast('Offenses cleared', 'ok', 1500);
  });
  $('#btnClearLog')?.addEventListener('click', () => {
    const el = $('#attackLog'); if (el) el.textContent = '';
  });

  // Session-age tick (every 15s) + Security Console live tick (every 5s).
  setInterval(() => { if (state.access) loadTrust(); }, 15_000);
  setInterval(() => {
    if (state.access && location.hash === '#/security') loadSecurityConsole();
  }, 5_000);
});
