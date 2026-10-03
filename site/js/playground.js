// Config playground. The YAML object is the source of truth: blocks write into it, the editor shows it (and can edit
// it), and makit's own config check — Go compiled to WebAssembly, with the bundled catalog — checks every version.
// Nothing is sent anywhere: the only network requests load this page, js-yaml and the WebAssembly file.

// The WebAssembly is built by scripts/playground.sh and published on the repository's "playground" branch.
const WASM_BASE = /^(localhost|127\.)/.test(location.hostname)
  ? 'playground/'
  : 'https://cdn.jsdelivr.net/gh/material-atomic/makit@playground/';

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, '');
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  kids.flat().forEach((c) => n.append(c instanceof Node ? c : document.createTextNode(c)));
  return n;
};

let cfg = {};
let catalog = null;
let ready = false;

// ── presets ──
const PRESETS = {
  'Single site': {
    mode: 'observe', ask: true,
    trusted_proxies: ['cloudflare'], client_ip_header: 'CF-Connecting-IP',
    report: { every: '5m', min_level: 'high' },
  },
  'Many domains': {
    mode: 'observe', ask: true,
    trusted_proxies: ['cloudflare'], client_ip_header: 'CF-Connecting-IP',
    ban_scope: 'server',
    sites: [
      { name: 'shop', match: ['shop.example.com'], mode: 'block' },
      { name: 'blog', match: ['blog.example.com', '*.blog.example.com'], scoring: { profiles: { wordpress: true } } },
    ],
  },
  'Behind Cloudflare': {
    mode: 'block', ask: true,
    trusted_proxies: ['cloudflare'], client_ip_header: 'CF-Connecting-IP',
    bots: { policy: { 'ai-crawler': 'block' } },
  },
  'Behind a load balancer (Kubernetes)': {
    mode: 'observe', ask: true, admin: '0.0.0.0:9180',
    client_ip_header: 'X-Forwarded-For', trusted_proxies: ['aws-alb'],
    cluster: { listen: ':9181', peers: ['dns:makit-shield-headless.makit.svc.cluster.local:9181'], sync: '250ms' },
  },
  'makit in front (edge)': {
    mode: 'observe', ask: false, edge: true,
    trusted_proxies: ['cloudflare'], client_ip_header: 'CF-Connecting-IP',
    listeners: [{ name: 'web', listen: ':443', upstream: 'http://127.0.0.1:8080', tls: { acme: ['example.com'] } }],
  },
};

// ── YAML <-> object ──
const dump = (o) => (Object.keys(o).length ? jsyaml.dump(o, { lineWidth: 120, noRefs: true, flowLevel: -1 }) : '');
function setCfg(next, from) {
  cfg = prune(next);
  if (from !== 'editor') $('#yaml').value = dump(cfg);
  if (from !== 'blocks') renderBlocks();
  scheduleCheck();
}
// Empty strings, lists and maps are left out, so the YAML only says what the person chose.
function prune(o) {
  if (Array.isArray(o)) return o.map(prune).filter((v) => v !== undefined);
  if (o && typeof o === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(o)) {
      const p = prune(v);
      const empty = p === undefined || p === '' || (Array.isArray(p) && !p.length) || (p && typeof p === 'object' && !Array.isArray(p) && !Object.keys(p).length);
      if (!empty) out[k] = p;
    }
    return out;
  }
  return o;
}
const get = (path, dflt) => path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), cfg) ?? dflt;
function set(path, value) {
  const keys = path.split('.');
  const next = structuredClone(cfg);
  let o = next;
  keys.slice(0, -1).forEach((k) => { if (!o[k] || typeof o[k] !== 'object') o[k] = {}; o = o[k]; });
  o[keys.at(-1)] = value;
  setCfg(next, 'blocks');
}
const lines = (s) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

// ── blocks ──
function field(label, input) { return el('label', {}, label, input); }
function select(path, options, dflt, onchange) {
  const s = el('select', { onchange: (e) => (onchange ? onchange(e.target.value) : set(path, e.target.value || undefined)) });
  options.forEach((o) => { const [v, t] = Array.isArray(o) ? o : [o, o]; s.append(el('option', { value: v }, t)); });
  s.value = get(path, dflt) ?? '';
  return s;
}
function check(path, text, dflt) {
  const c = el('input', { type: 'checkbox', onchange: (e) => set(path, e.target.checked) });
  c.checked = get(path, dflt);
  return el('label', { class: 'check' }, c, text);
}
function text(path, attrs = {}, toValue = (v) => v || undefined, fromValue = (v) => v ?? '') {
  const i = el('input', { ...attrs, onchange: (e) => set(path, toValue(e.target.value)) });
  i.value = fromValue(get(path));
  return i;
}
function list(path, placeholder) {
  const t = el('textarea', { class: 'mono', rows: 3, placeholder, onchange: (e) => set(path, lines(e.target.value)) });
  t.value = (get(path, []) || []).join('\n');
  return t;
}
function block(id, title, what, ...body) {
  const d = el('details', { class: 'block', 'data-id': id }, el('summary', {}, title, el('span', { class: 'what' }, what)), el('div', { class: 'body' }, body));
  d.open = openBlocks.has(id);
  d.addEventListener('toggle', () => (d.open ? openBlocks.add(id) : openBlocks.delete(id)));
  return d;
}
const openBlocks = new Set(['basics']);

const ACTIONS = ['', 'allow', 'log', 'block', 'ban 1h', 'ban 24h', 'limit 10/1m', 'limit 60/1m'];

function renderBlocks() {
  const root = $('#blocks');
  root.replaceChildren();
  const tp = get('trusted_proxies', ['cloudflare']) || [];
  const presets = ['cloudflare', 'aws-alb', 'vpc', 'loopback'];
  const togglePreset = (p, on) => set('trusted_proxies', on ? [...new Set([...tp, p])] : tp.filter((x) => x !== p));
  const cidrs = tp.filter((x) => !presets.includes(x));

  root.append(
    block('basics', 'Mode and switches', `${get('mode', 'observe')}${get('edge') ? ' · edge' : ''}`,
      el('div', { class: 'row' },
        field('Mode', select('mode', [['observe', 'observe — log what would be blocked'], ['block', 'block'], ['pass', 'pass — check nothing']], 'observe')),
        check('ask', 'ask: Caddy, nginx or a gateway asks makit', true),
        check('edge', 'edge: makit in front (listeners)', false)),
      el('p', { class: 'note' }, 'Start with observe: makit shield log --blocked shows what block would stop.')),
    block('proxies', 'Behind a proxy', tp.join(', ') || 'none',
      el('div', { class: 'row' }, presets.map((p) => {
        const c = el('input', { type: 'checkbox', onchange: (e) => togglePreset(p, e.target.checked) });
        c.checked = tp.includes(p);
        return el('label', { class: 'check' }, c, p);
      })),
      el('div', { class: 'row' },
        field('Client IP header', select('client_ip_header', ['CF-Connecting-IP', 'X-Forwarded-For'], 'CF-Connecting-IP')),
        field('More trusted ranges (CIDR, one per line)', (() => {
          const t = el('textarea', { class: 'mono', rows: 2, placeholder: '10.0.1.0/24', onchange: (e) => set('trusted_proxies', [...tp.filter((x) => presets.includes(x)), ...lines(e.target.value)]) });
          t.value = cidrs.join('\n');
          return t;
        })())),
      el('p', { class: 'note' }, 'X-Forwarded-For is read from the right: trusted proxies are skipped, so a visitor cannot pick its own IP. Anything trusted may name its client — narrow vpc/aws-alb to your load balancer subnets when you can.')),
    block('allow', 'Allowlist', `${(get('allow', []) || []).length} entries`,
      field('Never blocked: your office, monitoring, CI (IP or CIDR per line)', list('allow', '203.0.113.10\n198.51.100.0/24'))),
    botsBlock(),
    scoringBlock(),
    sitesBlock(),
    block('report', 'Reports', `every ${get('report.every', '5m')}`,
      el('div', { class: 'row' },
        field('Every', select('report.every', ['5m', '1m', '15m', '1h', 'off'], '5m')),
        field('Send when the batch reaches', select('report.min_level', ['high', 'medium', 'low', 'critical'], 'high'))),
      el('p', { class: 'note' }, 'Reports go through makit notify — build notify.yaml in the other tab.')),
    clusterBlock(),
    wafBlock(),
    listenersBlock(),
  );
}

function botsBlock() {
  if (!catalog || !catalog.bot_categories) return block('bots', 'Bots and AI agents', 'loading the catalog…');
  const cats = Object.entries(catalog.bot_categories).sort(([a], [b]) => a.localeCompare(b));
  const pol = get('bots.policy', {}) || {};
  const setPol = (k, v) => { const p = { ...pol }; if (v) p[k] = v; else delete p[k]; set('bots.policy', p); };
  const row = (key, label, dflt) => {
    const s = el('select', { onchange: (e) => setPol(key, e.target.value) });
    const opts = [...new Set([...ACTIONS, pol[key] || ''])];
    opts.forEach((a) => s.append(el('option', { value: a }, a ? a : `default (${dflt})`)));
    s.value = pol[key] || '';
    return el('label', {}, `${key} — ${label}`, s);
  };
  const changed = Object.keys(pol).length;
  return block('bots', 'Bots and AI agents', changed ? `${changed} policies` : 'catalog defaults',
    el('div', { class: 'cats' }, cats.map(([k, c]) => row(k, c.label, c.action)), row('spoofed', 'pretends to be a verifiable bot', catalog.spoofed || 'block')),
    el('p', { class: 'note' }, 'limit N/window is per IP (429 when over). Verified search engines and assistants pass; fake ones are caught by IP ranges or reverse DNS. Per bot: makit shield bots set <id> …'));
}

function scoringBlock() {
  const sc = catalog && catalog.score_http;
  if (!sc) return block('scoring', 'Request scoring', 'loading the catalog…');
  const acts = get('scoring.actions', {}) || {};
  const profs = get('scoring.profiles', {}) || {};
  return block('scoring', 'Request scoring', Object.keys(acts).length ? 'custom actions' : 'catalog defaults',
    el('div', { class: 'row' }, (sc.profiles || []).map((p) => {
      const c = el('input', { type: 'checkbox', onchange: (e) => set('scoring.profiles', { ...profs, [p]: e.target.checked || undefined }) });
      c.checked = !!profs[p];
      return el('label', { class: 'check' }, c, `profile: ${p}`);
    })),
    el('div', { class: 'cats' }, (sc.levels || []).map((l) => {
      const s = el('select', { onchange: (e) => { const a = { ...acts }; if (e.target.value) a[l] = e.target.value; else delete a[l]; set('scoring.actions', a); } });
      [...new Set([...ACTIONS, acts[l] || ''])].forEach((a) => s.append(el('option', { value: a }, a || `default (${sc.actions[l]})`)));
      s.value = acts[l] || '';
      return el('label', {}, `${l} (score ≥ ${sc.thresholds[l]})`, s);
    })),
    el('p', { class: 'note' }, `Probes, XSS, SQL injection, Log4Shell, command injection, raw requests and floods — ${(sc.signals || []).length} signals in the catalog.`));
}

function sitesBlock() {
  const sites = get('sites', []) || [];
  const upd = (i, k, v) => { const s = structuredClone(sites); if (v === undefined || v === '') delete s[i][k]; else s[i][k] = v; set('sites', s); };
  return block('sites', 'Sites (many domains)', `${sites.length} sites`,
    sites.map((s, i) => el('div', { class: 'item' },
      el('div', { class: 'row' },
        field('Name', (() => { const x = el('input', { value: s.name || '', onchange: (e) => upd(i, 'name', e.target.value) }); return x; })()),
        field('Hosts (one per line, *.example.com for subdomains)', (() => { const t = el('textarea', { class: 'mono', rows: 2, onchange: (e) => upd(i, 'match', lines(e.target.value)) }); t.value = (s.match || []).join('\n'); return t; })())),
      el('div', { class: 'row' },
        field('Mode', (() => { const x = el('select', { onchange: (e) => upd(i, 'mode', e.target.value || undefined) }, ['', 'observe', 'block', 'pass'].map((m) => el('option', { value: m }, m || 'global'))); x.value = s.mode || ''; return x; })()),
        field('Bans', (() => { const x = el('select', { onchange: (e) => upd(i, 'ban_scope', e.target.value || undefined) }, [['', 'global'], ['server', 'every site'], ['site', 'this site only']].map(([v, t]) => el('option', { value: v }, t))); x.value = s.ban_scope || ''; return x; })())),
      el('button', { class: 'btn small rm', onclick: () => set('sites', sites.filter((_, j) => j !== i)) }, 'Remove site'))),
    el('button', { class: 'btn small', onclick: () => set('sites', [...sites, { name: `site${sites.length + 1}`, match: [`site${sites.length + 1}.example.com`] }]) }, '+ Add site'),
    el('p', { class: 'note' }, 'Each site overrides the global settings above where it sets something.'));
}

function clusterBlock() {
  const on = !!get('cluster');
  return block('cluster', 'Replicas (Kubernetes)', on ? 'sharing bans, limits, scores' : 'off',
    el('label', { class: 'check' }, (() => {
      const c = el('input', { type: 'checkbox', onchange: (e) => set('cluster', e.target.checked ? { listen: ':9181', peers: ['dns:makit-shield-headless.makit.svc.cluster.local:9181'], sync: '250ms' } : undefined) });
      c.checked = on; return c;
    })(), 'Replicas share bans, allow entries, rate limits and scores'),
    on ? el('div', { class: 'row' },
      field('Listen', text('cluster.listen', { class: 'mono', placeholder: ':9181' })),
      field('Peers (host:port or dns:NAME:PORT)', list('cluster.peers', 'dns:makit-shield-headless.makit.svc.cluster.local:9181')),
      field('Sync', select('cluster.sync', ['250ms', '100ms', '500ms', '1s'], '250ms'))) : '',
    el('p', { class: 'note' }, 'The Helm chart fills this in for you. The shared secret comes from MAKIT_CLUSTER_SECRET — never from this file.'));
}

function wafBlock() {
  const on = !!get('aws_waf');
  return block('waf', 'Push bans to AWS WAF', on ? get('aws_waf.scope', 'REGIONAL') : 'off',
    el('label', { class: 'check' }, (() => {
      const c = el('input', { type: 'checkbox', onchange: (e) => set('aws_waf', e.target.checked ? { region: 'us-east-1', scope: 'REGIONAL', ipv4: { name: 'makit-bans-v4', id: '<ip set id>' } } : undefined) });
      c.checked = on; return c;
    })(), 'Keep an AWS WAF IP set equal to the live bans'),
    on ? el('div', { class: 'row' },
      field('Region', text('aws_waf.region', { class: 'mono' })),
      field('Scope', select('aws_waf.scope', ['REGIONAL', 'CLOUDFRONT'], 'REGIONAL')),
      field('IPv4 IP set name', text('aws_waf.ipv4.name', { class: 'mono' })),
      field('IPv4 IP set id', text('aws_waf.ipv4.id', { class: 'mono' })),
      field('IPv6 IP set name', text('aws_waf.ipv6.name', { class: 'mono' })),
      field('IPv6 IP set id', text('aws_waf.ipv6.id', { class: 'mono' }))) : '',
    el('p', { class: 'note' }, 'Needs wafv2:GetIPSet and wafv2:UpdateIPSet on those IP sets. Allowlisted and trusted ranges are never pushed.'));
}

function listenersBlock() {
  const ls = get('listeners', []) || [];
  const upd = (i, path, v) => {
    const next = structuredClone(ls);
    const keys = path.split('.');
    let o = next[i];
    keys.slice(0, -1).forEach((k) => { o[k] = o[k] || {}; o = o[k]; });
    if (v === undefined || v === '' || v === false || (Array.isArray(v) && !v.length)) delete o[keys.at(-1)]; else o[keys.at(-1)] = v;
    set('listeners', next);
  };
  return block('listeners', 'Edge listeners (makit in front)', `${ls.length} listeners`,
    ls.map((l, i) => el('div', { class: 'item' },
      el('div', { class: 'row' },
        field('Name', el('input', { value: l.name || '', onchange: (e) => upd(i, 'name', e.target.value) })),
        field('Listen', el('input', { class: 'mono', value: l.listen || '', onchange: (e) => upd(i, 'listen', e.target.value) })),
        field('Upstream', el('input', { class: 'mono', value: l.upstream || '', onchange: (e) => upd(i, 'upstream', e.target.value) }))),
      el('div', { class: 'row' },
        field('Automatic certificates for (one per line)', (() => { const t = el('textarea', { class: 'mono', rows: 2, onchange: (e) => upd(i, 'tls.acme', lines(e.target.value)) }); t.value = ((l.tls || {}).acme || []).join('\n'); return t; })()),
        (() => { const c = el('input', { type: 'checkbox', onchange: (e) => upd(i, 'accept_proxy_protocol', e.target.checked) }); c.checked = !!l.accept_proxy_protocol; return el('label', { class: 'check' }, c, 'PROXY protocol from a trusted load balancer (NLB)'); })()),
      el('button', { class: 'btn small rm', onclick: () => set('listeners', ls.filter((_, j) => j !== i)) }, 'Remove listener'))),
    el('button', { class: 'btn small', onclick: () => set('listeners', [...ls, { name: `web${ls.length || ''}`, listen: ':443', upstream: 'http://127.0.0.1:8080' }]) }, '+ Add listener'));
}

// ── the check ──
let timer = null;
function scheduleCheck() { clearTimeout(timer); timer = setTimeout(runCheck, 150); }
function runCheck() {
  if (!ready) return;
  const src = $('#yaml').value;
  let res;
  // A config for replicas runs in pods: listening on every address is right there.
  try { res = JSON.parse(globalThis.makitCheck(src, { kubernetes: !!cfg.cluster })); } catch (e) { res = { valid: false, issues: [{ level: 'error', message: String(e) }] }; }
  res.issues = res.issues || [];
  const errs = res.issues.filter((i) => i.level === 'error').length;
  const warns = res.issues.length - errs;
  const st = $('#status');
  st.className = 'status ' + (errs ? 'err' : warns ? 'warn' : 'ok');
  $('#status-text').textContent = errs
    ? `${errs} error${errs > 1 ? 's' : ''}${warns ? `, ${warns} warning${warns > 1 ? 's' : ''}` : ''} — makit would refuse this file`
    : warns ? `Valid, with ${warns} warning${warns > 1 ? 's' : ''}` : `Valid — makit ${res.version} would load it`;
  $('#issues').replaceChildren(...res.issues.map((i) => el('li', { class: i.level, title: 'Go to the line', onclick: () => goLine(i.line) },
    i.line ? el('span', { class: 'ln' }, `line ${i.line}`) : '', i.message)));
}
function goLine(n) {
  if (!n) return;
  const ta = $('#yaml');
  const start = ta.value.split('\n').slice(0, n - 1).join('\n').length + (n > 1 ? 1 : 0);
  const end = ta.value.indexOf('\n', start);
  ta.focus();
  ta.setSelectionRange(start, end < 0 ? ta.value.length : end);
  ta.scrollTop = Math.max(0, (n - 4) * 20);
}

$('#yaml').addEventListener('input', () => {
  scheduleCheck();
  try {
    const o = jsyaml.load($('#yaml').value);
    if (o && typeof o === 'object' && !Array.isArray(o)) { cfg = o; renderBlocks(); }
  } catch (e) { /* the check reports the syntax error with its line */ }
});

// ── exports (built in the page; downloads are blobs, nothing is uploaded) ──
function download(name, body) {
  const a = el('a', { href: URL.createObjectURL(new Blob([body], { type: 'text/yaml' })), download: name });
  document.body.append(a); a.click(); a.remove();
}
const indent = (s, n) => s.split('\n').map((l) => (l ? ' '.repeat(n) + l : l)).join('\n');
document.querySelector('#tab-shield .export').addEventListener('click', (e) => {
  const kind = e.target.dataset.export;
  if (!kind) return;
  const y = $('#yaml').value;
  if (kind === 'file') download('shield.yaml', y);
  if (kind === 'configmap') download('makit-shield-config.yaml', `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: makit-shield\n  namespace: makit\ndata:\n  shield.yaml: |\n${indent(y, 4)}`);
  if (kind === 'helm') {
    const c = structuredClone(cfg); delete c.cluster; // the chart fills cluster: in
    download('values.yaml', `# helm upgrade --install shield deploy/helm/makit-shield -n makit -f values.yaml\nconfig:\n${indent(dump(c), 2)}`);
  }
  if (kind === 'copy') copyText(y, e.target);
});

// ── notify.yaml ──
const CHANNELS = {
  telegram: [['token', 'Bot token', '<telegram bot token>', true], ['chat_id', 'Chat id', '<chat id>']],
  slack: [['url', 'Webhook URL', '<slack webhook url>', true]],
  googlechat: [['url', 'Webhook URL', '<google chat webhook url>', true]],
  discord: [['url', 'Webhook URL', '<discord webhook url>', true]],
  teams: [['url', 'Webhook URL', '<teams workflow url>', true]],
  ntfy: [['url', 'Topic URL', 'https://ntfy.sh/<topic>'], ['token', 'Access token (optional)', '', true]],
  webhook: [['url', 'URL', 'https://example.com/hook', true]],
  email: [['smtp', 'SMTP host:port', 'smtp.example.com:587'], ['from', 'From', 'makit@example.com'], ['to', 'To (comma-separated)', 'ops@example.com'],
    ['username', 'Username', ''], ['password', 'Password', '<smtp password>', true]],
};
let channels = [];
const ct = $('#ch-type');
Object.keys(CHANNELS).forEach((t) => ct.append(el('option', { value: t }, t)));
function renderChFields() {
  $('#ch-fields').replaceChildren(...CHANNELS[ct.value].map(([k, label, ph, secret]) =>
    field(label + (secret ? ' — secret' : ''), el('input', { class: 'mono', 'data-k': k, placeholder: ph, type: secret ? 'password' : 'text', autocomplete: 'off' }))));
}
ct.addEventListener('change', renderChFields);
$('#ch-add').addEventListener('click', () => {
  const ch = { name: $('#ch-name').value.trim() || ct.value, type: ct.value, min_level: $('#ch-level').value };
  CHANNELS[ct.value].forEach(([k, , ph]) => {
    const v = $(`#ch-fields [data-k="${k}"]`).value.trim() || ph;
    if (v) ch[k] = k === 'to' ? v.split(',').map((x) => x.trim()) : v;
  });
  channels = channels.filter((c) => c.name !== ch.name).concat(ch);
  renderChannels();
});
function renderChannels() {
  $('#channels').replaceChildren(...channels.map((c) => el('div', { class: 'item' },
    el('div', {}, el('b', {}, c.name), ` · ${c.type} · from ${c.min_level}`),
    el('button', { class: 'btn small rm', onclick: () => { channels = channels.filter((x) => x !== c); renderChannels(); } }, 'Remove'))));
  $('#notify-yaml').value = channels.length ? jsyaml.dump({ channels }, { lineWidth: 120 }) : '# add a channel on the left\n';
}
document.querySelector('#tab-notify .export').addEventListener('click', (e) => {
  const kind = e.target.dataset.nexport;
  if (!kind) return;
  const y = $('#notify-yaml').value;
  if (kind === 'file') download('notify.yaml', y);
  if (kind === 'secret') download('makit-notify-secret.yaml', `# kubectl apply -n makit -f makit-notify-secret.yaml; then notify.existingSecret: makit-notify\napiVersion: v1\nkind: Secret\nmetadata:\n  name: makit-notify\n  namespace: makit\nstringData:\n  notify.yaml: |\n${indent(y, 4)}`);
  if (kind === 'copy') copyText(y, e.target);
});

// ── tabs and presets ──
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('on', x === t));
  $('#tab-shield').hidden = t.dataset.tab !== 'shield';
  $('#tab-notify').hidden = t.dataset.tab !== 'notify';
}));
Object.keys(PRESETS).forEach((name, i) => {
  $('#presets').append(el('button', { class: 'preset' + (i ? '' : ' on'), onclick: (e) => {
    document.querySelectorAll('.preset').forEach((p) => p.classList.toggle('on', p === e.target));
    setCfg(structuredClone(PRESETS[name]));
  } }, name));
});

// ── start: the page works at once; the check and the catalog arrive with the WebAssembly ──
setCfg(structuredClone(PRESETS['Single site']));
renderChFields();
renderChannels();
(async () => {
  try {
    await new Promise((ok, fail) => { const s = el('script', { src: WASM_BASE + 'wasm_exec.js' }); s.onload = ok; s.onerror = fail; document.head.append(s); });
    const go = new Go();
    const res = await fetch(WASM_BASE + 'makit-check.wasm');
    if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
    const { instance } = await WebAssembly.instantiate(await res.arrayBuffer(), go.importObject);
    go.run(instance);
    catalog = JSON.parse(globalThis.makitCatalog());
    ready = true;
    renderBlocks();
    runCheck();
  } catch (e) {
    $('#status').className = 'status err';
    $('#status-text').textContent = `Could not load makit's config check (${e.message}). The YAML still builds; check it on the server with makit shield config check.`;
  }
})();
