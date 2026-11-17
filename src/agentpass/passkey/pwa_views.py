"""PWA app views: History and Devices tabs, push subscription, offline-queue retry.

Appended to the approval page's script and styles (``assets.APP_JS``/``APP_CSS``). Same rules
as the rest of the page: DOM built with ``h()`` and ``textContent``, never markup parsed from
data. Everything is fetched through the session-gated API.

The History formatting (dates, labels, grouping) lives in ``static/history-logic.mjs``, which
node:test loads directly; it is read here with its ``export`` keywords dropped.
"""

from __future__ import annotations

import re
from pathlib import Path

HISTORY_LOGIC_PATH = Path(__file__).parent / "static" / "history-logic.mjs"
HISTORY_LOGIC_JS = re.sub(
    r"^export ", "", HISTORY_LOGIC_PATH.read_text(encoding="utf-8"), flags=re.MULTILINE
)

VIEWS_CSS = r"""
/* History and Devices */
.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:var(--s3);
  margin-bottom:var(--s5);align-items:end}
.tools label{display:flex;flex-direction:column;gap:var(--s1);font-size:var(--fs-sm);
  color:var(--muted);min-width:0}
.tools .input{font-family:var(--font);min-height:44px;width:100%;min-width:0}
.tools .btn{min-height:44px}
.hist-day{margin-bottom:var(--s5)}
.hist-day-title{font-size:var(--fs-sm);font-weight:600;color:var(--muted);
  margin-bottom:var(--s2)}
.hist-list{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  box-shadow:var(--shadow-1)}
.hist-item{display:flex;flex-direction:column;gap:var(--s2);padding:var(--s3) var(--s4);
  min-width:0}
.hist-item+.hist-item{border-top:1px solid var(--border)}
.hist-top{display:flex;align-items:center;justify-content:space-between;gap:var(--s3)}
.hist-badge{font-size:var(--fs-sm);font-weight:700;border-radius:var(--r-pill);
  padding:.1rem .7rem;border:1px solid var(--border-strong);background:var(--surface-2);
  color:var(--text)}
.hist-badge.yes{background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok-text)}
.hist-badge.no{background:var(--danger-bg);border-color:var(--danger-border);
  color:var(--danger-text)}
.hist-badge.refused{background:var(--warn-bg);border-color:var(--warn-border);
  color:var(--warn-text)}
.hist-time{font-size:var(--fs-sm);color:var(--muted);font-variant-numeric:tabular-nums;
  white-space:nowrap}
.hist-call{font-family:var(--mono);font-size:var(--fs-sm);color:var(--muted);
  overflow-wrap:anywhere}
.hist-call strong{color:var(--text)}
.hist-meta{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s4);font-size:var(--fs-sm)}
.hist-key{color:var(--muted);margin-right:var(--s2)}
.hist-note{font-size:var(--fs-sm);color:var(--muted)}
.hist-note.no{color:var(--danger-text)}
.pager{display:flex;gap:var(--s3);align-items:center;justify-content:center;
  margin-top:var(--s4);color:var(--muted);font-size:var(--fs-sm);text-align:center}
.stale{color:var(--warn-text);font-size:var(--fs-sm);margin-bottom:var(--s2)}
.device{display:flex;flex-direction:column;gap:var(--s3);margin-bottom:var(--s3)}
.device-head{display:flex;gap:var(--s3);align-items:center;justify-content:space-between;
  flex-wrap:wrap}
.device-name{font-weight:700;font-size:var(--fs-lg)}
.device-meta{color:var(--muted);font-size:var(--fs-sm)}
.device-actions{display:flex;gap:var(--s2);flex-wrap:wrap}
.device-edit{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:center}
.device-edit .input{font-family:var(--font);flex:1 1 12rem}
.switch{display:flex;gap:var(--s3);align-items:flex-start}
.switch input{width:1.5rem;height:1.5rem;margin-top:.15rem;accent-color:var(--primary);flex:none}
.switch label{font-weight:600}
.switch .hint{display:block;font-weight:400;color:var(--muted);font-size:var(--fs-sm)}
.views-status{margin-bottom:var(--s3)}
"""

VIEWS_JS = (
    "\n/* ---- History formatting (static/history-logic.mjs) ---- */\n"
    + HISTORY_LOGIC_JS
    + r"""
/* ---- History and Devices tabs, push subscription, offline-queue retry ---- */
async function send(method, path, body) {
  const r = await fetch(path, {method, credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF': csrf},
    body: body === undefined ? undefined : JSON.stringify(body)});
  if (!r.ok) {
    const err = new Error(path + ': ' + r.status);
    err.status = r.status;
    err.detail = (await r.text()).slice(0, 200);
    throw err;
  }
  return r.json();
}

let viewsNeedSignIn = false;
/* Show a view failure in its panel. 401 returns to sign-in, a dead network to the banner. */
function viewError(box, e, what) {
  if (e && e.status === 401) {
    viewsNeedSignIn = true;
    signInPanel(true);
    box.replaceChildren(h('p', {cls: 'device-meta', text: 'Sign in to see ' + what + '.'}));
    return;
  }
  if (e && e.name === 'TypeError') { offline(true); return; }
  const f = failure(e);
  box.replaceChildren(h('div', {cls: 'panel panel-danger'}, icon('alert'),
    h('div', null, h('div', {cls: 'panel-title', text: f.title}), h('div', {text: f.text}))));
  paintIcons(box);
}
function viewsSignedIn() {  // the 5 s poll saw a live session again
  if (!viewsNeedSignIn) return;
  viewsNeedSignIn = false;
  for (const name of ['history', 'devices']) {
    if (!document.getElementById('panel-' + name).hidden) onTabShown(name);
  }
}

/* ---- History ---- */
const hv = {page: 1, agent: '', tool: '', decision: '', from: '', to: '', data: null, built: false};

function buildHistory() {
  const panel = document.getElementById('panel-history');
  const field = (label, input) => h('label', null, h('span', {text: label}), input);
  const agent = h('input', {cls: 'input', type: 'search', autocomplete: 'off', name: 'agent'});
  const tool = h('input', {cls: 'input', type: 'search', autocomplete: 'off', name: 'tool'});
  const decision = h('select', {cls: 'input', name: 'decision'},
    h('option', {value: '', text: 'Any'}), h('option', {value: 'ask', text: 'Asked'}),
    h('option', {value: 'allow', text: 'Allowed'}), h('option', {value: 'deny', text: 'Denied'}));
  const from = h('input', {cls: 'input', type: 'date', name: 'from'});
  const to = h('input', {cls: 'input', type: 'date', name: 'to'});
  const apply = h('button', {cls: 'btn btn-primary', type: 'submit'}, h('span', {text: 'Filter'}));
  const form = h('div', {cls: 'tools', role: 'search'}, field('Agent', agent), field('Tool', tool),
    field('Decision', decision), field('From', from), field('To', to), apply);
  const run = () => {
    hv.agent = agent.value.trim(); hv.tool = tool.value.trim();
    hv.decision = decision.value; hv.from = from.value; hv.to = to.value; hv.page = 1; loadHistory();
  };
  apply.addEventListener('click', run);
  for (const el of [agent, tool]) {
    el.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') run(); });
  }
  for (const el of [decision, from, to]) el.addEventListener('change', run);
  panel.replaceChildren(h('h2', {cls: 'page-title', text: 'History'}), form,
    h('div', {id: 'history-body', 'aria-live': 'polite'}));
  hv.built = true;
}

async function loadHistory() {
  if (!hv.built) buildHistory();
  const box = document.getElementById('history-body');
  const q = new URLSearchParams({page: String(hv.page), per_page: '50'});
  if (hv.agent) q.set('agent_id', hv.agent);
  if (hv.tool) q.set('tool_name', hv.tool);
  if (hv.decision) q.set('decision', hv.decision);
  if (hv.from) q.set('from', hv.from);
  if (hv.to) q.set('to', hv.to + 'T23:59:59');  // the whole last day
  try {
    hv.data = await api('/api/history?' + q);
  } catch (e) {
    viewError(box, e, 'the history');
    if (e && e.name === 'TypeError') {
      if (hv.data) drawHistory(box, true);  // keep the last view
      else box.replaceChildren(h('p', {cls: 'device-meta', text: 'No history loaded yet.'}));
    }
    return;
  }
  offline(false);
  drawHistory(box, false);
}

function historyItem({entry: e, date}) {
  const dec = decisionLabel(e);
  const call = splitCall(e);
  const by = resolvedByLabel(e.resolved_by);
  const note = resultNote(e);
  const pair = (key, value) => h('span', null, h('span', {cls: 'hist-key', text: key}), value);
  const meta = h('div', {cls: 'hist-meta'}, e.agent_id ? pair('Agent', e.agent_id) : null,
    by ? pair('Resolved by', by) : null);
  const time = date ? h('time', {cls: 'hist-time', datetime: date.toISOString(),
    title: date.toLocaleString(),
    text: date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}) : null;
  return h('li', {cls: 'hist-item'},
    h('div', {cls: 'hist-top'}, h('span', {cls: 'hist-badge ' + dec.tone, text: dec.text}), time),
    call.name || call.args ? h('div', {cls: 'hist-call'},
      call.name ? h('strong', {text: call.name}) : null, call.args || null) : null,
    meta.childElementCount ? meta : null,
    note ? h('div', {cls: 'hist-note ' + note.tone, text: note.text}) : null);
}

function drawHistory(box, stale) {
  const d = hv.data;
  const nodes = [];
  if (stale) nodes.push(h('p', {cls: 'stale', role: 'status',
    text: 'Showing the last loaded history. It will refresh when the gateway is reachable.'}));
  if (!d.entries.length) {
    nodes.push(h('div', {cls: 'card empty'}, icon('clock'), h('h2', {text: 'Nothing here'}),
      h('p', {text: hv.agent || hv.tool || hv.decision || hv.from || hv.to
        ? 'No entries match these filters.' : 'Past approvals will be listed here.'})));
    box.replaceChildren(...nodes);
    paintIcons(box);
    return;
  }
  for (const g of groupByDay(d.entries, new Date())) {
    nodes.push(h('section', {cls: 'hist-day'}, h('h3', {cls: 'hist-day-title', text: g.label}),
      h('ul', {cls: 'hist-list'}, ...g.items.map(historyItem))));
  }
  const prev = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Newer'}));
  const next = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Older'}));
  prev.disabled = d.page <= 1;
  next.disabled = d.page >= d.pages;
  prev.addEventListener('click', () => { hv.page = d.page - 1; loadHistory(); });
  next.addEventListener('click', () => { hv.page = d.page + 1; loadHistory(); });
  nodes.push(h('div', {cls: 'pager'}, prev,
    h('span', {text: 'Page ' + d.page + ' of ' + d.pages + ' (' + d.total + ' entries)'}), next));
  box.replaceChildren(...nodes);
}

/* ---- Devices ---- */
const DEVICE_KEY = 'agentpass.device';
function myDevice() { try { return localStorage.getItem(DEVICE_KEY) || ''; } catch (e) { return ''; } }
function rememberDevice(id) {
  try { if (id) localStorage.setItem(DEVICE_KEY, id); else localStorage.removeItem(DEVICE_KEY); }
  catch (e) { /* private mode: "this device" is just not marked */ }
}
function devStatus(tone, title, text) {
  const box = document.getElementById('devices-status');
  if (!box) return;
  if (!title) { box.replaceChildren(); return; }
  box.replaceChildren(h('div', {cls: 'panel panel-' + tone}, icon(tone === 'ok' ? 'check-circle' : 'alert'),
    h('div', null, h('div', {cls: 'panel-title', text: title}), h('div', {text: text}))));
  paintIcons(box);
}
function pushSupported() {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

async function enableNotifications(btn) {
  devStatus('', '');
  if (!pushSupported()) {
    devStatus('danger', 'Notifications not available', 'This browser cannot receive push notifications here.');
    return;
  }
  btn.disabled = true;
  try {
    if ((await Notification.requestPermission()) !== 'granted') {
      devStatus('danger', 'Notifications blocked',
        'Allow notifications for this site in the browser settings, then try again.');
      return;
    }
    const key = b64d((await api('/api/push/vapid')).public_key);
    const reg = await navigator.serviceWorker.ready;
    const subscribe = () => reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: key});
    let sub;
    try { sub = await subscribe(); } catch (e) {
      if (!e || e.name !== 'InvalidStateError') throw e;
      const old = await reg.pushManager.getSubscription();  // made with another key
      if (old) await old.unsubscribe();
      sub = await subscribe();
    }
    const j = sub.toJSON();
    const out = await api('/api/push/subscribe', {subscription: {endpoint: j.endpoint, keys: j.keys}});
    rememberDevice(out.device_id);
    devStatus('ok', 'Notifications enabled', 'This device will get a notification for each request.');
    await loadDevices(true);
  } catch (e) {
    if (e && e.status === 401) { viewError(document.getElementById('devices-body'), e, 'devices'); return; }
    const f = failure(e);
    devStatus('danger', e && e.status === 404 ? 'Push is not set up' : f.title,
      e && e.status === 404 ? 'The gateway has no push channel enabled.' : f.text);
  } finally {
    btn.disabled = false;
  }
}

function deviceCard(d, mine) {
  const name = h('div', {cls: 'device-name', text: d.label});
  const meta = h('div', {cls: 'device-meta', text: (mine ? 'This device. ' : '')
    + 'Last seen ' + stamp(d.last_seen) + (d.push_host ? ' via ' + d.push_host : '')});
  const card = h('div', {cls: 'card device'});
  const head = h('div', {cls: 'device-head'}, h('div', null, name, meta));
  const actions = h('div', {cls: 'device-actions'});
  const rename = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Rename'}));
  const remove = h('button', {cls: 'btn btn-deny', type: 'button'}, h('span', {text: 'Remove'}));
  actions.append(rename, remove);
  head.append(actions);

  rename.addEventListener('click', () => {
    const input = h('input', {cls: 'input', type: 'text', maxlength: '60', value: d.label,
      'aria-label': 'Device name'});
    const save = h('button', {cls: 'btn btn-primary', type: 'button'}, h('span', {text: 'Save'}));
    const cancel = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Cancel'}));
    const edit = h('div', {cls: 'device-edit'}, input, save, cancel);
    const done = async () => {
      const label = input.value.trim();
      if (!label) return;
      save.disabled = true;
      try { await send('PATCH', '/api/push/devices/' + encodeURIComponent(d.device_id), {label});
        await loadDevices(true);
      } catch (e) { save.disabled = false; devError(e); }
    };
    save.addEventListener('click', done);
    input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') done(); });
    cancel.addEventListener('click', () => edit.replaceWith(head));
    head.replaceWith(edit);
    input.focus();
  });

  let armed = false;
  remove.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      remove.querySelector('span').textContent = 'Confirm remove';
      setTimeout(() => { armed = false; remove.querySelector('span').textContent = 'Remove'; }, 4000);
      return;
    }
    remove.disabled = true;
    try {
      await send('DELETE', '/api/push/devices/' + encodeURIComponent(d.device_id));
      if (mine) {
        rememberDevice('');
        try {
          const reg = await navigator.serviceWorker.ready;
          const sub = await reg.pushManager.getSubscription();
          if (sub) await sub.unsubscribe();
        } catch (e) { /* the server forgot it; the browser copy is harmless */ }
      }
      await loadDevices(true);
    } catch (e) { remove.disabled = false; devError(e); }
  });

  const id = 'onetap-' + d.device_id;
  const toggle = h('input', {type: 'checkbox', id, role: 'switch',
    'aria-describedby': id + '-hint'});
  toggle.checked = !!d.one_tap_approve;
  toggle.addEventListener('change', async () => {
    const want = toggle.checked;
    toggle.disabled = true;
    devStatus('', '');
    const base = '/api/push/devices/' + encodeURIComponent(d.device_id);
    try {
      if (want) {
        const credential = await assertWith(await api(base + '/one-tap/options', {}));
        await api(base + '/one-tap', {enabled: true, credential});
      } else {
        await api(base + '/one-tap', {enabled: false});
      }
    } catch (e) {
      toggle.checked = !want;
      devError(e);
    } finally {
      toggle.disabled = false;
    }
  });
  const sw = h('div', {cls: 'switch'}, toggle, h('label', {for: id},
    document.createTextNode('One-tap approve'),
    h('span', {cls: 'hint', id: id + '-hint',
      text: "Approve from the notification without a fingerprint, for requests that don't require a passkey."})));
  card.append(head, sw);
  return card;
}
function devError(e) {
  if (e && e.status === 401) { viewError(document.getElementById('devices-body'), e, 'devices'); return; }
  if (e && e.name === 'TypeError') { offline(true); return; }
  const f = failure(e);
  devStatus('danger', f.title, f.text);
}

let devices = {data: null, built: false};
function buildDevices() {
  const panel = document.getElementById('panel-devices');
  panel.replaceChildren(h('h2', {cls: 'page-title', text: 'Devices'}),
    h('div', {id: 'devices-status', cls: 'views-status', role: 'status'}),
    h('div', {id: 'devices-body', 'aria-live': 'polite'}));
  devices.built = true;
}
async function loadDevices(quiet) {
  if (!devices.built) buildDevices();
  const box = document.getElementById('devices-body');
  if (!quiet) devStatus('', '');
  let data;
  try {
    data = await api('/api/push/devices');
  } catch (e) {
    if (e && e.status === 404) {
      box.replaceChildren(h('div', {cls: 'card empty'}, icon('info'), h('h2', {text: 'Push is not set up'}),
        h('p', {text: 'The gateway has no push channel enabled.'})));
      paintIcons(box);
      return;
    }
    viewError(box, e, 'devices');
    return;
  }
  offline(false);
  devices.data = data;
  const mine = myDevice();
  const nodes = [];
  const have = data.devices.some((d) => d.device_id === mine);
  if (!have) {
    const enable = h('button', {cls: 'btn btn-primary', type: 'button'}, icon('user'),
      h('span', {text: 'Enable notifications on this device'}));
    enable.addEventListener('click', () => enableNotifications(enable));
    nodes.push(h('div', {cls: 'card device'}, h('div', {cls: 'device-meta',
      text: 'Get a notification with Deny and Approve buttons when an agent asks for something.'}), enable));
  }
  if (!data.devices.length) {
    nodes.push(h('div', {cls: 'card empty'}, icon('shield-check'), h('h2', {text: 'No devices yet'}),
      h('p', {text: 'Devices that receive notifications will be listed here.'})));
  }
  for (const d of data.devices) nodes.push(deviceCard(d, d.device_id === mine));
  box.replaceChildren(...nodes);
  paintIcons(box);
}

function onTabShown(name) {
  if (name === 'history') loadHistory();
  else if (name === 'devices') loadDevices();
}

/* ---- queued notification actions: ask the worker to retry when the app opens or reconnects ---- */
function retryQueued() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.ready.then((reg) => {
    if (reg.active) reg.active.postMessage({type: 'retry-actions'});
  }).catch(() => {});
}
window.addEventListener('online', () => { retryQueued(); load(); });
retryQueued();
"""
)
