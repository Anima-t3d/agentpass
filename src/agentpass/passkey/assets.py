"""Static page assets. Scripts and styles are served as files so the CSP can stay strict."""

INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentpass approvals</title><link rel="stylesheet" href="/static/app.css"></head>
<body><h1>Pending approvals</h1><p id="status"></p><div id="list"></div>
<script src="/static/app.js"></script></body></html>
"""

ENROLL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentpass passkey enrolment</title><link rel="stylesheet" href="/static/app.css"></head>
<body><h1>Enrol a passkey</h1><p id="status"></p>
<button id="enroll">Register this device</button>
<script src="/static/app.js"></script></body></html>
"""

APP_CSS = """
body{font:16px system-ui,sans-serif;margin:1rem auto;max-width:42rem;padding:0 1rem}
.req{border:1px solid #888;border-radius:8px;padding:.75rem;margin:.75rem 0}
.risk-high{border-color:#c00}.risk-medium{border-color:#c80}
pre{white-space:pre-wrap;word-break:break-all;background:#8881;padding:.5rem}
button{font:inherit;padding:.5rem 1rem;margin-right:.5rem}
"""

APP_JS = """
'use strict';
const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')
  .padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const status = document.getElementById('status');
let csrf = '';

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF': csrf},
    body: JSON.stringify(body)});
  if (!r.ok) throw new Error(path + ': ' + r.status + ' ' + (await r.text()));
  return r.json();
}
async function session() { csrf = (await api('/api/session')).csrf; }

async function sign(id) {
  const opts = await api('/api/approvals/' + id + '/challenge', {});
  opts.challenge = b64d(opts.challenge);
  opts.allowCredentials = (opts.allowCredentials || []).map((c) => ({...c, id: b64d(c.id)}));
  const c = await navigator.credentials.get({publicKey: opts});
  return {id: c.id, rawId: b64e(c.rawId), type: c.type, response: {
    clientDataJSON: b64e(c.response.clientDataJSON),
    authenticatorData: b64e(c.response.authenticatorData),
    signature: b64e(c.response.signature),
    userHandle: c.response.userHandle ? b64e(c.response.userHandle) : null},
    clientExtensionResults: c.getClientExtensionResults()};
}

async function decide(id, approve) {
  try {
    if (approve) await api('/api/approvals/' + id + '/approve', {credential: await sign(id)});
    else await api('/api/approvals/' + id + '/deny', {});
    status.textContent = approve ? 'Approved.' : 'Denied.';
  } catch (e) { status.textContent = String(e); }
  load();
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

async function load() {
  const list = document.getElementById('list');
  const data = await api('/api/pending');
  list.replaceChildren();
  if (!data.enrolled) list.append(el('p', 'No passkey enrolled: run `agentpass passkey enroll`.'));
  for (const p of data.pending) {
    const box = el('div', undefined, 'req risk-' + p.risk);
    box.append(el('strong', p.agent + ' wants ' + p.tool),
      el('div', 'risk: ' + p.risk + ' - expires ' + p.expires_at),
      el('pre', JSON.stringify(p.args, null, 2)));
    const ok = el('button', 'Approve'), no = el('button', 'Deny');
    ok.onclick = () => decide(p.approval_id, true);
    no.onclick = () => decide(p.approval_id, false);
    box.append(ok, no);
    list.append(box);
  }
  if (!data.pending.length) list.append(el('p', 'Nothing pending.'));
}

async function enroll() {
  const token = new URLSearchParams(location.search).get('token');
  try {
    const opts = await api('/api/enroll/options', {token});
    opts.challenge = b64d(opts.challenge);
    opts.user.id = b64d(opts.user.id);
    opts.excludeCredentials = (opts.excludeCredentials || []).map((c) => ({...c, id: b64d(c.id)}));
    const c = await navigator.credentials.create({publicKey: opts});
    await api('/api/enroll/verify', {token, label: navigator.platform, credential: {
      id: c.id, rawId: b64e(c.rawId), type: c.type, response: {
        clientDataJSON: b64e(c.response.clientDataJSON),
        attestationObject: b64e(c.response.attestationObject),
        transports: c.response.getTransports ? c.response.getTransports() : []},
      clientExtensionResults: c.getClientExtensionResults()}});
    status.textContent = 'Passkey enrolled. You can close this page.';
  } catch (e) { status.textContent = String(e); }
}

session().then(() => {
  const btn = document.getElementById('enroll');
  if (btn) btn.onclick = enroll; else { load(); setInterval(load, 5000); }
});
"""
