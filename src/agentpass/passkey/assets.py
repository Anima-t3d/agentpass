"""Static page assets. Scripts and styles are served as files so the CSP can stay strict.

No external resources: system fonts, icons drawn as inline SVG by app.js, no images. The
script builds every node with ``textContent`` and ``setAttribute`` only, so nothing the
agent or a device wrote can become markup. The CSP forbids inline styles, so styling is
by class only.
"""

_HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>%(title)s</title><link rel="stylesheet" href="/static/app.css"></head>
"""

_BRAND = """<header class="topbar"><div class="topbar-in">
<span class="brand"><span class="brand-icon" data-icon="shield-check"></span>agentpass</span>
%(extra)s</div></header>
"""

INDEX_HTML = (
    _HEAD % {"title": "agentpass approvals"}
    + """<body class="page-approvals">
"""
    + _BRAND
    % {
        "extra": '<span class="count" id="count" hidden></span>',
    }
    + """<main class="wrap" id="main">
<h1 class="page-title">Approvals</h1>
<div id="banner" role="alert"></div>
<div id="results" role="status" aria-live="polite"></div>
<div id="list" aria-live="off" aria-busy="true">
<div class="card skeleton" aria-hidden="true"><div class="sk sk-title"></div>
<div class="sk sk-line"></div><div class="sk sk-line short"></div><div class="sk sk-box"></div></div>
<p class="sr-only">Loading pending approvals</p>
</div>
<noscript><p class="panel panel-warn">This page needs JavaScript to show and sign approvals.</p>
</noscript>
</main>
<script src="/static/app.js"></script></body></html>
"""
)

ENROLL_HTML = (
    _HEAD % {"title": "agentpass passkey enrolment"}
    + """<body class="page-enroll">
"""
    + _BRAND % {"extra": ""}
    + """<main class="wrap narrow" id="main">
<h1 class="page-title">Register a passkey</h1>
<section class="card enroll" aria-labelledby="enroll-h">
<h2 id="enroll-h" class="card-title">Use this device to approve requests</h2>
<p class="lead">Your agents ask here before they act. A passkey on this device lets only you
approve. Nothing is shared with the agent.</p>
<ol class="steps">
<li>Tap <strong>Register this device</strong>.</li>
<li>Confirm with your fingerprint, face or screen lock.</li>
</ol>
<button id="enroll" class="btn btn-primary btn-block" type="button">
<span class="btn-icon" data-icon="key"></span><span class="btn-label">Register this device</span>
</button>
<div id="enroll-status" class="status" role="status" aria-live="polite"></div>
</section>
<noscript><p class="panel panel-warn">This page needs JavaScript to register a passkey.</p>
</noscript>
</main>
<script src="/static/app.js"></script></body></html>
"""
)

APP_CSS = r"""
:root{
  color-scheme:light dark;
  --font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --fs-sm:.875rem;--fs-md:1rem;--fs-lg:1.125rem;--fs-xl:1.375rem;--fs-2xl:1.625rem;
  --s1:.25rem;--s2:.5rem;--s3:.75rem;--s4:1rem;--s5:1.5rem;--s6:2rem;--s7:3rem;
  --r-sm:6px;--r-md:12px;--r-lg:16px;--r-pill:999px;
  --bg:#f2f5f9;--surface:#fff;--surface-2:#f5f7fa;--border:#d5dce7;--border-strong:#8d9bb0;
  --text:#142033;--muted:#475569;
  --primary:#1d4ed8;--primary-hover:#1a41b5;--on-primary:#fff;--focus:#1d4ed8;
  --danger:#b42318;--danger-bg:#fdeceb;--danger-border:#e9a8a2;--danger-text:#9b1c13;
  --warn-bg:#fff3d4;--warn-border:#e2b350;--warn-text:#744000;
  --ok-bg:#e5f6ec;--ok-border:#86cba1;--ok-text:#0a5a2b;
  --info-bg:#e7effd;--info-border:#a7c0f2;--info-text:#173f9c;
  --note-bg:#f3efff;--note-border:#8f7bdc;--note-text:#2d205e;--note-label:#573bb5;
  --add-bg:#e2f5e9;--add-text:#0a5a2b;--del-bg:#fde8e6;--del-text:#9b1c13;
  --shadow-1:0 1px 2px rgba(20,32,51,.08),0 1px 3px rgba(20,32,51,.06);
  --shadow-2:0 4px 12px rgba(20,32,51,.10),0 1px 3px rgba(20,32,51,.08);
  --bar-shadow:0 -6px 16px rgba(20,32,51,.08);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0b1017;--surface:#141c27;--surface-2:#1a2432;--border:#2a3748;--border-strong:#64768d;
    --text:#e8eef6;--muted:#a6b5c8;
    --primary:#7aa7ff;--primary-hover:#9dbfff;--on-primary:#08142e;--focus:#9dbfff;
    --danger:#ff9a90;--danger-bg:#2b1517;--danger-border:#7d3530;--danger-text:#ffaba3;
    --warn-bg:#2b2110;--warn-border:#7d5c1c;--warn-text:#f6c96f;
    --ok-bg:#0f2a1b;--ok-border:#2b6b47;--ok-text:#7fe3ab;
    --info-bg:#13233f;--info-border:#32528a;--info-text:#adc7ff;
    --note-bg:#1d1836;--note-border:#6c5bab;--note-text:#e5ddff;--note-label:#cbbcff;
    --add-bg:#0f2a1b;--add-text:#8be8b3;--del-bg:#2b1517;--del-text:#ffaba3;
    --shadow-1:0 1px 2px rgba(0,0,0,.5);
    --shadow-2:0 6px 16px rgba(0,0,0,.5);
    --bar-shadow:0 -6px 16px rgba(0,0,0,.45);
  }
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;overflow-wrap:anywhere}
body{margin:0;background:var(--bg);color:var(--text);font:400 var(--fs-md)/1.5 var(--font);
  min-height:100vh;padding-bottom:env(safe-area-inset-bottom)}
h1,h2,h3,h4,p,ul,ol,dl,dd,pre,blockquote,figure{margin:0}
ul,ol{padding:0;list-style:none}
:focus{outline:none}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px;border-radius:var(--r-sm)}
.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;
  clip:rect(0,0,0,0);white-space:nowrap;border:0}
[hidden]{display:none!important}
.icon{width:1.25em;height:1.25em;flex:none;vertical-align:-.25em}

.topbar{background:var(--surface);border-bottom:1px solid var(--border);
  padding-top:env(safe-area-inset-top)}
.topbar-in{max-width:40rem;margin:0 auto;padding:var(--s3) var(--s4);display:flex;
  align-items:center;justify-content:space-between;gap:var(--s3)}
.brand{display:inline-flex;align-items:center;gap:var(--s2);font-weight:700;
  letter-spacing:.01em}
.brand-icon{color:var(--primary);display:inline-flex}
.brand-icon .icon{width:1.5rem;height:1.5rem}
.count{background:var(--primary);color:var(--on-primary);font-size:var(--fs-sm);font-weight:700;
  border-radius:var(--r-pill);padding:.1rem .65rem;min-width:1.75rem;text-align:center}

.wrap{max-width:40rem;margin:0 auto;padding:var(--s5) var(--s4) var(--s7);min-width:0}
.wrap.narrow{max-width:32rem}
.page-title{font-size:var(--fs-2xl);line-height:1.2;margin-bottom:var(--s4);letter-spacing:-.01em}
.lead{color:var(--muted);margin-bottom:var(--s4)}

.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
  box-shadow:var(--shadow-1);padding:var(--s4);margin-bottom:var(--s4);min-width:0}
.card-title{font-size:var(--fs-lg);margin-bottom:var(--s3)}

/* request card */
.req{border-left-width:6px;box-shadow:var(--shadow-2)}
.req.risk-high{border-left-color:var(--danger)}
.req.risk-medium{border-left-color:var(--warn-border)}
.req.risk-low{border-left-color:var(--ok-border)}
.req.risk-unknown{border-left-color:var(--border-strong)}
.req-head{display:flex;flex-direction:column;gap:var(--s3);margin-bottom:var(--s4)}
.req-top{display:flex;align-items:flex-start;justify-content:space-between;gap:var(--s3);
  flex-wrap:wrap}
.req-tool{font-size:var(--fs-xl);line-height:1.25;font-family:var(--mono);font-weight:700;
  min-width:0;flex:1 1 12rem}
.meta{display:flex;flex-wrap:wrap;gap:var(--s2)}
.chip{display:inline-flex;align-items:center;gap:var(--s2);font-size:var(--fs-sm);
  background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-pill);
  padding:.2rem .7rem;color:var(--text);max-width:100%}
.chip.soon{background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn-text);
  font-weight:600}
.chip.passkey{background:var(--info-bg);border-color:var(--info-border);color:var(--info-text);
  font-weight:600}
.badge{display:inline-flex;align-items:center;gap:var(--s2);font-size:var(--fs-sm);
  font-weight:700;border-radius:var(--r-pill);padding:.25rem .8rem;border:1px solid}
.badge.risk-low{background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok-text)}
.badge.risk-medium{background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn-text)}
.badge.risk-high{background:var(--danger-bg);border-color:var(--danger-border);
  color:var(--danger-text)}
.badge.risk-unknown{background:var(--surface-2);border-color:var(--border-strong);
  color:var(--text)}

/* preview */
.preview-title{font-size:var(--fs-lg);line-height:1.3;margin-bottom:var(--s3)}
.warnings{display:flex;flex-direction:column;gap:var(--s2);margin-bottom:var(--s3)}
.warning{display:flex;gap:var(--s3);align-items:flex-start;background:var(--danger-bg);
  border:1px solid var(--danger-border);color:var(--danger-text);border-radius:var(--r-md);
  padding:var(--s3) var(--s4);font-weight:600}
.warning .icon{margin-top:.15rem}
.sec{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);
  padding:var(--s3) var(--s4);margin-bottom:var(--s3);min-width:0}
.sec-label{font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin-bottom:var(--s2);font-weight:700}
.kv{display:grid;grid-template-columns:minmax(6rem,max-content) minmax(0,1fr);
  gap:var(--s2) var(--s4)}
.kv dt{color:var(--muted);font-size:var(--fs-sm);padding-top:.1rem}
.kv dd{min-width:0;font-weight:500}
@media (max-width:30rem){.kv{grid-template-columns:minmax(0,1fr);gap:0}
  .kv dd{margin-bottom:var(--s2)}}
.text,.diff,.args{font:400 var(--fs-sm)/1.5 var(--mono);white-space:pre-wrap;
  overflow-wrap:anywhere;max-height:22rem;overflow:auto;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--r-sm);padding:var(--s3)}
.diff .l{display:block}
.diff .add{background:var(--add-bg);color:var(--add-text)}
.diff .del{background:var(--del-bg);color:var(--del-text)}
.diff .hunk{color:var(--muted);font-style:italic}
.items li{padding:var(--s1) 0;border-bottom:1px solid var(--border)}
.items li:last-child{border-bottom:0}
.table-scroll{overflow-x:auto;max-width:100%}
.table-scroll table{border-collapse:collapse;font-size:var(--fs-sm);min-width:100%}
.table-scroll td{border:1px solid var(--border);padding:var(--s1) var(--s2);vertical-align:top}
.foot{color:var(--muted);font-size:var(--fs-sm);margin-bottom:var(--s3)}
.foot ul{margin-top:var(--s1)}
.foot li{display:flex;gap:var(--s2);align-items:baseline}
.panel{display:flex;gap:var(--s3);align-items:flex-start;border:1px solid;
  border-radius:var(--r-md);padding:var(--s3) var(--s4);margin-bottom:var(--s3)}
.panel .icon{margin-top:.15rem}
.panel-title{font-weight:700}
.panel-warn{background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn-text)}
.panel-info{background:var(--info-bg);border-color:var(--info-border);color:var(--info-text)}
.panel-danger{background:var(--danger-bg);border-color:var(--danger-border);
  color:var(--danger-text)}
.panel-ok{background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok-text)}

/* the agent's own words: fenced off, clearly not the gateway's */
.note{background:var(--note-bg);border:2px dashed var(--note-border);color:var(--note-text);
  border-radius:var(--r-md);padding:var(--s3) var(--s4);margin:var(--s4) 0}
.note-label{display:flex;gap:var(--s2);align-items:center;color:var(--note-label);
  font-size:var(--fs-sm);font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.note-sub{font-size:var(--fs-sm);margin:var(--s1) 0 var(--s2);opacity:.9}
.note-body{font-style:italic;white-space:pre-wrap;overflow-wrap:anywhere;
  border-left:3px solid var(--note-border);padding-left:var(--s3)}

details.raw{border:1px solid var(--border);border-radius:var(--r-md);margin-bottom:var(--s4);
  background:var(--surface)}
details.raw>summary{cursor:pointer;padding:var(--s3) var(--s4);font-weight:600;list-style:none;
  display:flex;align-items:center;gap:var(--s2);min-height:44px}
details.raw>summary::-webkit-details-marker{display:none}
details.raw>summary .icon{transition:transform .15s}
details.raw[open]>summary .icon{transform:rotate(180deg)}
details.raw>.args{margin:0 var(--s3) var(--s3)}

/* typed confirmation */
.confirm{margin-bottom:var(--s4);padding:var(--s3) var(--s4);border:1px solid var(--danger-border);
  background:var(--danger-bg);border-radius:var(--r-md)}
.confirm label{display:block;font-weight:600;margin-bottom:var(--s2);color:var(--danger-text)}
.confirm code{font-family:var(--mono);background:var(--surface);color:var(--text);
  padding:.05rem .4rem;border-radius:var(--r-sm);border:1px solid var(--border);
  overflow-wrap:anywhere}
.input{width:100%;font:400 var(--fs-md) var(--mono);min-height:48px;padding:var(--s2) var(--s3);
  color:var(--text);background:var(--surface);border:2px solid var(--border-strong);
  border-radius:var(--r-md)}
.input[aria-invalid="true"]{border-color:var(--danger)}
.input.valid{border-color:var(--ok-text)}
.hint{display:flex;gap:var(--s2);align-items:center;font-size:var(--fs-sm);
  margin-top:var(--s2);min-height:1.5rem;color:var(--muted)}
.hint.bad{color:var(--danger-text);font-weight:600}
.hint.good{color:var(--ok-text);font-weight:600}

/* actions */
.actionbar{position:sticky;bottom:0;display:flex;gap:var(--s3);
  margin:var(--s4) calc(-1*var(--s4)) calc(-1*var(--s4));
  padding:var(--s3) var(--s4) calc(var(--s3) + env(safe-area-inset-bottom));
  background:var(--surface);border-top:1px solid var(--border);box-shadow:var(--bar-shadow);
  border-radius:0 0 var(--r-lg) var(--r-lg);z-index:2}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--s2);
  min-height:48px;padding:var(--s2) var(--s5);border-radius:var(--r-md);cursor:pointer;
  font:600 var(--fs-md) var(--font);border:2px solid transparent;flex:1 1 0;white-space:nowrap;
  transition:background-color .12s,border-color .12s}
.btn-block{width:100%;flex:none}
.btn-primary{background:var(--primary);color:var(--on-primary);flex:1 1 auto}
.btn-primary:hover{background:var(--primary-hover)}
.btn-deny{background:var(--surface);color:var(--danger-text);border-color:var(--danger-border);
  flex:0 0 auto;padding:var(--s2) var(--s4)}
.btn-deny:hover{background:var(--danger-bg);border-color:var(--danger)}
.btn-quiet{background:var(--surface-2);color:var(--text);border-color:var(--border-strong);
  flex:none;min-height:44px;padding:var(--s2) var(--s4)}
.btn:disabled{cursor:not-allowed;background:var(--surface-2);color:var(--muted);
  border-color:var(--border)}
.spinner{width:1.1em;height:1.1em;border:3px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:spin .8s linear infinite;flex:none}
@keyframes spin{to{transform:rotate(360deg)}}
.inline-status{min-height:0}
.inline-status:not(:empty){margin-top:var(--s4)}
.req[aria-busy="true"] .sec,.req[aria-busy="true"] .warnings{opacity:.8}
.req.expired{opacity:.85}
.req.expired .actionbar{display:none}

/* results and states */
.result{display:flex;gap:var(--s3);align-items:flex-start;border-left-width:6px}
.result .icon{width:1.75rem;height:1.75rem;margin-top:.1rem}
.result-main{flex:1;min-width:0}
.result-title{font-weight:700;font-size:var(--fs-lg)}
.result.ok{border-left-color:var(--ok-text)}.result.ok .icon{color:var(--ok-text)}
.result.deny{border-left-color:var(--danger)}.result.deny .icon{color:var(--danger-text)}
.result.expired,.result.info{border-left-color:var(--border-strong)}
.result.expired .icon,.result.info .icon{color:var(--muted)}
.result .btn-quiet{min-height:44px}
.empty{text-align:center;padding:var(--s7) var(--s4);color:var(--muted)}
.empty .icon{width:3rem;height:3rem;color:var(--ok-text);margin-bottom:var(--s3)}
.empty h2{color:var(--text);font-size:var(--fs-xl);margin-bottom:var(--s2)}
.skeleton{box-shadow:none}
.sk{background:var(--surface-2);border-radius:var(--r-sm);margin-bottom:var(--s3);
  animation:pulse 1.4s ease-in-out infinite}
.sk-title{height:1.75rem;width:60%}.sk-line{height:1rem}.sk-line.short{width:45%}
.sk-box{height:5rem}
@keyframes pulse{50%{opacity:.5}}
#banner:not(:empty){margin-bottom:var(--s4)}
.enroll .steps{list-style:decimal;padding-left:1.4rem;margin-bottom:var(--s5);color:var(--muted)}
.enroll .steps li{padding:var(--s1) 0}
.enroll .status:not(:empty){margin-top:var(--s4)}
.btn-icon{display:inline-flex}

@media (min-width:40rem){
  .wrap{padding-top:var(--s6)}
  .actionbar{position:static;box-shadow:none;border-top:1px solid var(--border);
    margin-top:var(--s5)}
  .btn{flex:none;min-width:10rem}
  .actionbar{justify-content:flex-end}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important;
    scroll-behavior:auto!important}
  .spinner{border-right-color:currentColor;border-style:dotted}
}
"""

APP_JS = r"""
'use strict';
const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')
  .padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
let csrf = '';

/* ---- DOM helpers: text only. Nothing here ever parses markup. ---- */
const SVGNS = 'http://www.w3.org/2000/svg';
const ICONS = {
  'shield-check': 'M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z M9 12l2 2 4-4',
  'check-circle': 'M12 21a9 9 0 100-18 9 9 0 000 18z M8.5 12.5l2.5 2.5 4.5-5',
  'x-circle': 'M12 21a9 9 0 100-18 9 9 0 000 18z M9 9l6 6 M15 9l-6 6',
  'alert': 'M12 4L3 20h18L12 4z M12 10v4 M12 17v.01',
  'octagon': 'M8 3h8l5 5v8l-5 5H8l-5-5V8z M12 8v5 M12 16v.01',
  'info': 'M12 21a9 9 0 100-18 9 9 0 000 18z M12 11v5 M12 8v.01',
  'lock': 'M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 017 0v3',
  'key': 'M14 10a4 4 0 11-2.2 3.6L4 21v-3h2v-2h2l3-3 M16.5 8.5v.01',
  'clock': 'M12 21a9 9 0 100-18 9 9 0 000 18z M12 7v5l3 2',
  'bot': 'M7 8h10a3 3 0 013 3v5a3 3 0 01-3 3H7a3 3 0 01-3-3v-5a3 3 0 013-3z M12 4v4 M9 13v.01 M15 13v.01',
  'chevron': 'M6 9l6 6 6-6',
  'user': 'M12 12a4 4 0 100-8 4 4 0 000 8z M5 20a7 7 0 0114 0',
};
function icon(name) {
  const svg = document.createElementNS(SVGNS, 'svg');
  for (const [k, v] of Object.entries({viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round',
    'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false', class: 'icon'})) {
    svg.setAttribute(k, v);
  }
  const path = document.createElementNS(SVGNS, 'path');
  path.setAttribute('d', ICONS[name] || ICONS.info);
  svg.append(path);
  return svg;
}
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'text') e.textContent = v;
    else if (k === 'cls') e.className = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) e.append(kid);
  return e;
}
function paintIcons(root) {
  for (const slot of root.querySelectorAll('[data-icon]')) {
    if (!slot.firstChild) slot.append(icon(slot.dataset.icon));
  }
}

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {credentials: 'same-origin'} : {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF': csrf},
    body: JSON.stringify(body)});
  if (!r.ok) {
    const err = new Error(path + ': ' + r.status);
    err.status = r.status;
    err.detail = (await r.text()).slice(0, 200);
    throw err;
  }
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

/* ---- wording for every failure the operator can meet ---- */
function failure(e) {
  if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
    return {kind: 'cancelled', title: 'Passkey prompt cancelled',
      text: 'Nothing was approved. Tap Approve to try again, or Deny.'};
  }
  if (e && e.name === 'TypeError') {
    return {kind: 'network', title: 'Network error',
      text: 'Could not reach the gateway. Check your connection and try again.'};
  }
  if (e && e.status === 409) {
    return {kind: 'resolved', title: 'Already resolved',
      text: 'This request was answered elsewhere, or is no longer waiting.'};
  }
  if (e && (e.status === 404 || e.status === 410)) {
    return {kind: 'expired', title: 'Expired',
      text: 'This request is no longer pending. The agent was told no.'};
  }
  if (e && e.status === 429) {
    return {kind: 'failed', title: 'Too many failed attempts',
      text: 'Wait a few minutes before trying again.'};
  }
  if (e && e.status === 403) {
    return {kind: 'failed', title: 'Passkey not accepted',
      text: 'The gateway rejected the signature. Nothing was approved.'};
  }
  if (!window.PublicKeyCredential) {
    return {kind: 'failed', title: 'Passkeys not available',
      text: 'This browser cannot use passkeys on this page.'};
  }
  return {kind: 'failed', title: 'Passkey failed',
    text: 'Something went wrong (' + ((e && (e.name || e.status)) || 'error') + '). Nothing was approved.'};
}

/* ---- small formatters ---- */
function clock(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}
function ago(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 5) return 'just now';
  if (s < 90) return s + ' s ago';
  return Math.round(s / 60) + ' min ago';
}

/* ---- preview drawing ---- */
function drawSection(sec) {
  const box = h('section', {cls: 'sec', 'aria-label': sec.label},
    h('h4', {cls: 'sec-label', text: sec.label}));
  const data = sec.data;
  if (sec.kind === 'kv') {
    const dl = h('dl', {cls: 'kv'});
    for (const [k, v] of data) dl.append(h('dt', {text: k}), h('dd', {text: v}));
    box.append(dl);
  } else if (sec.kind === 'diff') {
    const pre = h('pre', {cls: 'diff', tabindex: '0', 'aria-label': sec.label});
    for (const line of String(data).split('\n')) {
      const kind = line.startsWith('@@') ? 'hunk' : line.startsWith('+') ? 'add'
        : line.startsWith('-') ? 'del' : '';
      pre.append(h('span', {cls: 'l ' + kind, text: line || ' '}));
    }
    box.append(pre);
  } else if (sec.kind === 'list') {
    const ul = h('ul', {cls: 'items'});
    for (const item of data) ul.append(h('li', {text: item}));
    box.append(ul);
  } else if (sec.kind === 'table') {
    const body = h('tbody');
    for (const row of data) {
      const tr = h('tr');
      for (const cell of row) tr.append(h('td', {text: cell}));
      body.append(tr);
    }
    box.append(h('div', {cls: 'table-scroll', tabindex: '0', role: 'region',
      'aria-label': sec.label}, h('table', null, body)));
  } else {
    box.append(h('pre', {cls: 'text', tabindex: '0', text: String(data)}));
  }
  return box;
}

function drawPreview(p, card) {
  const wrap = h('div', {cls: 'preview'});
  const pv = p.preview;
  if (!pv) return {node: null, rawOpen: true};
  if (pv.unavailable !== undefined) {
    wrap.append(h('div', {cls: 'panel panel-warn', role: 'note'}, icon('alert'),
      h('div', null, h('div', {cls: 'panel-title', text: 'Preview unavailable'}),
        h('div', {text: '(' + pv.unavailable + ') Check the raw arguments below before approving.'}))));
    return {node: wrap, rawOpen: true};
  }
  wrap.append(h('h3', {cls: 'preview-title', text: pv.title}));
  if (pv.warnings.length) {
    const ul = h('ul', {cls: 'warnings', 'aria-label': 'Warnings'});
    for (const w of pv.warnings) ul.append(h('li', {cls: 'warning'}, icon('alert'), h('span', {text: w})));
    wrap.append(ul);
  }
  for (const sec of pv.sections) wrap.append(drawSection(sec));
  const foot = h('div', {cls: 'foot'});
  const age = h('span', {text: 'Built ' + ago(pv.built_at)});
  age.dataset.built = pv.built_at;
  foot.append(age, document.createTextNode('. Lookups are a snapshot and are not part of what you sign.'));
  if (pv.lookups.length) {
    const ul = h('ul');
    for (const n of pv.lookups) {
      const raw = (n.raw_times || []).length ? ' · raw ' + n.raw_times.join(', ') : '';
      ul.append(h('li', null, icon(n.status === 'ok' ? 'check-circle' : 'x-circle'),
        h('span', {text: n.id + ': ' + (n.status === 'ok' ? 'ok' : 'failed' + (n.detail ? ' (' + n.detail + ')' : '')) + raw})));
    }
    foot.append(ul);
  }
  wrap.append(foot);
  return {node: wrap, rawOpen: false, confirm: pv.confirm_text || null};
}

function drawNote(text) {
  const id = 'note-' + Math.random().toString(36).slice(2);
  return h('section', {cls: 'note', 'aria-labelledby': id},
    h('h3', {cls: 'note-label', id: id},
      icon('bot'), document.createTextNode('Unverified text from the agent')),
    h('p', {cls: 'note-sub', text: 'Written by the agent, not checked by the gateway. It is not part of what you sign.'}),
    h('blockquote', {cls: 'note-body', text: text}));
}

/* ---- request cards ---- */
const cards = new Map();   // approval id -> {el, deadline, ...}
const RISKS = {low: ['check-circle', 'Low risk'], medium: ['alert', 'Medium risk'],
  high: ['octagon', 'High risk']};

function buildCard(p) {
  const risk = RISKS[p.risk] ? p.risk : 'unknown';
  const [riskIcon, riskText] = RISKS[risk] || ['info', 'Risk unknown'];
  const titleId = 'req-' + p.approval_id;
  const card = h('article', {cls: 'card req risk-' + risk, 'aria-labelledby': titleId});
  const left = h('span', {cls: 'chip countdown'}, icon('clock'), h('span', {text: ''}));
  card.append(h('header', {cls: 'req-head'},
    h('div', {cls: 'req-top'},
      h('h2', {cls: 'req-tool', id: titleId, text: p.tool}),
      h('span', {cls: 'badge risk-' + risk}, icon(riskIcon), h('span', {text: riskText}))),
    h('div', {cls: 'meta'},
      h('span', {cls: 'chip'}, icon('bot'), h('span', {text: p.agent})),
      left,
      h('span', {cls: 'chip passkey'}, icon('lock'), h('span', {text: 'Needs passkey'})))));

  const drawn = drawPreview(p, card);
  if (drawn.node) card.append(drawn.node);
  if (p.agent_note) card.append(drawNote(p.agent_note));
  const raw = h('details', {cls: 'raw', open: drawn.rawOpen},
    h('summary', null, icon('chevron'), document.createTextNode('Raw arguments')),
    h('pre', {cls: 'args', tabindex: '0', text: JSON.stringify(p.args, null, 2)}));
  card.append(raw);

  const ok = h('button', {cls: 'btn btn-primary', type: 'button'}, icon('key'),
    h('span', {cls: 'btn-label', text: 'Approve'}));
  const no = h('button', {cls: 'btn btn-deny', type: 'button'}, icon('x-circle'),
    h('span', {text: 'Deny'}));
  const status = h('div', {cls: 'inline-status', role: 'status', 'aria-live': 'polite'});
  const state = {id: p.approval_id, tool: p.tool, el: card, ok, no, status, left,
    deadline: Date.now() + p.expires_in * 1000, busy: false, confirmed: !drawn.confirm};

  if (drawn.confirm) {
    const inputId = 'confirm-' + p.approval_id;
    const hint = h('div', {cls: 'hint', id: inputId + '-hint'});
    const input = h('input', {cls: 'input', id: inputId, type: 'text', autocomplete: 'off',
      autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false',
      'aria-describedby': inputId + '-hint'});
    const update = () => {
      const v = input.value;
      state.confirmed = v === drawn.confirm;
      input.setAttribute('aria-invalid', String(v !== '' && !state.confirmed));
      input.classList.toggle('valid', state.confirmed);
      hint.className = 'hint' + (state.confirmed ? ' good' : v ? ' bad' : '');
      hint.replaceChildren(icon(state.confirmed ? 'check-circle' : v ? 'x-circle' : 'info'),
        h('span', {text: state.confirmed ? 'Matches. Approve is enabled.'
          : v ? 'Does not match yet. Type it exactly, including capitals.'
            : 'Required before you can approve.'}));
      syncButtons(state);
    };
    input.addEventListener('input', update);
    card.append(h('div', {cls: 'confirm'},
      h('label', {for: inputId}, document.createTextNode('To approve, type '),
        h('code', {text: drawn.confirm}), document.createTextNode(' exactly')),
      input, hint));
    update();
  }
  ok.addEventListener('click', () => decide(state, true));
  no.addEventListener('click', () => decide(state, false));
  card.append(h('div', {cls: 'actionbar'}, no, ok), status);
  paintIcons(card);
  syncButtons(state);
  tickCard(state);
  return state;
}

function syncButtons(s) {
  s.ok.disabled = s.busy || !s.confirmed || s.expired === true;
  s.no.disabled = s.busy || s.expired === true;
}

function say(s, panel) {
  s.status.replaceChildren(h('div', {cls: 'panel panel-' + panel.tone}, icon(panel.icon),
    h('div', null, h('div', {cls: 'panel-title', text: panel.title}), h('div', {text: panel.text}))));
}

function tickCard(s) {
  const left = (s.deadline - Date.now()) / 1000;
  const label = s.left.lastChild;
  if (left <= 0) {
    if (!s.expired) {
      s.expired = true;
      s.el.classList.add('expired');
      s.left.classList.remove('soon');
      say(s, {tone: 'warn', icon: 'clock', title: 'Expired',
        text: 'This request timed out. The agent was told no.'});
      syncButtons(s);
    }
    label.textContent = 'Expired';
    return;
  }
  label.textContent = 'Expires in ' + clock(left);
  s.left.classList.toggle('soon', left < 60);
}

async function decide(s, approve) {
  if (s.busy) return;
  s.busy = true;
  s.el.setAttribute('aria-busy', 'true');
  s.status.replaceChildren();
  const label = s.ok.querySelector('.btn-label');
  if (approve) {
    s.ok.querySelector('.icon').replaceWith(h('span', {cls: 'spinner', 'aria-hidden': 'true'}));
    label.textContent = 'Waiting for passkey…';
  }
  syncButtons(s);
  try {
    if (approve) await api('/api/approvals/' + s.id + '/approve', {credential: await sign(s.id)});
    else await api('/api/approvals/' + s.id + '/deny', {});
    closeCard(s, approve ? 'ok' : 'deny', approve ? 'Approved' : 'Denied',
      s.tool + (approve ? ' was approved and will run.' : ' was denied. The agent was told no.'));
  } catch (e) {
    const f = failure(e);
    if (f.kind === 'resolved' || f.kind === 'expired') {
      closeCard(s, f.kind === 'expired' ? 'expired' : 'info', f.title, s.tool + ': ' + f.text);
    } else {
      s.busy = false;
      s.el.removeAttribute('aria-busy');
      const spin = s.ok.querySelector('.spinner');
      if (spin) spin.replaceWith(icon('key'));
      label.textContent = 'Approve';
      say(s, {tone: f.kind === 'cancelled' ? 'info' : 'danger',
        icon: f.kind === 'cancelled' ? 'info' : 'alert', title: f.title, text: f.text});
      syncButtons(s);
    }
  }
}

/* ---- results, banner, list ---- */
function closeCard(s, kind, title, text) {
  s.closed = true;
  s.el.remove();
  cards.delete(s.id);
  const icons = {ok: 'check-circle', deny: 'x-circle', expired: 'clock', info: 'info'};
  const res = h('div', {cls: 'card result ' + kind}, icon(icons[kind]),
    h('div', {cls: 'result-main'}, h('div', {cls: 'result-title', text: title}), h('div', {text: text})));
  const close = h('button', {cls: 'btn btn-quiet', type: 'button', 'aria-label': 'Dismiss: ' + title},
    h('span', {text: 'Dismiss'}));
  close.addEventListener('click', () => { res.remove(); render(); });
  res.append(close);
  const box = document.getElementById('results');
  box.prepend(res);
  while (box.children.length > 3) box.lastChild.remove();
  render();
}

function banner(on) {
  const b = document.getElementById('banner');
  if (!on) { b.replaceChildren(); return; }
  if (b.firstChild) return;
  const retry = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Retry now'}));
  retry.addEventListener('click', load);
  b.append(h('div', {cls: 'panel panel-danger'}, icon('alert'),
    h('div', null, h('div', {cls: 'panel-title', text: 'Cannot reach the gateway'}),
      h('div', {text: 'Showing the last known state. Retrying every few seconds.'})), retry));
  paintIcons(b);
}

let enrolled = true, loaded = false;
function render() {
  const list = document.getElementById('list');
  list.removeAttribute('aria-busy');
  for (const sk of list.querySelectorAll('.skeleton, .sr-only')) sk.remove();
  let extra = list.querySelector('.extra');
  if (!extra) { extra = h('div', {cls: 'extra'}); list.prepend(extra); }
  const notes = [];
  if (!enrolled) {
    notes.push(h('div', {cls: 'panel panel-warn'}, icon('key'), h('div', null,
      h('div', {cls: 'panel-title', text: 'No passkey enrolled'}),
      h('div', {text: 'Run `agentpass passkey enroll` on the gateway and open the link on this device.'}))));
  }
  if (loaded && !cards.size && !document.getElementById('results').children.length) {
    notes.push(h('div', {cls: 'card empty'}, icon('shield-check'),
      h('h2', {text: 'No pending approvals'}),
      h('p', {text: 'When an agent needs your OK, it shows up here. This page checks every few seconds.'})));
  }
  extra.replaceChildren(...notes);
  paintIcons(extra);
  const n = cards.size, count = document.getElementById('count');
  count.hidden = n === 0;
  count.textContent = n + ' pending';
  document.title = (n ? '(' + n + ') ' : '') + 'agentpass approvals';
}

async function load() {
  let data;
  try {
    data = await api('/api/pending');
  } catch (e) {
    banner(true);
    return;
  }
  banner(false);
  enrolled = data.enrolled > 0;
  loaded = true;
  const list = document.getElementById('list');
  const seen = new Set(data.pending.map((p) => p.approval_id));
  for (const [id, s] of [...cards]) {
    if (!seen.has(id) && !s.busy) {
      const late = s.deadline <= Date.now();
      closeCard(s, late ? 'expired' : 'info', late ? 'Expired' : 'Already resolved',
        s.tool + (late ? ' timed out. The agent was told no.' : ' was answered elsewhere.'));
    }
  }
  for (const p of data.pending) {
    if (cards.has(p.approval_id)) continue;
    const s = buildCard(p);
    cards.set(p.approval_id, s);
    list.append(s.el);
  }
  render();
}

setInterval(() => {
  for (const s of cards.values()) tickCard(s);
  for (const e of document.querySelectorAll('[data-built]')) {
    e.textContent = 'Built ' + ago(e.dataset.built);
  }
}, 1000);

/* ---- enrolment ---- */
function enrolStatus(tone, iconName, title, text) {
  const box = document.getElementById('enroll-status');
  box.replaceChildren(h('div', {cls: 'panel panel-' + tone}, icon(iconName),
    h('div', null, h('div', {cls: 'panel-title', text: title}), h('div', {text: text}))));
}
async function enroll() {
  const btn = document.getElementById('enroll');
  const label = btn.querySelector('.btn-label');
  const token = new URLSearchParams(location.search).get('token');
  if (!token) {
    enrolStatus('danger', 'alert', 'This link has no enrolment token',
      'Run `agentpass passkey enroll` again and open the new link.');
    return;
  }
  btn.disabled = true;
  label.textContent = 'Waiting for your device…';
  document.getElementById('enroll-status').replaceChildren();
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
    btn.hidden = true;
    enrolStatus('ok', 'check-circle', 'Passkey registered', 'You can close this page.');
  } catch (e) {
    btn.disabled = false;
    label.textContent = 'Try again';
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
      enrolStatus('info', 'info', 'Cancelled', 'No passkey was registered. Tap Try again when ready.');
    } else if (e && e.name === 'TypeError') {
      enrolStatus('danger', 'alert', 'Network error', 'Could not reach the gateway. Check your connection.');
    } else if (e && (e.status === 403 || e.status === 429)) {
      enrolStatus('danger', 'alert', 'Link not accepted',
        'The enrolment link is invalid or expired. Run `agentpass passkey enroll` for a new one.');
    } else {
      enrolStatus('danger', 'alert', 'Registration failed',
        'Something went wrong (' + ((e && (e.name || e.status)) || 'error') + '). Nothing was saved.');
    }
  }
}

paintIcons(document);
session().then(() => {
  const btn = document.getElementById('enroll');
  if (btn) btn.addEventListener('click', enroll);
  else { load(); setInterval(load, 5000); document.addEventListener('visibilitychange',
    () => { if (!document.hidden) load(); }); }
}).catch(() => {
  if (document.getElementById('enroll')) {
    enrolStatus('danger', 'alert', 'Cannot reach the gateway', 'Reload the page to try again.');
  } else { banner(true); render(); }
});
"""
