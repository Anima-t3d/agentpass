"""PWA shell assets: web manifest, service worker skeleton and the tab/shell styles and script.

Served from the same origin as the approval page. Nothing here carries approval data: the
shell is static, and the script fetches everything through the session-gated API. Icons live
in ``pwa_icons`` (embedded PNG bytes; there is no build step).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

THEME = "#0b1017"

MANIFEST = {
    "name": "AgentPass",
    "short_name": "AgentPass",
    "description": "Approve what your agents ask to do.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": THEME,
    "theme_color": THEME,
    "icons": [
        {"src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {
            "src": "/icons/icon-maskable-512.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "maskable",
        },
    ],
}
MANIFEST_JSON = json.dumps(MANIFEST, indent=2)

# The worker's logic lives in static/sw-logic.mjs, which node:test loads directly. Here it is read
# once, its `export` keywords are dropped (a classic worker has no modules) and the glue that
# hands it the real worker globals is appended. `__VERSION__` in it is replaced with a hash of
# the shell assets, so a new build changes the worker bytes: a new worker and a fresh cache.
SW_LOGIC_PATH = Path(__file__).parent / "static" / "sw-logic.mjs"
_SW_GLUE = """
setup(self, {
  caches,
  fetch: (...args) => fetch(...args),
  store: idbStore(indexedDB),
  now: () => Date.now(),
  delay: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
});
"""


def build_sw(source: str) -> str:
    return "'use strict';\n" + re.sub(r"^export ", "", source, flags=re.MULTILINE) + _SW_GLUE


SW_JS = build_sw(SW_LOGIC_PATH.read_text(encoding="utf-8"))

SHELL_CSS = r"""
/* PWA shell: offline notice, tabs, panels */
.offline{display:flex;gap:var(--s3);align-items:center;justify-content:space-between;
  flex-wrap:wrap;background:var(--warn-bg);border:1px solid var(--warn-border);
  color:var(--warn-text);border-radius:var(--r-md);padding:var(--s3) var(--s4);
  margin-bottom:var(--s4);animation:rise .18s ease-out}
.offline .panel-title{display:block}
.tabs{display:flex;gap:var(--s1);border-bottom:1px solid var(--border);margin-bottom:var(--s4);
  position:sticky;top:0;background:var(--bg);z-index:3;overflow-x:auto}
.tab{flex:1 1 0;display:inline-flex;align-items:center;justify-content:center;gap:var(--s2);
  min-height:48px;padding:var(--s2) var(--s3);background:none;border:0;
  border-bottom:3px solid transparent;color:var(--muted);font:600 var(--fs-md) var(--font);
  cursor:pointer;white-space:nowrap;transition:color .15s,border-color .15s}
.tab:hover{color:var(--text)}
.tab[aria-selected="true"]{color:var(--primary);border-bottom-color:var(--primary)}
.tab .count{font-size:var(--fs-sm);padding:0 .5rem;min-width:1.5rem}
.tabpanel{animation:fade .18s ease-out}
.tabpanel .page-title{font-size:var(--fs-xl)}
.req,.result{animation:rise .18s ease-out}
.req.highlight{outline:.2rem solid var(--primary);outline-offset:.2rem}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes rise{from{opacity:0;transform:translateY(.4rem)}to{opacity:1;transform:none}}
@media (max-width:23rem){.tab{padding:var(--s2)}.brand{font-size:var(--fs-md)}}
"""

SHELL_JS = r"""
/* ---- PWA shell: tabs, offline notice, deep link, service worker ---- */
const TABS = ['pending', 'history', 'devices'];
function switchTab(name, focus) {
  if (!TABS.includes(name)) return;
  for (const t of TABS) {
    const tab = document.getElementById('tab-' + t), panel = document.getElementById('panel-' + t);
    if (!tab || !panel) return;
    const on = t === name;
    tab.setAttribute('aria-selected', String(on));
    tab.tabIndex = on ? 0 : -1;
    panel.hidden = !on;
    if (on && focus) tab.focus();
  }
  onTabShown(name);
}
function wireTabs() {
  const bar = document.querySelector('[role="tablist"]');
  if (!bar) return;
  for (const t of TABS) {
    document.getElementById('tab-' + t).addEventListener('click', () => switchTab(t));
  }
  bar.addEventListener('keydown', (ev) => {
    const i = TABS.findIndex((t) => document.getElementById('tab-' + t).tabIndex === 0);
    const next = ev.key === 'ArrowRight' ? i + 1 : ev.key === 'ArrowLeft' ? i - 1
      : ev.key === 'Home' ? 0 : ev.key === 'End' ? TABS.length - 1 : null;
    if (next === null) return;
    ev.preventDefault();
    switchTab(TABS[(next + TABS.length) % TABS.length], true);
  });
}

/* A failed fetch (no HTTP response at all) means the device is off the tailnet. */
let netDown = false;
const TAILSCALE_INTENT = 'intent://#Intent;package=com.tailscale.ipn;end';
function offline(on) {
  const box = document.getElementById('offline');
  if (!box) return;
  const changed = netDown !== on;
  netDown = on;  // Approve and Deny stay disabled until the gateway answers again
  if (changed) for (const s of cards.values()) syncButtons(s);
  if (!on) { box.hidden = true; box.replaceChildren(); return; }
  if (!box.hidden) return;
  const retry = h('button', {cls: 'btn btn-quiet', type: 'button'}, h('span', {text: 'Retry now'}));
  retry.addEventListener('click', load);
  box.replaceChildren(icon('alert'), h('div', null,
    h('span', {cls: 'panel-title', text: 'Not connected to Tailscale'}),
    h('span', {text: 'Showing the last known state. Retrying every few seconds.'}),
    /Android/i.test(navigator.userAgent)
      ? h('a', {cls: 'panel-title', href: TAILSCALE_INTENT, text: 'Open Tailscale'})
      : h('span', {text: 'Connect Tailscale on this device to reach the gateway.'})), retry);
  box.hidden = false;
}

/* /a/<approval id>: open that approval once the list has loaded */
let deepLinkDone = false;
function openDeepLink() {
  if (deepLinkDone) return;
  deepLinkDone = true;
  const m = /^\/a\/([^/]+)$/.exec(location.pathname);
  if (!m) return;
  let id = m[1];
  try { id = decodeURIComponent(id); } catch (e) { /* keep the raw id */ }
  switchTab('pending');
  const s = cards.get(id);
  if (!s) {
    const res = h('div', {cls: 'card result info'}, icon('info'),
      h('div', {cls: 'result-main'}, h('div', {cls: 'result-title', text: 'Not pending'}),
        h('div', {text: 'This request is no longer pending'})));
    document.getElementById('results').prepend(res);
    paintIcons(res);
    render();
    return;
  }
  s.el.classList.add('highlight');
  s.el.scrollIntoView({block: 'start'});
  s.el.setAttribute('tabindex', '-1');
  s.el.focus({preventScroll: true});
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', {scope: '/'}).catch(() => {});
  });
}
wireTabs();
"""
