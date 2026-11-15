// AgentPass service worker logic. This file is the single source of the worker: pwa_assets.py
// reads it at import, strips the `export` keywords and appends the glue that calls setup()
// with the real `self`, `caches`, `fetch` and IndexedDB. node:test loads it as a module with
// stubs (tests/js/sw-logic.test.mjs).
//
// Nothing here may cache an /api/* response, and the navigation response cached under `/`
// must stay static (no per-user content): the document served for / and /a/<id> is the same
// shell for everyone and carries no approval data.

const CACHE = 'agentpass-shell-__VERSION__';
const SHELL = [
  '/', '/static/app.js', '/static/app.css', '/manifest.webmanifest',
  '/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon-maskable-512.png',
];
const ACTION_URL = '/api/push/action';
const SYNC_TAG = 'agentpass-actions';
const DB_NAME = 'agentpass';
const STORE_NAME = 'actions';
const SYSTEM_REASONS = ['restart', 'gateway_shutdown', 'no_channel', 'rejected_proof'];
const RESOLVED_SHOWN_MS = 4000;

const isApi = (url) => url.pathname.startsWith('/api/');
const isShellPage = (url) => url.pathname === '/' || url.pathname.startsWith('/a/');
const isNavigation = (req, url) => req.mode === 'navigate' || isShellPage(url);
const appUrl = (payload) => '/a/' + encodeURIComponent(payload.approval_id);

export function notificationFor(payload) {
  // A require: telegram rule can never be approved from a notification: Deny only.
  const actions = [{action: 'deny', title: 'Deny'}];
  if (payload.require !== 'telegram') actions.unshift({action: 'approve', title: 'Approve'});
  return {
    title: payload.title,
    options: {
      body: payload.body,
      tag: payload.approval_id,
      requireInteraction: true,
      actions,
      data: payload,
    },
  };
}

// Deny posts. Approve posts only when this device has one-tap on and the rule is not a
// passkey one (the server decides again and answers 409 if it disagrees). Anything else,
// including a tap on the notification body, opens the app on that request.
export function decideClick(action, payload) {
  const open = {kind: 'open', url: appUrl(payload)};
  if (action === 'deny') return {kind: 'post', action: 'deny', url: ACTION_URL};
  if (action === 'approve' && payload.one_tap === true && payload.require !== 'passkey') {
    return {kind: 'post', action: 'approve', url: ACTION_URL};
  }
  return open;
}

// `expires_at` is epoch seconds, `now` is epoch milliseconds.
export function queueDecision(item, now) {
  return now >= item.expires_at * 1000 ? 'drop' : 'send';
}

export function resolvedText(payload) {
  if (payload.approved) return 'Approved elsewhere';
  if (SYSTEM_REASONS.includes(payload.reason)) return 'Cancelled by the gateway';
  return payload.reason === 'timeout' || payload.reason === 'expired'
    ? 'Expired. The agent was told no.' : 'Denied elsewhere';
}

// The offline queue: one row per approval, a later tap replaces the earlier one.
export function idbStore(indexedDB) {
  const open = () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME, {keyPath: 'approval_id'});
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const run = async (mode, fn) => {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, mode);
        const req = fn(tx.objectStore(STORE_NAME));
        tx.oncomplete = () => resolve(req.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  };
  return {
    put: (item) => run('readwrite', (s) => s.put(item)),
    delete: (id) => run('readwrite', (s) => s.delete(id)),
    all: () => run('readonly', (s) => s.getAll()),
  };
}

async function sendAction(env, item) {
  let res;
  try {
    res = await env.fetch(ACTION_URL, {
      method: 'POST', credentials: 'omit',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({approval_id: item.approval_id, action: item.action, token: item.token}),
    });
  } catch (e) {
    return {result: 'offline'};
  }
  if (res.ok) return {result: 'sent'};
  if (res.status === 409) {
    let url = null;
    try { url = (await res.json()).open; } catch (e) { /* fall back to the deep link */ }
    const safe = typeof url === 'string' && url.startsWith('/a/') ? url
      : appUrl(item);
    return {result: 'open', url: safe};
  }
  if (res.status === 410) return {result: 'gone'};
  return {result: 'refused'};
}

export function setup(self, env) {
  let retrying = null;
  const settled = new Set();  // approvals whose action already got a final answer

  const notice = (id, title, body) => self.registration.showNotification(title, {
    body, tag: id, requireInteraction: false, data: {type: 'notice', approval_id: id},
  });

  async function openUrl(url) {
    const wins = await self.clients.matchAll({type: 'window', includeUncontrolled: true});
    const mine = wins.find((c) => c.url && new URL(c.url).origin === self.location.origin);
    if (mine && mine.navigate) {
      try {
        await mine.navigate(url);
        await mine.focus();
        return;
      } catch (e) { /* fall through to a new window */ }
    }
    await self.clients.openWindow(url);
  }

  async function queueOffline(item) {
    await env.store.put(item);
    try {
      if (self.registration.sync) await self.registration.sync.register(SYNC_TAG);
    } catch (e) { /* no Background Sync: retried on wake and when the app opens */ }
    await notice(item.approval_id, 'Waiting for Tailscale…',
      'Your answer is sent when this device is back on Tailscale. Tap to open.');
  }

  async function afterSend(item, outcome) {
    if (outcome.result === 'open') return openUrl(outcome.url);
    if (outcome.result === 'gone') {
      return notice(item.approval_id, 'Already resolved', 'This request was answered elsewhere.');
    }
    if (outcome.result === 'refused') {
      return notice(item.approval_id, 'Could not send your answer',
        'It expired or was already used. Tap to open AgentPass.');
    }
    return undefined;
  }

  async function doClick(action, payload) {
    const d = decideClick(action, payload);
    if (d.kind === 'open') return openUrl(d.url);
    // A retry may be posting this very approval's queued action: let it finish, and do not
    // post a second time if it got a final answer (the token is single use).
    if (retrying) await retrying.catch(() => {});
    if (settled.has(payload.approval_id)) return undefined;
    const item = {approval_id: payload.approval_id, action: d.action, token: payload.token,
      expires_at: payload.expires_at};
    const outcome = await sendAction(env, item);
    if (outcome.result === 'offline') return queueOffline(item);
    settled.add(item.approval_id);
    return afterSend(item, outcome);
  }

  // Returns true when nothing is left waiting. Concurrent callers share one run, so a push and
  // an activate arriving together cannot post the same token twice.
  function retryQueue() {
    if (retrying) return retrying;
    retrying = (async () => {
      let clear = true;
      for (const item of await env.store.all()) {
        if (queueDecision(item, env.now()) === 'drop') {
          await env.store.delete(item.approval_id);
          await notice(item.approval_id, 'Expired before it could be sent',
            'The request timed out while this device was off Tailscale.');
          continue;
        }
        const outcome = await sendAction(env, item);
        if (outcome.result === 'offline') { clear = false; break; }
        settled.add(item.approval_id);
        await env.store.delete(item.approval_id);
        await afterSend(item, outcome);
      }
      return clear;
    })().finally(() => { retrying = null; });
    return retrying;
  }
  const retrySafely = () => retryQueue().catch(() => false);

  async function onPush(event) {
    let payload = null;
    try { payload = event.data.json(); } catch (e) { payload = null; }
    if (!payload || typeof payload.approval_id !== 'string') {
      await self.registration.showNotification('AgentPass', {
        body: 'Open AgentPass to see what changed.', tag: 'agentpass', data: {type: 'notice'}});
    } else if (payload.type === 'resolved') {
      // The browser wants every push to show something: replace the notification with a
      // short note under the same tag, then close it.
      await self.registration.showNotification(resolvedText(payload), {
        tag: payload.approval_id, silent: true, requireInteraction: false,
        data: {type: 'notice', approval_id: payload.approval_id}});
      await env.delay(RESOLVED_SHOWN_MS);
      for (const n of await self.registration.getNotifications({tag: payload.approval_id})) {
        n.close();
      }
    } else {
      const {title, options} = notificationFor(payload);
      await self.registration.showNotification(title, options);
    }
    await retrySafely();
  }

  self.addEventListener('install', (event) => {
    event.waitUntil(env.caches.open(CACHE).then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()));
  });

  self.addEventListener('activate', (event) => {
    event.waitUntil(env.caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => env.caches.delete(k))))
      .then(() => self.clients.claim())
      .then(retrySafely));
  });

  self.addEventListener('fetch', (event) => {
    const req = event.request;
    const url = new URL(req.url);
    if (req.method !== 'GET' || url.origin !== self.location.origin) return;
    if (isApi(url)) {  // network only: API responses are never cached
      event.respondWith(env.fetch(req));
      return;
    }
    if (isNavigation(req, url)) {
      if (!isShellPage(url)) {  // /enroll?token=... and the like: network only, never cached
        event.respondWith(env.fetch(req));
        return;
      }
      // the shell is one document for / and /a/<id>
      event.respondWith(env.fetch(req).then((res) => {
        // Only the static shell is cached: /enroll?token=... and the like are network-only.
        if (res.ok && (url.pathname === '/' || url.pathname.startsWith('/a/'))) {
          const copy = res.clone();
          env.caches.open(CACHE).then((cache) => cache.put('/', copy));
        }
        return res;
      }).catch(() => env.caches.open(CACHE).then((cache) => cache.match('/'))
        .then((hit) => hit || Response.error())));
      return;
    }
    event.respondWith(env.caches.open(CACHE).then((cache) => cache.match(req).then((hit) => {
      if (hit) return hit;
      return env.fetch(req).then((res) => {
        if (res.ok && SHELL.includes(url.pathname)) cache.put(req, res.clone());
        return res;
      });
    })));
  });

  self.addEventListener('push', (event) => event.waitUntil(onPush(event)));

  self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const payload = event.notification.data || {};
    if (typeof payload.approval_id !== 'string') {
      event.waitUntil(openUrl('/'));
      return;
    }
    event.waitUntil(doClick(event.action, payload));
  });

  self.addEventListener('sync', (event) => {
    if (event.tag !== SYNC_TAG) return;
    event.waitUntil(retryQueue().then((clear) => {
      if (!clear) throw new Error('still offline');  // the browser schedules another sync
    }));
  });

  self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'retry-actions') event.waitUntil(retrySafely());
  });
}
