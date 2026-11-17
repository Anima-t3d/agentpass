import assert from 'node:assert/strict';
import test from 'node:test';
import * as sw from '../../src/agentpass/passkey/static/sw-logic.mjs';

const payload = (extra = {}) => ({
  type: 'approval', approval_id: 'a1', title: 'Send email', body: 'hermes wants gmail_send',
  require: 'any_trusted', one_tap: false, token: 'tok', expires_at: 2000, ...extra,
});

test('notificationFor: tag, interaction, actions, data', () => {
  const p = payload();
  const {title, options} = sw.notificationFor(p);
  assert.equal(title, 'Send email');
  assert.equal(options.body, 'hermes wants gmail_send');
  assert.equal(options.tag, 'a1');
  assert.equal(options.requireInteraction, true);
  assert.deepEqual(options.actions, [
    {action: 'approve', title: 'Approve'}, {action: 'deny', title: 'Deny'}]);
  assert.deepEqual(options.data, p);
});

test('notificationFor: a require telegram request has no Approve action', () => {
  const {options} = sw.notificationFor(payload({require: 'telegram', one_tap: true}));
  assert.deepEqual(options.actions, [{action: 'deny', title: 'Deny'}]);
  assert.equal(options.data.approval_id, 'a1');  // the body tap still opens the app
});

test('decideClick matrix', () => {
  for (const oneTap of [true, false]) {
    const p = payload({one_tap: oneTap});
    assert.equal(sw.decideClick('deny', p).kind, 'post');
    assert.equal(sw.decideClick('deny', p).action, 'deny');
    assert.deepEqual(sw.decideClick('', p), {kind: 'open', url: '/a/a1'});
    assert.deepEqual(sw.decideClick(undefined, p), {kind: 'open', url: '/a/a1'});
  }
  const on = sw.decideClick('approve', payload({one_tap: true}));
  assert.equal(on.kind, 'post');
  assert.equal(on.action, 'approve');
  assert.equal(on.url, '/api/push/action');
  assert.deepEqual(sw.decideClick('approve', payload({one_tap: false})),
    {kind: 'open', url: '/a/a1'});
});

test('decideClick: an approve for a passkey rule never posts, even with one_tap', () => {
  assert.equal(sw.decideClick('approve', payload({one_tap: true, require: 'passkey'})).kind,
    'open');
});

test('decideClick escapes the approval id in the deep link', () => {
  assert.equal(sw.decideClick('', payload({approval_id: 'a/b c'})).url, '/a/a%2Fb%20c');
});

test('queueDecision at the expiry boundary (expires_at is seconds)', () => {
  const item = {expires_at: 2000};
  assert.equal(sw.queueDecision(item, 1999999), 'send');
  assert.equal(sw.queueDecision(item, 2000000), 'drop');
  assert.equal(sw.queueDecision(item, 2000001), 'drop');
});

test('resolvedText', () => {
  assert.match(sw.resolvedText({approved: true}), /approved/i);
  assert.match(sw.resolvedText({approved: false, reason: 'timeout'}), /denied|expired|timed out/i);
  assert.match(sw.resolvedText({approved: false}), /denied/i);
  for (const reason of ['restart', 'gateway_shutdown', 'no_channel', 'rejected_proof']) {
    assert.equal(sw.resolvedText({approved: false, reason}), 'Cancelled by the gateway');
  }
  assert.equal(sw.resolvedText({approved: false, reason: 'denied'}), 'Denied elsewhere');
  assert.equal(sw.resolvedText({approved: false, reason: 'expired'}), 'Expired. The agent was told no.');
});

// --- worker wiring with stubbed self / caches / fetch ---

function harness({fetchImpl, items = [], now = 1000000} = {}) {
  const handlers = {};
  const cache = {puts: [], addAll: async () => {}, match: async () => undefined,
    put: async (...a) => { cache.puts.push(a); }};
  const opened = [];
  const shown = [];
  const closed = [];
  const store = {
    items: new Map(items.map((i) => [i.approval_id, i])),
    put: async (i) => { store.items.set(i.approval_id, i); },
    delete: async (id) => { store.items.delete(id); },
    all: async () => [...store.items.values()],
  };
  const opens = [];
  const registrations = {
    showNotification: async (title, options) => { shown.push({title, options}); },
    getNotifications: async ({tag}) => [{tag, close: () => closed.push(tag)}],
    sync: {register: async (tag) => { registrations.syncTags.push(tag); }},
    syncTags: [],
  };
  const self = {
    location: {origin: 'https://gate.example'},
    addEventListener: (type, fn) => { handlers[type] = fn; },
    registration: registrations,
    clients: {claim: async () => {}, matchAll: async () => [],
      openWindow: async (url) => { opens.push(url); }},
    skipWaiting: async () => {},
  };
  const env = {
    caches: {open: async (name) => { opened.push(name); return cache; }, keys: async () => [],
      delete: async () => true},
    fetch: fetchImpl || (async () => new Response('ok')),
    store, now: () => now, delay: async () => {},
  };
  sw.setup(self, env);
  const waits = [];
  const evt = (extra) => ({waitUntil: (p) => waits.push(p), ...extra});
  return {handlers, cache, opened, shown, closed, store, opens, registrations, waits, evt};
}

async function dispatchFetch(h, url, init = {}) {
  let response;
  const req = {method: 'GET', mode: 'cors', url, ...init};
  h.handlers.fetch({request: req, respondWith: (p) => { response = p; }});
  return response ? await response : undefined;
}

test('an /api/* fetch never reaches the cache', async () => {
  const h = harness({fetchImpl: async () => new Response('{"secret":1}')});
  for (const path of ['/api/pending', '/api/history?page=2', '/api/push/devices']) {
    const res = await dispatchFetch(h, 'https://gate.example' + path);
    assert.equal(await res.text(), '{"secret":1}');
  }
  assert.deepEqual(h.cache.puts, []);
  assert.deepEqual(h.opened, []);
});

test('a navigation is cached under / (control for the API test)', async () => {
  const h = harness({fetchImpl: async () => new Response('<html>')});
  await dispatchFetch(h, 'https://gate.example/a/x', {mode: 'navigate'});
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(h.cache.puts.map((p) => p[0]), ['/']);
});

test('only / and /a/<id> navigations are cached; others are network-only', async () => {
  for (const path of ['/enroll?token=secret', '/dashboard', '/other']) {
    const h = harness({fetchImpl: async () => new Response('<html>enroll')});
    const res = await dispatchFetch(h, 'https://gate.example' + path, {mode: 'navigate'});
    assert.equal(await res.text(), '<html>enroll');
    await new Promise((r) => setTimeout(r, 0));
    assert.deepEqual(h.cache.puts, [], path);
    assert.deepEqual(h.opened, [], path);
  }
  const h = harness({fetchImpl: async () => new Response('<html>')});
  await dispatchFetch(h, 'https://gate.example/', {mode: 'navigate'});
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(h.cache.puts.map((p) => p[0]), ['/']);
});

test('push approval shows the notification; resolved closes it by tag', async () => {
  const h = harness();
  const data = payload();
  h.handlers.push(h.evt({data: {json: () => data}}));
  await Promise.all(h.waits);
  assert.equal(h.shown[0].title, 'Send email');
  assert.equal(h.shown[0].options.tag, 'a1');
  h.waits.length = 0;
  h.handlers.push(h.evt({data: {json: () => ({type: 'resolved', approval_id: 'a1',
    approved: true, reason: ''})}}));
  await Promise.all(h.waits);
  assert.ok(h.closed.includes('a1'));
});

test('a push with unreadable data still shows something', async () => {
  const h = harness();
  h.handlers.push(h.evt({data: {json: () => { throw new Error('bad'); }}}));
  await Promise.all(h.waits);
  assert.equal(h.shown.length, 1);
});

function click(h, action, data) {
  const closedByClick = [];
  h.handlers.notificationclick(h.evt({action, notification: {data, close: () => closedByClick.push(1)}}));
  return closedByClick;
}

test('deny click posts the token; no cookie, token in body', async () => {
  const calls = [];
  const h = harness({fetchImpl: async (url, init) => {
    calls.push([url, init]); return new Response('{"ok":true}', {status: 200}); }});
  click(h, 'deny', payload());
  await Promise.all(h.waits);
  assert.equal(calls[0][0], '/api/push/action');
  assert.deepEqual(JSON.parse(calls[0][1].body),
    {approval_id: 'a1', action: 'deny', token: 'tok'});
  assert.equal(h.store.items.size, 0);
});

test('approve without one-tap opens the app and posts nothing', async () => {
  let posted = false;
  const h = harness({fetchImpl: async () => { posted = true; return new Response('{}'); }});
  click(h, 'approve', payload({one_tap: false}));
  await Promise.all(h.waits);
  assert.equal(posted, false);
  assert.deepEqual(h.opens, ['/a/a1']);
});

test('a 409 with {"open"} opens that URL', async () => {
  const h = harness({fetchImpl: async () => new Response('{"open":"/a/a1"}', {status: 409})});
  click(h, 'approve', payload({one_tap: true}));
  await Promise.all(h.waits);
  assert.deepEqual(h.opens, ['/a/a1']);
  assert.equal(h.store.items.size, 0);
});

test('a 410 tells the user it was already resolved and queues nothing', async () => {
  const h = harness({fetchImpl: async () => new Response('gone', {status: 410})});
  click(h, 'deny', payload());
  await Promise.all(h.waits);
  assert.match(h.shown.at(-1).title, /already/i);
  assert.equal(h.store.items.size, 0);
});

test('a network failure queues the action, registers sync and shows Waiting for Tailscale', async () => {
  const h = harness({fetchImpl: async () => { throw new TypeError('offline'); }});
  click(h, 'deny', payload());
  await Promise.all(h.waits);
  assert.deepEqual(h.store.items.get('a1'),
    {approval_id: 'a1', action: 'deny', token: 'tok', expires_at: 2000});
  assert.deepEqual(h.registrations.syncTags, ['agentpass-actions']);
  assert.match(h.shown.at(-1).title, /Waiting for Tailscale/);
  assert.equal(h.shown.at(-1).options.tag, 'a1');
});

test('a later tap for the same approval replaces the queued one', async () => {
  const h = harness({fetchImpl: async () => { throw new TypeError('offline'); }});
  click(h, 'deny', payload());
  await Promise.all(h.waits);
  click(h, 'approve', payload({one_tap: true}));
  await Promise.all(h.waits);
  assert.equal(h.store.items.size, 1);
  assert.equal(h.store.items.get('a1').action, 'approve');
});

test('sync retries the queue: sends live items, drops expired ones with a notice', async () => {
  const sent = [];
  const h = harness({
    now: 1500000,
    items: [
      {approval_id: 'live', action: 'deny', token: 't1', expires_at: 2000},
      {approval_id: 'old', action: 'deny', token: 't2', expires_at: 1000},
    ],
    fetchImpl: async (url, init) => { sent.push(JSON.parse(init.body).approval_id);
      return new Response('{}', {status: 200}); },
  });
  h.handlers.sync(h.evt({tag: 'agentpass-actions'}));
  await Promise.all(h.waits);
  assert.deepEqual(sent, ['live']);
  assert.equal(h.store.items.size, 0);
  const expired = h.shown.find((s) => /Expired before it could be sent/.test(s.title));
  assert.ok(expired);
  assert.equal(expired.options.tag, 'old');
});

test('sync keeps items and rejects (so the browser retries) while still offline', async () => {
  const h = harness({
    items: [{approval_id: 'a1', action: 'deny', token: 't', expires_at: 2000}],
    fetchImpl: async () => { throw new TypeError('offline'); },
  });
  h.handlers.sync(h.evt({tag: 'agentpass-actions'}));
  await assert.rejects(Promise.all(h.waits));
  assert.equal(h.store.items.size, 1);
});

test('sync with another tag does nothing', async () => {
  const h = harness();
  h.handlers.sync(h.evt({tag: 'other'}));
  assert.equal(h.waits.length, 0);
});

test('retry-actions message, push and activate also retry the queue', async () => {
  for (const trigger of ['message', 'push', 'activate']) {
    const sent = [];
    const h = harness({
      items: [{approval_id: 'q', action: 'deny', token: 't', expires_at: 2000}],
      fetchImpl: async (url, init) => { sent.push(url); return new Response('{}'); },
    });
    const extra = trigger === 'message' ? {data: {type: 'retry-actions'}}
      : trigger === 'push' ? {data: {json: () => payload()}} : {};
    h.handlers[trigger](h.evt(extra));
    await Promise.all(h.waits);
    assert.ok(sent.includes('/api/push/action'), trigger);
    assert.equal(h.store.items.size, 0, trigger);
  }
});

test('an unrelated message does not retry', async () => {
  const h = harness();
  h.handlers.message(h.evt({data: {type: 'something'}}));
  assert.equal(h.waits.length, 0);
});

test('a tap during an in-flight retry does not post the same approval twice', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const posts = [];
  const h = harness({
    items: [{approval_id: 'a1', action: 'deny', token: 'tok', expires_at: 2000}],
    fetchImpl: async (url, init) => {
      posts.push(JSON.parse(init.body).approval_id);
      await gate;
      return new Response('{}', {status: 200});
    },
  });
  h.handlers.sync(h.evt({tag: 'agentpass-actions'}));
  await new Promise((r) => setTimeout(r, 0));  // the retry's post is now in flight
  click(h, 'deny', payload());
  await new Promise((r) => setTimeout(r, 0));
  release();
  await Promise.all(h.waits);
  assert.deepEqual(posts, ['a1']);
  assert.equal(h.shown.length, 0);  // no "could not send" notice over the success
  assert.equal(h.store.items.size, 0);
});

// --- every notification carries the app icon and the monochrome status-bar badge ---

const BRAND = {icon: '/icons/icon-192.png', badge: '/icons/badge-96.png'};
const branded = (n) => n.options.icon === BRAND.icon && n.options.badge === BRAND.badge;

test('notificationFor uses the app icon and the status-bar badge', () => {
  const {options} = sw.notificationFor(payload());
  assert.equal(options.icon, BRAND.icon);
  assert.equal(options.badge, BRAND.badge);
});

test('the badge and icon are in the shell cache, so offline notices have them', () => {
  for (const path of Object.values(BRAND)) assert.ok(sw.SHELL.includes(path), path);
});

test('approval, resolved, unreadable and notice notifications are all branded', async () => {
  const h = harness({fetchImpl: async () => { throw new TypeError('offline'); }});
  h.handlers.push(h.evt({data: {json: () => payload()}}));
  h.handlers.push(h.evt({data: {json: () => ({type: 'resolved', approval_id: 'a1',
    approved: true, reason: ''})}}));
  h.handlers.push(h.evt({data: {json: () => { throw new Error('bad'); }}}));
  click(h, 'deny', payload());  // offline: the "Waiting for Tailscale" notice
  await Promise.all(h.waits);
  assert.equal(h.shown.length, 4);
  for (const n of h.shown) assert.ok(branded(n), JSON.stringify(n));
});
