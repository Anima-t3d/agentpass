import assert from 'node:assert/strict';
import test from 'node:test';
import * as hl from '../../src/agentpass/passkey/static/history-logic.mjs';

const entry = (extra = {}) => ({
  request_id: 'r1', timestamp: 1763366400, agent_id: 'hermes', tool_name: 'gmail_send',
  signature: 'gmail_send(to=a@example.com)', decision: 'ask', resolution: 'approved',
  resolved_by: 'passkey:phone', execution_result: null, ...extra,
});

test('entryDate reads audit timestamps as epoch seconds', () => {
  assert.equal(hl.entryDate(1763366400).toISOString(), '2025-11-17T08:00:00.000Z');
  assert.equal(hl.entryDate(1763366400.5).getTime(), 1763366400500);
  assert.equal(hl.entryDate('2025-11-17T08:00:00Z').toISOString(), '2025-11-17T08:00:00.000Z');
  assert.equal(hl.entryDate(null), null);
  assert.equal(hl.entryDate('not a date'), null);
});

test('dayLabel: Today, Yesterday, then a date (year only when it differs)', () => {
  const now = new Date(2026, 10, 17, 9, 30);
  assert.equal(hl.dayLabel(new Date(2026, 10, 17, 0, 5), now), 'Today');
  assert.equal(hl.dayLabel(new Date(2026, 10, 16, 23, 59), now), 'Yesterday');
  const older = hl.dayLabel(new Date(2026, 10, 14, 12), now);
  assert.match(older, /14/);
  assert.doesNotMatch(older, /2026/);
  assert.match(hl.dayLabel(new Date(2025, 11, 31, 12), now), /2025/);
});

test('groupByDay keeps the order and starts a group per local day', () => {
  const now = new Date(2026, 10, 17, 9, 30);
  const at = (d) => d.getTime() / 1000;
  const groups = hl.groupByDay([
    entry({request_id: 'a', timestamp: at(new Date(2026, 10, 17, 9))}),
    entry({request_id: 'b', timestamp: at(new Date(2026, 10, 17, 1))}),
    entry({request_id: 'c', timestamp: at(new Date(2026, 10, 16, 22))}),
    entry({request_id: 'd', timestamp: 'garbage'}),
  ], now);
  assert.deepEqual(groups.map((g) => g.label), ['Today', 'Yesterday', 'Unknown date']);
  assert.deepEqual(groups.map((g) => g.items.map((i) => i.entry.request_id)),
    [['a', 'b'], ['c'], ['d']]);
  assert.ok(groups[0].items[0].date instanceof Date);
});

test('splitCall separates the tool name from its arguments', () => {
  assert.deepEqual(hl.splitCall(entry()), {name: 'gmail_send', args: '(to=a@example.com)'});
  assert.deepEqual(hl.splitCall(entry({signature: 'other(x)'})), {name: '', args: 'other(x)'});
  assert.deepEqual(hl.splitCall(entry({signature: '', tool_name: 't'})), {name: 't', args: ''});
  assert.deepEqual(hl.splitCall(entry({signature: null, tool_name: ''})), {name: '', args: ''});
});

test('resultNote shows only errors and reasons, not a plain success', () => {
  assert.equal(hl.resultNote(entry()), null);
  assert.equal(hl.resultNote(entry({execution_result: {status: 200}})), null);
  assert.deepEqual(hl.resultNote(entry({execution_result: {error: 'upstream 503'}})),
    {text: 'Error: upstream 503', tone: 'no'});
  assert.deepEqual(hl.resultNote(entry({execution_result: {reason: 'approval timed out'}})),
    {text: 'approval timed out', tone: ''});
  assert.deepEqual(hl.resultNote(entry({execution_result: 'x'.repeat(300)})),
    {text: 'x'.repeat(160), tone: ''});
});

test('decisionLabel', () => {
  const L = (e) => hl.decisionLabel(entry(e));
  assert.deepEqual(L({request_id: 'login'}), {text: 'Sign-in refused', tone: 'refused'});
  assert.deepEqual(L({request_id: 'one-tap:d1'}), {text: 'One-tap enable refused', tone: 'refused'});
  assert.deepEqual(L({resolution: 'approval_rejected'}), {text: 'Approval rejected', tone: 'refused'});
  assert.deepEqual(L({}), {text: 'Approved', tone: 'yes'});
  assert.deepEqual(L({resolution: 'denied'}), {text: 'Denied', tone: 'no'});
  assert.deepEqual(L({resolution: 'timed_out'}), {text: 'Timed out', tone: 'no'});
  assert.deepEqual(L({resolution: 'remembered_allow'}), {text: 'Allowed (remembered)', tone: 'yes'});
  assert.deepEqual(L({resolution: 'remembered_deny'}), {text: 'Denied (remembered)', tone: 'no'});
  assert.deepEqual(L({resolution: null, decision: 'allow'}), {text: 'Allowed by policy', tone: 'yes'});
  assert.deepEqual(L({resolution: null, decision: 'deny'}), {text: 'Denied by policy', tone: 'no'});
  assert.deepEqual(L({resolution: null}), {text: 'Waiting', tone: ''});
  assert.deepEqual(L({resolution: 'some_thing'}), {text: 'some thing', tone: ''});
});

test('resolvedByLabel', () => {
  assert.equal(hl.resolvedByLabel(''), '');
  assert.equal(hl.resolvedByLabel(null), '');
  assert.equal(hl.resolvedByLabel('push:Pixel 8:notification'), 'Pixel 8 (notification)');
  assert.equal(hl.resolvedByLabel('push:Pixel 8'), 'Pixel 8');
  assert.equal(hl.resolvedByLabel('passkey:phone'), 'passkey:phone');
});

test('whenText formats epoch seconds and ISO strings, empty for nothing', () => {
  assert.match(hl.whenText(1763366400), /2025/);
  assert.match(hl.whenText('2026-11-17T01:00:00Z'), /2026/);
  assert.equal(hl.whenText(null), '');
  assert.equal(hl.whenText('nope'), '');
});

test('waitText', () => {
  assert.equal(hl.waitText(0), 'under a second');
  assert.equal(hl.waitText(42.4), '42 s');
  assert.equal(hl.waitText(125), '2 min');
  assert.equal(hl.waitText(3 * 3600 + 5 * 60), '3 h 5 min');
  assert.equal(hl.waitText(-3), '');
  assert.equal(hl.waitText(NaN), '');
});

const keys = (rows) => rows.map((r) => r.key);
const row = (rows, key) => rows.find((r) => r.key === key);

test('detailRows: everything the list leaves out, empty fields skipped', () => {
  const rows = hl.detailRows(entry({
    resolved_at: 1763366442, preview_title: 'Comment on #42', preview_status: 'ok',
    agent_note: 'posting the summary', execution_result: {sha: 'abc', fetched_bytes: 10},
  }));
  assert.deepEqual(keys(rows), ['Requested', 'Answered', 'Policy', 'Resolution', 'Preview',
    'Agent note (written by the agent)', 'Result', 'Request ID']);
  assert.match(row(rows, 'Answered').text, /after 42 s$/);
  assert.equal(row(rows, 'Policy').text, 'ask');
  assert.equal(row(rows, 'Preview').text, 'Comment on #42');
  assert.equal(row(rows, 'Result').text, '{\n  "sha": "abc",\n  "fetched_bytes": 10\n}');
  assert.equal(row(rows, 'Result').block, true);
  assert.equal(row(rows, 'Request ID').mono, true);
});

test('detailRows: a preview that could not be built says why; a long result is clipped', () => {
  const rows = hl.detailRows(entry({preview_status: 'unavailable:timeout',
    execution_result: {body: 'x'.repeat(9000)}, resolution: null, resolved_at: null}));
  assert.equal(row(rows, 'Preview').text, 'Not available (timeout)');
  assert.equal(row(rows, 'Result').text.length, 4001);
  assert.ok(row(rows, 'Result').text.endsWith('\u2026'));
  assert.equal(row(rows, 'Answered'), undefined);
  assert.equal(row(rows, 'Resolution'), undefined);
});

test('detailRows: a partial preview keeps its title and says so', () => {
  const rows = hl.detailRows(entry({preview_title: 'Send to bob', preview_status: 'partial'}));
  assert.equal(row(rows, 'Preview').text, 'Send to bob (partial)');
});
