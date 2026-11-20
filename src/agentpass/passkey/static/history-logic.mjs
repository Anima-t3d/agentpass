// History tab formatting: pure functions over audit rows from /api/history. pwa_views.py reads
// this file at import, drops the `export` keywords and adds it to the page script; node:test
// loads it as a module (tests/js/history-logic.test.mjs). No DOM here.

const CLIP = 160;
const RESULT_CLIP = 4000;
const DAY_MS = 86400000;

// Audit timestamps are epoch seconds. Anything else is parsed as a date string.
export function entryDate(ts) {
  if (ts === null || ts === undefined || ts === '') return null;
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
  return isNaN(d) ? null : d;
}

const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();

export function dayLabel(date, now) {
  const days = Math.round((startOfDay(now) - startOfDay(date)) / DAY_MS);
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  const opts = {weekday: 'short', day: 'numeric', month: 'short'};
  if (date.getFullYear() !== now.getFullYear()) opts.year = 'numeric';
  return date.toLocaleDateString([], opts);
}

// Entries arrive newest first; a new group starts whenever the local day changes.
export function groupByDay(entries, now) {
  const groups = [];
  for (const entry of entries) {
    const date = entryDate(entry.timestamp);
    const label = date ? dayLabel(date, now) : 'Unknown date';
    const last = groups[groups.length - 1];
    if (last && last.label === label) last.items.push({entry, date});
    else groups.push({label, items: [{entry, date}]});
  }
  return groups;
}

// The signature is `tool(args)`: show the tool name in bold and the arguments after it.
export function splitCall(e) {
  const sig = e.signature || '';
  const name = e.tool_name || '';
  if (name && sig.startsWith(name + '(')) return {name, args: sig.slice(name.length)};
  if (!sig) return {name, args: ''};
  return {name: '', args: sig};
}

// execution_result is null when nothing ran, {reason} for a refusal, {error} for a failure.
// A plain success says nothing the decision badge doesn't.
export function resultNote(e) {
  const r = e.execution_result;
  if (r === null || r === undefined) return null;
  if (typeof r !== 'object') return {text: String(r).slice(0, CLIP), tone: ''};
  if (typeof r.error === 'string') return {text: ('Error: ' + r.error).slice(0, CLIP), tone: 'no'};
  if (typeof r.reason === 'string') return {text: r.reason.slice(0, CLIP), tone: ''};
  return null;
}

export function decisionLabel(e) {
  if (e.request_id === 'login') return {text: 'Sign-in refused', tone: 'refused'};
  if (typeof e.request_id === 'string' && e.request_id.startsWith('one-tap:')) {
    return {text: 'One-tap enable refused', tone: 'refused'};  // not an approval rejection
  }
  const res = e.resolution || '';
  if (res === 'approval_rejected') return {text: 'Approval rejected', tone: 'refused'};
  if (res === 'approved') return {text: 'Approved', tone: 'yes'};
  if (res === 'denied') return {text: 'Denied', tone: 'no'};
  if (res === 'timed_out') return {text: 'Timed out', tone: 'no'};
  if (res === 'remembered_allow') return {text: 'Allowed (remembered)', tone: 'yes'};
  if (res === 'remembered_deny') return {text: 'Denied (remembered)', tone: 'no'};
  if (!res && e.decision === 'allow') return {text: 'Allowed by policy', tone: 'yes'};
  if (!res && e.decision === 'deny') return {text: 'Denied by policy', tone: 'no'};
  return {text: res ? res.replace(/_/g, ' ') : 'Waiting', tone: ''};
}

export function resolvedByLabel(v) {
  if (!v) return '';
  if (v.startsWith('push:')) {
    const rest = v.slice(5);
    return rest.endsWith(':notification')
      ? rest.slice(0, -':notification'.length) + ' (notification)' : rest;
  }
  return v;
}

// A full local date and time, for details and device cards. Empty when there is no date.
export function whenText(v) {
  const d = entryDate(v);
  return d ? d.toLocaleString([], {dateStyle: 'medium', timeStyle: 'medium'}) : '';
}

// How long an approval waited for an answer.
export function waitText(seconds) {
  if (typeof seconds !== 'number' || !isFinite(seconds) || seconds < 0) return '';
  if (seconds < 1) return 'under a second';
  if (seconds < 60) return Math.round(seconds) + ' s';
  if (seconds < 3600) return Math.floor(seconds / 60) + ' min';
  const hours = Math.floor(seconds / 3600);
  return hours + ' h ' + Math.floor((seconds - hours * 3600) / 60) + ' min';
}

function previewText(e) {
  const status = e.preview_status || '';
  const title = e.preview_title || '';
  if (status.startsWith('unavailable')) {
    const why = status.split(':')[1];
    return 'Not available' + (why ? ' (' + why + ')' : '');
  }
  if (status === 'partial') return title ? title + ' (partial)' : 'Partial';
  return title;
}

// What a tapped entry shows beyond the list line. The call arguments are not in /api/history.
export function detailRows(e) {
  const rows = [];
  const add = (key, text, extra = {}) => { if (text) rows.push({key, text, ...extra}); };
  add('Requested', whenText(e.timestamp));
  if (e.resolved_at) {
    const wait = waitText(e.resolved_at - e.timestamp);
    add('Answered', whenText(e.resolved_at) + (wait ? ', after ' + wait : ''));
  }
  add('Policy', e.decision || '');
  add('Resolution', e.resolution || '');
  add('Preview', previewText(e));
  add('Agent note (written by the agent)', e.agent_note || '');
  const r = e.execution_result;
  if (r !== null && r !== undefined) {
    let text = typeof r === 'string' ? r : JSON.stringify(r, null, 2);
    if (text.length > RESULT_CLIP) text = text.slice(0, RESULT_CLIP) + '\u2026';
    add('Result', text, {mono: true, block: true});
  }
  add('Request ID', e.request_id || '', {mono: true});
  return rows;
}
