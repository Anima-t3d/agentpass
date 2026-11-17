// History tab formatting: pure functions over audit rows from /api/history. pwa_views.py reads
// this file at import, drops the `export` keywords and adds it to the page script; node:test
// loads it as a module (tests/js/history-logic.test.mjs). No DOM here.

const CLIP = 160;
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
