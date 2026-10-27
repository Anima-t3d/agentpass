# Remembered decisions (Allow always / Deny always)

Status: implemented. See "Decisions" at the end.

Goal: after the operator answers an approval once with "always", identical later requests from that agent resolve without a prompt. A remembered rule can make the gateway stricter at no risk and more permissive only inside tight, checked limits.

## Principles

1. **Only a human on a trusted channel creates a rule**, as part of winning the approval race for a real pending request. No agent API, MCP tool, dashboard or CLI call can create a rule.
2. **The rule is derived server-side from the pending request**, never from data in the button. The button carries only a scope code.
3. **Remembered allow is weaker than every static deny and every restriction.** It only turns `ask` into `allow`, and only while the request is still eligible under *current* policy (re-checked on every call, not just at creation).
4. **Remembered deny acts like an agent deny rule.**
5. **Matching is exact string equality**, never glob. Nothing the agent sends is ever interpreted as a pattern.
6. **Fail safe:** any doubt (DB error, unknown risk, missing tool definition, expired, revoked) means "no rule applies", so the normal `ask` happens.

## 1. Data model and migration

New table, created by migration **v4** (`SCHEMA_VERSION = 4`; also added to `_TABLES` for fresh databases). Lives in the same SQLite DB as the audit log (`/etc/agentpass` stays read-only).

```sql
CREATE TABLE IF NOT EXISTS remembered_rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id          TEXT NOT NULL,
    scope             TEXT NOT NULL CHECK (scope IN ('exact', 'tool')),
    tool_name         TEXT NOT NULL,
    signature         TEXT,            -- exact scope: the signature string; NULL for tool scope
    args_hash         TEXT,            -- exact scope: sha256 of canonical JSON of the agent-supplied args; NULL for tool scope
    pattern           TEXT NOT NULL,   -- display only: 'tool(signature)' or 'tool(*)'. Never matched against.
    action            TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
    created_by        TEXT NOT NULL,   -- Telegram user id (string)
    created_at        TEXT NOT NULL,   -- ISO-8601 UTC, same format as pending_requests
    expires_at        TEXT,            -- NULL = never
    revoked_at        TEXT,
    revoked_by        TEXT,            -- 'cli' | 'dashboard' | telegram id
    source_request_id TEXT NOT NULL,   -- the approval that created it (audit_log.request_id)
    use_count         INTEGER NOT NULL DEFAULT 0,
    last_used_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_remembered_lookup
    ON remembered_rules(agent_id, tool_name) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_remembered_unique
    ON remembered_rules(agent_id, scope, tool_name, COALESCE(signature, ''),
                        COALESCE(args_hash, ''), action) WHERE revoked_at IS NULL;
```

Migration v4 also adds `audit_log.remembered_rule_id INTEGER` (nullable). Both steps are idempotent (`IF NOT EXISTS`, column check), like v1 to v3. Old gateway versions refuse a newer DB (existing guard), so a downgrade fails loudly rather than silently ignoring rules.

Rows are never deleted: revoked and expired rules remain as history.

**Why not a `pattern` glob column as the matcher?** A glob would let metacharacters in a stored signature widen the match. Signatures already forbid `* ? [ ] ( ) ,`, but equality removes the whole class of bug and the safety no longer depends on that filter. `pattern` is a label for humans.

**Why `args_hash`?** A signature template need not mention every argument (e.g. `gmail_send` signature `{to}` but a free-text `body`). An "exact call" rule matching on signature alone would allow any body. The hash is over the full agent-supplied args (before defaults are applied), so "exact" means exact. Consequence: tools with free-text args effectively get "once" or "tool" scope only. If the operator wants "exact" to mean "exact signature" for tools whose signature covers all meaningful args, that is a per-tool opt-in (see open questions).

## 2. Evaluation order

In `Pipeline._run`, after validation and signature building, unchanged rate limiter first (so rate limits and pending limits apply exactly as today):

```
static   = engine.evaluate(...)                 # floor + agent-file + extends, as today
rule     = remembered.match(agent, tool, signature, args_hash, now)   # active, unexpired, unrevoked, may be None

1. static is DENY                        -> DENY   (floor / agent / extends deny; remembered rules not even consulted)
2. rule is a deny                        -> DENY   (behaves like an agent deny rule: beats a static allow)
3. static is ALLOW                       -> ALLOW
4. static is ASK and rule is an allow
      and allow_eligible(rule, tool_def, static.approval)   -> ALLOW, audited as remembered rule #id
5. otherwise                             -> ASK    (normal prompt, pending cap applies)
```

`allow_eligible` is the same function used when offering buttons (section 3), evaluated now against current policy:

- `static.approval.require` is not `passkey` (and not stricter than telegram);
- effective risk (max of the tool's `risk` and the matched rule's `approval.risk`) is not `high`; an unknown or unparseable risk value counts as high; for `tool` scope an *unset* risk also disqualifies;
- the tool still exists in the registry;
- the rule's agent still exists.

Ineligible rules are ignored (not deleted); the dashboard marks them "inactive: policy now requires passkey/high risk".

Only one query per call (`WHERE agent_id=? AND tool_name=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`), no cache, so revoke and expiry take effect on the next request. If both an exact and a tool rule match, any deny wins; otherwise the exact rule is reported.

### Worked example

Floor (`policy/_floor.yaml`): `deny gmail_delete_*`.
Agent `assistant`: `deny gmail_send(*@competitor.com*)`, `allow gmail_get_message(*)`, default `ask *`.
Tool risk: `gmail_list_messages` low, `gmail_send` medium, `gmail_delete_message` high.
Remembered rules for `assistant`: #7 allow exact `gmail_list_messages(in:inbox newer_than:14d)`; #8 allow tool `gmail_send(*)`; #9 deny exact `gmail_list_messages(in:spam)`.

| Request | Static | Remembered | Result |
| --- | --- | --- | --- |
| `gmail_delete_message(abc)` | floor DENY | (even if a rule existed) | **DENY**, step 1 |
| `gmail_send(bob@competitor.com)` | agent DENY | #8 matches | **DENY**, step 1: the agent deny beats #8 |
| `gmail_send(carol@example.com)` | ASK | #8 | **ALLOW** via #8, if #8 is still eligible (tool risk medium; fine) |
| `gmail_list_messages(in:inbox newer_than:14d)` | ASK | #7 | **ALLOW** via #7 |
| `gmail_list_messages(in:inbox newer_than:30d)` | ASK | none (different signature) | **ASK** |
| `gmail_list_messages(in:spam)` | ASK | #9 deny | **DENY** via #9 |
| `gmail_get_message(abc)` | ALLOW | none | **ALLOW** |
| `gmail_get_message(x)` after a later `deny` remembered for it | ALLOW | deny | **DENY**, step 2 |
| `gmail_send(carol@example.com)` after the operator raises gmail_send to `risk: high` | ASK | #8 ineligible | **ASK** |
| any call after #7 expired or was revoked | ASK | none | **ASK** |

## 3. Telegram UX and callback data

### Buttons

Step 1 (the approval message):

```
[Allow once] [Deny once]
[Allow always...] [Deny always...]      <- second row; "Allow always..." omitted when not eligible
```

Eligibility is computed in the pipeline when it builds the `ApprovalRequest` and passed to channels as `req.remember = RememberOffer(allow_exact, allow_tool, deny_exact, deny_tool, allow_expires, ...)`. "Allow always" is **not offered** when: the rule requires passkey; effective risk is high (or unknown, see above); the signature is too long to be shown in full in the scope step (> 1500 chars); the request came from a floor or explicit deny (no prompt exists). The `tool` scope is additionally not offered when risk is high/unknown/unset. "Deny always" is offered for every prompt, including passkey and high-risk (deny is always safe, both scopes).

Step 2 (after tapping "Allow always..." or "Deny always..."): the message is edited in place to show exactly what will be stored, then waits for a scope tap:

```
Allow always for agent assistant?
  This exact call:   gmail_list_messages(in:inbox newer_than:14d)   (expires 2027-01-24)
  [This exact call]  [This tool, any args: gmail_list_messages(*)]  [Back]
```

The **exact call is the first, default button.** The tool-wide button carries a warning line ("any arguments, 30 days"). Tapping a scope button is the final answer (approve/deny this request *and* store the rule); there is no third confirmation, because the text above the button already states the consequence. "Back" restores step 1.

On resolution, `finalize` edits the message as today with the header extended: `✅ Approved (always: exact, rule #12)`.

### Callback data

Telegram limits callback data to 64 bytes. Format: `<approval_id (uuid, 36)>:<code>`; the current `y|n` stay. New codes:

| Code | Meaning | Resolves? |
| --- | --- | --- |
| `y` / `n` | allow once / deny once (unchanged) | yes |
| `a` / `d` | open the allow-always / deny-always scope step | no (edit message only) |
| `ae` / `at` | allow always, exact / tool | yes + rule |
| `de` / `dt` | deny always, exact / tool | yes + rule |
| `b` | back to step 1 | no |

Max length 39. `CALLBACK_PATTERN` becomes `^[0-9a-f-]{36}:(y|n|a|d|ae|at|de|dt|b)$`. The scope is therefore part of the callback data, but **the pattern, tool, agent and expiry are not**: the gateway rebuilds them from the pending request it already holds. A forged or replayed button can at most pick a scope for a request that is pending right now.

### Validation (server side, every callback)

1. `query.from_user.id` in `allowed_users` (existing check), and (new hardening) `query.message.chat.id == config.chat_id`. Anything else is silently ignored.
2. Parse and match the pattern; unknown codes fall to the existing "button has expired" handler.
3. The request must be pending (`ApprovalSink.answer` returns `ALREADY_RESOLVED` otherwise).
4. For `ae/at/de/dt`: the coordinator recomputes eligibility from the pending request (`req.remember`, built from current policy) and returns `AnswerStatus.REJECTED` ("This choice is not available for this request") if the chosen scope is not offered, for example an `at` for a high-risk tool or `ae/at` on a passkey rule. Offering is UX; this check is the enforcement.
5. Satisfies the existing `satisfies(channel, answer, require)` proof rule. A passkey-required request can never get an allow-always rule from Telegram, so the passkey channel needs no change (it offers only once-style answers).
6. Rule creation is done by the coordinator **in the same step that wins the race** (`transition_pending` to `resolved`, then `INSERT`). The loser of a race creates nothing. A crash between the two steps loses the rule and the decision, which is the safe direction.

`Answer.scope` (reserved today) becomes `Answer.remember: Literal["exact","tool"] | None`.

## 4. Expiry

- **Allow: 90 days for exact scope, 30 days for tool scope.** Tool scope is broader, so it lapses sooner. Configurable (`approval.remember.allow_exact_days`, `allow_tool_days`; max-capped, `0`/null is rejected for allow, so an allow rule can never be permanent).
- **Deny: no expiry** (deny is the safe direction; the operator revokes explicitly).
- The step-2 text shows the exact expiry date. Expired rules stay in the table, show as "expired" in the dashboard, and re-prompt on the next request. Optionally one Telegram notice per rule when it first lapses is out of scope.

## 5. Dashboard and CLI

All on the existing admin-only Unix socket; nothing on TCP.

- `GET /remembered/` page: table of rules (id, agent, scope, pattern, action, created by/at, expires, last used, use count, state: active / expired / revoked / inactive-by-policy), filter active/all, with a Revoke button.
- `GET /remembered/api/rules?agent=&state=` JSON.
- `POST /remembered/api/rules/{id}/revoke` sets `revoked_at`, `revoked_by='dashboard'`, writes the audit row. Requires the `X-Requested-With` header and a same-origin `Origin` check (CSRF guard in case the socket is ever proxied).
- **There is deliberately no create endpoint.**
- CLI (talks to the admin socket, so there is one writer and the audit row is written by the gateway):
  - `agentpass remembered list [--agent ID] [--all] [--json]`
  - `agentpass remembered revoke ID [ID...]`, `agentpass remembered revoke --agent ID --all` (bulk, for a re-created or compromised agent).
- `check-config` (offline) opens the DB read-only if it exists and reports `Remembered rules: N active (A allow, D deny), E expired, I inactive-by-policy`; it warns (lint) about active rules whose agent or tool no longer exists, and about allow rules now ineligible. Exit codes unchanged (these are warnings; `--strict` makes them errors as with other lints). The startup log prints the same count line.

## 6. Audit

Existing `audit_log` rows keep their meaning; additions:

- **Auto-resolved call**: normal row, `decision` = `allow` or `deny`, `resolution` = `remembered_allow` / `remembered_deny`, `resolved_by` = `rule:#<id>`, `remembered_rule_id` = id. Rule `use_count` and `last_used_at` are updated too.
- **Rule created**: row with `tool_name` = `_remembered.create`, `args.source_request_id` = the source approval's id, `signature` = the rule's pattern, `decision` = rule action, `resolution` = `rule_created`, `resolved_by` = Telegram user id, `remembered_rule_id` = id. The approval's own audit row is resolved as usual (`approved` / `denied`, with the rule id).
- **Rule revoked**: `tool_name` = `_remembered.revoke`, `resolution` = `rule_revoked`, `resolved_by` = `cli` / `dashboard` / Telegram id, `remembered_rule_id` = id.
- Expiry is implicit (no write at expiry); the dashboard derives it.

These pseudo tool names start with `_` so they cannot collide with registry tools (tool names validated as normal identifiers) and the audit dashboard can filter them.

## 7. Threat model

Assumption: the attacker controls an agent (token, prompts, tool call content) on an untrusted device. They cannot reach the admin socket, the DB, `/etc/agentpass` or the operator's Telegram.

| Threat | Why it is contained |
| --- | --- |
| Agent creates or extends a rule itself | No agent-facing API creates rules. Creation needs a Telegram callback from an `allowed_users` account in the configured chat, for a pending request, winning the answer race. |
| Agent crafts a request so that "always" covers more than it looks like (glob, injection) | Matching is string equality on stored values; the pattern field is never matched. Signature metacharacters are rejected anyway; free-text args are covered by `args_hash`, not the signature. |
| Agent changes a non-signature argument (body, recipient field) after an exact allow | `args_hash` covers all agent-supplied args; any difference re-prompts. |
| Social engineering: look benign once, get permanent trust | Exact is the default; allow rules expire (90/30 days); tool scope is hidden for high/unknown risk; scope step shows the stored pattern and expiry in full. Residual: the operator approving something harmful once and choosing "always" is still the operator's decision. |
| Prompt fatigue to push the operator into "always" | Rate and pending limits unchanged. "Always" reduces total prompts for repeated identical calls, which is the point. Daily-volume anomalies still visible in audit. |
| Override of a floor or agent deny | Impossible: static deny is step 1, before remembered rules are read. Remembered allow only acts when static is `ask`. |
| Policy tightened later (passkey added, risk raised) | Eligibility is re-evaluated on every call against current policy; a stale allow is ignored, not honoured. |
| Passkey or high-risk action approved by "always" from Telegram | Not offered, and rejected server-side if the callback is forged; also ignored at match time if it somehow existed. |
| Forged, forwarded or replayed callback | Checked against `allowed_users` and chat id; the request must still be pending; pattern is rebuilt server-side; the scope code is validated against what was offered. |
| Rule outlives the agent identity (agent file deleted and re-created with the same id) | Rules match on agent id, so a new agent with that id would inherit them. Mitigation: `check-config` lints rules whose agent is gone; `remembered revoke --agent ID --all`; documented in the agent-removal steps. Rules for an agent not currently loaded never match. |
| Tool definition changes meaning under the same name | Residual risk, bounded by expiry and the risk gate. Possible hardening (open question): store a hash of the tool definition and ignore the rule on mismatch. |
| Attacker with write access to the DB adds an allow rule | Out of scope: such an attacker can already rewrite the audit log and pending rows. The DB is owned by the service user and not agent-reachable. |
| Revoke races an in-flight call | Lookup is per call with no cache, so the next request sees the revoke. A call already executing is not aborted. |
| Remembered deny used to DoS an agent | It is only created by the operator; it is per agent and revocable. |
| Clock tampering | Gateway clock only; expiry compares ISO UTC strings against `now` on the gateway. |

## 8. Implementation plan (after approval)

1. `db.py`: migration v4, `RememberedStore` (create, match, list, revoke, count) plus tests.
2. `pipeline.py` / `engine.py`: the section 2 order, `allow_eligible`, audit columns.
3. `approval/`: `RememberOffer` on `ApprovalRequest`, `Answer.remember`, coordinator creation-on-win and re-validation.
4. `telegram_channel.py`: buttons, two-step flow, callback pattern, chat-id check.
5. `dashboard/routes.py`, `cli.py`/`__main__.py`: list and revoke; `check.py` and startup log counts.
6. Tests: scope matching, glob-injection safety, deny precedence (floor, agent, remembered), expiry, revoke, passkey and high-risk exclusion, `args_hash` mismatch, callback data parsing and validation (wrong user, wrong chat, stale, ineligible scope), migration from v3, audit rows. Shellcheck on any shell touched.

## 9. Decisions and implementation notes

1. Expiry: allow 90 days (exact) / 30 days (tool), deny none. The values are constants (`ALLOW_EXACT_DAYS`, `ALLOW_TOOL_DAYS` in `remembered.py`) and travel on the `RememberOffer`; they are not yet configurable in YAML.
2. `args_hash` stays the default for exact scope. A tool may opt in to signature-only matching with `remember: signature` (documented in the README tools reference). Switching a tool between the two modes changes its fingerprint, so older allow rules go inactive.
3. No `critical` level; `high` is enough. Unknown risk values count as high.
4. Medium risk may get tool scope. The shipped Gmail, Calendar and Home Assistant tools now carry a `risk` (see the README).
5. Tool-definition fingerprint: `remembered_rules.tool_fingerprint` is a sha256 of the tool definition without its description (`remembered.tool_fingerprint`). An **allow** whose fingerprint no longer matches is ignored and shown as "inactive: tool changed" (dashboard, `check-config`). A **deny** is kept in force whatever changed, since ignoring it would be the unsafe direction.

Implementation notes:

- The "create" audit row has its own `request_id` (the source approval is in `args.source_request_id`): `update_audit_resolution` keys on `request_id` and must not rewrite it.
- The dashboard/CLI list shows active and inactive-by-policy rules by default; `--all` / `?all=1` adds expired and revoked ones.
- A DB error while looking up rules propagates (the request fails) rather than being read as "no rule", because a missed remembered deny would otherwise let a call through.
- The Telegram channel also checks that the callback comes from the configured chat, not only from an allowed user.
