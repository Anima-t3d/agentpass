# Approval previews: show what is being approved

Status: design only, not implemented. For owner review.

Goal: when the operator approves, especially with a passkey, they see what the call will do, not just the tool name and a JSON blob. An email as it will be sent, a diff of the file change, what a repo delete removes, which device a Home Assistant call acts on.

## Principles

1. **The agent is untrusted.** The trusted part of a preview is built by the gateway from (a) the validated args and (b) read-only lookups the gateway makes itself with its own credentials. Nothing the agent writes is rendered in the trusted part.
2. **Agent context is allowed but fenced.** An optional `agent_note` ("why I want this", sent as a gateway-added tool property, see section 5) is shown in a separate box labelled "Unverified text from the agent", length-limited, plain text only.
3. **Fail visible, never fail open.** A preview failure never blocks an approval and never approves. The page shows "Preview unavailable (reason)" and the raw args exactly as today.
4. **Declarative first.** Previews are declared per tool in the tool YAML. A small set of built-in renderers covers what YAML cannot express. New tools can usually add a preview with no Python.
5. **Display is not proof.** The proof (Telegram callback, passkey assertion) binds tool + canonical args (+ expiry). Lookups are context. Section "What the proof covers" is explicit about the gap.
6. **Previews are private data.** They may contain mail bodies. Trusted channels only; never notify-only channels; minimal audit footprint.

## 1. Where it fits

```
Pipeline._run
  validate args, build signature, engine decides "ask"
  -> ApprovalCoordinator.request(...)
       -> PreviewService.build(tool, args)          # NEW, bounded by a timeout
            returns Preview | PreviewUnavailable
       -> store preview JSON on the pending row     # so the page and a restart see the same thing
       -> fan out to channels with req.preview
```

`PreviewService` runs once per pending request, before fan-out, with a hard overall timeout (default 3 s, per lookup 2 s). Channels receive `ApprovalRequest.preview: Preview | None` next to the existing `arg_display`. The passkey page renders the full preview; Telegram renders `preview.summary` only (see section 6).

The preview is computed once and stored. The page shows what was computed at request time and shows its age ("built 40 s ago"). It is not refreshed on page load, so that what the operator saw is a single, recordable thing (see audit). An optional "refresh preview" button on the page re-runs the lookups and shows a new timestamp; the page tracks which version the operator confirmed.

### Data model

```python
@dataclass
class Preview:
    version: int                  # schema version of this structure
    built_at: str                 # ISO-8601 UTC
    title: str                    # one line, e.g. "Send email to bob@example.com"
    summary: str                  # <= 300 chars plain text, used by Telegram
    sections: list[Section]       # trusted, gateway-built
    warnings: list[str]           # e.g. "recipient is outside your domain"
    lookups: list[LookupNote]     # what was fetched, when, ok/failed
    confirm_text: str | None      # typed confirmation required on the page (delete)
    truncated: bool
    digest: str                   # sha256 of canonical JSON of the above

@dataclass
class Section:
    kind: Literal["kv", "text", "diff", "list", "table"]
    label: str
    data: Any                     # shape depends on kind; always plain strings, never HTML
```

Sections carry plain strings and structured kinds only. The page template decides how to draw each kind. No renderer ever emits HTML; escaping happens in one place (the page), which keeps the XSS surface to one function.

## 2. Config format

A `preview:` block per tool in the tool YAML, next to `signature:`, `risk:`, `audit:`.

```yaml
tools:
  ha_call_service:
    ...
    preview:
      renderer: entity_state          # built-in renderer, or "template"
      entity: "{entity_id}"
      lookups:
        - id: state
          method: GET
          path: "/api/states/{entity_id}"
          on_error: unavailable        # unavailable (default) | omit
      title: "{domain}.{service} on {state.attributes.friendly_name}"
      fields:
        - { label: "Device",  value: "{state.attributes.friendly_name} ({entity_id})" }
        - { label: "Now",     value: "{state.state}" }
        - { label: "Action",  value: "{domain}.{service}" }
      summary: "{domain}.{service} {state.attributes.friendly_name} (now: {state.state})"
```

Rules:

- `renderer: template` (default when `fields` is given) is pure data: `lookups` plus `fields`, with `{arg}` and `{lookup_id.json.path}` substitution. Substitution output is always a plain string, capped at `max_chars` (default 2000 per field). No expressions, no conditionals, no code.
- `renderer: <name>` selects a built-in (`email`, `diff`, `entity_state`, `resource_summary`). A built-in takes its own parameters under the same block.
- `lookups` are **GET-only**, run through the same service client as normal calls (same credentials, same SSRF-safe URL building, same response size cap). `config.py` rejects any lookup whose method is not GET/HEAD at load time. `check-config` lints that every `{placeholder}` refers to a declared arg or lookup id.
- A lookup is made **by the service named by the tool**. A preview cannot call another service, and the URL host cannot come from an arg.
- `warnings:` is an optional list of `{when: <simple comparison>, text: ...}` using a tiny fixed comparison set (`equals`, `in`, `not_in`, `endswith_not`); anything richer belongs in a built-in renderer.
- `audit.redact_args` keeps working and applies to the audit record. It does not hide anything from the approver.

Tools without a `preview:` block show the current raw-args view. `check-config --strict` may warn when a `risk: high` tool has no preview.

## 3. Built-in renderers

| Renderer | Input | Output sections |
| --- | --- | --- |
| `email` | base64url RFC 5322 message | headers kv, body text, attachments list, warnings |
| `diff` | old text (lookup), new text (arg) | unified diff, stats |
| `entity_state` | entity id + service call | device kv, current state, effect line |
| `resource_summary` | one or more GETs | kv table of selected fields, counts |

Each renderer is a pure function `(args, lookup_results) -> Preview` and is unit-testable without network.

### Size limits (all configurable, defaults)

- Whole preview: 64 KiB serialized; beyond that, `truncated: true` with "N more bytes not shown".
- Text body: 20,000 chars. Diff: 400 lines or 40,000 chars. Lists: 50 items.
- Lookup response: reuses the service's `response.max_bytes`.
- Truncation is always labelled. A truncated preview on a high-risk tool shows a warning "preview is partial".

## 4. Per-tool designs

### 4.1 gmail_send_message

Arg is `raw`: a base64url RFC 5322 message, up to 100,000 chars of base64. The existing signature is the whole `raw`, so the passkey challenge already binds the exact bytes of the message. The preview decodes those same bytes, so what is shown is exactly what would be sent.

Renderer `email`:

- Parse with Python's `email` package using `policy=email.policy.default`, in a try block, bounded depth (max 10 MIME parts, max 20 attachments listed).
- Show: From, To, Cc, Bcc, Reply-To, Subject, Date, full body, attachment list (filename, content type, size; never contents).
- **Address display**: show the decoded address and, if a display name is present, both, e.g. `"Boss" <x@evil.example>`. The domain is rendered in a distinct style; IDN domains are shown in both Unicode and punycode with a warning if they differ (homograph).
- **Header integrity**: the message actually sent by Gmail comes from the same `raw`, so To/Cc/Bcc shown are the real recipients. Warn on: duplicate `To`/`From`/`Subject` headers, header names the renderer does not know that look like routing (`Resent-*`), bare newlines in headers, non-UTF-8 charset that had to be replaced.
- **Plain text vs HTML**: prefer `text/plain` if present. If only `text/html`, convert to text with a small whitelist converter (strip all tags, drop `<script>`, `<style>`, `<head>`, comments; turn `<a href=URL>text</a>` into `text [URL]`; keep paragraph breaks) and label it "HTML message, shown as text". The raw HTML is never rendered in the page, not even in a sandboxed iframe. If both parts exist and differ materially (different link sets or different text after normalization), warn "plain and HTML parts differ; recipients may see different text", and show both, plain first.
- **Links**: every URL in the body is listed under the body as text with its host highlighted. Link text that looks like a URL but points elsewhere is flagged.
- **No remote content**: no images, no `<img>`, no CSS, no fonts, no tracking pixel is ever fetched or embedded. The page ships with a strict CSP (`default-src 'none'; style-src 'self'; script-src 'self'; img-src 'none'`).
- **Inline images / attachments**: listed only.
- External recipients: if config has `preview.internal_domains: [example.com]`, recipients outside get a warning.
- Summary for Telegram: `To: bob@example.com · "Subject…" · 1 attachment · 1,204 chars`.

Parsing failure (not valid RFC 5322, base64 error): `Preview unavailable (message could not be decoded)`. The raw args view stays.

### 4.2 calendar_create_event

Args: `calendar_id`, `summary`, `start`, `end` (Calendar API objects), and, in the proposed definition, `attendees` and `location`/`description` (not in the YAML today; the preview block would be added with them).

Template renderer plus a small time helper (built-in `datetime` formatter):

- Title (`summary`).
- Start and end in the event's own time zone (`start.timeZone` or the offset in `dateTime`) **and** in the operator's configured zone (`approval.display_timezone`, see below), e.g. `Tue 3 Nov 2026 14:00 America/New_York (20:00 Europe/Berlin)`. The zone name is always printed next to every time; a time is never shown without its zone.
- Duration, computed. All-day events (`date` instead of `dateTime`) shown as such. Warn if end <= start, duration > 12 h, or the date is in the past.
- Calendar: look up `GET /calendar/v3/calendars/{calendar_id}` for the calendar name ("Work"), so `primary` or an opaque id is readable.
- **Attendees who will get an invite**: list every attendee email with response status "invite will be sent". The Calendar API sends invites depending on `sendUpdates` (default for create is `none` unless the request sets it). The preview states the effective behaviour: the tool definition pins `sendUpdates` in its `query:` so the preview can say "invites WILL be emailed to N people" or "no emails will be sent". This must be pinned in the YAML, not an agent arg, so the statement is true.
- Optional lookup: `GET .../events?timeMin&timeMax` for conflicts: "overlaps with: Dentist 14:30-15:00". Failure just omits the conflict line with a note.

Summary: `"Standup" Tue 14:00-14:30 (New York), 3 invitees`.

### 4.3 gh_put_contents

Not in `tools/github.yaml` yet (added in plan step 9, with `gh_create_branch`, `gh_get_branch`, `gh_get_contents`). Proposed definition: `PUT /repos/{owner}/{repo}/contents/{path}` with `branch`, `message`, `content` (base64), and `sha` (blob sha of the file being replaced; absent for a new file).

Renderer `diff`:

1. Trusted lookup: `GET /repos/{owner}/{repo}/contents/{path}?ref={branch}` using the gateway token.
   - 404: **new file** ("creates path on branch, N bytes").
   - 200: decode current content; produce a unified diff against the decoded new content.
   - Too large (lookup `size` over `diff.max_bytes`, default 256 KiB) or `content` empty because GitHub withheld it: show only sizes and old/new blob sha, "diff not shown (too large)".
2. Binary detection (NUL byte or invalid UTF-8): no diff, show sizes and sha256 of old and new.
3. Show: repo, branch (and whether it is the default branch: warn "writes directly to default branch"), path, commit message (the arg, shown as the exact commit message), mode (new / modify / identical, "no change"), +/- counts, unified diff with 3 lines of context. Large diffs truncate at 400 lines with a count.
4. **Base sha binding.** The tool declares `sha` as a required arg for updates, and the preview checks that the lookup's current blob sha equals the `sha` the agent sent:
   - equal: "Diff is against the version the agent based its change on."
   - different: red warning "File changed since the agent read it. Executing would be rejected by GitHub (409)". In practice GitHub itself rejects a PUT whose `sha` does not match the current blob, so a stale base fails safe at execution.
   - Because `sha` is an ordinary arg, it is part of the canonical args and therefore **in the passkey challenge**. That is the binding: the operator approves "replace blob X with content Y", and GitHub refuses to apply it if the branch moved. The gateway does not need to re-check at execution, but the audit entry records the GitHub result.
   - For new files (`sha` absent), the preview does lookup; if the file now exists the PUT is rejected by GitHub (422), also fail-safe.
   - Branch moves that do not change this file's blob do not matter: the diff is still exact for that file.
5. Path safety display: show the path in a monospace line with control characters escaped; warn on `..` segments, a leading `.github/workflows/` ("changes CI"), `.gitmodules`, or hidden dot-directories. These are warnings, not blocks; policy decides blocks.

### 4.4 gh_delete_repo

Existing tool, args `owner`, `repo`. Renderer `resource_summary` with lookups:

- `GET /repos/{owner}/{repo}`: full name, private/public, `archived`, `fork`, `default_branch`, `pushed_at` ("last push 3 days ago"), `created_at`, `stargazers_count`, `forks_count`, `open_issues_count` (GitHub counts issues and PRs together here), `size`, `visibility`, `has_pages`, `parent`.
- `GET /repos/{owner}/{repo}/pulls?state=open&per_page=1` and read the count via the `Link` header, or `GET /search/issues?q=repo:..+type:pr+state:open` for an exact PR count. If only the combined count is available, say "open issues and PRs: N".
- Optional: collaborators count, whether Actions secrets exist (may need scopes the token lacks; omitted on failure).

Display, in red: "PERMANENTLY DELETES `owner/repo`. Code, issues, PRs, wiki, releases, and stars are removed. Forks are not deleted." Plus the facts above. Warnings: public with many stars, pushed within the last 30 days, not archived, has open PRs.

**Typed confirmation.** `confirm_text: "<repo>"`. On the passkey page the "Approve with passkey" button is disabled until the operator types the exact repo name (case-sensitive). The check is client-side UX only and is not a security boundary; the real boundary is the passkey assertion. It makes the operator read the name instead of tapping through. For Telegram, a delete has `require: passkey` (recommended default for this tool; see section 8), so the button just links to the page.

### 4.5 gh_create_pull, gh_update_pull, issues

`gh_create_pull` exists; `gh_update_pull` and `gh_update_issue` are added in plan step 9 and follow the same pattern.

Template renderer:

- Repo, title (exact), base <- head (with "from fork `x`" if head is `user:branch`), draft or not, labels, body in a text section (Markdown shown as plain text, not rendered; limit 20,000 chars).
- Lookups for `gh_create_pull`: `GET /repos/{o}/{r}/compare/{base}...{head}` gives ahead_by, commit count, and `files` (first 50: filename, status, additions, deletions). Shown as "Changed files: 7 (+120 / -30)" plus a list. If the compare fails (branch missing): `unavailable (head branch not found)`. Warn if ahead_by is 0.
- For `gh_update_pull` / `gh_update_issue`: `GET` the current object and show a field-level before/after for every changed field (title, body diff, state open -> closed, base branch change, labels added/removed, assignees). Fields not in the args are not shown as changing.
- For `gh_create_issue`: title, body, labels (and a warning if a label does not exist, via the label list lookup, optional).
- For `gh_create_issue_comment`: target issue/PR title and state (lookup) plus the comment body.

### 4.6 ha_call_service and ha_fire_event

Renderer `entity_state`:

- `ha_call_service` with `entity_id`: lookup `GET /api/states/{entity_id}`; friendly name (`attributes.friendly_name`), current state, device class, last changed. Effect line from a small built-in table of `(domain, service) -> verb` for common ones: `lock.unlock` "UNLOCK", `lock.lock` "lock", `cover.open_cover`, `alarm_control_panel.alarm_disarm`, `light.turn_on`, `switch.turn_off`, `climate.set_temperature`, `homeassistant.restart`. Unknown services: "calls `domain.service`" plus the raw service data. Example: **"UNLOCK Front door (lock.front_door), now: locked"**.
- Service data args (brightness etc.) listed as a kv table, as validated.
- Missing `entity_id`: services like `homeassistant.restart` or `script.turn_on` may target everything. Show "no entity specified: acts on ALL matching targets / the whole system" as a warning. If the HA lookup 404s: "entity not found; HA will reject or ignore".
- `ha_fire_event`: no entity. Show event type and the request body (event data) as JSON. Optional lookup: none. Warning: events can trigger automations, whose effect the gateway cannot see. Optionally, if the config provides `preview.automations_lookup`, `GET /api/states` filtered to automations is not feasible generically, so by default say only "may trigger automations listening for this event".
- Honest limit: for `script.*`, `scene.*`, `automation.trigger`, the preview shows the entity's friendly name and state but not what the script does (HA does not expose that over the plain REST API). The renderer prints "runs script X (contents not shown)".

## 5. Agent-supplied context (`agent_note`)

### Transport

An MCP client such as Hermes can only fill the arguments the tool's `inputSchema` offers; it has no envelope to write into. So the note travels as an ordinary optional property that the **gateway adds to every tool's inputSchema** on `tools/list` (MCP) and `tools` (WebSocket API). This follows the existing `idempotency_key` precedent in `mcp.py`, which is also added to each schema after `input_schema(tool.args)` and popped before the pipeline sees the args.

```json
"agent_note": {
  "type": "string",
  "maxLength": 500,
  "description": "Optional: explain to the human approver why you need this call. Shown to them as unverified agent text."
}
```

- The property is never declared in tool YAML and never appears in `tool.args`. A tool YAML that declares an arg named `agent_note` (or `idempotency_key`) is rejected at load time by `config.py`, so a real arg can never be shadowed.
- `maxLength` is advisory to the model. The gateway enforces the limit itself (below).
- Not `required`; omitting it is normal. Gateway-native tools (`GATEWAY_TOOLS`) do not get it.

### Stripping point

The note is removed at the **transport adapter**, before `Pipeline.process` is called, in the same place `idempotency_key` is popped (`_tool_call` in `mcp.py`, the equivalent handler in `server.py`):

```python
args = dict(arguments)
key  = args.pop("idempotency_key", None)
note = args.pop("agent_note", None)          # NEW
note = sanitize_note(note)                   # type check, strip, truncate to 500
outcome = await pipeline.process(identity, name, args, idempotency_key=key, agent_note=note)
```

Consequently the note never reaches: arg validation (`validate_args`, so unknown-arg rejection does not trip on it), signature building, the canonical-args hash (passkey challenge and remembered-rule `args_hash`), remembered-rule matching, the rate limiter, the engine, or the executor and the upstream request. `Pipeline.process` gets it as a separate keyword and hands it only to the coordinator (display) and the audit writer (record). Stripping at the adapter, not inside the pipeline, means a third adapter cannot forget it silently: `process` has no `args["agent_note"]` path at all, and a stray `agent_note` that reaches `validate_args` is rejected as an undeclared arg.

`sanitize_note`: non-string becomes `invalid_params` (the model is told its note was malformed, the call is not run); empty or whitespace becomes `None`; control and bidi-override characters are removed, newlines collapse to spaces, then truncate to 500 characters with an ellipsis. Idempotent replay: the note is not part of the idempotency fingerprint, so a retry with a reworded note joins the original call and keeps the first note.

### Display, signing, audit

- **Display**: its own box titled "Unverified text from the agent", plain text, visually distinct (different background, icon), always below the trusted preview, never interleaved. Not shown in Telegram except behind the page link (keeps Telegram text small and avoids a social-engineering channel on the most casual surface). Never used to build `summary`, `title` or `warnings`. Never sent to notify-only channels.
- **Passkey challenge: not included** (agreed). The note is context, not authority. Including it would make the proof cover text the operator cannot meaningfully verify and would let the agent alter proof inputs by rewording. The tool and args are what executes, so those are what is bound.
- **Audit: stored** (agreed) in `audit_log.agent_note`, same 500-char limit, labelled unverified in the dashboard. It is short and agent-chosen, so `audit.redact_args` does not apply to it.
- It is never fed into policy decisions, rate limits or remembered-rule matching.

### Tests

1. `tools/list` over MCP and the WebSocket API: every YAML tool's schema has `agent_note` with the description above; gateway-native tools do not.
2. Config: a tool YAML declaring an `agent_note` arg is rejected; `check-config` reports it.
3. Stripping: for each adapter, a call with `agent_note` produces exactly the same `validate_args` input, signature, canonical args, passkey challenge bytes, remembered-rule `args_hash` and upstream request as the same call without it (assert equality, parametrized over several tools).
4. A remembered "exact" rule created from a call with note A matches a later call with note B or no note.
5. Executor never receives the key: the mocked HTTP service sees no `agent_note` in query, body or headers.
6. Sanitising: non-string rejected; 10,000-char note truncated to 500; control/bidi characters removed; empty becomes `None`.
7. Idempotent replay with a different note joins the original and keeps the first note.
8. Audit row holds the sanitized note; the passkey page shows it in the unverified box (HTML-escaped; hostile `<script>` string is inert); Telegram message does not contain it; a notify-only channel never receives it.
9. A bare `agent_note` passed straight into `Pipeline.process` args (adapter bypassed) is rejected by validation as an undeclared arg.

## 6. Where previews are shown

| Surface | Content | Why |
| --- | --- | --- |
| Passkey page | Full preview, warnings, lookup notes with timestamps, raw args (collapsible), agent note box, typed confirmation where declared | Page has room, is the place where the cryptographic proof is made |
| Telegram (trusted channel) | `title`, `summary` (<= 300 chars), top 3 warnings, link to the page | Telegram messages are small, and the message may sit in notifications and screenshots |
| Notify-only channels (webhook, command) | **No preview.** Today's tool + signature + `arg_display` only | These are not trusted: webhooks go to third parties or logs |
| Audit dashboard | Preview digest and title only (section 7) | Dashboard is list/revoke; avoid a second store of bodies |

The `require: passkey` and Telegram flows are unchanged. Telegram "Approve" buttons are still shown for tools that allow Telegram approval; the Telegram summary is deliberately limited, so for `risk: high` tools whose preview is richer than the summary (email, delete), the owner may set `preview.require_page: true` on the tool, which hides Telegram approve buttons and leaves only the link. Recommendation: set this for `gmail_send_message` and `gh_delete_repo`.

`preview.require_page` matters only for rules Telegram may approve. A rule with `approval.require: passkey` can only be approved on the page anyway (Telegram shows the link only), so there it is redundant. The two compose: `require: passkey` restricts the proof kind per rule, `require_page` restricts the surface per tool; either one alone removes the Telegram approve button.

The page is only reachable on the private network (existing constraint) and the preview is served only to a request that has the approval link token; it is fetched via the same authenticated endpoint as today, never embedded in a public URL.

### 6a. Display time zone

A gateway config key `approval.display_timezone` (IANA name, default `UTC`), e.g.:

```yaml
approval:
  display_timezone: Europe/Berlin
```

It is used by every renderer that shows a time (calendar start/end, "last push", `built_at`, preview age) and by the page header. Validated at load with `zoneinfo.ZoneInfo`; an unknown name is a config error (`check-config` exit 1), not a silent fallback. The zone is shown in the preview ("times in Europe/Berlin"). Event times keep their own zone as well, so both are visible. Display only: it never enters the challenge or the args.

## 7. What the approval proof covers

The passkey challenge today is `SHA-256(approval_id || agent_id || tool || canonical_json(args) || expires_at)`. Telegram callbacks bind the approval id.

Covered by the proof: tool, args (every field the agent sent after validation), agent, approval id, expiry.

Not covered, and by design: the lookup results, the rendered text, the agent note, and anything about the outside world at execution time.

Consequences, stated plainly:

- **What the operator reads is derived from the signed args** for the args-derived parts (email message, new file content, commit message, PR title). Those are exact.
- **Lookup-derived parts are a snapshot.** Current file content, device state, repo stats, attendee conflicts may change between preview and execution (up to the approval timeout). If the world changes:
  - `gh_put_contents`: blob `sha` is a signed arg, GitHub rejects on mismatch. Fails safe.
  - `gh_delete_repo`: the repo might have gained a PR or push since. The delete acts on the repo by name, which is what was signed. Accepted: the operator approved deleting that repo. The preview age is displayed.
  - `ha_call_service`: the lock may have been unlocked meanwhile; "unlock" still means unlock. Accepted.
  - PR/issue updates: before/after is a snapshot; the executed PATCH sets the fields signed in args.
- **Should the preview digest be in the challenge?** Option A: include `preview.digest` in the challenge, so the proof covers exactly what was displayed. Option B: keep it out. Recommendation: **B for now.** It makes approval fail whenever a refresh changes a harmless field, couples the verify code to the renderer, and gives no execution-time guarantee (the executed call is still args-only). Instead, **record the digest in the audit row** (`preview_digest`) along with the page's confirmed version, so after the fact you can say which preview the approver saw. This is revisited in open questions.
- A passkey signature proves a human with the device confirmed *the challenge*. The challenge does not include the preview, so a compromised gateway could show one preview and approve different args. The threat model already treats the gateway as trusted; the page is served by it. If the owner wants protection from a malicious page, the preview digest must also be derivable by the authenticator side (not possible with plain WebAuthn; a hardware key with a display would be needed). Out of scope.

## 8. Privacy and audit

- **Notify-only channels never get a preview** (enforced in the coordinator by `channel.trust == "trusted"`, not by the renderer).
- **Storage of the preview**: the full preview JSON is stored on the `pending_requests` row while pending (needed so a restart can re-serve the page) and **deleted when the request resolves** (approved, denied, timed out). A short retention exception: none.
- **Audit log** stores: `preview_digest`, `preview_title`, `preview_status` (`ok`, `partial`, `unavailable:<reason>`), and `agent_note`. It does **not** store mail bodies, diffs, or lookup content. Args in the audit remain handled by `audit.redact_args` as today (e.g. `gmail_send_message` `raw` should be added to `redact_args`, since it is the whole mail).
- Option for owners who want it: `audit.store_preview: true` per tool, which stores the full preview text. Default off.
- **Logs**: preview content is never logged at INFO and below. Lookup errors log the tool, lookup id and status code only.
- **Telegram retention**: Telegram messages persist on their servers. The summary deliberately excludes body text. Subjects can be sensitive, so `summary` for email defaults to recipient + subject length rather than subject: configurable (`preview.telegram: minimal|summary`), default `summary` without body.
- Lookups use the gateway's credentials and are read-only, but they are still requests the agent can trigger. They are made only when a request has reached "ask" (after validation and policy), and are rate-limited with the pending-request limit, so an agent cannot use previews to scan a repo.

## 9. Threat notes

| Threat | Mitigation |
| --- | --- |
| Agent puts markup or script in a body/title to attack the page | Renderers emit plain strings only; one escaping point in the template; strict CSP; no HTML rendering of mail |
| Agent hides recipients (Bcc, `Resent-To`, duplicate headers, folded headers) | Parse the exact `raw` that will be sent; show Bcc; warn on odd headers; message sent is byte-for-byte the signed `raw` |
| Homograph or display-name spoofing of addresses | Show address and display name separately, punycode alongside Unicode, warn on mismatch |
| HTML mail shows different text from plain part | Warn when parts differ; never render HTML |
| Agent text imitates trusted UI ("Verified safe: yes") | Separate box, label, length limit, control/bidi stripping, never in Telegram or `summary` |
| Bidi/control characters in paths, names, bodies reverse text visually | Escape control and bidi override characters in all agent-derived strings (shown as `‮`) |
| Preview lookups used for SSRF or data exfil | GET-only, host fixed to the tool's service, path from validated args, response size cap |
| Preview hangs or errors to delay or trick | Timeout; failure means "unavailable" with raw args; never auto-approve; request still expires normally |
| Large payload exhausts memory | Hard caps on bytes, lines, parts; lookups reuse response caps |
| Stale preview | Show built-at age; `sha` binding for file edits; optional refresh; limitations in section 7 |
| Preview leaks to notify channels or audit | Trust check in coordinator; audit stores digest/title only |
| Operator over-trusts a green preview | Language always says what is not shown ("script contents not shown", "diff not shown (too large)", "preview is partial") |
| Agent causes lookup for a repo it cannot access | Lookup uses gateway token; any result is shown only to the operator, never returned to the agent |

## 10. Open questions, with recommendations

1. **Should the agent note be signed?** No (section 5). Store it in audit.
2. **Preview digest in the passkey challenge?** Not now; record in audit (section 7). Revisit if the owner wants "what you saw is what you signed" for high-risk tools; would need a challenge version bump and a pinned preview during approval (no refresh).
3. **Refresh button on the page?** Yes, but optional and off for the first iteration. Without refresh, an expired preview just shows its age.
4. **Telegram: allow approve button for tools with rich previews?** Recommend `preview.require_page: true` for `gmail_send_message` and `gh_delete_repo`, so a quick tap cannot approve what was not read.
5. **Remembered decisions ("Allow always") with previews?** Recommend: previews are shown for the first approval only; remembered "exact" matches skip them (same as skipping the prompt). "Tool" scope for tools with `preview.require_page` should be hidden, since a blanket allow defeats the point of reading each one.
6. **Calendar: which tool args are signed?** The current signature is `{calendar_id}, {summary}`; the canonical-args hash covers all args. Fine. Pin `sendUpdates` in the YAML.
7. **Template language scope?** Start with the tiny `{path}` substitution above; add built-ins instead of expanding the language. Revisit only if three or more tools need the same new feature.
8. **HTML mail: sanitized rendering later?** Not planned. Text conversion only.
9. **Typed confirmation for other destructive tools** (`gh_update_branch_protection`, `gh_delete_deploy_key`, `gh_set_actions_secret`)? Recommend yes via `confirm_text: "{repo}"`, cheap once the mechanism exists.
10. **Large attachments** in `raw` (100 KB base64 cap): list only. No decision needed.
11. **Time zone for the operator**: decided, see section 6a.

## 11. Implementation plan

1. **Model and storage.** Add `Preview`/`Section` dataclasses (`preview/model.py`), `ApprovalRequest.preview`, `pending_requests.preview_json` column and `audit_log.preview_digest/preview_title/preview_status/agent_note` (migration v5, idempotent). Clear `preview_json` on resolution.
2. **Config.** Parse and validate the `preview:` block in `config.py` (GET-only lookups, placeholder checks, limits). Extend `check-config` with the lints. Unit tests with bad configs.
3. **PreviewService.** Lookup runner on top of the existing service client (timeouts, size caps, GET-only), template renderer, escape/strip helpers for control and bidi characters. Failure returns `Unavailable(reason)`.
4. **Coordinator wiring.** Build the preview before fan-out, attach to `ApprovalRequest`, never to notify channels, never block on failure. Tests: failure, timeout, and notify-channel exclusion.
5. **Passkey page.** Render sections, warnings, lookup notes, raw args collapsible, agent note box, CSP, typed confirmation. Tests on escaping with hostile strings.
6. **Telegram.** Add `summary`, top warnings and the page link; honour `require_page`.
7. **Built-in renderers, one at a time, each with fixtures:** `entity_state` (HA), `resource_summary` (gh_delete_repo, gh_get-style), `email`, `diff` (with `sha` handling).
8. **Agent note.** Add the `agent_note` property to the MCP and WebSocket tool schemas, the adapter-level pop and `sanitize_note`, the `agent_note` keyword on `Pipeline.process`, the config-load reject for a tool arg of that name, and the tests listed in section 5.
9. **Tool YAML (public `tools/github.yaml`).** Add the tools below, each with a `preview:` block from this design, and update the GitHub policy file so the new writes ask:
   - `gh_get_branch` (GET `/repos/{o}/{r}/branches/{branch}`), `gh_get_contents` (GET `/repos/{o}/{r}/contents/{path}?ref=`): `risk: low`, allowed like the other reads.
   - `gh_create_branch` (POST `/repos/{o}/{r}/git/refs`, `ref: refs/heads/{branch}` pinned in the YAML, `sha` arg): `risk: medium`.
   - `gh_put_contents` (PUT `/repos/{o}/{r}/contents/{path}`; args `branch`, `message`, `content`, `sha` signed): `risk: medium`, `preview: renderer: diff`.
   - `gh_update_issue` and `gh_update_pull` (PATCH): `risk: medium`, `preview` with before/after fields.
   - **Writes never go to the default branch unless a rule allows it.** `gh_put_contents` and `gh_create_branch` gain a deny rule in `policy/github.yaml` for the repository's default branch names (`main`, `master`) by signature (`{owner}/{repo}, {branch}`), which an operator can override per repo with an explicit allow/ask rule. Because the default branch name is not always `main`, the preview also looks it up (`gh_get_repo` lookup) and warns "writes directly to the default branch"; the deny rule is the enforcement, the warning is the backstop.
   - Other tool changes: add `sendUpdates` (pinned) and `attendees` to `calendar_create_event`; add `raw` to `redact_args` for `gmail_send_message`; add `preview:` to the existing tools in section 4.
10. **Audit.** Store digest, title, status, agent note; dashboard shows them.
11. **Docs.** Update `DESIGN.md` and `CLAUDE.md` structure listing; document the `preview:` format in `config.example.yaml`.
12. **Later (separate cards):** refresh button, digest in challenge (if chosen), optional full-preview audit storage.

Step 8 can ship independently of 1-7 only for the schema and stripping; the display half needs step 5. Steps 1-5 are enough to ship the template renderer and a first tool (`ha_call_service`). Renderers in step 7 add the delete-repo flow; email and diff are the largest and can follow.
