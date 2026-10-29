# Agent Gateway design

Goal: a self-hosted gateway that holds the operator's full-scope tokens (GitHub, Google, Home Assistant, more later) on a host that agents can also reach. Agents act through it under allow / ask / deny rules plus human approval. Agents must never read the real tokens and must never approve their own requests.

## 0. Summary of decisions

| Topic | Decision |
| --- | --- |
| Trust boundary | The gateway runs as its own Unix user (for example `agentpass`) under a service manager such as systemd, outside any container daemon the agents control. All secrets, the DB and the token store are owned by that user, mode 0600/0700. |
| Agent access | Per-agent token over a Unix socket (WS/JSON-RPC and MCP) plus optional loopback TCP. Tokens are stored hashed. |
| Approval authority | Only *trusted* channels can approve: Telegram (dedicated bot, token unreachable to agents) and a passkey (WebAuthn) approval page. Chat-bridge, webhook and command channels are *notify-only* unless they relay a WebAuthn assertion. |
| Approval proof | The passkey challenge is a hash over request id, agent, tool, canonical args and expiry, so an approval cannot be replayed or applied to different args. |
| Config | One gateway file plus one file per service, per agent and a shared deny floor. Secrets live in a separate secrets file and are resolved after YAML parsing. |
| Channels | Gateway-owned `ApprovalCoordinator`: fan-out, atomic first-answer-wins, gateway-owned timeout, explicit result reasons. Adapters only send and report. |
| MCP | Streamable HTTP (and a stdio shim). Long approvals: inline wait with progress notifications, then a non-error `pending_approval` result and a `gateway_result` retry tool. |
| OAuth | `auth.type: oauth2` with a single-flight token provider, a 0600 token store, and `agentpass auth <provider>` using a paste-back redirect with PKCE. |
| Dashboard | Unix-socket only by default. `/healthz` on loopback exposes no data. |

## 1. Trust model and deployment

### 1.1 Threat model

Agents run as an unprivileged user on the same host as the gateway. We assume an agent (or a prompt-injected agent) can run arbitrary commands as that user, including starting containers it owns, reading anything that user can read, and talking to any localhost port or Unix socket it can reach. We assume agents cannot become root and cannot read files owned by another user with mode 0600/0700.

The gateway must hold up against:

- reading tokens (service tokens, OAuth refresh tokens, the Telegram bot token);
- approving its own request (via a channel it can reach, via the Bot API, via the approval web page);
- changing its own permissions or another agent's;
- reading other agents' pending results or audit rows;
- tampering with the audit log.

Out of scope: root compromise, compromise of the operator's phone or passkey, a malicious upstream service.

### 1.2 Process isolation

- A dedicated system user such as `agentpass` (no login shell, no membership in the agents' groups, not in any container-runtime group). The gateway runs as a service under that user, from its own Python virtualenv. It must **not** run inside a container daemon owned by the agent user: that user could inspect, exec into or replace the container.
- Suggested layout:

  | Path | Owner / mode | Contents |
  | --- | --- | --- |
  | `/etc/agentpass/` | service user, 0700 | `gateway.yaml`, `services/`, `tools/`, `agents/`, `policy/` |
  | `/etc/agentpass/secrets.yaml` | service user, 0600 | service tokens, OAuth client secrets, Telegram bot token |
  | `/var/lib/agentpass/` | service user, 0700 | `agentpass.db`, `tokens/` (OAuth store), passkey public keys |
  | `/run/agentpass/agent.sock` | service user, group `agentpass-clients`, 0660 | agent-facing socket |
  | `/run/agentpass/admin.sock` | service user, group `agentpass-admin`, 0660 | dashboard and admin API |

- Service hardening (systemd example): `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths=/var/lib/agentpass /run/agentpass`, and a memory cap.
- Config writes are by the operator (as root or via `sudo -u agentpass`). The agent user cannot edit policy. A policy change by an agent has to go through the operator, not through the gateway.
- No agent user is in `agentpass-admin`. Only the user that runs the agent is in `agentpass-clients`, which grants the ability to *connect*, not to authenticate.

### 1.3 Ports

By default the agent API uses a Unix socket and needs no port. Optional listeners, all loopback:

| Port | Use |
| --- | --- |
| none (Unix socket) | Agent API (WS and MCP) by default |
| 127.0.0.1:8205 (example) | Optional loopback TCP for MCP clients that cannot use a socket |
| 127.0.0.1:8206 (example) | Approval/passkey web page. WebAuthn needs HTTPS, so publish it only on a private network, for example with `tailscale serve`. Never expose it on the public internet |

TLS is terminated in front of the gateway for the approval page, so the gateway itself runs plaintext on loopback only; the WSS-by-default rule remains for any non-loopback listener. List ports that other software on the host uses in `gateway.reserved_ports` and `check-config` rejects collisions. The sample `docker-compose.yml` is a generic example only; it does not give the isolation described above.

### 1.4 Prerequisites that need root

Creating the service user, the two groups, `/etc/agentpass` and the service unit needs root on the gateway host. Everything else in this document is buildable without root once that exists.

## 2. Risks and how the design handles them

| # | Risk | Decision | Reason / where |
| --- | --- | --- | --- |
| 1 | Same-host trust | **Mitigate** | Separate service user (section 1). Deployment requirement, not code. |
| 2 | Telegram bot token = approval authority | **Mitigate** | Dedicated bot, token only in `secrets.yaml`, never shared with any agent tooling (section 3.5). |
| 3 | Container deployment conflicts with isolation | **Mitigate** | Service-manager deployment, loopback binds, data under `/var/lib/agentpass` (section 1.3). Compose is an example only. |
| 4 | Unauthenticated dashboard | **Mitigate** | Unix-socket-only dashboard; `/healthz` returns no data (section 9). |
| 5 | Plaintext args/results in audit | **Accept with mitigation** | Needed for audit value. Per-tool `audit.redact_args` and `audit.store_result: none/truncated/full`. The DB is readable by the service user only. Back it up by a job the operator controls. |
| 6 | Uncaught engine error, no reply | **Mitigate** | Evaluation is wrapped; value and type errors map to a JSON-RPC invalid-params error. A request is never left unanswered. |
| 7 | Signature mismatch between audit and policy | **Mitigate** | The signature is built once, with the registry, and used for policy, audit and the approval message. |
| 8 | Argument validation gaps | **Mitigate** | `fullmatch`; undeclared args are rejected; all scalar and nested values are checked; path args are percent-encoded as single segments; optional args render as absent, not empty string (section 8). |
| 9 | Unknown tools reach a human | **Mitigate** | Unknown tool names are rejected before the engine with a distinct error. |
| 10 | Pattern semantics fragile | **Partly mitigate** | `agentpass check-config` lints unreachable defaults and patterns that match no tool, and a golden test loads the example permission files against the real tool YAML. `defaults` are first-match and `rules` are deny-wins. Signature templates are part of a tool's public contract; changing one is a breaking change. |
| 11 | Auth weaknesses | **Mitigate** | `hmac.compare_digest`; the connection slot is taken only *after* auth; per-source auth-failure rate limit with logging of offenders. |
| 12 | Channel send failure orphans a pending row | **Mitigate** | The coordinator treats send failure per channel and fails the request only if no channel received it (section 4). |
| 13 | Restart behaviour | **Mitigate** | On start, leftover `pending` rows become `abandoned`, their messages are edited ("gateway restarted, request expired"), and the agent can retry. Callback data is stateless (`<approval_id>:<y\|n>`). |
| 14 | Offline results leak across identities | **Mitigate** | `agent_id` column on `pending_requests`; `get_pending_results` and `gateway_result` filter on it. |
| 15 | HTTP service robustness | **Mitigate** | Response types and `max_bytes`; per-tool `timeout`; upstream error bodies are truncated and never echoed unless the tool opts in; redirects are disabled by default and never followed cross-origin with credentials. |
| 16 | Audit not tamper-evident | **Defer** | With the gateway on its own user the agent cannot write the DB. A hash chain (`row_hash = sha256(prev_hash || canonical_row)`) is cheap and can be added if off-box audit export is wanted. |
| 17 | Env substitution on raw YAML | **Mitigate** | YAML is parsed first, then substituted per scalar (`${env:X}`, `${secret:name}`), so values cannot change structure. |
| 18 | Dead `ToolResult`, unset `timeout_task` | **Mitigate** | The result type is the pipeline `Outcome`; timeout ownership is in the gateway. |

## 3. Out-of-band approval proof

### 3.1 The problem

If an approval can be produced by anything an agent can run, an agent can approve its own request. That includes: a chat-bridge or notification plugin that exposes an "approve" action on the same host; any HTTP approval page reachable on localhost; the Telegram Bot API if the agent holds the bot token; a one-time code that is sent over a channel the agent can read.

### 3.2 Channel trust classes

Every channel is configured with a `trust` level, which determines whether its answer can resolve an approval.

| Trust | May approve? | Examples | Why |
| --- | --- | --- | --- |
| `trusted` | Yes | Telegram bot (dedicated, token held by the service user), passkey approval page | The decisive act happens on an operator device outside the host. The gateway verifies the origin itself. |
| `notify` | No, may only display and deep-link | Chat-bridge plugin, webhook, command, desktop notifications | Co-located with agents; anything it reports can be forged by an agent that shares the host. |

A `notify` channel may show the request (agent, tool, args) and a link to the approval page. If it wants to be able to approve, it can relay a **WebAuthn assertion** (section 3.4), which is verified by the gateway and cannot be minted by anything on the host.

### 3.3 Telegram as a trusted channel

- The gateway holds the bot token; only the service user can read it. A tap arrives as a Telegram update fetched by the gateway with its own token and carries `from_user.id`, which Telegram sets; the gateway checks it against `allowed_users` (numeric ids, not usernames). An agent cannot forge a tap from the operator's account.
- An agent *with* the bot token could call the Bot API, post messages and read updates (not forge taps). Hence the token never leaves the service user's files (section 3.5).
- Weakness: a Telegram tap is a bearer action by an account. If the operator's Telegram account is compromised, so are approvals. Rules marked `approval.require: passkey` remove Telegram from the decision (section 3.4) for high-risk actions. Telegram then only leads to the page: the message shows an "Approve with passkey" URL button and Deny, with no Allow buttons.
- Approval ids are 128-bit random and callback data is `<approval_id>:<y|n>`. The gateway rejects callbacks for ids that are not currently `pending`.

### 3.4 Passkey-protected approval page

The strongest option and the recommended default for high-risk rules.

- The gateway serves a small web app on a loopback port (example `127.0.0.1:8206`), published only on a private network over HTTPS, for example with `tailscale serve` (WebAuthn needs a secure origin; see 1.3). It is never published on the public internet. Anything on the host can *reach* the page, but nothing on the host can *complete* it.
- Enrolment: the operator runs `sudo -u agentpass agentpass passkey enroll`, which prints a one-time enrolment URL valid for 10 minutes. The operator opens it on their phone or laptop and registers a platform passkey (resident key, user verification required). The gateway stores only the public key (under `/var/lib/agentpass/`). The private key never exists on the host.
- Approval: the page lists pending requests (agent, tool, full args, risk). On Approve or Deny, the browser calls `navigator.credentials.get` with `challenge = SHA-256(approval_id || agent_id || tool || canonical_json(args) || expires_at)` and user verification required. Each of the five fields is UTF-8 encoded and length-prefixed (4-byte big-endian byte length, then the bytes), so field boundaries are unambiguous (`"a"+"bc"` and `"ab"+"c"` hash differently). `canonical_json` uses sorted keys, no whitespace and ASCII-only output; `expires_at` is normalised to `YYYY-MM-DDTHH:MM:SSZ`. The gateway verifies the assertion against the enrolled public key, checks the challenge matches the pending approval and that it has not expired, and checks the signature counter increases. Synced platform passkeys report a sign count of 0, so the increase check is exempt when both the stored and the reported counter are 0. A Deny does not need a passkey signature (denying is always safe); an Approve always does.
- Because the challenge covers the canonical args, an approval cannot be replayed on another request or on altered args.
- Page sessions are not trusted: each Approve is its own assertion, so a stolen session cookie is useless. The page sets `Content-Security-Policy`, `X-Frame-Options: DENY` and `SameSite=Strict`, and is served only on the exact configured origin (checked against the WebAuthn `rpId`/origin).
- A request that arrives without a valid assertion is logged to the audit trail as `approval_rejected` with the source address. Failed attempts are rate limited.

### 3.5 Keeping the Telegram token and approval credentials unreachable

- Telegram token, OAuth client secrets, service tokens: in `/etc/agentpass/secrets.yaml` (0600, service user), loaded into memory at start. systemd `LoadCredential=` is the preferred mechanism so the file need not be readable after start.
- Never in env vars of anything an agent user can inspect, never in a container an agent user runs, never in the repo, `ps` arguments or logs (log redaction filter for anything matching a known secret value).
- A **dedicated** approval bot. If the agent tooling has its own Telegram bot, the approval bot must be a separate one, in a chat only the operator is in. The agent side must never be configured with it.
- Passkey: only public keys are stored on the host, so there is nothing to steal.
- One-time codes are **not** used as a primary mechanism: a code displayed on a channel the agent can read would be readable by the agent. They are used only for enrolment, delivered by the operator's own root or service-user terminal.
- Admin API (section 9) is on `admin.sock`, group `agentpass-admin`, which no agent user belongs to.

### 3.6 Rule-level requirements

A rule can say how strong the approval must be (section 5.3):

```yaml
- pattern: "gmail_send(*)"
  action: ask
  approval: { require: passkey, timeout: 900 }
```

`require` is `any_trusted` (default), `telegram` or `passkey`. The coordinator only counts answers from channels satisfying it.

## 4. Approval channel interface and coordinator

### 4.1 Interface

```python
class ApprovalChannel(ABC):
    name: str
    trust: Literal["trusted", "notify"]
    proof_kinds: set[str]            # {"telegram_callback", "webauthn"}

    async def start(self, sink: ApprovalSink) -> None: ...
    async def stop(self) -> None: ...
    async def send(self, req: ApprovalRequest) -> ChannelHandle: ...
    async def finalize(self, handle: ChannelHandle, outcome: ApprovalOutcome) -> None: ...
```

- `ApprovalRequest` carries `approval_id`, `agent_id` (name), `tool`, `signature`, full `args` (with per-arg display hints), `risk`, `expires_at`, `require`.
- Adapters call `sink.answer(approval_id, Answer(approved, channel, approver_id, proof))`. They never decide anything and hold no race state.
- `finalize` edits or removes the message on every channel once the request is resolved (approved by X, denied, expired, restart).
- Lifecycle (`start`/`stop`, the PTB manual lifecycle from `CLAUDE.md`) is behind the adapter; `main` builds channels with `build_channels(config)`.

### 4.2 Coordinator (gateway-owned)

`ApprovalCoordinator.request(ApprovalRequest) -> ApprovalOutcome`:

1. Insert the `pending_requests` row (`state=pending`).
2. Fan out `send` to all channels listed for the rule (default: all configured channels). A failed `send` on one channel is logged and does not fail the request; if **no** channel accepted the request, the row is deleted and the agent gets a `no_channel` error.
3. Wait on a future with `asyncio.wait_for(timeout)` owned by the coordinator. The adapter has no timeout logic.
4. **First valid answer wins.** `sink.answer` validates the channel's trust and proof against the rule's `require`, then does an atomic transition `UPDATE pending_requests SET state=? WHERE id=? AND state='pending'`. Only the answer that changed one row wins; later answers get "already resolved" and are ignored. The race handling lives once, in the coordinator, using the DB as the arbiter (it also survives restarts).
5. After resolution call `finalize` on every channel.

`ApprovalOutcome.reason` is an enum: `approved`, `denied`, `timeout`, `no_channel`, `gateway_shutdown`, `restart`, `rejected_proof`.

### 4.3 Timeouts and restart

- Default `approval_timeout: 900`, overridable globally, per agent and per rule. Timeout resolves as `denied/timeout` and is audited.
- On start, any leftover `pending` row becomes `abandoned`, channels are asked to finalize their messages as expired, and the operator is not asked again. Agents get `restart` and retry (idempotency key, section 7.4).
- Scoped approvals ("allow for N minutes") are out of scope for the first version. `ApprovalChoice` stays Allow/Deny, but `Answer` has an optional `scope` field to avoid a schema change later.

### 4.4 Channels shipped, in order

1. Telegram (refactor of the existing adapter: stateless callbacks, no persistence file).
2. Passkey approval page.
3. `notify`-only adapters: webhook and command (display plus link, for chat bridges and notification tools). Whether a plugin ever relays assertions is deferred.

## 5. Configuration and rule format

### 5.1 File layout

```
/etc/agentpass/
  gateway.yaml          # listeners, channels, storage, defaults
  secrets.yaml          # 0600; ${secret:name} targets
  services/<name>.yaml  # one file per upstream service/account
  tools/<name>.yaml     # tool definitions (extended, section 8)
  policy/_floor.yaml    # gateway-wide deny rules that no agent file can override
  agents/<agent>.yaml   # identity + that agent's permission rules
```

Rules for loading: parse YAML, then resolve `${env:X}` and `${secret:name}` per scalar . Unknown keys are errors. `agentpass check-config` validates everything offline (compiles regexes, resolves tool names, lints rules) and can be run by systemd `ExecStartPre`.

### 5.2 `gateway.yaml`

```yaml
listeners:
  agent_socket: /run/agentpass/agent.sock
  agent_tcp:   { host: 127.0.0.1, port: 8205 }   # optional
  admin_socket: /run/agentpass/admin.sock
  approval_web: { host: 127.0.0.1, port: 8206, origin: "https://<host>.<tailnet>.ts.net" }  # served on a private network only; never a public hostname
channels:
  telegram:
    type: telegram
    trust: trusted
    token: ${secret:telegram_bot_token}
    chat_id: 123456789
    allowed_users: [123456789]
  passkey: { type: passkey, trust: trusted }
  chat-bridge: { type: webhook, trust: notify, url: "${secret:notify_url}" }
approval: { timeout: 900, max_pending_per_agent: 10 }
storage: { path: /var/lib/agentpass/agentpass.db }
```

### 5.3 Agent file and rules

```yaml
# agents/my-agent.yaml
id: my-agent
token_hash: "sha256:..."          # see section 6
rate_limit: { requests_per_minute: 60 }
extends: []                        # optional shared rule sets
defaults:                          # first match wins
  - { pattern: "ha_get_*", action: allow }
  - { pattern: "*", action: ask }
rules:                             # order irrelevant; deny always wins
  - pattern: "gmail_send(*)"
    action: ask
    approval: { require: passkey }
  - pattern: "ha_call_service(lock.*)"
    action: deny
    description: "Locks never"
```

- Pattern syntax is unchanged: `fnmatch` on `tool(signature)`, signature from the tool template, built once with the registry.
- Evaluation order: deny rules from `policy/_floor.yaml`, then the agent's deny rules, then allow, then ask, then the agent's `defaults` (first match), then fallback `ask`. A floor deny cannot be overridden by any agent file. There are no cross-agent rules: each agent file stands alone.
- New optional fields per rule: `approval.require`, `approval.timeout`, `approval.channels`, `risk` (`low|medium|high`, display hint only).
- Tool names not in the registry are rejected before evaluation. Rules that name no tool are warnings in `check-config`.

### 5.4 Services

```yaml
# services/google_personal.yaml
type: http
url: "https://gmail.googleapis.com"
auth: { type: oauth2, provider: google, account: personal, scopes: [https://www.googleapis.com/auth/gmail.modify] }
tools: tools/gmail.yaml
health: { method: GET, path: /gmail/v1/users/me/profile, expect_status: 200 }
```

One service file per upstream host and account. Plugin services (`handler: python`) do not need a `url` or `auth` they do not use.

## 6. Per-agent identities and audit

- Token format `agp_<id>_<secret>`; `<secret>` is 32 random bytes. Only `sha256` of the full token is stored in the agent file (tokens are high entropy, so no password KDF is needed). Auth looks the agent up by the `<id>` prefix, then `hmac.compare_digest`. `agentpass agent create NAME` prints the token once.
- Agents never hold service credentials, only their agent token. The token is how the agent proves who it is to the socket; the socket permissions only control who may attempt to connect. Optionally the gateway records `SO_PEERCRED` uid in the audit row.
- Connection state becomes a per-connection context holding `AgentIdentity`. The single-connection slot goes away: an agent may have several sessions (needed for MCP). The "one connection" behaviour moves to an optional per-agent `max_sessions`.
- Per-agent: permission file, rate limiter, pending cap, offline results, audit rows, agent name shown in every approval message.
- Audit: `audit_log.agent_id` is set from the identity. `pending_requests.agent_id` is added. A migration step based on `PRAGMA user_version` is added before any schema change. Audit also records `approval_channel`, `approver_id`, `proof_kind`, `reason`.
- Agent-visible audit: an agent can read only its own recent rows (via the `gateway_audit` MCP tool). Full audit is on the admin socket (section 9).

## 7. MCP tool surface

### 7.1 Transport

- Streamable HTTP MCP endpoint at `/mcp` on the agent socket (and optional loopback TCP), authenticated with `Authorization: Bearer <agent token>`. It is never served from the dashboard app.
- Because many MCP clients are stdio-only, `agentpass mcp-stdio` is a small shim that reads the token from `AGENTPASS_TOKEN_FILE` and proxies to the socket.
- The MCP adapter and the WebSocket adapter both call the transport-neutral `Pipeline.process(agent, tool, args, idempotency_key)` and nothing else. No policy logic lives in an adapter.

### 7.2 Tools exposed

| MCP tool | Purpose |
| --- | --- |
| one MCP tool per registry tool (e.g. `ha_get_state`, `gmail_send`) | Generated from the registry with JSON Schema `inputSchema` (section 8.1). Tools the agent's policy denies with no possible allow/ask are omitted from `tools/list`. |
| `gateway_result` | `{request_id, wait_seconds?}`: fetch the result of an earlier call that returned `pending_approval`. Long-polls up to `wait_seconds`. |
| `gateway_pending` | List this agent's open approvals. |
| `gateway_audit` | This agent's recent calls, own rows only. |

Tool `annotations` (`readOnlyHint`, `destructiveHint`) are generated from `risk` and the HTTP method.

### 7.3 Long approvals (decision)

An `ask` can take up to 15 minutes; MCP clients often time out much sooner and progress notifications do not reliably extend client timeouts. Decision: **hybrid, with pending-plus-retry as the guaranteed path**.

1. The call waits inline up to `mcp.inline_wait` (default 50 s). If the client sent a `progressToken`, the server emits progress notifications every ~10 s ("waiting for approval").
2. If approval arrives in that window, the call returns the real result.
3. Otherwise it returns a **normal (non-error) result** `{status: "pending_approval", request_id, expires_at, retry: "call gateway_result"}`.
4. Execution happens once, when approved, whether or not any session is still connected (current behaviour for the WebSocket path). The result is stored against `(agent_id, request_id)` for 24 h, then purged.
5. `gateway_result(request_id, wait_seconds)` returns `pending_approval`, `denied`, `timeout`, or the executed result. Fetching a final result marks it delivered; it is deleted after a short grace period, not at first read.

### 7.4 Idempotency

Tool calls accept an optional `idempotency_key`. A repeat of the same `(agent, key)` returns the existing approval or result instead of asking the operator again. This also covers retry after a gateway restart (section 4.3).

### 7.5 Errors

Stable error codes are shared by both transports: `invalid_params`, `unknown_tool`, `policy_denied`, `approval_denied`, `approval_timeout`, `no_channel`, `rate_limited`, `execution_failed`, `service_unauthorized`. Upstream error bodies are not echoed unless the tool opts in.

## 8. Tool YAML extensions

### 8.1 Arg definitions

```yaml
args:
  to:       { type: string, required: true, validate: "[^@\\s]+@[^@\\s]+", description: "Recipient" }
  subject:  { type: string, max_length: 200 }
  body:     { type: text, max_length: 20000, signature: false }
  limit:    { type: integer, min: 1, max: 100, default: 25 }
  format:   { type: enum, values: [full, metadata], default: metadata }
  labels:   { type: array, items: { type: string, validate: "[A-Za-z0-9_-]+" }, max_items: 10 }
```

- Types: `string`, `text`, `integer`, `number`, `boolean`, `enum`, `array`, `object`. `description` and the type produce the MCP `inputSchema`.
- `additionalArgs` is false by default: undeclared args are rejected, not forwarded. `validate` is a **fullmatch**.
- Forbidden-character checks (`* ? [ ] ( ) ,` and control characters) apply to every string that appears in the **signature**, recursively. Free text (`type: text`, `signature: false`) is exempt, because mail and issue bodies legitimately contain such characters, and is never part of the signature. The approval message shows all args in full (long values truncated with the rest on the passkey page).
- Path substitution percent-encodes every value as one path segment. `{name:path}` allows multiple segments with each segment checked against `.`/`..`/empty.

### 8.2 Request shape

```yaml
request:
  method: GET
  path: "/gmail/v1/users/me/messages/{id}"
  query:   { format: "{format}", maxResults: "{limit}" }        # omitted when arg is absent
  headers: { If-Match: "{etag}" }                                # Authorization/Host/Cookie are forbidden here
  body:    { include: [to, subject, body], map: { raw: "{raw}" } }
  timeout: 20
response:
  type: json                  # json | text | binary | none
  max_bytes: 1048576
  wrap: messages
audit: { redact_args: [body], store_result: truncated }
risk: medium
```

- `query` and `headers` values are templates over declared args; a query entry is dropped if its arg is absent (no empty-string interpolation).
- `body` with `include` (allowlist, replaces `body_exclude` as the primary mechanism) and `map` for computed fields. `multipart` is deferred.
- HA's `?x={arg}` path workaround is migrated to `query`.
- Existing `tools/homeassistant.yaml` is migrated in the same change, with a golden test that signatures remain stable.

## 9. Dashboard and admin surface

- The audit dashboard and its JSON API move to `admin.sock` (group `agentpass-admin`), served via `curl --unix-socket`, an SSH tunnel, or `agentpass admin` CLI commands. No TCP listener serves audit data.
- `/healthz` stays on loopback TCP, returns only `{"status":"ok"}` (no args, no agent names).
- Optionally the passkey web app can host a read-only audit page behind a passkey-authenticated session.

## 10. Google OAuth and token storage

### 10.1 Components

- `TokenProvider` interface: `async def header() -> dict`, with implementations `StaticBearer` (existing), `OAuth2Refresh` (Google, general OAuth2), and later `GitHubAppInstallation`. `GenericHTTPService` asks the provider for a header on each request instead of baking static headers into the session.
- `OAuth2Refresh`: single-flight refresh guarded by an `asyncio.Lock` per account; refresh when fewer than 120 s remain, and once on a `401`. Writes are atomic (temp file, `fsync`, rename).
- Failure handling: `invalid_grant` marks the account `needs_consent`, tools on it fail with `service_unauthorized` (no upstream detail), the health check goes red, and the operator is notified on `notify`/trusted channels with the exact consent command. No automatic retry loop.

### 10.2 Token store

- `/var/lib/agentpass/tokens/<provider>-<account>.json`, 0600, service user: `{refresh_token, access_token, expires_at, scopes, obtained_at}`. Written only by the gateway. Refresh tokens rotate, so they are never in YAML or env.
- Client id and client secret are in `secrets.yaml`, not the token store.
- Redirect URI and consent-screen app: use a dedicated OAuth client with a consent-screen homepage and privacy-policy page you control.

### 10.3 Consent command

`sudo -u agentpass agentpass auth google --account personal --scopes gmail.modify,calendar` :

1. Prints an authorization URL with `state`, PKCE `code_challenge` (S256), `access_type=offline`, `prompt=consent`, and the requested scopes.
2. The operator opens it in any browser. Google redirects to `http://127.0.0.1:1/` (which fails to load); the operator pastes the full redirect URL back into the terminal. This works on a headless host without an SSH tunnel. The device flow is not used because Google's device flow does not allow the Gmail/Drive scopes needed.
3. The command checks `state`, exchanges the code, writes the token store and prints granted scopes. Re-running with extra scopes does incremental consent.

`agentpass auth status` shows account, scopes, expiry, and `needs_consent`; `agentpass auth revoke` revokes at Google and deletes the file.

### 10.4 Scope control

Tokens are full scope; the real control is **narrow, per-endpoint tool YAML** with fullmatch arg validation, plus the per-agent rules. No generic "call any Google API" tool exists. This is a rule for tool authors.

### 10.5 Google 7-day refresh token expiry

OAuth apps left in "Testing" publishing status get refresh tokens that expire after 7 days. The consent screen must be moved to "In production" (sensitive-scope verification is not required for a single-user, unverified app with a warning screen, but confirm this for your project) or re-consent weekly.

GitHub: initial version stores a fine-grained PAT as a static bearer secret; GitHub App installation tokens are a later `TokenProvider`.

## 11. Pipeline (shared by all transports)

Order, once, in `Pipeline.process`:

1. Resolve agent identity (done by the transport at auth).
2. Rate limit per agent.
3. Look up tool in the registry (unknown tool → `unknown_tool`).
4. Validate and normalise args (types, fullmatch, undeclared, nested).
5. Build the signature once.
6. Evaluate policy (floor, agent) → allow / ask / deny.
7. Audit row created with decision.
8. `allow`: execute. `ask`: coordinator (section 4) then execute on approval. `deny`: error.
9. Update the audit row; return `Outcome`.

The WebSocket handler and the MCP handler are thin adapters. Typed errors map to JSON-RPC codes in one table.

## 12. Open questions

- **Approval strength for high-risk rules.** Recommendation: Telegram for reads and low-risk writes, passkey for anything that sends email, moves money or files, changes sharing or acts on locks and security devices.
- **Google OAuth project.** Use a separate OAuth client, and move the consent screen out of "Testing" (see 10.5).
- **Backup of gateway data.** Back up the audit DB (not the token store, which is re-creatable via consent) with a job the operator controls and encrypts.
- **"Allow for N minutes" approvals.** Deferred; per-request approval and remembered decisions (docs/REMEMBERED-DECISIONS.md) cover the need for now.
- **Audit page in the passkey web app, or admin socket only?** Admin socket and CLI only at first.
- **Tamper-evident audit (hash chain).** Deferred.
- **Should notify channels ever relay passkey assertions?** Not for now; notify-only.
