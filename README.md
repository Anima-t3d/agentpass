# agentpass

**An execution gateway for AI agents on untrusted devices.**

Your agent asks, you approve, the gateway passes it through. Connect any HTTP API via YAML -- no Python code required. The agent never sees service credentials.

---

## Quick Start

### Gateway (trusted device — e.g., a home server, NAS, Raspberry Pi)

The gateway holds all service credentials, runs the permission engine, and talks to Telegram for human approvals. The agent never sees this configuration.

**1. Install**

```bash
pip install agentpass
```

**2. Configure**

Create a Telegram bot via [@BotFather](https://t.me/botfather) and get your bot token. Then create a `.env` file:

```env
AGENT_TOKEN=any-secret-string-you-choose
GUARDIAN_BOT_TOKEN=your-telegram-bot-token
HA_TOKEN=your-home-assistant-long-lived-access-token
```

Create `config.yaml`:

```yaml
listen:
  socket: /run/agentpass/agent.sock
  group: agentpass-clients

gateway:
  # health_port: 8210   # optional: /healthz only; the audit dashboard is on listen.admin_socket (docs/DESIGN.md, section 9)

agent:
  token: "${AGENT_TOKEN}"

messenger:
  type: "telegram"
  telegram:
    token: "${GUARDIAN_BOT_TOKEN}"
    chat_id: -100123456789 # your Telegram group chat ID
    allowed_users: [123456789] # Telegram user IDs who can approve

services:
  homeassistant:
    url: "http://homeassistant.local:8123"
    auth:
      type: bearer
      token: "${HA_TOKEN}"
    health:
      path: "/api/"
    tools: "tools/homeassistant.yaml"

storage:
  type: "sqlite"
  path: "./data/agentpass.db"
```

Create `permissions.yaml`:

```yaml
defaults:
  - pattern: "ha_get_*"
    action: allow
  - pattern: "*"
    action: ask

rules:
  - pattern: "ha_call_service(lock.*)"
    action: deny
```

**3. Start the gateway**

```bash
# Development (no TLS)
agentpass serve --insecure

# Production (TLS required)
agentpass serve
```

### Agent device (untrusted — e.g., a laptop, cloud VM, Raspberry Pi running an AI agent)

The agent device only needs the gateway URL and the agent token. It never sees service credentials, Telegram tokens, or permission rules.

**1. Install**

```bash
pip install agentpass
```

**2. Send requests**

```bash
# Same machine: the Unix socket (group agentpass-clients, no TLS or --insecure needed)
agentpass tools --socket /run/agentpass/agent.sock --token $AGENT_TOKEN
# (equivalent: --url unix:///run/agentpass/agent.sock)

# Over TCP: wss:// in production, ws:// only if the gateway was started with --insecure

# List available tools
agentpass tools --url ws://gateway:8443 --token $AGENT_TOKEN

# Auto-allowed -- returns immediately
agentpass request ha_get_state entity_id=sensor.temp \
  --url ws://gateway:8443 --token $AGENT_TOKEN

# Requires approval -- check Telegram for the button
agentpass request ha_call_service domain=light service=turn_on entity_id=light.bedroom \
  --url ws://gateway:8443 --token $AGENT_TOKEN
```

Or use the Python SDK — see [Python SDK](#python-sdk) below.

---

## How It Works

```
Agent Device (untrusted)            Gateway (trusted)
+-----------------+                 +-------------------------------+
|                 |                 |  agentpass                    |
|  AI Agent       |                 |  +-------------------------+  |
|  (any agent)    |-- WebSocket --> |  | Permission Engine       |  |
|                 |                 |  | deny > allow > ask      |  |
|  Holds:         |                 |  +-----------+-------------+  |
|  - Agent token  |                 |              |                |
|  - LLM key      |                 |  +-----------v-------------+  |
|                 |<-- result ----- |  | Telegram Messenger      |  |
|                 |                 |  | (human approval)        |  |
+-----------------+                 |  +-----------+-------------+  |
                                    |              |                |
      You <-- Telegram ------------ |  +-----------v-------------+  |
                                    |  | Generic HTTP Executor   |  |
                                    |  | (any service via YAML)  |  |
                                    |  +-------------------------+  |
                                    |                               |
                                    |  Holds: service credentials,  |
                                    |  bot token, TLS certs, DB     |
                                    +-------------------------------+
```

### Security Model

| Property                 | How                                                                                |
| ------------------------ | ---------------------------------------------------------------------------------- |
| **Credential isolation** | Service tokens live only on the gateway. The agent device never sees them.         |
| **Policy engine**        | Every request matches YAML permission rules using glob patterns. Deny always wins. |
| **Human-in-the-loop**    | `ask` rules trigger a Telegram message with inline approve/deny buttons.           |
| **Transport security**   | Unix socket by default (0660, group `agentpass-clients`, plaintext OK). TCP needs TLS or `--insecure`; wildcard binds refused. |
| **Input validation**     | Glob metacharacters, control chars, and invalid identifiers are rejected.          |
| **Rate limiting**        | Max 10 pending approvals, max 60 requests/minute (configurable).                   |
| **Remembered decisions** | "Allow always" / "Deny always" in Telegram store a revocable rule in the database. A remembered allow can only turn `ask` into `allow` (never overrides a deny, a passkey rule or a high-risk tool), and expires after 90 days (exact call) or 30 days (whole tool). See `docs/REMEMBERED-DECISIONS.md`. |

---

## CLI Reference

```bash
# Gateway (trusted device)
agentpass serve [--insecure] [--config config.yaml] [--permissions permissions.yaml]

# Agent device (untrusted)
agentpass request <tool> [key=value ...] --url <ws-url> --token <token> [--timeout 900]
agentpass tools --url <ws-url> --token <token>
agentpass pending --url <ws-url> --token <token>

# Gateway (trusted device): remembered "Allow always" / "Deny always" rules, via the admin socket
agentpass remembered list [--agent ID] [--all] [--json] [--config config.yaml | --socket PATH]
agentpass remembered revoke ID [ID ...]
agentpass remembered revoke --agent ID --all
```

| Command   | Runs on      | Description                                               |
| --------- | ------------ | --------------------------------------------------------- |
| `serve`   | Gateway      | Start the gateway server (default if no subcommand given) |
| `request` | Agent device | Send a one-shot tool request and print the JSON result    |
| `tools`   | Agent device | List available tools with their arguments                 |
| `pending` | Agent device | Retrieve results for requests resolved while offline      |
| `remembered` | Gateway   | List or revoke remembered Allow/Deny always rules         |

**Exit codes:** 0 = success, 1 = denied, 2 = timeout, 3 = connection error, 4 = invalid args.

**Environment variables:** `AGENTPASS_URL` and `AGENT_TOKEN` can replace `--url` and `--token`.

---

## Python SDK

Use this on the **agent device** to integrate agentpass into your Python agent code.

```python
from agentpass import AgentPassClient, AgentPassDenied, AgentPassTimeout

async with AgentPassClient("wss://gateway:8443", token="your-agent-token") as gw:

    # Auto-allowed by policy -- returns immediately
    state = await gw.tool_request("ha_get_state", entity_id="sensor.temp")

    # Requires human approval -- blocks until approved/denied/timeout
    try:
        await gw.tool_request(
            "ha_call_service",
            domain="light", service="turn_on", entity_id="light.bedroom",
        )
    except AgentPassDenied as e:
        print(f"Denied: {e.message}")
    except AgentPassTimeout as e:
        print(f"Timed out: {e.message}")

    # List available tools
    tools = await gw.list_tools()

    # Retrieve offline results
    results = await gw.get_pending_results()
```

Auto-reconnects with exponential backoff (1s to 30s). Limit retries with `max_retries=5`.

---

## OpenClaw Integration

agentpass ships with an [OpenClaw](https://github.com/openclaw/openclaw) skill that teaches the agent to control Home Assistant devices through the gateway. The skill is available on [ClawHub](https://clawhub.ai/) and as a bundled `SKILL.md` in this repo.

### Install from ClawHub

```bash
clawhub install agentpass
```

### Manual install

Copy the skill directory to your OpenClaw skills folder:

```bash
cp -r skills/openclaw ~/.openclaw/skills/agentpass
```

Or on a remote device (e.g., a Raspberry Pi running OpenClaw):

```bash
scp -r skills/openclaw user@agent-device:~/.openclaw/skills/agentpass
```

### Configure environment variables

Add the gateway URL and agent token to `~/.openclaw/openclaw.json`:

```json
{
  "skills": {
    "entries": {
      "agentpass": {
        "enabled": true,
        "env": {
          "AGENTPASS_URL": "wss://your-gateway-host:8443",
          "AGENT_TOKEN": "your-agent-token-here"
        }
      }
    }
  }
}
```

If the file already exists, merge the `agentpass` entry into `skills.entries`.

### Install the CLI on the agent device

The agent device needs the `agentpass` CLI. On systems with externally-managed Python environments (e.g., Raspberry Pi OS), use `pipx`:

```bash
pipx install agentpass
```

Otherwise:

```bash
pip install agentpass
```

Start a new OpenClaw session and the skill will be available. Read-only queries (states, history, config) execute instantly. State-changing actions (turning lights on/off, calling services) block until the Telegram guardian approves or denies.

---

## Adding a Service (YAML Only)

All service configuration happens on the **gateway**. Any HTTP API can be connected with just two files -- no Python code needed.

### 1. Define tools in a YAML file

Create `tools/my_api.yaml`:

```yaml
tools:
  get_item:
    description: "Fetch an item by ID"
    signature: "{item_id}"
    args:
      item_id:
        required: true
        validate: "^[a-zA-Z0-9_-]+$"
    request:
      method: GET
      path: "/api/items/{item_id}"

  create_item:
    description: "Create a new item"
    signature: "{name}"
    args:
      name:
        required: true
    request:
      method: POST
      path: "/api/items"
      body_exclude: []
    response:
      wrap: "result"
```

### 2. Add the service to config.yaml

```yaml
services:
  my_api:
    url: "https://api.example.com"
    auth:
      type: header
      header_name: "X-API-Key"
      token: "${MY_API_KEY}"
    health:
      path: "/health"
    tools: "tools/my_api.yaml"
```

### 3. Add permission rules

```yaml
defaults:
  - pattern: "get_*"
    action: allow
  - pattern: "create_*"
    action: ask
```

That's it. Restart the gateway and the tools are available.

---

## Transports, Approval Channels and Operations

### Listeners

The agent API listens on a Unix socket by default (`listen.socket`, mode 0660, group `listen.group`). Plaintext is fine there because the kernel limits access to the service user and that group. `listen.tcp` is optional and loopback-only; wildcard binds (`0.0.0.0`, `::`) are refused unless `allow_wildcard: true`, and TCP needs TLS unless the gateway is started with `--insecure`.

The audit dashboard and the remembered-rules page live on their own admin Unix socket (`listen.admin_socket`, group `listen.admin_group`), never on the agent socket. `/healthz` is off unless `gateway.health_port` is set. List ports that other software on the host owns in `gateway.reserved_ports`; `check-config` rejects a health or dashboard port that collides.

### MCP endpoint

With `mcp.enabled: true` the gateway also serves MCP over streamable HTTP (`POST /mcp`, `Authorization: Bearer agp_<id>_<secret>`). It runs on its own loopback port (or a Unix socket via `mcp.socket`) and needs per-agent identities. It calls the same request pipeline as the WebSocket API, so policy, approvals, audit and rate limits are identical. Tools that need approval wait up to `mcp.inline_wait` seconds, then return `pending_approval`; the agent polls with the `gateway_result` tool (`gateway_pending` lists open approvals).

### Per-agent identities

```bash
agentpass agent create my-agent --config config.yaml   # prints the token once
```

Setting `agent.agents_dir` replaces the shared `agent.token`. Each agent has a file (`agents/NAME.yaml`) with a token hash, rate limit and rules. `agent.policy_dir/_floor.yaml` holds denies that no agent file can override, and shared rule sets (such as `policy/github.yaml`) are pulled in with `extends`. Audit and pending rows record the agent id.

### Approval channels

Approval requests fan out to every channel configured for the rule:

| Channel | Type | Can approve? |
| --- | --- | --- |
| Telegram Guardian bot | `telegram` | Yes (inline buttons, allow-listed users) |
| Passkey approval page | `passkey` | Yes (WebAuthn assertion bound to the request) |
| Webhook / command | `webhook`, `command` | No, display-only notifications with a link |

The passkey page is an aiohttp app on loopback. Publish it only on a private network (for example with `tailscale serve`), set `passkey.rp_id` and `passkey.origin` to that name, and enrol a device with `agentpass passkey enroll`. Only public keys are stored on the host. An `ask` rule can require a channel kind (`approval: { require: passkey }`, or `telegram`, default `any_trusted`) so a chat button cannot approve high-risk calls. For such a request the Telegram message says "🔐 Needs passkey approval" and shows an **Approve with passkey** link button to `passkey.origin` plus **Deny** (a trusted deny needs no passkey); there is no Allow button. If the passkey page is not enabled the message says so instead of linking, and `agentpass check-config` reports a passkey rule with no passkey channel as an error. Resolving on the page updates the Telegram message like any other resolution. Use the `channels:` list in `config.yaml` instead of the `messenger:` shorthand to configure several. See [docs/DESIGN.md](docs/DESIGN.md) for the threat model and the approval proof.

### Offline validation

```bash
agentpass check-config --config config.yaml [--strict] [--json]
```

Loads the config, tool files, agent files and rules with the same loaders as `serve`, then lints the rules (rules matching no tool, reserved ports, missing groups, risky dashboard setups). It makes no network calls and never prints secret values. Exit codes: 0 clean, 1 errors (or warnings with `--strict`), 2 warnings only. Run it before every restart, for example as a systemd `ExecStartPre`.

### Google OAuth (Gmail, Calendar, Drive)

Services with `auth: {type: oauth2, provider: google, account: NAME}` use refresh tokens stored under `<storage dir>/tokens/` (mode 0600). Put the OAuth client id and secret in a `secrets.yaml` next to the config, never in `config.yaml`.

```bash
agentpass auth google --account personal --scopes gmail.modify,calendar,drive
agentpass auth status
agentpass auth revoke --account personal
```

The auth CLI resolves the token directory exactly as the gateway does and refuses to start the consent flow if it cannot write there. When consent is missing or expired, tool calls fail with a generic "needs operator action" error and the operator is notified once.

### Remembered decisions

"Allow always" / "Deny always" buttons store a revocable rule in the database. Eligibility depends on the tool's `risk` and `remember` keys (see Tool Definition YAML below). List and revoke rules with `agentpass remembered list|revoke` or on the dashboard's remembered-rules page; details are in [docs/REMEMBERED-DECISIONS.md](docs/REMEMBERED-DECISIONS.md).

## Configuration Reference

### config.yaml

```yaml
listen:
  socket: /run/agentpass/agent.sock # default; mode 0660, group below. null disables it
  group: agentpass-clients # the service user must be a member
  # tcp: # optional, loopback only
  #   host: "127.0.0.1" # 0.0.0.0 and :: are refused unless allow_wildcard: true
  #   port: 8205
  #   allow_wildcard: false

gateway:
  # health_port: 8210   # optional: /healthz only; the audit dashboard is on listen.admin_socket (docs/DESIGN.md, section 9)
  tls: # for listen.tcp; omit for --insecure mode
    cert: "/path/to/cert.pem"
    key: "/path/to/key.pem"

agent:
  token: "${AGENT_TOKEN}" # Bearer token for agent authentication

messenger:
  type: "telegram"
  telegram:
    token: "${GUARDIAN_BOT_TOKEN}" # Telegram Bot API token
    chat_id: -100123456789 # Chat ID (negative for groups)
    allowed_users: [123456789] # User IDs authorized to approve

services:
  <service_name>:
    url: "https://..." # Base URL
    auth: # Authentication (see below)
      type: bearer
      token: "${TOKEN}"
    handler: http # "http" (default) or "python"
    handler_class: "" # For handler=python: "module.path:ClassName"
    health: # Health check endpoint
      method: GET
      path: "/"
      expect_status: 200
    tools: "tools/my_api.yaml" # Path to tool definitions
    errors: # Custom error mappings
      - status: 401
        message: "Auth failed: {body}"
      - status: 404
        message: "Not found: {body}"

storage:
  type: "sqlite"
  path: "./data/agentpass.db"

approval_timeout: 900 # Seconds before approvals expire (default: 900)
rate_limit:
  max_pending_approvals: 10
  max_requests_per_minute: 60
```

### Authentication Types

| Type     | Fields                 | Header sent                     |
| -------- | ---------------------- | ------------------------------- |
| `bearer` | `token`                | `Authorization: Bearer <token>` |
| `header` | `token`, `header_name` | `<header_name>: <token>`        |
| `query`  | `token`, `query_param` | `?<query_param>=<token>`        |
| `basic`  | `username`, `password` | `Authorization: Basic <base64>` |

### Tool Definition YAML

```yaml
tools:
  <tool_name>:
    description: "Human-readable description"
    signature: "{arg1}.{arg2}, {arg3}" # Template for permission matching
    args:
      <arg_name>:
        required: true|false # Default: false
        validate: "^regex$" # Optional validation pattern
    request:
      method: GET|POST|PUT|DELETE|PATCH
      path: "/api/path/{arg_name}" # Path with {arg} interpolation
      body_exclude: [arg1, arg2] # Args excluded from POST body
    response:
      wrap: "key_name" # Wrap response in {"key_name": data}
    risk: low|medium|high # Shown in the approval message; gates "Allow always" (see below)
    remember: args|signature # What "Allow always, exact call" matches. Default: args
```

**`risk`** is a display hint and also limits remembered decisions: a tool with `risk: high` never
offers "Allow always"; a tool with no `risk` offers only the exact-call scope. Set it on every tool.

**`remember`** decides what "Allow always: this exact call" compares. The default `args` matches the
signature *and* every argument the agent sent (a different time window, body or extra argument
asks again). `signature` matches the signature alone, for read-only tools whose signature already
names what matters (`gmail_list_messages(in:inbox)` repeated with another `max_results` is the same
request). Use it only on `risk: low` reads; never on a tool that writes or sends.

**Signature templates** control how permission patterns match. For example, with `signature: "{domain}.{service}, {entity_id}"`, calling `ha_call_service` with `domain=light, service=turn_on, entity_id=light.bedroom` produces the signature `ha_call_service(light.turn_on, light.bedroom)`, which is matched against permission rules using glob patterns.

### permissions.yaml

```yaml
defaults: # Evaluated in order, first match wins
  - pattern: "ha_get_*"
    action: allow
  - pattern: "*"
    action: ask

rules: # Checked before defaults; deny always wins
  - pattern: "ha_call_service(lock.*)"
    action: deny
    description: "Lock control is always denied"
```

**Precedence:** deny rules > allow rules > ask rules > defaults (first match) > global fallback (ask)

Patterns use `fnmatch` glob syntax (`*` matches anything, `?` matches one character, `[seq]` matches character sets).

### Python Plugin Services

For non-HTTP protocols, use `handler: python`:

```yaml
services:
  mqtt_broker:
    url: "mqtt://broker.local"
    auth:
      type: bearer
      token: "${MQTT_TOKEN}"
    handler: python
    handler_class: "my_plugin:MQTTService"
    tools: "tools/mqtt.yaml"
```

The class must extend `ServiceHandler` and accept `(config, tools)`:

```python
from agentpass.config import ServiceConfig, ToolDefinition
from agentpass.services.base import ServiceHandler

class MQTTService(ServiceHandler):
    def __init__(self, config: ServiceConfig, tools: list[ToolDefinition]):
        ...
    async def execute(self, tool_name: str, args: dict) -> dict:
        ...
    async def health_check(self) -> bool:
        ...
    async def close(self) -> None:
        ...
```

---

## JSON-RPC Protocol

For non-Python agents on the **agent device**, the gateway uses JSON-RPC 2.0 over WebSocket. Any language with WebSocket support can integrate.

### Authentication (must be first message, within 10 seconds)

```json
{
  "jsonrpc": "2.0",
  "method": "auth",
  "params": { "token": "..." },
  "id": "auth-1"
}
```

### Tool Request

```json
{
  "jsonrpc": "2.0",
  "method": "tool_request",
  "params": { "tool": "ha_get_state", "args": { "entity_id": "sensor.temp" } },
  "id": 1
}
```

### List Tools

```json
{ "jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": 2 }
```

### Get Pending Results

```json
{ "jsonrpc": "2.0", "method": "get_pending_results", "params": {}, "id": 3 }
```

### Error Codes

| Code     | Meaning                                                |
| -------- | ------------------------------------------------------ |
| `-32700` | Parse error (malformed JSON)                           |
| `-32600` | Invalid request (missing fields, forbidden characters) |
| `-32601` | Method not found                                       |
| `-32001` | Denied by user                                         |
| `-32002` | Approval timed out                                     |
| `-32003` | Policy denied                                          |
| `-32004` | Execution failed                                       |
| `-32005` | Not authenticated                                      |
| `-32006` | Rate limit exceeded                                    |

---

## Docker

Run the gateway in Docker on your **trusted device**:

```bash
docker compose up -d
docker compose logs -f agentpass
```

Mounts: `config.yaml`, `permissions.yaml`, `tools/` (read-only), `data/` (read-write), `certs/` (read-only). Secrets via `.env` file.

---

## Development

```bash
git clone https://github.com/TorbenWetter/agentpass.git
cd agentpass
pip install -e ".[dev]"
pytest                              # 377 tests
ruff check src/ tests/              # lint
ruff format src/ tests/             # format
```

---

## License

MIT -- see [LICENSE](LICENSE) for details.
