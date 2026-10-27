# agentpass

An execution gateway for AI agents on untrusted devices. Agents request, policies decide, humans approve, the gateway executes.

## Tech Stack

- Python 3.12+
- `websockets` >= 14.0 — WebSocket server (agent connections)
- `python-telegram-bot[callback-data]` >= 21.0 — Telegram Guardian bot
- `aiosqlite` >= 0.20.0 — async SQLite
- `aiohttp` >= 3.10.0 — HTTP client for services
- `pyyaml` >= 6.0 — config loading

## Project Structure

```
agentpass/
├── src/agentpass/
│   ├── __init__.py
│   ├── __main__.py           # CLI entrypoint + orchestration
│   ├── cli.py                # Client-side subcommands (request, tools, pending)
│   ├── check.py              # `check-config`: offline validation + rule lints (exit 0/1/2, --strict, --json)
│   ├── config.py             # YAML loading + env var substitution
│   ├── models.py             # Dataclasses (Decision, ToolRequest, etc.)
│   ├── engine.py             # Permission engine (fnmatch, signature builders)
│   ├── executor.py           # Action dispatch (tool → service via registry)
│   ├── schema.py             # Arg definitions → JSON Schema (single converter), MCP annotations
│   ├── registry.py           # ToolRegistry (tool name → service mapping)
│   ├── remembered.py         # Allow/Deny always: eligibility, matching, fingerprints, RememberedService
│   ├── pipeline.py           # Transport-neutral Pipeline.process, Outcome, typed errors, approval timeout
│   ├── server.py             # WebSocket adapter + ERROR_CODES table (pipeline error → JSON-RPC code)
│   ├── listen.py             # Group-restricted Unix socket (0660), stale-socket removal
│   ├── db.py                 # SQLite (audit_log, pending_requests)
│   ├── client.py             # Agent SDK (AgentPassClient)
│   ├── mcp.py                # MCP frontend (streamable HTTP /mcp), second adapter on Pipeline
│   ├── approval/
│   │   ├── __init__.py       # build_channels (config → approval channels)
│   │   ├── channel.py        # ApprovalChannel interface
│   │   ├── coordinator.py    # ApprovalCoordinator: pending row, fan-out, timeout, answer race
│   │   ├── telegram_channel.py # Telegram Guardian bot (PTB v21)
│   │   └── notify_channel.py # Display-only webhook/command notify channels
│   ├── dashboard/            # Audit + remembered-rules pages (admin socket): list and revoke only
│   ├── passkey/
│   │   ├── channel.py        # Passkey approval channel
│   │   ├── page.py           # Approval page (aiohttp, loopback, private network only)
│   │   ├── verify.py         # Challenge construction + WebAuthn verification
│   │   ├── store.py          # Enrolled public keys + enrolment tokens
│   │   └── assets.py         # Static page assets
│   └── services/
│       ├── base.py           # ServiceHandler ABC
│       └── http.py           # Generic HTTP service (any API via YAML)
├── tools/
│   ├── homeassistant.yaml    # HA tool definitions
│   └── github.yaml           # GitHub tools (reads allow, writes ask, destructive deny)
├── policy/
│   └── github.yaml           # Shared rule set for the GitHub tools (extends: [github])
├── tests/                    # see pytest
├── specs/                    # Feature specs (dated)
├── config.example.yaml
├── permissions.example.yaml
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

## Key Patterns

### Extensible Tool System

Tools are defined in YAML files, not Python code. Each service gets a YAML file with tool definitions:

```yaml
tools:
  ha_get_state:
    signature: "{entity_id}"
    args:
      entity_id:
        { required: true, validate: "^[a-z_][a-z0-9_]*(\\.[a-z0-9_]+)?$" }
    request:
      method: GET
      path: "/api/states/{entity_id}"
```

`ToolRegistry` maps tool names → services. `GenericHTTPService` (`services/http.py`) handles execution for any YAML-defined tool. For non-HTTP protocols, use `handler: python` with a `ServiceHandler` subclass.

### PTB Event Loop

PTB v21's `run_polling()` creates its own event loop — DO NOT use it. Use manual lifecycle:

```python
async with ptb_app:
    await ptb_app.start()
    await ptb_app.updater.start_polling()
    # ... run websockets.serve() here ...
    await ptb_app.updater.stop()
    await ptb_app.stop()
```

### Permission Engine Precedence

Deny always wins: `deny rules → allow rules → ask rules → defaults (first match) → fallback (ask)`

### Signature Builders

Signatures are built from YAML `signature` templates (e.g., `"{domain}.{service}, {entity_id}"`). Fallback for tools without a template: sorted keys for determinism.

### Input Validation

Reject argument values containing: `* ? [ ] ( ) , \x00-\x1f`
Per-tool validation via `validate` regex in YAML. HA identifiers: `^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)?$`

### Transport Security

The agent API listens on a Unix socket by default (0660, group agentpass-clients; plaintext is fine there). TCP: WSS (TLS) required by default, plaintext `ws://` only with explicit `--insecure`; 0.0.0.0/:: refused unless `allow_wildcard: true`.

## Linting & Formatting

- **Ruff** — single tool for linting + formatting, configured in `pyproject.toml`
- Lint: `ruff check src/ tests/`
- Format: `ruff format --check src/ tests/`
- Pre-commit hook runs: ruff format → ruff check → pytest

## Testing

- `pytest` + `pytest-asyncio` (asyncio_mode = "auto")
- Mock external services: WebSocket, Telegram Bot API, HTTP APIs
- Unit tests per module, integration test for full flow
- Run `pytest` for the current suite; test_request_path.py covers the full request path
