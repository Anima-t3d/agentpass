# Landing page claims

Every capability the page states, the section it is in, and where the code or docs back it.
Not published (the Pages workflow removes this file). Keep it in step with `index.html`:
`tests/site/test_site.py` checks that each section has rows and each path exists.

| Claim (as on the page) | Section id | Backed by (path in repo) |
| --- | --- | --- |
| Approve or deny with a tap in Telegram | `pain-blocked` | `src/agentpass/approval/telegram_channel.py` |
| Approval page with passkey confirmation | `pain-blocked` | `src/agentpass/passkey/page.py`, `src/agentpass/passkey/verify.py` |
| Rules per tool and per argument: allow, ask, deny | `pain-blocked` | `src/agentpass/engine.py`, `policy/github.yaml` |
| "Allow always" / "Deny always" for the exact call or the tool, within checked limits | `pain-blocked` | `src/agentpass/remembered.py`, `docs/REMEMBERED-DECISIONS.md` |
| Previews: file diff, email as sent, comment text and its issue | `pain-blind` | `src/agentpass/preview/diff_render.py`, `src/agentpass/preview/email_render.py`, `tools/github.yaml` |
| Previews built by the gateway from checked args and read-only lookups | `pain-blind` | `src/agentpass/preview/service.py`, `docs/APPROVAL-PREVIEWS.md` |
| Agent's own note shown separately, labelled as agent-written | `pain-blind` | `src/agentpass/approval/channel.py`, `src/agentpass/passkey/assets.py` |
| Preview failure shows raw args and never approves | `pain-blind` | `src/agentpass/preview/service.py`, `docs/APPROVAL-PREVIEWS.md` |
| The agent never holds service credentials; they stay with the gateway under another user | `pain-bitten` | `docs/DESIGN.md` |
| Policy floor deny/ask rules beat agent files, rule sets and remembered allows | `pain-bitten` | `policy/_floor.example.yaml`, `src/agentpass/engine.py` |
| Collaborators, deploy keys, Actions secrets, branch protection denied in shipped GitHub rules | `pain-bitten` | `policy/github.yaml` |
| No service token on the agent's side to exfiltrate | `pain-burned` | `docs/DESIGN.md` |
| Sending mail / changing a file asks; sensitive calls can require a passkey; deleting a repo is denied | `pain-burned` | `policy/github.yaml`, `policy/_floor.example.yaml` |
| Audit log of who asked, what, decision and by whom; agent can't edit it | `pain-burned` | `src/agentpass/db.py`, `src/agentpass/dashboard/routes.py`, `docs/DESIGN.md` |
| Agent drafts an issue comment, you see full text and issue, gateway posts with its own token | `github` | `tools/github.yaml` |
| Agents connect over a Unix socket, WebSocket or MCP, each with its own token | `how` | `src/agentpass/listen.py`, `src/agentpass/server.py`, `src/agentpass/mcp.py`, `src/agentpass/agents.py` |
| Deny beats allow, allow beats ask | `how` | `src/agentpass/engine.py`, `README.md` |
| Request goes to every approval channel; first valid answer wins | `how` | `src/agentpass/approval/coordinator.py` |
| Each agent has its own rules and audit trail | `how` | `src/agentpass/agents.py`, `docs/DESIGN.md` |
| Policy patterns on the call signature, e.g. `gh_put_contents(*, main)` | `features` | `src/agentpass/engine.py`, `policy/github.yaml` |
| Policy floor no agent file can relax | `features` | `policy/_floor.example.yaml` |
| Telegram buttons and passkey page; a rule can require a passkey | `features` | `src/agentpass/approval/telegram_channel.py`, `src/agentpass/passkey/channel.py`, `README.md` |
| WebAuthn passkeys; only public keys stored | `features` | `src/agentpass/passkey/store.py`, `README.md` |
| Previews: diffs, email, comment text, device state, what a delete removes | `features` | `src/agentpass/preview/renderers.py`, `tools/github.yaml`, `tools/homeassistant.yaml` |
| Remembered decisions per exact call or tool, with limits | `features` | `docs/REMEMBERED-DECISIONS.md` |
| Audit log and admin-only dashboard | `features` | `src/agentpass/dashboard/routes.py`, `README.md` |
| Unix socket, WebSocket, MCP, CLI, Python SDK; token and rules per agent | `features` | `src/agentpass/listen.py`, `src/agentpass/mcp.py`, `src/agentpass/cli.py`, `src/agentpass/client.py`, `src/agentpass/agents.py` |
| Tools declared in YAML; GitHub, Gmail, Calendar, Drive, Home Assistant ship | `features` | `tools/github.yaml`, `tools/gmail.yaml`, `tools/calendar.yaml`, `tools/drive.yaml`, `tools/homeassistant.yaml` |
| `agentpass check-config` offline check | `features` | `src/agentpass/check.py` |
| Threat model: protects against token reads, self-approval, own-permission changes, audit tampering; not root, operator phone/passkey, malicious service | `security` | `docs/DESIGN.md` |
| Previews come from the gateway, so the approval shows what will run | `security` | `docs/APPROVAL-PREVIEWS.md` |
| Install by clone + venv + `pip install .`; client via pip from git | `quickstart` | `pyproject.toml` |
| Root prerequisites: service user, `agentpass-clients` group, socket dir | `quickstart` | `src/agentpass/listen.py`, `docs/DESIGN.md` |
| Quickstart deny rules for deletes and access-granting tools | `quickstart` | `policy/github.yaml`, `src/agentpass/config.py` |
| Minimal config (`gateway: {}` required): socket listener, agent token, Telegram, GitHub service, SQLite | `quickstart` | `config.example.yaml`, `README.md` |
| `check-config`, `serve --config --permissions`, `tools --socket --token` | `quickstart` | `src/agentpass/__main__.py`, `src/agentpass/cli.py` |
| CLI, Python SDK, MCP endpoint, OpenClaw skill | `faq` | `src/agentpass/cli.py`, `src/agentpass/client.py`, `src/agentpass/mcp.py`, `skills/openclaw/SKILL.md` |
| Unanswered request times out (15 min default) and isn't run | `faq` | `src/agentpass/approval/coordinator.py`, `src/agentpass/pipeline.py`, `config.example.yaml` |
| Python plugin services for non-HTTP APIs | `faq` | `README.md` |
| Created by Torben Wetter, MIT | `faq` | `LICENSE`, `pyproject.toml` |
