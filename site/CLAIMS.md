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
