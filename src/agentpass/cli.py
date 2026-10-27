"""CLI client commands -- one-shot tool requests via the gateway."""

from __future__ import annotations

import asyncio
import json
import sys
from argparse import Namespace

from agentpass.client import (
    AgentPassClient,
    AgentPassConnectionError,
    AgentPassDenied,
    AgentPassError,
    AgentPassTimeout,
    socket_url,
)

# Exit codes
EXIT_SUCCESS = 0
EXIT_DENIED = 1
EXIT_TIMEOUT = 2
EXIT_CONNECTION_ERROR = 3
EXIT_INVALID_ARGS = 4


def gateway_url(args: Namespace) -> str:
    """The gateway URL: --socket PATH wins over --url / AGENTPASS_URL."""
    socket_path = getattr(args, "socket", None)
    return socket_url(socket_path) if socket_path else args.url


def parse_key_value_args(raw_args: list[str]) -> dict[str, str]:
    """Parse a list of 'key=value' strings into a dict.

    Raises ValueError if any arg is malformed.
    """
    result: dict[str, str] = {}
    for item in raw_args:
        if "=" not in item:
            raise ValueError(f"Invalid argument format (expected key=value): {item!r}")
        key, _, value = item.partition("=")
        if not key:
            raise ValueError(f"Empty key in argument: {item!r}")
        result[key] = value
    return result


async def run_request(args: Namespace) -> int:
    """Execute a one-shot tool request via the gateway.

    Returns exit code (0=success, 1=denied, 2=timeout, 3=connection, 4=invalid args).
    """
    url = gateway_url(args)
    token = args.token
    tool = args.tool
    timeout = args.timeout

    if not url:
        print("Error: Gateway URL required (--url, --socket or AGENTPASS_URL)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    if not token:
        print("Error: Agent token required (--token or AGENT_TOKEN)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    # Parse key=value arguments
    try:
        tool_args = parse_key_value_args(args.args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    try:
        async with AgentPassClient(url, token, max_retries=0) as client:
            result = await asyncio.wait_for(
                client.tool_request(tool, **tool_args),
                timeout=timeout,
            )
        print(json.dumps(result, indent=2))
        return EXIT_SUCCESS

    except AgentPassDenied as e:
        print(f"Error: Denied ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_DENIED
    except AgentPassTimeout as e:
        print(f"Error: Timeout ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_TIMEOUT
    except TimeoutError:
        print("Error: Request timed out waiting for response", file=sys.stderr)
        return EXIT_TIMEOUT
    except AgentPassConnectionError as e:
        print(f"Error: Connection failed ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except AgentPassError as e:
        print(f"Error: Gateway error ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_DENIED
    except OSError as e:
        print(f"Error: Connection failed: {e}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR


async def run_tools(args: Namespace) -> int:
    """List available tools from the gateway. Returns exit code."""
    url = gateway_url(args)
    token = args.token

    if not url:
        print("Error: Gateway URL required (--url, --socket or AGENTPASS_URL)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    if not token:
        print("Error: Agent token required (--token or AGENT_TOKEN)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    try:
        async with AgentPassClient(url, token, max_retries=0) as client:
            tools = await client.list_tools()

        print(json.dumps(tools, indent=2))
        return EXIT_SUCCESS

    except AgentPassConnectionError as e:
        print(f"Error: Connection failed ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except AgentPassError as e:
        print(f"Error: Gateway error ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_DENIED
    except OSError as e:
        print(f"Error: Connection failed: {e}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except TimeoutError:
        print("Error: Timed out waiting for tool list", file=sys.stderr)
        return EXIT_TIMEOUT


async def run_pending(args: Namespace) -> int:
    """Retrieve pending results from the gateway. Returns exit code."""
    url = gateway_url(args)
    token = args.token

    if not url:
        print("Error: Gateway URL required (--url, --socket or AGENTPASS_URL)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    if not token:
        print("Error: Agent token required (--token or AGENT_TOKEN)", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    try:
        async with AgentPassClient(url, token, max_retries=0) as client:
            results = await client.get_pending_results()
        print(json.dumps(results, indent=2))
        return EXIT_SUCCESS

    except AgentPassConnectionError as e:
        print(f"Error: Connection failed ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except AgentPassError as e:
        print(f"Error: Gateway error ({e.code}): {e.message}", file=sys.stderr)
        return EXIT_DENIED
    except TimeoutError:
        print("Error: Connection timed out", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except OSError as e:
        print(f"Error: Connection failed: {e}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR


# --- remembered rules (admin socket) ---


def _admin_socket(args: Namespace) -> str:
    if getattr(args, "socket", None):
        return args.socket
    from agentpass.config import ConfigError, load_config

    try:
        path = load_config(args.config).listen.admin_socket
    except ConfigError as e:
        raise ConfigError(f"{e} (or pass --socket)") from None
    if not path:
        raise ConfigError("listen.admin_socket is not configured (or pass --socket)")
    return path


async def _admin_request(socket_path: str, method: str, path: str) -> tuple[int, dict]:
    import aiohttp

    from agentpass.dashboard.remembered_routes import CSRF_HEADER, CSRF_VALUE

    connector = aiohttp.UnixConnector(path=socket_path)
    async with (
        aiohttp.ClientSession(connector=connector) as session,
        session.request(method, f"http://admin{path}", headers={CSRF_HEADER: CSRF_VALUE}) as resp,
    ):
        return resp.status, await resp.json(content_type=None)


def _format_rules(rules: list[dict]) -> str:
    if not rules:
        return "No remembered rules."
    lines = [f"{'ID':>4}  {'AGENT':<14} {'ACTION':<6} {'STATE':<9} {'EXPIRES':<21} PATTERN"]
    for r in rules:
        state = r["state"] + (f" ({r['state_reason']})" if r["state_reason"] else "")
        lines.append(
            f"{r['id']:>4}  {r['agent_id']:<14} {r['action']:<6} {state:<9} "
            f"{r['expires_at'] or 'never':<21} {r['pattern']}"
        )
    return "\n".join(lines)


def run_remembered(args: Namespace) -> int:
    """`agentpass remembered list|revoke`, through the admin socket (one writer, audited)."""
    from urllib.parse import urlencode

    from agentpass.config import ConfigError

    try:
        sock = _admin_socket(args)
        if args.remembered_command == "list":
            query = {
                "all": "1" if args.all else "0",
                **({"agent": args.agent} if args.agent else {}),
            }
            status, body = asyncio.run(
                _admin_request(sock, "GET", f"/remembered/api/rules?{urlencode(query)}")
            )
            if status != 200:
                print(f"error: admin socket answered {status}", file=sys.stderr)
                return 1
            print(
                json.dumps(body["rules"], indent=2) if args.json else _format_rules(body["rules"])
            )
            return 0

        ids = list(args.ids)
        if args.all:
            if not args.agent or ids:
                print("error: --all needs --agent and no ids", file=sys.stderr)
                return 4
            status, body = asyncio.run(
                _admin_request(sock, "GET", f"/remembered/api/rules?agent={args.agent}&all=1")
            )
            if status != 200:
                print(f"error: admin socket answered {status}", file=sys.stderr)
                return 1
            ids = [r["id"] for r in body["rules"] if r["state"] != "revoked"]
        if not ids:
            print("error: give rule ids, or --agent NAME --all", file=sys.stderr)
            return 4
        failed = 0
        for rule_id in ids:
            status, _ = asyncio.run(
                _admin_request(sock, "POST", f"/remembered/api/rules/{rule_id}/revoke?by=cli")
            )
            ok = status == 200
            failed += not ok
            print(f"#{rule_id}: {'revoked' if ok else 'not found or already revoked'}")
        return 1 if failed else 0
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: cannot reach the admin socket: {e}", file=sys.stderr)
        return 3
