"""CLI entrypoint and orchestration for agentpass."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib
import logging
import os
import signal
import ssl
import sys
from pathlib import Path

import websockets
import websockets.asyncio.server
import yaml
from aiohttp import web

from agentpass.agents import load_agents, write_agent_file
from agentpass.approval import ApprovalCoordinator, ApprovalReason, build_channels
from agentpass.config import (
    ConfigError,
    ServiceConfig,
    approval_warnings,
    load_config,
    load_permissions,
    substitute_env_vars_in_text,
    validate_rule_channels,
)
from agentpass.dashboard import build_dashboard_app
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.listen import bind_group_socket, remove_socket
from agentpass.mcp import McpServer
from agentpass.models import Decision
from agentpass.preview import PreviewService
from agentpass.registry import build_registry
from agentpass.remembered import RememberedService, format_summary
from agentpass.server import GatewayServer
from agentpass.services.base import ServiceHandler
from agentpass.services.http import GenericHTTPService

logger = logging.getLogger("agentpass")


def _load_plugin_service(config: ServiceConfig) -> ServiceHandler:
    """Load a Python plugin service handler from handler_class spec.

    The handler_class field must be in "module.path:ClassName" format.
    The class receives (config, tools) as constructor arguments.
    """
    handler_class = config.handler_class
    if not handler_class:
        raise ConfigError(
            f"Service '{config.name}' has handler=python but no handler_class specified"
        )

    # Parse "module.path:ClassName"
    if ":" not in handler_class:
        raise ConfigError(
            f"Invalid handler_class format for service '{config.name}': "
            f"expected 'module.path:ClassName', got '{handler_class}'"
        )

    module_path, class_name = handler_class.rsplit(":", 1)

    try:
        module = importlib.import_module(module_path)
    except ImportError as e:
        raise ConfigError(
            f"Cannot import module '{module_path}' for service '{config.name}': {e}"
        ) from e

    try:
        cls = getattr(module, class_name)
    except AttributeError:
        raise ConfigError(
            f"Class '{class_name}' not found in module '{module_path}' for service '{config.name}'"
        ) from None

    return cls(config, config.tools)


KNOWN_COMMANDS = {
    "serve",
    "request",
    "tools",
    "pending",
    "agent",
    "auth",
    "passkey",
    "remembered",
    "check-config",
}


def _resolve_agents_dir(config_path: str, override: str | None) -> tuple[Path, str]:
    """Where `agent create` writes, matching what load_config reads.

    Returns (absolute dir, source) with source "from --agents-dir", "from config"
    or "default". Reads only the agent.agents_dir key, without env substitution,
    so a config that references unset variables does not block it.
    """
    config_file = Path(config_path)
    base = config_file.parent
    if override is not None:
        return (base / override).resolve(), "from --agents-dir"
    try:
        raw = yaml.safe_load(config_file.read_text())
    except (OSError, yaml.YAMLError):
        raw = None
    agent = raw.get("agent") if isinstance(raw, dict) else None
    configured = agent.get("agents_dir") if isinstance(agent, dict) else None
    if configured and isinstance(configured, str):
        return (base / configured).resolve(), "from config"
    return (base / "agents").resolve(), "default"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments with subcommand routing.

    Subcommands:
        serve     Start the gateway server (default if no subcommand given)
        request   Send a one-shot tool request
        tools     List available tools
        pending   Retrieve pending results

    Backward compat: if the first positional arg is not a known subcommand,
    'serve' is prepended automatically.
    """
    raw = list(argv) if argv is not None else sys.argv[1:]

    # Backward compat: if no subcommand given, default to "serve"
    first_positional = next((a for a in raw if not a.startswith("-")), None)
    if first_positional not in KNOWN_COMMANDS:
        raw = ["serve", *raw]

    parser = argparse.ArgumentParser(description="agentpass: execution gateway for AI agents")
    subparsers = parser.add_subparsers(dest="command")

    # serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Start the gateway server")
    serve_parser.add_argument("--insecure", action="store_true", help="Allow plaintext WS (no TLS)")
    serve_parser.add_argument("--config", default="config.yaml", help="Config file path")
    serve_parser.add_argument(
        "--permissions", default="permissions.yaml", help="Permissions file path"
    )

    # check-config subcommand
    check_parser = subparsers.add_parser(
        "check-config",
        help="Validate config and permissions offline (exit 0 ok, 1 errors, 2 warnings)",
    )
    check_parser.add_argument("--config", default="config.yaml", help="Config file path")
    check_parser.add_argument(
        "--permissions", default="permissions.yaml", help="Permissions file path"
    )
    check_parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    check_parser.add_argument("--json", action="store_true", help="Machine-readable output")

    # request subcommand
    request_parser = subparsers.add_parser("request", help="Send a tool request")
    request_parser.add_argument("tool", help="Tool name")
    request_parser.add_argument("args", nargs="*", default=[], help="key=value arguments")
    request_parser.add_argument(
        "--url",
        default=os.environ.get("AGENTPASS_URL", ""),
        help="Gateway WebSocket URL (wss://host:port, or unix:///run/agentpass/agent.sock)",
    )
    request_parser.add_argument(
        "--socket",
        default=os.environ.get("AGENTPASS_SOCKET", ""),
        help="Unix socket path of the gateway (same as --url unix://PATH)",
    )
    request_parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_TOKEN", ""),
        help="Agent token",
    )
    request_parser.add_argument("--timeout", type=float, default=900.0, help="Timeout in seconds")

    # tools subcommand
    tools_parser = subparsers.add_parser("tools", help="List available tools")
    tools_parser.add_argument(
        "--url",
        default=os.environ.get("AGENTPASS_URL", ""),
        help="Gateway WebSocket URL (wss://host:port, or unix:///run/agentpass/agent.sock)",
    )
    tools_parser.add_argument(
        "--socket",
        default=os.environ.get("AGENTPASS_SOCKET", ""),
        help="Unix socket path of the gateway (same as --url unix://PATH)",
    )
    tools_parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_TOKEN", ""),
        help="Agent token",
    )

    # pending subcommand
    pending_parser = subparsers.add_parser("pending", help="Retrieve pending results")
    pending_parser.add_argument(
        "--url",
        default=os.environ.get("AGENTPASS_URL", ""),
        help="Gateway WebSocket URL (wss://host:port, or unix:///run/agentpass/agent.sock)",
    )
    pending_parser.add_argument(
        "--socket",
        default=os.environ.get("AGENTPASS_SOCKET", ""),
        help="Unix socket path of the gateway (same as --url unix://PATH)",
    )
    pending_parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_TOKEN", ""),
        help="Agent token",
    )

    # agent subcommand
    agent_parser = subparsers.add_parser("agent", help="Manage agent identities")
    agent_sub = agent_parser.add_subparsers(dest="agent_command", required=True)
    create_parser = agent_sub.add_parser("create", help="Create an agent file and token")
    create_parser.add_argument("name", help="Agent id (lowercase letters, digits, '-')")
    create_parser.add_argument("--config", default="config.yaml", help="Config file path")
    create_parser.add_argument(
        "--agents-dir",
        default=None,
        help="Directory of agent files, relative to the config file "
        "(default: agent.agents_dir from the config, else 'agents')",
    )

    # auth subcommand
    auth_parser = subparsers.add_parser("auth", help="Manage OAuth tokens")
    auth_sub = auth_parser.add_subparsers(dest="auth_command", required=True)

    def _auth_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", default=None, help="Config file path (default: ./config.yaml)")
        sp.add_argument("--data-dir", default=None, help="Token data dir (default: storage dir)")

    google_parser = auth_sub.add_parser("google", help="Run the Google consent flow")
    _auth_common(google_parser)
    google_parser.add_argument("--account", required=True, help="Account name, e.g. personal")
    google_parser.add_argument(
        "--scopes", required=True, help="Comma list, e.g. gmail.modify,calendar"
    )
    google_parser.add_argument(
        "--secrets", default=None, help="secrets.yaml (default: next to config)"
    )
    status_parser = auth_sub.add_parser("status", help="Show stored accounts")
    _auth_common(status_parser)
    revoke_parser = auth_sub.add_parser("revoke", help="Revoke upstream and delete the token file")
    _auth_common(revoke_parser)
    revoke_parser.add_argument("--provider", default="google")
    revoke_parser.add_argument("--account", required=True)

    # passkey subcommand
    passkey_parser = subparsers.add_parser("passkey", help="Manage the approval passkey")
    passkey_sub = passkey_parser.add_subparsers(dest="passkey_command", required=True)
    enroll_parser = passkey_sub.add_parser(
        "enroll", help="Print a one-time enrolment URL (valid 10 minutes)"
    )
    enroll_parser.add_argument("--config", default="config.yaml", help="Config file path")

    remembered_parser = subparsers.add_parser(
        "remembered", help="List or revoke remembered Allow/Deny always rules"
    )
    remembered_sub = remembered_parser.add_subparsers(dest="remembered_command", required=True)
    for name, text in (("list", "List remembered rules"), ("revoke", "Revoke rules")):
        sub = remembered_sub.add_parser(name, help=text)
        sub.add_argument("--config", default="config.yaml", help="Config file path")
        sub.add_argument("--socket", help="Admin socket path (default: listen.admin_socket)")
    list_parser = remembered_sub.choices["list"]
    list_parser.add_argument("--agent", help="Only this agent")
    list_parser.add_argument("--all", action="store_true", help="Include expired and revoked")
    list_parser.add_argument("--json", action="store_true", help="Machine-readable output")
    revoke_parser = remembered_sub.choices["revoke"]
    revoke_parser.add_argument("ids", nargs="*", type=int, help="Rule ids")
    revoke_parser.add_argument("--agent", help="With --all: revoke every active rule of this agent")
    revoke_parser.add_argument("--all", action="store_true", help="Revoke all of --agent's rules")

    return parser.parse_args(raw)


def _auth_store(config_path: str | None, data_dir: str | None):
    """Token store at <storage dir>/tokens, resolved the way the gateway does.

    Env substitution happens before YAML parsing. An explicit --config (or an
    existing ./config.yaml) that cannot be read, parsed or has no storage.path is
    an error; ./data is only used when no config file exists and none was named.
    """
    from agentpass.services.auth import TokenStore

    if data_dir is not None:
        return TokenStore(Path(data_dir) / "tokens")
    path = config_path or "config.yaml"
    if config_path is None and not Path(path).exists():
        return TokenStore(Path("./data/tokens"))
    try:
        raw = yaml.safe_load(substitute_env_vars_in_text(Path(path).read_text()))
        storage_path = raw["storage"]["path"]
        if not isinstance(storage_path, str) or not storage_path:
            raise TypeError("storage.path must be a non-empty string")
    except (OSError, yaml.YAMLError, ConfigError, KeyError, TypeError) as e:
        raise ConfigError(
            f"cannot resolve token dir from {path}: {e!r}; "
            "pass --data-dir to choose the token directory"
        ) from None
    return TokenStore(Path(storage_path).parent / "tokens")


def run_auth(args: argparse.Namespace) -> int:
    from agentpass.services import consent

    try:
        store = _auth_store(args.config, args.data_dir)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    try:
        if args.auth_command == "google":
            secrets_file = args.secrets or str(
                Path(args.config or "config.yaml").parent / "secrets.yaml"
            )
            asyncio.run(
                consent.run_google_consent(
                    store=store,
                    secrets_file=secrets_file,
                    account=args.account,
                    scopes_csv=args.scopes,
                )
            )
        elif args.auth_command == "status":
            lines = consent.auth_status(store)
            print("\n".join(lines) if lines else "No accounts.")
        elif args.auth_command == "revoke":
            asyncio.run(consent.revoke(store, args.provider, args.account))
            print(f"Revoked and deleted {args.provider}/{args.account}")
    except (consent.ConsentError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def run_passkey(args: argparse.Namespace) -> int:
    from agentpass.passkey.channel import issue_enrolment_url
    from agentpass.passkey.page import PasskeyConfig

    try:
        config = PasskeyConfig.from_config_file(args.config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print("Open this URL on your phone or Mac within 10 minutes (single use):")
    print(issue_enrolment_url(config))
    return 0


async def run(args: argparse.Namespace) -> None:
    """Main async entrypoint -- orchestrates all components."""
    # 1. Load config
    config = load_config(args.config)
    permissions = load_permissions(args.permissions)

    # 2. TLS check
    tcp = config.listen.tcp
    if tcp is not None and not args.insecure and config.gateway.tls is None:
        logger.error("TLS not configured for TCP. Use --insecure to allow plaintext WS.")
        sys.exit(1)

    # 3. Signal handling
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    # 4. Initialize database
    db = Database(config.storage.path)
    await db.initialize()

    # 5. Build registry from all service tool definitions
    registry = build_registry(config.services)

    # 6. Initialize services + health checks
    services: dict[str, ServiceHandler] = {}
    for name, svc_config in config.services.items():
        if svc_config.handler == "python":
            service = _load_plugin_service(svc_config)
        else:
            service = GenericHTTPService(svc_config)
        if not await service.health_check():
            logger.warning("Service '%s' unreachable — continuing anyway", name)
        services[name] = service

    executor = Executor(services, registry)

    # 7. Initialize permission engines (one per agent when agent files are used)
    engine = PermissionEngine(permissions, registry=registry)
    agent_registry = None
    if config.agent.agents_dir:
        agent_registry = load_agents(config.agent.agents_dir, config.agent.policy_dir)
        for identity in agent_registry.all():
            identity.engine = PermissionEngine(identity.permissions, registry=registry)
    # Rules that name channels must name configured ones; other mismatches only warn
    policies = (
        [permissions, *(a.permissions for a in agent_registry.all())]
        if agent_registry
        else [permissions]
    )
    for policy in policies:
        rules = [*policy.defaults, *policy.rules]
        validate_rule_channels(rules, config.channels)
        for warning in approval_warnings(rules, config.channels):
            logger.warning(warning)

    # 7b. Remembered decisions (Allow always / Deny always)
    def _agent_known(agent_id: str) -> bool:
        return agent_registry is None or agent_registry.get(agent_id) is not None

    def _approval_for(agent_id: str, tool: str, signature: str):
        identity = agent_registry.get(agent_id) if agent_registry else None
        verdict = ((identity.engine if identity else None) or engine).evaluate(
            tool, {}, signature=signature
        )
        return verdict.approval if verdict.decision is Decision.ASK else None

    remembered = RememberedService(
        db, registry, agent_known=_agent_known, approval_for=_approval_for
    )
    logger.info("Remembered rules: %s", format_summary(await remembered.counts()))

    # 8. Approval channels and coordinator
    coordinator = ApprovalCoordinator(
        db,
        build_channels(config, db=db),
        remembered,
        PreviewService(registry, services, display_timezone=config.display_timezone),
    )

    # 9. Initialize gateway server
    gateway = GatewayServer(
        agent_token=config.agent.token or None,
        agents=agent_registry,
        engine=engine,
        executor=executor,
        coordinator=coordinator,
        db=db,
        approval_timeout=config.approval_timeout,
        rate_limit_config=config.rate_limit,
        registry=registry,
        services=services,
        remembered=remembered,
    )

    # 10. Start the channels (manual PTB lifecycle lives behind Telegram's start/stop)
    # and abandon approvals left over from the previous run; then settle their results
    await coordinator.start()
    try:
        await db.settle_orphans()  # approvals nobody can answer any more get a final result
        await db.cleanup_stale_requests()

        # OAuth providers notify the owner (once) when consent is needed
        for service in services.values():
            provider = getattr(service, "provider", None)
            if hasattr(provider, "set_notifier"):
                provider.set_notifier(coordinator.notify)

        # 11. SSL context
        ssl_ctx = None
        if config.gateway.tls:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(config.gateway.tls.cert, config.gateway.tls.key)

        # 12. Start health HTTP server
        async def _health_handler(request: web.Request) -> web.Response:
            try:
                status = await gateway.health_status()
                code = 200 if status["status"] == "healthy" else 503
                return web.json_response(status, status=code)
            except Exception:
                logger.exception("Health check failed")
                return web.json_response(
                    {"status": "unhealthy", "error": "internal error"},
                    status=500,
                )

        # healthz: no data, only when gateway.health_port is set. Never carries the dashboard.
        health_runner = None
        if config.gateway.health_port is not None:
            health_app = web.Application()
            health_app.router.add_get("/healthz", _health_handler)
            health_runner = web.AppRunner(health_app)
            await health_runner.setup()
            health_host = config.gateway.health_host
            health_port = config.gateway.health_port
            await web.TCPSite(health_runner, health_host, health_port).start()
            logger.info("healthz on http://%s:%d/healthz", health_host, health_port)

        # Audit dashboard: its own admin socket (group agentpass-admin); TCP only on opt-in,
        # and then always behind the bearer admin token.
        dashboard_runners: list[web.AppRunner] = []
        if config.listen.admin_socket:
            runner = web.AppRunner(build_dashboard_app(db, remembered=remembered))
            await runner.setup()
            dashboard_runners.append(runner)
            admin_sock = bind_group_socket(config.listen.admin_socket, config.listen.admin_group)
            await web.SockSite(runner, admin_sock).start()
            logger.info(
                "audit dashboard on unix://%s (group %s)",
                config.listen.admin_socket,
                config.listen.admin_group,
            )
        dash_tcp = config.listen.dashboard_tcp
        if dash_tcp is not None:
            if not dash_tcp.admin_token:
                logger.error("listen.dashboard_tcp needs admin_token; refusing to serve it")
                sys.exit(1)
            logger.warning(
                "audit dashboard on TCP %s:%d (bearer token)", dash_tcp.host, dash_tcp.port
            )
            runner = web.AppRunner(
                build_dashboard_app(db, dash_tcp.admin_token, remembered=remembered)
            )
            await runner.setup()
            dashboard_runners.append(runner)
            await web.TCPSite(runner, dash_tcp.host, dash_tcp.port).start()

        # 12b. MCP frontend: its own app and port, never the healthz or dashboard app
        mcp_runner = None
        if config.mcp.enabled:
            assert agent_registry is not None  # enforced by load_config
            mcp_server = McpServer(
                pipeline=gateway.pipeline,
                agents=agent_registry,
                registry=registry,
                db=db,
                inline_wait=config.mcp.inline_wait,
            )
            mcp_runner = web.AppRunner(mcp_server.build_app())
            await mcp_runner.setup()
            if config.mcp.socket:
                mcp_sock = bind_group_socket(config.mcp.socket, config.listen.group)
                await web.SockSite(mcp_runner, mcp_sock).start()
                logger.info("MCP on unix://%s/mcp", config.mcp.socket)
            else:
                await web.TCPSite(mcp_runner, config.mcp.host, config.mcp.port).start()
                logger.info("MCP on http://%s:%d/mcp", config.mcp.host, config.mcp.port)

        # 13. Start the WebSocket listeners: Unix socket and/or TCP, one handler for both
        async with contextlib.AsyncExitStack() as listeners:
            if config.listen.socket:
                agent_sock = bind_group_socket(config.listen.socket, config.listen.group)
                await listeners.enter_async_context(
                    websockets.asyncio.server.unix_serve(gateway.handle_connection, sock=agent_sock)
                )
                logger.info(
                    "agentpass ready on unix://%s (group %s)",
                    config.listen.socket,
                    config.listen.group,
                )
            if tcp is not None:
                await listeners.enter_async_context(
                    websockets.asyncio.server.serve(
                        gateway.handle_connection, tcp.host, tcp.port, ssl=ssl_ctx
                    )
                )
                logger.info(
                    "agentpass ready on %s://%s:%d",
                    "wss" if ssl_ctx else "ws",
                    tcp.host,
                    tcp.port,
                )
            await stop_event.wait()

        # 14. Graceful shutdown
        logger.info("Shutting down...")
        if health_runner is not None:
            await health_runner.cleanup()
        for runner in dashboard_runners:
            await runner.cleanup()
        await gateway.resolve_all_pending(ApprovalReason.GATEWAY_SHUTDOWN)
        if mcp_runner is not None:
            await mcp_runner.cleanup()  # lets MCP calls store their shutdown result first
        for sock_path in (
            config.listen.socket,
            config.listen.admin_socket,
            config.mcp.socket if mcp_runner else None,
        ):
            if sock_path:
                remove_socket(sock_path)
    finally:
        await coordinator.stop()

    for svc in services.values():
        await svc.close()
    await db.close()
    logger.info("agentpass stopped")


def main(argv: list[str] | None = None) -> None:
    """Synchronous entrypoint for the CLI."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    args = parse_args(argv)

    if args.command == "serve":
        try:
            asyncio.run(run(args))
        except ConfigError as e:
            logger.error("Configuration error: %s", e)
            sys.exit(1)
    elif args.command == "agent":
        agents_dir, source = _resolve_agents_dir(args.config, args.agents_dir)
        try:
            token = write_agent_file(agents_dir, args.name)
        except ConfigError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Created {agents_dir / (args.name + '.yaml')} ({source})")
        print("Token (shown once, store it now):")
        print(token)
    elif args.command == "check-config":
        from agentpass.check import run_check

        sys.exit(run_check(args))
    elif args.command == "auth":
        sys.exit(run_auth(args))
    elif args.command == "remembered":
        from agentpass.cli import run_remembered

        sys.exit(run_remembered(args))
    elif args.command == "passkey":
        sys.exit(run_passkey(args))
    elif args.command == "request":
        from agentpass.cli import run_request

        exit_code = asyncio.run(run_request(args))
        sys.exit(exit_code)
    elif args.command == "tools":
        from agentpass.cli import run_tools

        exit_code = asyncio.run(run_tools(args))
        sys.exit(exit_code)
    elif args.command == "pending":
        from agentpass.cli import run_pending

        exit_code = asyncio.run(run_pending(args))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
