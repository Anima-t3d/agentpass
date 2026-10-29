"""Configuration loading with env var substitution and validation."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
WILDCARD_HOSTS = {"0.0.0.0", "::", "", "*"}
DEFAULT_AGENT_SOCKET = "/run/agentpass/agent.sock"  # matches RuntimeDirectory=agentpass
DEFAULT_SOCKET_GROUP = "agentpass-clients"
DEFAULT_ADMIN_SOCKET = "/run/agentpass/admin.sock"
DEFAULT_ADMIN_GROUP = "agentpass-admin"


class ConfigError(Exception):
    """Raised on configuration loading or validation errors."""


# --- Env var substitution ---

_ENV_VAR_RE = re.compile(r"\$\{(\w+)\}")


def _replacer(match: re.Match) -> str:
    var = match.group(1)
    val = os.environ.get(var)
    if val is None:
        raise ConfigError(f"Environment variable {var} is not set")
    return val


def substitute_env_vars(obj: Any) -> Any:
    """Recursively substitute ${VAR} in all string values."""
    if isinstance(obj, str):
        return _ENV_VAR_RE.sub(_replacer, obj)
    if isinstance(obj, dict):
        return {k: substitute_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_env_vars(item) for item in obj]
    return obj


def substitute_env_vars_in_text(text: str) -> str:
    """Substitute ${VAR} in raw text before YAML parsing."""
    return _ENV_VAR_RE.sub(_replacer, text)


# --- Config dataclasses ---


@dataclass
class TLSConfig:
    cert: str
    key: str


@dataclass
class TcpListen:
    host: str
    port: int
    allow_wildcard: bool = False


@dataclass
class DashboardTcp:
    """Explicit opt-in: the audit dashboard on loopback TCP, behind a bearer admin token."""

    host: str
    port: int
    admin_token: str = ""  # empty is a config error that check-config reports and serve refuses


@dataclass
class ListenConfig:
    """Where the agent API listens: a group-restricted Unix socket and/or TCP.

    The audit dashboard has its own admin socket (group agentpass-admin), never the agent group.
    """

    socket: str | None = DEFAULT_AGENT_SOCKET
    group: str = DEFAULT_SOCKET_GROUP
    tcp: TcpListen | None = None
    admin_socket: str | None = DEFAULT_ADMIN_SOCKET
    admin_group: str = DEFAULT_ADMIN_GROUP
    dashboard_tcp: DashboardTcp | None = None


@dataclass
class GatewayConfig:
    host: str
    port: int
    tls: TLSConfig | None = None
    health_port: int | None = None  # /healthz is off unless a port is set
    health_host: str = "127.0.0.1"
    reserved_ports: list[int] = field(default_factory=list)  # ports other software owns


@dataclass
class AgentConfig:
    token: str = ""  # legacy single shared token; empty when agents_dir is used
    agents_dir: str | None = None  # per-agent files (agents/NAME.yaml)
    policy_dir: str | None = None  # _floor.yaml and shared rule sets


@dataclass
class TelegramConfig:
    token: str
    chat_id: int
    allowed_users: list[int]


@dataclass
class MessengerConfig:
    type: str
    telegram: TelegramConfig | None = None


@dataclass
class NotifyConfig:
    """Delivery settings of a display-only channel (DESIGN 4.4 item 3)."""

    transport: str  # webhook | command
    url: str = ""
    command: list[str] = field(default_factory=list)
    timeout: float = 5.0


@dataclass
class ChannelConfig:
    """One approval channel (DESIGN 5.2)."""

    name: str
    type: str
    trust: str = "trusted"
    telegram: TelegramConfig | None = None
    passkey: Any = None  # PasskeyConfig, filled in by load_config
    notify: NotifyConfig | None = None  # webhook / command channels


@dataclass
class StorageConfig:
    type: str
    path: str


@dataclass
class RateLimitConfig:
    max_pending_approvals: int = 10
    max_requests_per_minute: int = 60


@dataclass
class McpConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8205
    inline_wait: int = 50  # seconds a tools/call waits for approval before returning pending
    socket: str | None = None  # Unix socket path (same group and mode as the agent socket)


@dataclass
class Config:
    gateway: GatewayConfig
    agent: AgentConfig
    messenger: MessengerConfig
    services: dict[str, ServiceConfig]
    storage: StorageConfig
    approval_timeout: int = 900
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    channels: list[ChannelConfig] = field(default_factory=list)
    listen: ListenConfig = field(default_factory=ListenConfig)
    passkey: Any = None  # PasskeyConfig when the deployment configures the approval page


# --- Tool / Service dataclasses (extensible tools) ---


ARG_TYPES = ("string", "text", "integer", "number", "boolean", "enum", "array", "object")
RISK_LEVELS = ("low", "medium", "high")
REMEMBER_MODES = ("args", "signature")
RESPONSE_TYPES = ("json", "text", "binary", "none")
STORE_RESULT_MODES = ("none", "truncated", "full")
FORBIDDEN_HEADERS = frozenset({"authorization", "host", "cookie"})
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


@dataclass
class ArgDefinition:
    required: bool = False
    validate: str | None = None  # regex pattern string, matched with fullmatch
    type: str = "string"  # one of ARG_TYPES
    description: str = ""
    max_length: int | None = None
    min: int | float | None = None
    max: int | float | None = None
    default: Any = None
    values: list[Any] | None = None  # type: enum
    items: ArgDefinition | None = None  # type: array
    max_items: int | None = None
    signature: bool = True  # False: never part of the signature, no forbidden-char check


@dataclass
class RequestDefinition:
    method: str  # GET, POST, PUT, DELETE, PATCH
    path: str  # "/api/states/{entity_id}", "{name:path}" allows several segments
    body_exclude: list[str] | None = None
    query: dict[str, str] | None = None  # templates over declared args
    headers: dict[str, str] | None = None
    body_include: list[str] | None = None  # allowlist; set together with body_map by `body:`
    body_map: dict[str, str] | None = None  # computed fields
    has_body_spec: bool = False
    timeout: float | None = None


@dataclass
class ResponseDefinition:
    wrap: str | None = None  # wrap response in {wrap: data}
    type: str = "json"
    max_bytes: int | None = None


RESERVED_ARG_NAMES = ("agent_note", "idempotency_key")  # gateway-added properties on every tool
PREVIEW_RENDERERS = ("template", "email", "diff", "entity_state", "resource_summary")
PREVIEW_ON_ERROR = ("unavailable", "omit")
PREVIEW_COMPARISONS = ("equals", "in", "not_in", "endswith_not")
PREVIEW_MAX_LOOKUPS = 5
PREVIEW_MAX_FIELDS = 50
PREVIEW_MAX_WARNINGS = 20
PREVIEW_MAX_CHARS = 20000
PREVIEW_DEFAULT_MAX_CHARS = 2000
PREVIEW_MAX_LOOKUP_TIMEOUT = 10.0
PREVIEW_DEFAULT_LOOKUP_TIMEOUT = 2.0


@dataclass
class PreviewLookup:
    """A read-only GET the gateway makes (with the tool's own service) to build a preview."""

    id: str
    path: str  # "/api/states/{entity_id}", over declared args
    method: str = "GET"
    query: dict[str, str] | None = None
    on_error: str = "unavailable"  # unavailable | omit
    timeout: float = PREVIEW_DEFAULT_LOOKUP_TIMEOUT


@dataclass
class PreviewField:
    label: str
    value: str  # template over args and lookup results


@dataclass
class PreviewWarning:
    """``text`` is shown when ``value`` satisfies the one comparison."""

    text: str
    value: str  # template
    comparison: str  # one of PREVIEW_COMPARISONS
    operand: Any = None  # str for equals/endswith_not, list[str] for in/not_in


@dataclass
class PreviewSpec:
    """A tool's ``preview:`` block (docs/APPROVAL-PREVIEWS.md section 2)."""

    renderer: str = "template"
    lookups: list[PreviewLookup] = field(default_factory=list)
    title: str = ""
    summary: str = ""
    fields: list[PreviewField] = field(default_factory=list)
    warnings: list[PreviewWarning] = field(default_factory=list)
    max_chars: int = PREVIEW_DEFAULT_MAX_CHARS
    confirm_text: str | None = None  # template: typed confirmation on the page
    require_page: bool = False  # hide Telegram approve buttons (part 2)
    params: dict[str, Any] = field(default_factory=dict)  # built-in renderer parameters


@dataclass
class ToolDefinition:
    name: str
    service_name: str
    description: str = ""
    signature: str = ""  # "{domain}.{service}, {entity_id}"
    args: dict[str, ArgDefinition] = field(default_factory=dict)
    request: RequestDefinition | None = None
    response: ResponseDefinition | None = None
    redact_args: list[str] = field(default_factory=list)
    store_result: str = "full"  # none | truncated | full
    risk: str | None = None  # low | medium | high; display hint and MCP annotations
    remember: str = "args"  # what "Allow always, exact" matches: args (all) | signature
    preview: PreviewSpec | None = None


@dataclass
class AuthConfig:
    type: str  # bearer, header, query, basic, oauth2
    token: str = ""
    header_name: str = ""  # for type=header
    query_param: str = ""  # for type=query
    username: str = ""  # for type=basic
    password: str = ""  # for type=basic
    provider: str = ""  # for type=oauth2 ("google")
    account: str = ""  # for type=oauth2
    token_dir: str = ""  # for type=oauth2: derived from storage.path
    secrets_file: str = ""  # for type=oauth2: secrets.yaml next to the config
    token_url: str = ""  # for type=oauth2: override the token endpoint (tests)


@dataclass
class HealthCheckConfig:
    method: str = "GET"
    path: str = "/"
    expect_status: int = 200


@dataclass
class ErrorMapping:
    status: int
    message: str  # supports {status}, {body} templates


@dataclass
class ServiceConfig:
    name: str
    url: str
    auth: AuthConfig
    handler: str = "http"
    handler_class: str = ""
    health: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    tools_file: str = ""
    tools: list[ToolDefinition] = field(default_factory=list)
    errors: list[ErrorMapping] = field(default_factory=list)


# --- Permission dataclasses ---


APPROVAL_REQUIRE = ("any_trusted", "telegram", "passkey")
APPROVAL_RISK = ("low", "medium", "high")
_APPROVAL_KEYS = {"require", "timeout", "channels", "risk"}


@dataclass(frozen=True)
class ApprovalSpec:
    """A rule's ``approval`` block (DESIGN 3.6, 5.3). ``None`` fields mean "not set"."""

    require: str | None = None
    timeout: int | None = None  # seconds
    channels: tuple[str, ...] | None = None  # configured channel names; None = all
    risk: str | None = None  # display hint only
    source: str = field(default="", compare=False)  # file the rule came from, for messages


@dataclass
class PermissionRule:
    pattern: str
    action: str
    description: str = ""
    approval: ApprovalSpec | None = None


def parse_approval(raw: Any, source: str, pattern: str) -> ApprovalSpec | None:
    """Validate a rule's ``approval`` mapping; *source* is the file, for error messages."""
    if raw is None:
        return None
    where = f"{source}: rule {pattern!r}: approval"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    unknown = set(raw) - _APPROVAL_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key {', '.join(sorted(map(str, unknown)))}")
    require = raw.get("require")
    if require is not None and require not in APPROVAL_REQUIRE:
        raise ConfigError(f"{where}.require must be one of {', '.join(APPROVAL_REQUIRE)}")
    timeout = raw.get("timeout")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0
    ):
        raise ConfigError(f"{where}.timeout must be a positive integer (seconds)")
    channels = raw.get("channels")
    if channels is not None:
        if not isinstance(channels, list) or not all(isinstance(c, str) for c in channels):
            raise ConfigError(f"{where}.channels must be a list of channel names")
        channels = tuple(channels)
    risk = raw.get("risk")
    if risk is not None and risk not in APPROVAL_RISK:
        raise ConfigError(f"{where}.risk must be one of {', '.join(APPROVAL_RISK)}")
    return ApprovalSpec(require, timeout, channels, risk, source)


def validate_rule_channels(rules: list[PermissionRule], channels: list[ChannelConfig]) -> None:
    """Raise ConfigError when a rule's ``approval.channels`` names an unconfigured channel."""
    known = {c.name for c in channels}
    for rule in rules:
        spec = rule.approval
        for name in (spec.channels or ()) if spec else ():
            if name not in known:
                raise ConfigError(
                    f"{spec.source}: rule {rule.pattern!r}: approval.channels names unknown "
                    f"channel {name!r} (configured: {', '.join(sorted(known))})"
                )


def approval_warnings(rules: list[PermissionRule], channels: list[ChannelConfig]) -> list[str]:
    """Lint messages for rules whose approval block cannot work with *channels*."""
    return [message for _kind, message in approval_findings(rules, channels)]


def approval_findings(
    rules: list[PermissionRule], channels: list[ChannelConfig]
) -> list[tuple[str, str]]:
    """Like `approval_warnings`, as (kind, message): `passkey-without-channel` or `other`."""
    trusted_types = {c.type for c in channels if c.trust == "trusted"}
    out: list[tuple[str, str]] = []
    for rule in rules:
        spec = rule.approval
        if spec is None:
            continue
        where = f"{spec.source}: rule {rule.pattern!r}"
        if spec.require in ("telegram", "passkey") and spec.require not in trusted_types:
            kind = "passkey-without-channel" if spec.require == "passkey" else "other"
            out.append(
                (
                    kind,
                    f"{where}: approval.require is {spec.require} but no trusted "
                    f"{spec.require} channel is configured; requests will be refused",
                )
            )
        if spec.require is not None and spec.channels is not None and not spec.channels:
            out.append(("other", f"{where}: approval.channels is empty while require is set"))
    return out


@dataclass
class Permissions:
    defaults: list[PermissionRule]
    rules: list[PermissionRule]


# --- Helpers ---


def _require(data: dict, key: str, context: str) -> Any:
    """Get a required key from a dict or raise ConfigError."""
    if key not in data or data[key] is None:
        raise ConfigError(f"Missing required config: {context}.{key}")
    return data[key]


def _coerce_int(value: Any, field_name: str) -> int:
    """Coerce a value to int (handles env-substituted strings)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"Cannot convert {field_name} to int: {value!r}") from None


def _parse_reserved_ports(raw: Any) -> list[int]:
    """gateway.reserved_ports: a list of ints 1-65535 (default empty)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("gateway.reserved_ports must be a list of port numbers")
    ports: list[int] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ConfigError(f"gateway.reserved_ports: {item!r} is not a port (1-65535)")
        ports.append(item)
    return ports


def is_wildcard_host(host: str) -> bool:
    """True for an address that binds every interface (0.0.0.0, ::, empty, *)."""
    host = host.strip()
    if host in WILDCARD_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_unspecified
    except ValueError:
        return False


def _parse_tcp_listen(tcp_raw: Any, where: str) -> TcpListen:
    allow = tcp_raw.get("allow_wildcard", False)
    if not isinstance(allow, bool):
        raise ConfigError(f"{where}.allow_wildcard must be true or false")
    tcp = TcpListen(
        host=str(_require(tcp_raw, "host", where)),
        port=_coerce_int(_require(tcp_raw, "port", where), f"{where}.port"),
        allow_wildcard=allow,
    )
    if not 0 < tcp.port < 65536:
        raise ConfigError(f"{where}.port must be between 1 and 65535, got: {tcp.port}")
    if is_wildcard_host(tcp.host) and not tcp.allow_wildcard:
        raise ConfigError(
            f"{where}.host {tcp.host!r} binds every network interface; refused. "
            f"Use 127.0.0.1, or set {where}.allow_wildcard: true if you really mean it"
        )
    return tcp


_LISTEN_KEYS = {"socket", "group", "tcp", "admin_socket", "admin_group", "dashboard_tcp"}


def _parse_dashboard_tcp(raw: Any) -> DashboardTcp:
    if not isinstance(raw, dict):
        raise ConfigError("listen.dashboard_tcp must be a mapping with host, port, admin_token")
    host = str(raw.get("host", "127.0.0.1"))
    if host not in LOOPBACK_HOSTS:
        raise ConfigError(f"listen.dashboard_tcp.host must be a loopback address, got: {host!r}")
    port = _coerce_int(_require(raw, "port", "listen.dashboard_tcp"), "listen.dashboard_tcp.port")
    return DashboardTcp(host=host, port=port, admin_token=str(raw.get("admin_token") or ""))


def _parse_listen(listen_raw: Any, gw_raw: dict, host: str, port: int) -> ListenConfig:
    """Resolve the agent API listeners from the listen block (or legacy gateway.host/port)."""
    if listen_raw is None:
        legacy = {
            "host": host,
            "port": port,
            "allow_wildcard": gw_raw.get("allow_wildcard", False),
        }
        # Legacy shape: no admin socket, so no dashboard until the listen block is adopted
        return ListenConfig(
            socket=None, admin_socket=None, tcp=_parse_tcp_listen(legacy, "gateway")
        )
    if not isinstance(listen_raw, dict):
        raise ConfigError("listen must be a mapping")
    unknown = sorted(map(str, set(listen_raw) - _LISTEN_KEYS))
    if unknown:
        raise ConfigError(f"unknown listen key(s): {', '.join(unknown)}")
    sock = listen_raw.get("socket", DEFAULT_AGENT_SOCKET)
    if sock is not None and (not isinstance(sock, str) or not os.path.isabs(sock)):
        raise ConfigError(f"listen.socket must be an absolute path or null, got: {sock!r}")
    group = listen_raw.get("group", DEFAULT_SOCKET_GROUP)
    if not isinstance(group, str) or not group:
        raise ConfigError("listen.group must be a group name")
    tcp = None
    if listen_raw.get("tcp") is not None:
        tcp_raw = listen_raw["tcp"]
        if not isinstance(tcp_raw, dict):
            raise ConfigError("listen.tcp must be a mapping with host and port")
        tcp = _parse_tcp_listen(tcp_raw, "listen.tcp")
    if sock is None and tcp is None:
        raise ConfigError("listen needs a socket or a tcp listener")
    admin_sock = listen_raw.get("admin_socket", DEFAULT_ADMIN_SOCKET)
    if admin_sock is not None and (
        not isinstance(admin_sock, str) or not os.path.isabs(admin_sock)
    ):
        raise ConfigError(
            f"listen.admin_socket must be an absolute path or null, got: {admin_sock!r}"
        )
    admin_group = listen_raw.get("admin_group", DEFAULT_ADMIN_GROUP)
    if not isinstance(admin_group, str) or not admin_group:
        raise ConfigError("listen.admin_group must be a group name")
    dash_tcp = None
    if listen_raw.get("dashboard_tcp") is not None:
        dash_tcp = _parse_dashboard_tcp(listen_raw["dashboard_tcp"])
    return ListenConfig(
        socket=sock,
        group=group,
        tcp=tcp,
        admin_socket=admin_sock,
        admin_group=admin_group,
        dashboard_tcp=dash_tcp,
    )


# --- Loaders ---


def _telegram_settings(tg_raw: Any, where: str) -> TelegramConfig:
    if not isinstance(tg_raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    token = _require(tg_raw, "token", where)
    chat_id = _coerce_int(_require(tg_raw, "chat_id", where), f"{where}.chat_id")
    allowed_users = _require(tg_raw, "allowed_users", where)
    if not allowed_users:
        raise ConfigError(f"{where}.allowed_users must be a non-empty list")
    return TelegramConfig(
        token=token,
        chat_id=chat_id,
        allowed_users=[_coerce_int(u, f"{where}.allowed_users[]") for u in allowed_users],
    )


CHANNEL_TRUST = ("trusted", "notify")
CHANNEL_TYPES = ("telegram", "passkey", "webhook", "command")
NOTIFY_TYPES = ("webhook", "command")
_NOTIFY_KEYS = {
    "webhook": {"name", "type", "trust", "url", "timeout"},
    "command": {"name", "type", "trust", "command", "timeout"},
}


def _notify_settings(entry: dict[str, Any], ctype: str, where: str) -> NotifyConfig:
    unknown = set(entry) - _NOTIFY_KEYS[ctype]
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)} for type {ctype}")
    timeout_raw = entry.get("timeout", 5)
    try:
        timeout = float(timeout_raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{where}.timeout must be a number") from None
    if not 0 < timeout <= 60:
        raise ConfigError(f"{where}.timeout must be between 0 and 60 seconds")
    if ctype == "webhook":
        url = _require(entry, "url", where)
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ConfigError(f"{where}.url must be an http(s) URL")
        return NotifyConfig(transport="webhook", url=url, timeout=timeout)
    command = _require(entry, "command", where)
    if isinstance(command, str):
        command = shlex.split(command)
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(c, str) and c for c in command)
    ):
        raise ConfigError(f"{where}.command must be a non-empty list of strings (argv)")
    return NotifyConfig(transport="command", command=command, timeout=timeout)


def _load_channels(raw: dict[str, Any]) -> list[ChannelConfig]:
    """Parse ``channels`` (list of entries with ``name``, or mapping name -> entry).

    The old ``messenger: {type: telegram, telegram: {...}}`` block stays valid as a
    one-channel shorthand named ``telegram``. Giving both is an error.
    """
    if "channels" in raw and "messenger" in raw:
        raise ConfigError("Use either 'channels' or 'messenger', not both")
    if "channels" not in raw:
        msg_raw = _require(raw, "messenger", "")
        msg_type = _require(msg_raw, "type", "messenger")
        if msg_type != "telegram":
            raise ConfigError(
                f"Unsupported messenger type: {msg_type!r} (only 'telegram' is supported)"
            )
        tg = _telegram_settings(_require(msg_raw, "telegram", "messenger"), "messenger.telegram")
        return [ChannelConfig(name="telegram", type="telegram", telegram=tg)]

    entries = raw["channels"]
    if isinstance(entries, dict):
        entries = [{"name": name, **(body or {})} for name, body in entries.items()]
    if not isinstance(entries, list) or not entries:
        raise ConfigError("channels must be a non-empty list or mapping")
    channels: list[ChannelConfig] = []
    for i, entry in enumerate(entries):
        where = f"channels[{i}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a mapping")
        name = _require(entry, "name", where)
        where = f"channels.{name}"
        ctype = _require(entry, "type", where)
        if ctype not in CHANNEL_TYPES:
            raise ConfigError(f"Unsupported channel type: {ctype!r} (one of {CHANNEL_TYPES})")
        trust = entry.get("trust", "notify" if ctype in NOTIFY_TYPES else "trusted")
        if trust not in CHANNEL_TRUST:
            raise ConfigError(f"{where}.trust must be one of {CHANNEL_TRUST}")
        if any(c.name == name for c in channels):
            raise ConfigError(f"Duplicate channel name: {name}")
        if ctype in NOTIFY_TYPES:
            if trust != "notify":
                raise ConfigError(f"{where}: type {ctype} is display-only, trust must be 'notify'")
            notify = _notify_settings(entry, ctype, where)
            channels.append(ChannelConfig(name=name, type=ctype, trust=trust, notify=notify))
            continue
        if ctype == "passkey":
            # The passkey page is configured once, in the top-level `passkey` block.
            channels.append(ChannelConfig(name=name, type=ctype, trust=trust))
            continue
        settings = entry.get("telegram", entry)  # settings inline or under `telegram:`
        tg = _telegram_settings(settings, where)
        channels.append(ChannelConfig(name=name, type=ctype, trust=trust, telegram=tg))
    return channels


def load_config(path: str = "config.yaml") -> Config:
    """Load and validate config.yaml, returning a typed Config."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Config file not found: {path}")

    with open(p) as f:
        raw = yaml.safe_load(substitute_env_vars_in_text(f.read()))

    # Gateway
    gw_raw = _require(raw, "gateway", "")
    listen_raw = raw.get("listen")
    if listen_raw is None:
        # Legacy shape: gateway.host/port is the only listener (TCP)
        host = _require(gw_raw, "host", "gateway")
        port = _coerce_int(_require(gw_raw, "port", "gateway"), "gateway.port")
    else:
        # gateway.host/port are unused when a listen block exists
        host = str(gw_raw.get("host", "127.0.0.1"))
        port = _coerce_int(gw_raw.get("port", 0), "gateway.port")
    listen = _parse_listen(listen_raw, gw_raw, host, port)

    tls = None
    if gw_raw.get("tls"):
        tls_raw = gw_raw["tls"]
        tls = TLSConfig(
            cert=_require(tls_raw, "cert", "gateway.tls"),
            key=_require(tls_raw, "key", "gateway.tls"),
        )

    health_port = None
    if gw_raw.get("health_port") is not None:
        health_port = _coerce_int(gw_raw["health_port"], "gateway.health_port")
    if listen.tcp and health_port is not None and health_port == listen.tcp.port:
        raise ConfigError(
            f"gateway.health_port ({health_port}) must not equal the TCP listen port "
            f"({listen.tcp.port})"
        )
    health_host = gw_raw.get("health_host", "127.0.0.1")
    reserved_ports = _parse_reserved_ports(gw_raw.get("reserved_ports"))
    gateway = GatewayConfig(
        host=host,
        port=port,
        tls=tls,
        health_port=health_port,
        health_host=health_host,
        reserved_ports=reserved_ports,
    )

    # Agent
    agent_raw = _require(raw, "agent", "")
    config_dir = Path(path).parent
    agents_dir = agent_raw.get("agents_dir")
    policy_dir = agent_raw.get("policy_dir")
    if agents_dir:
        if agent_raw.get("token"):
            raise ConfigError(
                "agent.token and agent.agents_dir are mutually exclusive: "
                "a shared token would bypass per-agent policy and audit attribution"
            )
        agents_dir = str(config_dir / agents_dir)
        policy_dir = str(config_dir / policy_dir) if policy_dir else None
        token = ""
    else:
        token = _require(agent_raw, "token", "agent")
        if not token:
            raise ConfigError("Missing required config: agent.token")
        agents_dir = policy_dir = None
    agent = AgentConfig(token=token, agents_dir=agents_dir, policy_dir=policy_dir)

    # Approval channels: a `channels` list/mapping, or the single `messenger` shorthand
    channels = _load_channels(raw)
    first_tg = next((c.telegram for c in channels if c.telegram), None)
    messenger = MessengerConfig(type="telegram", telegram=first_tg)

    # Services
    svc_raw = _require(raw, "services", "")
    services: dict[str, ServiceConfig] = {}
    for svc_name, svc_data in svc_raw.items():
        if not isinstance(svc_data, dict):
            raise ConfigError(f"Service '{svc_name}' must be a mapping")
        url = _require(svc_data, "url", f"services.{svc_name}")

        # Parse auth
        auth_raw = _require(svc_data, "auth", f"services.{svc_name}")
        auth_type = _require(auth_raw, "type", f"services.{svc_name}.auth")
        auth = AuthConfig(
            type=auth_type,
            token=auth_raw.get("token", ""),
            header_name=auth_raw.get("header_name", ""),
            query_param=auth_raw.get("query_param", ""),
            username=auth_raw.get("username", ""),
            password=auth_raw.get("password", ""),
            provider=auth_raw.get("provider", ""),
            account=auth_raw.get("account", ""),
            token_url=auth_raw.get("token_url", ""),
        )
        if auth_type == "oauth2":
            if not auth.provider or not auth.account:
                raise ConfigError(f"services.{svc_name}.auth: oauth2 needs provider and account")
            storage_path = _require(_require(raw, "storage", ""), "path", "storage")
            auth.token_dir = str(Path(storage_path).parent / "tokens")
            auth.secrets_file = str(Path(path).parent / auth_raw.get("secrets", "secrets.yaml"))

        # Parse health check
        health_raw = svc_data.get("health", {})
        health = HealthCheckConfig(
            method=health_raw.get("method", "GET"),
            path=health_raw.get("path", "/"),
            expect_status=_coerce_int(
                health_raw.get("expect_status", 200),
                f"services.{svc_name}.health.expect_status",
            ),
        )

        # Parse errors
        errors = []
        for i, err in enumerate(svc_data.get("errors", [])):
            if not isinstance(err, dict):
                raise ConfigError(f"services.{svc_name}.errors[{i}] must be a mapping")
            if "status" not in err:
                raise ConfigError(
                    f"Missing required key 'status' in services.{svc_name}.errors[{i}]"
                )
            if "message" not in err:
                raise ConfigError(
                    f"Missing required key 'message' in services.{svc_name}.errors[{i}]"
                )
            errors.append(
                ErrorMapping(
                    status=_coerce_int(err["status"], f"services.{svc_name}.errors[{i}].status"),
                    message=err["message"],
                )
            )

        # Load tools
        tools_file = svc_data.get("tools", "")
        tools: list[ToolDefinition] = []
        if tools_file:
            config_dir = Path(path).parent
            tools_path = str(config_dir / tools_file)
            tools = load_tools_file(tools_path, svc_name)

        services[svc_name] = ServiceConfig(
            name=svc_name,
            url=url,
            auth=auth,
            handler=svc_data.get("handler", "http"),
            handler_class=svc_data.get("handler_class", ""),
            health=health,
            tools_file=tools_file,
            tools=tools,
            errors=errors,
        )

    if not services:
        raise ConfigError("At least one service must be configured")

    # Storage
    stor_raw = _require(raw, "storage", "")
    stor_type = _require(stor_raw, "type", "storage")
    if stor_type != "sqlite":
        raise ConfigError(f"Unsupported storage type: {stor_type!r} (only 'sqlite' is supported)")
    storage = StorageConfig(
        type=stor_type,
        path=_require(stor_raw, "path", "storage"),
    )

    # Optional top-level
    approval_timeout = raw.get("approval_timeout", 900)
    if not isinstance(approval_timeout, int) or approval_timeout <= 0:
        raise ConfigError(f"approval_timeout must be a positive integer, got: {approval_timeout!r}")
    rate_limit_raw = raw.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        max_pending_approvals=rate_limit_raw.get("max_pending_approvals", 10),
        max_requests_per_minute=rate_limit_raw.get("max_requests_per_minute", 60),
    )

    mcp_raw = raw.get("mcp") or {}
    if not isinstance(mcp_raw, dict):
        raise ConfigError("mcp must be a mapping")
    mcp = McpConfig(
        enabled=bool(mcp_raw.get("enabled", False)),
        host=str(mcp_raw.get("host", "127.0.0.1")),
        port=_coerce_int(mcp_raw.get("port", 8205), "mcp.port"),
        inline_wait=_coerce_int(mcp_raw.get("inline_wait", 50), "mcp.inline_wait"),
    )
    if mcp.host not in LOOPBACK_HOSTS:
        raise ConfigError(f"mcp.host must be a loopback address, got: {mcp.host!r}")
    if mcp.inline_wait < 0:
        raise ConfigError("mcp.inline_wait must not be negative")
    if mcp.enabled and mcp.port in (port, health_port):
        raise ConfigError(f"mcp.port ({mcp.port}) must differ from the gateway and health ports")
    other_ports = (port, health_port, listen.tcp and listen.tcp.port)
    if listen.dashboard_tcp and listen.dashboard_tcp.port in other_ports:
        raise ConfigError("listen.dashboard_tcp.port must differ from the other listener ports")
    if listen.admin_socket and listen.admin_socket in (listen.socket, mcp.socket):
        raise ConfigError("listen.admin_socket must differ from the agent and MCP sockets")
    if mcp.enabled and mcp.socket and mcp.socket == listen.socket:
        raise ConfigError("mcp.socket must differ from listen.socket")
    if mcp.enabled and not agents_dir:
        raise ConfigError("mcp.enabled requires per-agent tokens (agent.agents_dir)")

    # Approval page. Configured once; a `type: passkey` channel points at it.
    passkey = None
    if raw.get("passkey") is not None:
        from agentpass.passkey.page import PasskeyConfig

        passkey = PasskeyConfig.from_mapping(raw["passkey"], storage.path)
    for channel in channels:
        if channel.type != "passkey":
            continue
        if passkey is None:
            raise ConfigError(f"Channel '{channel.name}': type passkey needs a passkey block")
        if not passkey.enabled:
            raise ConfigError(f"Channel '{channel.name}': passkey.enabled is false")
        channel.passkey = passkey

    return Config(
        gateway=gateway,
        agent=agent,
        messenger=messenger,
        channels=channels,
        services=services,
        storage=storage,
        approval_timeout=approval_timeout,
        rate_limit=rate_limit,
        mcp=mcp,
        listen=listen,
        passkey=passkey,
    )


def load_permissions(path: str = "permissions.yaml") -> Permissions:
    """Load and parse permissions.yaml into typed Permissions."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Permissions file not found: {path}")

    with open(p) as f:
        raw = yaml.safe_load(substitute_env_vars_in_text(f.read()))

    _VALID_ACTIONS = {"allow", "deny", "ask"}

    defaults = []
    for item in raw.get("defaults", []):
        action = item["action"]
        if action not in _VALID_ACTIONS:
            raise ConfigError(f"Invalid permission action: {action!r} (must be allow/deny/ask)")
        defaults.append(
            PermissionRule(
                pattern=item["pattern"],
                action=action,
                description=item.get("description", ""),
                approval=parse_approval(item.get("approval"), path, item["pattern"]),
            )
        )

    rules = []
    for item in raw.get("rules", []) or []:
        action = item["action"]
        if action not in _VALID_ACTIONS:
            raise ConfigError(f"Invalid permission action: {action!r} (must be allow/deny/ask)")
        rules.append(
            PermissionRule(
                pattern=item["pattern"],
                action=action,
                description=item.get("description", ""),
                approval=parse_approval(item.get("approval"), path, item["pattern"]),
            )
        )

    return Permissions(defaults=defaults, rules=rules)


def load_tools_file(path: str, service_name: str) -> list[ToolDefinition]:
    """Load and parse a tools YAML file, returning typed ToolDefinition objects.

    - Reads YAML file
    - Runs substitute_env_vars() on it
    - Validates each tool entry
    - Compiles validation regexes at load time (raise ConfigError if invalid)
    - Returns list of ToolDefinition objects
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Tools file not found: {path}")

    with open(p) as f:
        raw = yaml.safe_load(substitute_env_vars_in_text(f.read()))

    if raw is None:
        return []

    tools_raw = raw.get("tools")
    if not tools_raw:
        return []

    result: list[ToolDefinition] = []
    for tool_name, tool_data in tools_raw.items():
        if tool_data is None:
            tool_data = {}
        result.append(_parse_tool(tool_name, tool_data, service_name))

    return result


_TEMPLATE_REF_RE = re.compile(r"\{(\w+)(?::path)?\}")


def _parse_arg(label: str, data: Any, *, nested: bool = False) -> ArgDefinition:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{label}: arg definition must be a mapping")
    atype = data.get("type", "string")
    if atype not in ARG_TYPES:
        raise ConfigError(f"{label}: unknown type {atype!r} (expected one of {ARG_TYPES})")
    validate = data.get("validate")
    if validate is not None:
        if not isinstance(validate, str):
            raise ConfigError(f"{label}: validate must be a string")
        try:
            re.compile(validate)
        except re.error as e:
            raise ConfigError(f"Invalid regex pattern for {label}: {e}") from None
        if atype not in ("string", "text"):
            raise ConfigError(f"{label}: validate only applies to string or text args")
    for key in ("max_length", "max_items"):
        v = data.get(key)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
            raise ConfigError(f"{label}: {key} must be a non-negative integer")
    if data.get("max_length") is not None and atype not in ("string", "text"):
        raise ConfigError(f"{label}: max_length only applies to string or text args")
    for key in ("min", "max"):
        v = data.get(key)
        if v is not None:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ConfigError(f"{label}: {key} must be a number")
            if atype not in ("integer", "number"):
                raise ConfigError(f"{label}: {key} only applies to integer or number args")
    values = data.get("values")
    if atype == "enum":
        if not isinstance(values, list) or not values:
            raise ConfigError(f"{label}: enum requires a non-empty values list")
    elif values is not None:
        raise ConfigError(f"{label}: values only applies to enum args")
    items: ArgDefinition | None = None
    if atype == "array":
        if data.get("items") is None:
            raise ConfigError(f"{label}: array requires items")
        items = _parse_arg(f"{label}[]", data["items"], nested=True)
        if items.type in ("array", "object"):
            raise ConfigError(f"{label}: array items must be scalar")
    elif data.get("items") is not None or data.get("max_items") is not None:
        raise ConfigError(f"{label}: items and max_items only apply to array args")
    signature = data.get("signature", True)
    if not isinstance(signature, bool):
        raise ConfigError(f"{label}: signature must be true or false")
    arg = ArgDefinition(
        required=bool(data.get("required", False)),
        validate=validate,
        type=atype,
        description=str(data.get("description", "")),
        max_length=data.get("max_length"),
        min=data.get("min"),
        max=data.get("max"),
        default=data.get("default"),
        values=values,
        items=items,
        max_items=data.get("max_items"),
        signature=signature and atype != "text",
    )
    if arg.default is not None:
        if arg.required:
            raise ConfigError(f"{label}: a required arg cannot have a default")
        # Imported lazily: engine imports this module
        from agentpass.engine import check_value

        try:
            check_value(label, arg.default, arg)
        except ValueError as e:
            raise ConfigError(f"Invalid default: {e}") from None
    return arg


def _check_template(label: str, template: Any, args: dict[str, ArgDefinition]) -> None:
    if not isinstance(template, str):
        raise ConfigError(f"{label}: template must be a string")
    for ref in _TEMPLATE_REF_RE.findall(template):
        if ref not in args:
            raise ConfigError(f"{label}: references undeclared arg {ref!r}")


_PREVIEW_REF_RE = re.compile(r"\{(\w+)((?:\.[\w-]+)*)\}")
_PREVIEW_COMMON_KEYS = {
    "renderer",
    "lookups",
    "title",
    "summary",
    "fields",
    "warnings",
    "max_chars",
    "confirm_text",
    "require_page",
}
_PREVIEW_LOOKUP_KEYS = {"id", "method", "path", "query", "on_error", "timeout"}


def _preview_template(label: str, template: Any, roots: set[str]) -> str:
    """Check a preview template: ``{arg}`` or ``{lookup_id.json.path}`` over known roots."""
    if not isinstance(template, str):
        raise ConfigError(f"{label}: must be a string")
    for root, _ in _PREVIEW_REF_RE.findall(template):
        if root not in roots:
            raise ConfigError(
                f"{label}: references {root!r}, which is not a declared arg or lookup"
            )
    return template


def _parse_preview_lookup(where: str, i: int, raw: Any, args: dict, seen: list) -> PreviewLookup:
    lw = f"{where} lookup #{i + 1}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{lw}: must be a mapping")
    bad = set(raw) - _PREVIEW_LOOKUP_KEYS
    if bad:
        raise ConfigError(f"{lw}: unknown key(s): {', '.join(sorted(map(str, bad)))}")
    lid = raw.get("id")
    if not isinstance(lid, str) or not re.fullmatch(r"[A-Za-z_]\w*", lid):
        raise ConfigError(f"{lw}: id must be a name (letters, digits, underscore)")
    lw = f"{where} lookup '{lid}'"
    if lid in args:
        raise ConfigError(f"{lw}: id collides with an arg of the same name")
    if any(lid == other.id for other in seen):
        raise ConfigError(f"{lw}: duplicate lookup id")
    method = str(raw.get("method", "GET")).upper()
    if method not in ("GET", "HEAD"):
        raise ConfigError(f"{lw}: lookups are read-only; method must be GET (got {method!r})")
    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ConfigError(f"{lw}: path must start with a single '/' (the host is fixed)")
    if "://" in path or "\\" in path:
        raise ConfigError(f"{lw}: path must not contain a scheme or backslash")
    _check_template(f"{lw} path", path, args)
    for ref in _TEMPLATE_REF_RE.findall(path):
        if not args[ref].required:
            raise ConfigError(f"{lw}: path arg {ref!r} must be required")
    query = raw.get("query")
    if query is not None:
        if not isinstance(query, dict):
            raise ConfigError(f"{lw}: query must be a mapping")
        for k, v in query.items():
            _check_template(f"{lw} query '{k}'", v, args)
    on_error = raw.get("on_error", "unavailable")
    if on_error not in PREVIEW_ON_ERROR:
        raise ConfigError(f"{lw}: on_error must be one of {PREVIEW_ON_ERROR}")
    timeout = raw.get("timeout", PREVIEW_DEFAULT_LOOKUP_TIMEOUT)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= PREVIEW_MAX_LOOKUP_TIMEOUT
    ):
        raise ConfigError(f"{lw}: timeout must be above 0 and at most {PREVIEW_MAX_LOOKUP_TIMEOUT}")
    return PreviewLookup(lid, path, method, query, on_error, float(timeout))


def _parse_preview_warning(ww: str, raw: Any, roots: set[str]) -> PreviewWarning:
    if not isinstance(raw, dict) or set(raw) != {"when", "text"}:
        raise ConfigError(f"{ww}: must be a mapping with when and text")
    text = _preview_template(f"{ww} text", raw["text"], roots)
    when = raw["when"]
    if not isinstance(when, dict) or "value" not in when:
        raise ConfigError(f"{ww}: when needs a value and one comparison")
    ops = [k for k in when if k != "value"]
    if len(ops) != 1 or ops[0] not in PREVIEW_COMPARISONS:
        raise ConfigError(f"{ww}: when takes exactly one of {PREVIEW_COMPARISONS}")
    op, operand = ops[0], when[ops[0]]
    if op in ("in", "not_in"):
        if not isinstance(operand, list) or not all(isinstance(x, (str, int)) for x in operand):
            raise ConfigError(f"{ww}: {op} needs a list of strings")
        operand = [str(x) for x in operand]
    elif isinstance(operand, bool) or not isinstance(operand, (str, int, float)):
        raise ConfigError(f"{ww}: {op} needs a string")
    else:
        operand = str(operand)
    return PreviewWarning(text, _preview_template(f"{ww} value", when["value"], roots), op, operand)


def _parse_preview(where: str, data: Any, args: dict[str, ArgDefinition]) -> PreviewSpec:
    where = f"{where} preview"
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: must be a mapping")
    renderer = data.get("renderer") or "template"
    if renderer not in PREVIEW_RENDERERS:
        raise ConfigError(f"{where}: unknown renderer {renderer!r} (one of {PREVIEW_RENDERERS})")
    unknown = set(data) - _PREVIEW_COMMON_KEYS
    if renderer == "template" and unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    params = {k: data[k] for k in unknown}  # built-in renderers take their own parameters

    max_chars = data.get("max_chars", PREVIEW_DEFAULT_MAX_CHARS)
    if (
        isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or not 1 <= max_chars <= PREVIEW_MAX_CHARS
    ):
        raise ConfigError(f"{where}: max_chars must be an integer from 1 to {PREVIEW_MAX_CHARS}")
    require_page = data.get("require_page", False)
    if not isinstance(require_page, bool):
        raise ConfigError(f"{where}: require_page must be true or false")

    lookups_raw = data.get("lookups") or []
    if not isinstance(lookups_raw, list):
        raise ConfigError(f"{where}: lookups must be a list")
    if len(lookups_raw) > PREVIEW_MAX_LOOKUPS:
        raise ConfigError(f"{where}: at most {PREVIEW_MAX_LOOKUPS} lookups")
    lookups: list[PreviewLookup] = []
    for i, raw in enumerate(lookups_raw):
        lookups.append(_parse_preview_lookup(where, i, raw, args, lookups))

    roots = set(args) | {lk.id for lk in lookups}
    title = _preview_template(f"{where} title", data.get("title", ""), roots)
    summary = _preview_template(f"{where} summary", data.get("summary", ""), roots)
    confirm_text = data.get("confirm_text")
    if confirm_text is not None:
        confirm_text = _preview_template(f"{where} confirm_text", confirm_text, roots)

    fields_raw = data.get("fields") or []
    if not isinstance(fields_raw, list):
        raise ConfigError(f"{where}: fields must be a list")
    if len(fields_raw) > PREVIEW_MAX_FIELDS:
        raise ConfigError(f"{where}: at most {PREVIEW_MAX_FIELDS} fields")
    fields: list[PreviewField] = []
    for i, raw in enumerate(fields_raw):
        fw = f"{where} field #{i + 1}"
        if not isinstance(raw, dict) or set(raw) != {"label", "value"}:
            raise ConfigError(f"{fw}: must be a mapping with label and value")
        label = _preview_template(f"{fw} label", raw["label"], roots)
        fields.append(PreviewField(label, _preview_template(f"{fw} value", raw["value"], roots)))
    if renderer == "template" and not fields:
        raise ConfigError(f"{where}: the template renderer needs at least one field")

    warnings_raw = data.get("warnings") or []
    if not isinstance(warnings_raw, list):
        raise ConfigError(f"{where}: warnings must be a list")
    if len(warnings_raw) > PREVIEW_MAX_WARNINGS:
        raise ConfigError(f"{where}: at most {PREVIEW_MAX_WARNINGS} warnings")
    warnings = [
        _parse_preview_warning(f"{where} warning #{i + 1}", raw, roots)
        for i, raw in enumerate(warnings_raw)
    ]

    return PreviewSpec(
        renderer=renderer,
        lookups=lookups,
        title=title,
        summary=summary,
        fields=fields,
        warnings=warnings,
        max_chars=max_chars,
        confirm_text=confirm_text,
        require_page=require_page,
        params=params,
    )


def _parse_tool(tool_name: str, data: dict, service_name: str) -> ToolDefinition:
    where = f"tool '{tool_name}'"
    args: dict[str, ArgDefinition] = {}
    for arg_name, arg_data in (data.get("args") or {}).items():
        if arg_name in RESERVED_ARG_NAMES:
            raise ConfigError(
                f"{where}: arg name {arg_name!r} is reserved (the gateway adds it to every tool)"
            )
        args[arg_name] = _parse_arg(f"{where} arg '{arg_name}'", arg_data)

    signature = data.get("signature", "")
    for ref in re.findall(r"\{(\w+)\}", signature):
        if ref not in args:
            raise ConfigError(f"{where}: signature references undeclared arg {ref!r}")
        if not args[ref].signature:
            raise ConfigError(f"{where}: arg {ref!r} is exempt from the signature")

    request: RequestDefinition | None = None
    req_raw = data.get("request")
    if req_raw is not None:
        method = str(req_raw.get("method", "GET")).upper()
        if method not in HTTP_METHODS:
            raise ConfigError(f"{where}: unsupported method {method!r}")
        path = req_raw.get("path", "/")
        _check_template(f"{where} path", path, args)
        for ref in _TEMPLATE_REF_RE.findall(path):
            if not args[ref].required:
                raise ConfigError(f"{where}: path arg {ref!r} must be required")
        query = req_raw.get("query")
        headers = req_raw.get("headers")
        for field_name, mapping in (("query", query), ("headers", headers)):
            if mapping is None:
                continue
            if not isinstance(mapping, dict):
                raise ConfigError(f"{where}: {field_name} must be a mapping")
            for k, v in mapping.items():
                _check_template(f"{where} {field_name} '{k}'", v, args)
        for name in headers or {}:
            if str(name).lower() in FORBIDDEN_HEADERS:
                raise ConfigError(f"{where}: header {name!r} is not allowed")
        body_exclude = req_raw.get("body_exclude")
        body_raw = req_raw.get("body")
        body_include = body_map = None
        if body_raw is not None:
            if not isinstance(body_raw, dict) or set(body_raw) - {"include", "map"}:
                raise ConfigError(f"{where}: body takes only include and map")
            if body_exclude is not None:
                raise ConfigError(f"{where}: body and body_exclude are mutually exclusive")
            body_include = body_raw.get("include")
            body_map = body_raw.get("map")
            for name in body_include or []:
                if name not in args:
                    raise ConfigError(f"{where}: body.include references undeclared arg {name!r}")
            for k, v in (body_map or {}).items():
                _check_template(f"{where} body.map '{k}'", v, args)
        timeout = req_raw.get("timeout")
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
        ):
            raise ConfigError(f"{where}: timeout must be a positive number")
        request = RequestDefinition(
            method=method,
            path=path,
            body_exclude=body_exclude,
            query=query,
            headers=headers,
            body_include=body_include,
            body_map=body_map,
            has_body_spec=body_raw is not None,
            timeout=timeout,
        )

    response: ResponseDefinition | None = None
    resp_raw = data.get("response")
    if resp_raw is not None:
        rtype = resp_raw.get("type", "json")
        if rtype not in RESPONSE_TYPES:
            raise ConfigError(f"{where}: unknown response type {rtype!r}")
        max_bytes = resp_raw.get("max_bytes")
        if max_bytes is not None and (
            isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0
        ):
            raise ConfigError(f"{where}: response.max_bytes must be a positive integer")
        response = ResponseDefinition(wrap=resp_raw.get("wrap"), type=rtype, max_bytes=max_bytes)

    audit = data.get("audit") or {}
    redact = audit.get("redact_args") or []
    for name in redact:
        if name not in args:
            raise ConfigError(f"{where}: audit.redact_args references undeclared arg {name!r}")
    store_result = audit.get("store_result", "full")
    if store_result not in STORE_RESULT_MODES:
        raise ConfigError(f"{where}: audit.store_result must be one of {STORE_RESULT_MODES}")
    risk = data.get("risk")
    if risk is not None and risk not in RISK_LEVELS:
        raise ConfigError(f"{where}: risk must be one of {RISK_LEVELS}")
    remember = data.get("remember", "args")
    if remember not in REMEMBER_MODES:
        raise ConfigError(f"{where}: remember must be one of {REMEMBER_MODES}")
    preview = _parse_preview(where, data["preview"], args) if data.get("preview") else None

    return ToolDefinition(
        name=tool_name,
        service_name=service_name,
        description=data.get("description", ""),
        signature=signature,
        args=args,
        request=request,
        response=response,
        redact_args=list(redact),
        store_result=store_result,
        risk=risk,
        remember=remember,
        preview=preview,
    )
