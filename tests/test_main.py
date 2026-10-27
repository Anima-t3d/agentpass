"""Tests for agentpass.__main__ — CLI entrypoint and orchestration."""

from __future__ import annotations

import argparse
import logging
import signal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentpass.config import ListenConfig, TcpListen

# ---------------------------------------------------------------------------
# parse_args tests
# ---------------------------------------------------------------------------


class TestParseArgs:
    """Tests for the parse_args() function."""

    def test_defaults(self):
        """Default values for all flags."""
        from agentpass.__main__ import parse_args

        args = parse_args([])
        assert args.config == "config.yaml"
        assert args.permissions == "permissions.yaml"
        assert args.insecure is False

    def test_insecure_flag(self):
        """--insecure flag is recognized."""
        from agentpass.__main__ import parse_args

        args = parse_args(["--insecure"])
        assert args.insecure is True

    def test_custom_config_path(self):
        """--config PATH overrides the default."""
        from agentpass.__main__ import parse_args

        args = parse_args(["--config", "custom.yaml"])
        assert args.config == "custom.yaml"

    def test_custom_permissions_path(self):
        """--permissions PATH overrides the default."""
        from agentpass.__main__ import parse_args

        args = parse_args(["--permissions", "custom-perms.yaml"])
        assert args.permissions == "custom-perms.yaml"

    def test_all_flags_combined(self):
        """All flags together."""
        from agentpass.__main__ import parse_args

        args = parse_args(["--insecure", "--config", "c.yaml", "--permissions", "p.yaml"])
        assert args.insecure is True
        assert args.config == "c.yaml"
        assert args.permissions == "p.yaml"


# ---------------------------------------------------------------------------
# Helpers to build mock config and components
# ---------------------------------------------------------------------------


def _make_mock_config(*, tls=None):
    """Build a mock Config object with all required fields."""
    config = MagicMock()
    config.gateway.host = "127.0.0.1"
    config.gateway.port = 8765
    config.gateway.health_port = 8080
    config.gateway.health_host = "127.0.0.1"
    config.gateway.tls = tls
    config.listen = ListenConfig(
        socket=None, admin_socket=None, tcp=TcpListen(host="127.0.0.1", port=8765)
    )
    config.mcp.socket = None
    config.agent.token = "secret-token"
    config.agent.agents_dir = None
    config.services = {"homeassistant": MagicMock()}
    config.storage.path = "/tmp/test-gate.db"
    config.approval_timeout = 900
    config.mcp.enabled = False
    config.rate_limit = MagicMock()
    return config


def _make_mock_permissions():
    """Build a mock Permissions object."""
    return MagicMock()


def _make_ws_serve_cm():
    """Build a mock async context manager for websockets.serve."""
    mock_ws = AsyncMock()
    mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_ws.__aexit__ = AsyncMock(return_value=False)
    return mock_ws


def _make_mock_health_server():
    """Build mock aiohttp web objects for the health endpoint."""
    mock_runner = AsyncMock()
    mock_runner.setup = AsyncMock()
    mock_runner.cleanup = AsyncMock()
    mock_site = AsyncMock()
    mock_site.start = AsyncMock()
    return mock_runner, mock_site


@pytest.fixture(autouse=True)
def _patch_health_server():
    """Patch aiohttp web module to prevent binding to real ports."""
    mock_runner, mock_site = _make_mock_health_server()
    with (
        patch(f"{_PATCH_PREFIX}.web.Application", return_value=MagicMock()),
        patch(f"{_PATCH_PREFIX}.web.AppRunner", return_value=mock_runner),
        patch(f"{_PATCH_PREFIX}.web.TCPSite", return_value=mock_site),
    ):
        yield


# ---------------------------------------------------------------------------
# run() orchestration tests
# ---------------------------------------------------------------------------

# Common patch targets for run() tests
_PATCH_PREFIX = "agentpass.__main__"


class TestRunTlsCheck:
    """TLS requirement enforcement."""

    @pytest.mark.asyncio
    async def test_no_tls_no_insecure_exits(self):
        """Without TLS config and without --insecure, run() calls sys.exit(1)."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=False)
        mock_config = _make_mock_config(tls=None)

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.sys") as mock_sys,
        ):
            # sys.exit raises SystemExit — simulate that
            mock_sys.exit = MagicMock(side_effect=SystemExit(1))
            with pytest.raises(SystemExit):
                await run(args)
            mock_sys.exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_no_tls_with_insecure_proceeds(self):
        """With --insecure, startup proceeds even without TLS."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        # Make stop_event.wait() return immediately
        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
        ):
            await run(args)

        # Should have reached the end without sys.exit
        mock_db.initialize.assert_awaited_once()
        mock_db.close.assert_awaited_once()


class TestRunStartupSequence:
    """Startup sequence verification."""

    @pytest.mark.asyncio
    async def test_startup_order(self):
        """Startup calls components in correct order:
        config -> db -> services -> health checks -> channels start -> WS serve -> log ready.
        """
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        call_order = []

        # Track the order of async calls
        async def track_db_init():
            call_order.append("db.initialize")

        async def track_db_cleanup():
            call_order.append("db.cleanup_stale_requests")

        async def track_health_check():
            call_order.append("ha.health_check")
            return True

        async def track_coordinator_start():
            call_order.append("coordinator.start")

        async def track_stop_wait():
            call_order.append("ws_ready")

        mock_db.initialize = AsyncMock(side_effect=track_db_init)
        mock_db.cleanup_stale_requests = AsyncMock(side_effect=track_db_cleanup)
        mock_ha.health_check = AsyncMock(side_effect=track_health_check)
        mock_coordinator.start = AsyncMock(side_effect=track_coordinator_start)
        mock_stop_event.wait = AsyncMock(side_effect=track_stop_wait)

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
        ):
            await run(args)

        # Verify order: db -> health check -> channels -> WS ready
        assert call_order.index("db.initialize") < call_order.index("ha.health_check")
        assert call_order.index("ha.health_check") < call_order.index("coordinator.start")
        assert call_order.index("coordinator.start") < call_order.index("ws_ready")

    @pytest.mark.asyncio
    async def test_logs_ready_message(self, caplog):
        """Logs 'ready' when startup completes."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            caplog.at_level(logging.INFO, logger="agentpass"),
        ):
            await run(args)

        assert any("ready" in record.message for record in caplog.records)


class TestRunHealthCheck:
    """HA health check failure is non-fatal."""

    @pytest.mark.asyncio
    async def test_failed_health_check_logs_warning(self, caplog):
        """Failed HA health check logs warning but does not prevent startup."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=False)  # Health check fails
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            caplog.at_level(logging.WARNING, logger="agentpass"),
        ):
            await run(args)

        # Should log a warning about HA being unreachable
        assert any("unreachable" in record.message.lower() for record in caplog.records)
        # But startup should still complete (db.close confirms clean shutdown)
        mock_db.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_successful_health_check_no_warning(self, caplog):
        """Successful HA health check does NOT log a warning."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            caplog.at_level(logging.WARNING, logger="agentpass"),
        ):
            await run(args)

        # No warning about HA unreachable
        assert not any("unreachable" in record.message.lower() for record in caplog.records)


class TestRunShutdownSequence:
    """Shutdown sequence."""

    @pytest.mark.asyncio
    async def test_shutdown_resolves_pending_and_closes_all(self):
        """Shutdown resolves pending, stops channels, closes HA, closes DB."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
        ):
            await run(args)

        # Verify shutdown sequence
        mock_gateway.resolve_all_pending.assert_awaited_once_with("gateway_shutdown")
        mock_coordinator.stop.assert_awaited_once()
        mock_ha.close.assert_awaited_once()
        mock_db.close.assert_awaited_once()


class TestRunSignalHandling:
    """Signal handling registration."""

    @pytest.mark.asyncio
    async def test_signal_handlers_registered(self):
        """SIGTERM and SIGINT handlers are registered."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        registered_signals = []

        def track_add_signal_handler(sig, callback):
            registered_signals.append(sig)

        mock_loop = MagicMock()
        mock_loop.add_signal_handler = track_add_signal_handler

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            patch(f"{_PATCH_PREFIX}.asyncio.get_running_loop", return_value=mock_loop),
        ):
            await run(args)

        assert signal.SIGTERM in registered_signals
        assert signal.SIGINT in registered_signals


class TestRunChannelLifecycle:
    """Channels (and Telegram's manual PTB lifecycle) are started and stopped by the coordinator."""

    @pytest.mark.asyncio
    async def test_coordinator_started_and_stopped(self):
        """start() before serving, resolve_all_pending then stop() on shutdown."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
        ):
            await run(args)

        mock_coordinator.start.assert_awaited_once()
        mock_coordinator.stop.assert_awaited_once()
        mock_gateway.resolve_all_pending.assert_awaited_once()


class TestRunTlsContext:
    """TLS context is built when TLS config is present."""

    @pytest.mark.asyncio
    async def test_tls_ssl_context_built(self):
        """When config has TLS, an SSLContext is created and passed to websockets.serve."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=False)
        mock_tls = MagicMock()
        mock_tls.cert = "/path/to/cert.pem"
        mock_tls.key = "/path/to/key.pem"
        mock_config = _make_mock_config(tls=mock_tls)
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        mock_ssl_ctx = MagicMock()
        mock_ssl_class = MagicMock(return_value=mock_ssl_ctx)

        mock_serve = MagicMock(return_value=mock_ws_cm)

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", mock_serve),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            patch(f"{_PATCH_PREFIX}.ssl.SSLContext", mock_ssl_class),
        ):
            await run(args)

        # SSLContext should have been created and cert chain loaded
        mock_ssl_class.assert_called_once()
        mock_ssl_ctx.load_cert_chain.assert_called_once_with(
            "/path/to/cert.pem", "/path/to/key.pem"
        )

        # websockets.serve should have been called with the ssl context
        mock_serve.assert_called_once()
        _, kwargs = mock_serve.call_args
        assert kwargs.get("ssl") is mock_ssl_ctx


class TestRunTokenNeverLogged:
    """Agent token must never be logged."""

    @pytest.mark.asyncio
    async def test_token_not_in_logs(self, caplog):
        """The agent token does not appear in any log message."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_config.agent.token = "super-secret-agent-token-12345"
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()
        mock_gateway = AsyncMock()
        mock_gateway.resolve_all_pending = AsyncMock()
        mock_gateway.handle_connection = AsyncMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=_make_mock_permissions()),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", return_value=mock_gateway),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
            caplog.at_level(logging.DEBUG, logger="agentpass"),
        ):
            await run(args)

        for record in caplog.records:
            assert "super-secret-agent-token-12345" not in record.message


class TestRunGatewayServerWiring:
    """Verify that GatewayServer is created with the correct arguments."""

    @pytest.mark.asyncio
    async def test_gateway_server_creation(self):
        """GatewayServer is wired with engine, executor, coordinator, db, etc."""
        from agentpass.__main__ import run

        args = argparse.Namespace(config="c.yaml", permissions="p.yaml", insecure=True)
        mock_config = _make_mock_config(tls=None)
        mock_permissions = _make_mock_permissions()
        mock_ws_cm = _make_ws_serve_cm()

        mock_db = AsyncMock()
        mock_ha = AsyncMock()
        mock_ha.health_check = AsyncMock(return_value=True)
        mock_coordinator = AsyncMock()

        mock_gateway_cls = MagicMock()
        mock_gateway_instance = AsyncMock()
        mock_gateway_instance.resolve_all_pending = AsyncMock()
        mock_gateway_instance.handle_connection = AsyncMock()
        mock_gateway_cls.return_value = mock_gateway_instance

        mock_engine_cls = MagicMock()
        mock_executor_cls = MagicMock()

        mock_stop_event = AsyncMock()
        mock_stop_event.wait = AsyncMock()
        mock_stop_event.set = MagicMock()

        with (
            patch(f"{_PATCH_PREFIX}.load_config", return_value=mock_config),
            patch(f"{_PATCH_PREFIX}.load_permissions", return_value=mock_permissions),
            patch(f"{_PATCH_PREFIX}.Database", return_value=mock_db),
            patch(f"{_PATCH_PREFIX}.GenericHTTPService", return_value=mock_ha),
            patch(f"{_PATCH_PREFIX}.build_registry", return_value=MagicMock()),
            patch(f"{_PATCH_PREFIX}.build_channels", return_value=[]),
            patch(f"{_PATCH_PREFIX}.ApprovalCoordinator", return_value=mock_coordinator),
            patch(f"{_PATCH_PREFIX}.GatewayServer", mock_gateway_cls),
            patch(f"{_PATCH_PREFIX}.PermissionEngine", mock_engine_cls),
            patch(f"{_PATCH_PREFIX}.Executor", mock_executor_cls),
            patch(f"{_PATCH_PREFIX}.websockets.asyncio.server.serve", return_value=mock_ws_cm),
            patch(f"{_PATCH_PREFIX}.asyncio.Event", return_value=mock_stop_event),
        ):
            await run(args)

        # GatewayServer was created with all required kwargs
        mock_gateway_cls.assert_called_once()
        kwargs = mock_gateway_cls.call_args.kwargs
        assert kwargs["agent_token"] == mock_config.agent.token
        assert kwargs["engine"] == mock_engine_cls.return_value
        assert kwargs["executor"] == mock_executor_cls.return_value
        assert kwargs["coordinator"] == mock_coordinator
        assert kwargs["db"] == mock_db
        assert kwargs["approval_timeout"] == mock_config.approval_timeout
        assert kwargs["rate_limit_config"] == mock_config.rate_limit
        assert "registry" in kwargs  # Registry is now passed to GatewayServer


class TestMain:
    """Tests for the synchronous main() entrypoint."""

    def test_config_error_exits_with_1(self):
        """main() catches ConfigError and exits with code 1."""
        from agentpass.__main__ import main

        mock_args = argparse.Namespace(command="serve")

        with (
            patch(f"{_PATCH_PREFIX}.parse_args", return_value=mock_args),
            patch(f"{_PATCH_PREFIX}.asyncio.run") as mock_run,
            patch(f"{_PATCH_PREFIX}.sys") as mock_sys,
        ):
            from agentpass.config import ConfigError

            mock_run.side_effect = ConfigError("bad config")
            mock_sys.exit = MagicMock(side_effect=SystemExit(1))

            with pytest.raises(SystemExit):
                main(["--insecure"])

            mock_sys.exit.assert_called_once_with(1)


# ---------------------------------------------------------------------------
# Subcommand parsing tests
# ---------------------------------------------------------------------------


class TestParseArgsSubcommands:
    """Tests for subcommand routing in parse_args()."""

    def test_serve_subcommand_explicit(self):
        """Explicit 'serve' subcommand is recognized."""
        from agentpass.__main__ import parse_args

        args = parse_args(["serve", "--insecure"])
        assert args.command == "serve"
        assert args.insecure is True

    def test_no_subcommand_defaults_to_serve(self):
        """No subcommand defaults to 'serve'."""
        from agentpass.__main__ import parse_args

        args = parse_args([])
        assert args.command == "serve"
        assert args.insecure is False
        assert args.config == "config.yaml"
        assert args.permissions == "permissions.yaml"

    def test_no_subcommand_with_flags(self):
        """Flags without subcommand still route to 'serve'."""
        from agentpass.__main__ import parse_args

        args = parse_args(["--insecure"])
        assert args.command == "serve"
        assert args.insecure is True

    def test_request_subcommand(self):
        """'request' subcommand parses tool and args."""
        from agentpass.__main__ import parse_args

        args = parse_args(["request", "ha_get_state", "entity_id=sensor.temp"])
        assert args.command == "request"
        assert args.tool == "ha_get_state"
        assert args.args == ["entity_id=sensor.temp"]

    def test_request_with_url_and_token(self):
        """'request' subcommand parses --url and --token."""
        from agentpass.__main__ import parse_args

        args = parse_args(
            [
                "request",
                "ha_get_state",
                "--url",
                "wss://gw:8443",
                "--token",
                "my-token",
            ]
        )
        assert args.command == "request"
        assert args.url == "wss://gw:8443"
        assert args.token == "my-token"

    def test_tools_subcommand(self):
        """'tools' subcommand parses --url."""
        from agentpass.__main__ import parse_args

        args = parse_args(["tools", "--url", "wss://gw:8443"])
        assert args.command == "tools"
        assert args.url == "wss://gw:8443"

    def test_pending_subcommand(self):
        """'pending' subcommand is recognized."""
        from agentpass.__main__ import parse_args

        args = parse_args(["pending"])
        assert args.command == "pending"


class TestLogLevel:
    """LOG_LEVEL environment variable support."""

    def _run_main_with_log_level(self, level: str | None):
        """Helper: run main() with a given LOG_LEVEL and return the root logger level."""
        from agentpass.__main__ import main

        # Reset root logger so basicConfig takes effect
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        root.setLevel(logging.WARNING)  # reset to non-INFO default

        mock_args = argparse.Namespace(command="serve")
        env = {"LOG_LEVEL": level} if level else {}
        with (
            patch(f"{_PATCH_PREFIX}.parse_args", return_value=mock_args),
            patch(f"{_PATCH_PREFIX}.asyncio.run"),
            patch.dict("os.environ", env, clear=False),
        ):
            if level is None:
                import os

                os.environ.pop("LOG_LEVEL", None)
            main(["--insecure"])

        return root.level

    def test_default_log_level_is_info(self):
        """Without LOG_LEVEL env var, logging defaults to INFO."""
        assert self._run_main_with_log_level(None) == logging.INFO

    def test_log_level_debug(self):
        """LOG_LEVEL=DEBUG sets root logger to DEBUG."""
        assert self._run_main_with_log_level("DEBUG") == logging.DEBUG

    def test_log_level_warning(self):
        """LOG_LEVEL=WARNING sets root logger to WARNING."""
        assert self._run_main_with_log_level("WARNING") == logging.WARNING

    def test_invalid_log_level_defaults_to_info(self):
        """Invalid LOG_LEVEL falls back to INFO."""
        assert self._run_main_with_log_level("INVALID") == logging.INFO
