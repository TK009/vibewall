from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from vibewall.config import NotificationsConfig, VibewallConfig
from vibewall.notifications import Notifier


class TestNotifierAvailability:
    async def test_disabled_notifier_never_sends(self) -> None:
        notifier = Notifier(enabled=False)
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            await notifier.notify_blocked("npm", "evil-pkg", "blocklisted")
            mock_exec.assert_not_called()

    async def test_unavailable_notify_send_is_noop(self) -> None:
        notifier = Notifier(enabled=True)
        with patch("shutil.which", return_value=None):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                await notifier.notify_blocked("npm", "evil-pkg", "blocklisted")
                mock_exec.assert_not_called()

    async def test_availability_is_cached(self) -> None:
        notifier = Notifier(enabled=True)
        with patch("shutil.which", return_value=None) as mock_which:
            await notifier._is_available()
            await notifier._is_available()
            mock_which.assert_called_once()


class TestNotifyBlocked:
    async def test_fires_critical_notification(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=5000)
        notifier._available = True  # skip which() check

        mock_proc = AsyncMock()
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc) as mock_exec:
            await notifier.notify_blocked("npm", "evil-pkg", "package is blocklisted")
            # The task is created, let it run
            await asyncio.sleep(0)

            mock_exec.assert_called_once_with(
                "notify-send",
                "--app-name=vibewall",
                "--urgency=critical",
                "--expire-time=5000",
                "Blocked: evil-pkg",
                "package is blocklisted",
            )


class TestNotifyWarned:
    async def test_fires_normal_notification(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=8000)
        notifier._available = True

        mock_proc = AsyncMock()
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc) as mock_exec:
            await notifier.notify_warned("npm", "sketchy-pkg", ["low downloads", "new package"])
            await asyncio.sleep(0)

            mock_exec.assert_called_once_with(
                "notify-send",
                "--app-name=vibewall",
                "--urgency=normal",
                "--expire-time=8000",
                "Warning: sketchy-pkg",
                "low downloads\nnew package",
            )


class TestPromptAsk:
    async def test_allow_action(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=10000)
        notifier._available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"allow\n", b""))
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await notifier.prompt_ask("npm_advisories", "lodash", "critical vulnerability")
            assert result is True

    async def test_block_action(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=10000)
        notifier._available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"block\n", b""))
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await notifier.prompt_ask("npm_advisories", "lodash", "critical vulnerability")
            assert result is False

    async def test_dismissed_returns_none(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=10000)
        notifier._available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await notifier.prompt_ask("npm_advisories", "lodash", "critical vulnerability")
            assert result is None

    async def test_unavailable_returns_none(self) -> None:
        notifier = Notifier(enabled=False)
        result = await notifier.prompt_ask("npm_advisories", "lodash", "critical vulnerability")
        assert result is None

    async def test_prompt_ask_passes_correct_args(self) -> None:
        notifier = Notifier(enabled=True, expire_ms=15000)
        notifier._available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"allow\n", b""))
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc) as mock_exec:
            await notifier.prompt_ask("npm_advisories", "lodash", "critical vulnerability")
            mock_exec.assert_called_once_with(
                "notify-send",
                "--app-name=vibewall",
                "--urgency=critical",
                "--expire-time=15000",
                "--action=allow=Allow",
                "--action=block=Block",
                "--wait",
                "Ask: lodash",
                "npm_advisories: critical vulnerability",
                stdout=asyncio.subprocess.PIPE,
            )


class TestSendErrorHandling:
    async def test_send_swallows_exceptions(self) -> None:
        notifier = Notifier(enabled=True)
        notifier._available = True

        with patch("asyncio.create_subprocess_exec", side_effect=OSError("no such file")):
            # Should not raise
            await notifier._send("critical", "test", "body")


class TestNotificationsConfig:
    def test_defaults(self) -> None:
        cfg = NotificationsConfig()
        assert cfg.enabled is True
        assert cfg.blocked is True
        assert cfg.warned is True
        assert cfg.ask is True
        assert cfg.expire_ms == 10000

    def test_load_from_toml(self, tmp_path: Path) -> None:
        toml = tmp_path / "test.toml"
        toml.write_text("""
[notifications]
enabled = false
blocked = false
warned = true
ask = false
expire_ms = 5000
""")
        cfg = VibewallConfig.load(toml)
        assert cfg.notifications.enabled is False
        assert cfg.notifications.blocked is False
        assert cfg.notifications.warned is True
        assert cfg.notifications.ask is False
        assert cfg.notifications.expire_ms == 5000

    def test_defaults_when_no_section(self, tmp_path: Path) -> None:
        toml = tmp_path / "test.toml"
        toml.write_text("port = 8888\n")
        cfg = VibewallConfig.load(toml)
        assert cfg.notifications.enabled is True
        assert cfg.notifications.expire_ms == 10000

    def test_partial_override(self, tmp_path: Path) -> None:
        toml = tmp_path / "test.toml"
        toml.write_text("""
[notifications]
expire_ms = 20000
""")
        cfg = VibewallConfig.load(toml)
        assert cfg.notifications.enabled is True
        assert cfg.notifications.expire_ms == 20000
