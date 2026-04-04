# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scheduled task delivery."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from airut.conversation import ConversationLayout
from airut.gateway.config import ScheduleConfig, ScheduleDelivery
from airut.gateway.email.adapter import EmailChannelAdapter
from airut.gateway.scheduler.delivery import (
    _deliver_via_email,
    deliver_result,
)
from airut.gateway.service.message_processing import SandboxTaskResult
from airut.gateway.service.usage_stats import UsageStats
from airut.sandbox import Outcome


def _make_schedule_config() -> ScheduleConfig:
    return ScheduleConfig(
        cron="0 9 * * *",
        deliver=ScheduleDelivery(channel="email", to="user@example.com"),
        prompt="Test prompt",
    )


def _make_result(
    conversation_id: str = "abc12345",
    response_text: str = "Result text",
    usage_stats: UsageStats | None = None,
    outbox_exists: bool = False,
) -> SandboxTaskResult:
    layout = MagicMock(spec=ConversationLayout)
    if outbox_exists:
        layout.outbox = MagicMock()
        layout.outbox.exists.return_value = True
    else:
        layout.outbox = MagicMock()
        layout.outbox.exists.return_value = False
    return SandboxTaskResult(
        outcome=Outcome.SUCCESS,
        conversation_id=conversation_id,
        response_text=response_text,
        usage_stats=usage_stats,
        layout=layout,
        is_error=False,
    )


class TestDeliverResult:
    """Test deliver_result routing."""

    def test_email_delivery(self) -> None:
        handler = MagicMock()
        handler.config.repo_id = "test-repo"
        adapter = MagicMock(spec=EmailChannelAdapter)
        handler.adapters = {"email": adapter}

        config = _make_schedule_config()
        result = _make_result()

        deliver_result(handler, "daily", config, result)

        adapter.send_new_message.assert_called_once()
        call_kwargs = adapter.send_new_message.call_args.kwargs
        assert call_kwargs["to"] == "user@example.com"
        assert "daily" in call_kwargs["subject"]
        assert "abc12345" in call_kwargs["subject"]
        assert call_kwargs["conversation_id"] == "abc12345"

    def test_missing_adapter(self) -> None:
        handler = MagicMock()
        handler.config.repo_id = "test-repo"
        handler.adapters = {}

        config = _make_schedule_config()
        result = _make_result()

        # Should not raise
        deliver_result(handler, "daily", config, result)

    def test_unsupported_adapter_type(self) -> None:
        handler = MagicMock()
        handler.config.repo_id = "test-repo"
        # Non-email adapter
        adapter = MagicMock()
        handler.adapters = {"email": adapter}

        config = _make_schedule_config()
        result = _make_result()

        # Should not raise, just log error
        deliver_result(handler, "daily", config, result)


class TestDeliverViaEmail:
    """Test email-specific delivery."""

    def test_basic_delivery(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        result = _make_result(response_text="Task done")

        _deliver_via_email(adapter, "daily", config, result)

        adapter.send_new_message.assert_called_once()
        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["to"] == "user@example.com"
        assert "[ID:abc12345] daily" == kwargs["subject"]
        assert "Task done" in kwargs["body"]

    def test_delivery_with_usage_stats(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        stats = UsageStats(total_cost_usd=0.05)
        result = _make_result(usage_stats=stats)

        _deliver_via_email(adapter, "daily", config, result)

        kwargs = adapter.send_new_message.call_args.kwargs
        assert "$0.05" in kwargs["body"]

    def test_delivery_with_outbox_files(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        result = _make_result(outbox_exists=True)

        with MagicMock() as mock_collect:
            mock_collect.return_value = [("file.txt", b"content")]
            with pytest.MonkeyPatch.context() as m:
                m.setattr(
                    "airut.gateway.scheduler.delivery.collect_outbox_files",
                    mock_collect,
                )
                _deliver_via_email(adapter, "daily", config, result)

        adapter.send_new_message.assert_called_once()

    def test_delivery_failure_logged(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.side_effect = RuntimeError("SMTP down")
        config = _make_schedule_config()
        result = _make_result()

        # Should not raise
        _deliver_via_email(adapter, "daily", config, result)
