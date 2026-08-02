# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scheduled task delivery."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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
    outbox: Path | None = None,
) -> SandboxTaskResult:
    layout = MagicMock(spec=ConversationLayout)
    if outbox is None:
        # No outbox on disk: nothing to attach and nothing to clear.
        layout.outbox = MagicMock()
        layout.outbox.exists.return_value = False
    else:
        layout.outbox = outbox
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

    def test_subject_override(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = ScheduleConfig(
            cron="0 9 * * *",
            deliver=ScheduleDelivery(channel="email", to="user@example.com"),
            subject="Weekly PR Summary",
            prompt="Test prompt",
        )
        result = _make_result()

        _deliver_via_email(adapter, "weekly-prs", config, result)

        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["subject"] == "[ID:abc12345] Weekly PR Summary"

    def test_delivery_with_usage_stats(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        stats = UsageStats(total_cost_usd=0.05)
        result = _make_result(usage_stats=stats)

        _deliver_via_email(adapter, "daily", config, result)

        kwargs = adapter.send_new_message.call_args.kwargs
        assert "$0.05" in kwargs["body"]

    def test_delivery_with_outbox_files(self, tmp_path: Path) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file.txt").write_text("content")
        result = _make_result(outbox=outbox)

        _deliver_via_email(adapter, "daily", config, result)

        adapter.send_new_message.assert_called_once()
        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["attachments"] == [("file.txt", b"content")]
        # The conversation survives the run — recipients can reply to it —
        # so delivered files must not be attached again to that reply.
        assert list(outbox.iterdir()) == []

    def test_delivery_failure_logged(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.side_effect = RuntimeError("SMTP down")
        config = _make_schedule_config()
        result = _make_result()

        # Should not raise
        _deliver_via_email(adapter, "daily", config, result)

    def test_unreadable_outbox_file_named_in_body(self, tmp_path: Path) -> None:
        """A file that cannot be read is named in the delivered body."""
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "locked.bin").write_text("unreadable")
        result = _make_result(outbox=outbox)

        with patch.object(Path, "read_bytes", side_effect=OSError("denied")):
            _deliver_via_email(adapter, "daily", config, result)

        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["attachments"] == []
        assert "Could not attach 1 file(s): locked.bin" in kwargs["body"]

    def test_outbox_kept_when_delivery_fails(self, tmp_path: Path) -> None:
        """A failed send leaves the files for the next attempt."""
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.side_effect = RuntimeError("SMTP down")
        config = _make_schedule_config()
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file.txt").write_text("content")
        result = _make_result(outbox=outbox)

        _deliver_via_email(adapter, "daily", config, result)

        assert [p.name for p in outbox.iterdir()] == ["file.txt"]
