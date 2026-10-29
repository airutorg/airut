# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scheduled task delivery."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from airut.conversation import (
    ConversationLayout,
    ConversationStore,
    create_conversation_layout,
    prepare_conversation,
)
from airut.gateway.channel import UndeliveredFile
from airut.gateway.config import ScheduleConfig, ScheduleDelivery
from airut.gateway.email.adapter import EmailChannelAdapter
from airut.gateway.scheduler.delivery import (
    _deliver_via_email,
    deliver_result,
)
from airut.gateway.service.message_processing import SandboxTaskResult
from airut.gateway.service.usage_stats import UsageStats
from airut.sandbox import Outcome


def _make_layout(tmp_path: Path) -> ConversationLayout:
    layout = create_conversation_layout(tmp_path / "abc12345")
    prepare_conversation(layout)
    return layout


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
    layout: ConversationLayout | None = None,
) -> SandboxTaskResult:
    if layout is None:
        # No outbox on disk: nothing to attach and nothing to clear.
        layout = MagicMock(spec=ConversationLayout)
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
        adapter.send_new_message.return_value = []
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
        adapter.send_new_message.return_value = []
        config = _make_schedule_config()
        result = _make_result(response_text="Task done")

        _deliver_via_email(adapter, "daily", config, result)

        adapter.send_new_message.assert_called_once()
        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["to"] == "user@example.com"
        assert "[ID:abc12345] daily" == kwargs["subject"]
        assert "Task done" in kwargs["body"]
        assert kwargs["footer"] == ""

    def test_subject_override(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.return_value = []
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
        adapter.send_new_message.return_value = []
        config = _make_schedule_config()
        stats = UsageStats(total_cost_usd=0.05)
        result = _make_result(usage_stats=stats)

        _deliver_via_email(adapter, "daily", config, result)

        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["body"] == "Result text"
        assert kwargs["footer"] == stats.format_summary()
        assert "$0.05" in kwargs["footer"]

    def test_delivery_with_outbox_files(self, tmp_path: Path) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.return_value = []
        config = _make_schedule_config()
        layout = _make_layout(tmp_path)
        (layout.outbox / "file.txt").write_text("content")
        result = _make_result(layout=layout)

        _deliver_via_email(adapter, "daily", config, result)

        adapter.send_new_message.assert_called_once()
        kwargs = adapter.send_new_message.call_args.kwargs
        assert kwargs["outbox_files"] == [layout.outbox / "file.txt"]
        # The conversation survives the run — recipients can reply to it —
        # so delivered files must not be attached again to that reply.
        assert list(layout.outbox.iterdir()) == []

    def test_undelivered_files_set_aside(self, tmp_path: Path) -> None:
        """Files the email left out wait in storage for the reply turn."""
        adapter = MagicMock(spec=EmailChannelAdapter)
        config = _make_schedule_config()
        layout = _make_layout(tmp_path)
        (layout.outbox / "summary.txt").write_text("summary")
        dump = layout.outbox / "dump.bin"
        dump.write_bytes(b"x" * 100)
        adapter.send_new_message.return_value = [
            UndeliveredFile(dump, "did not fit in the 25.0MB email size limit")
        ]
        result = _make_result(layout=layout)

        _deliver_via_email(adapter, "daily", config, result)

        assert list(layout.outbox.iterdir()) == []
        assert (layout.storage / "undelivered" / "dump.bin").read_bytes() == (
            b"x" * 100
        )
        store = ConversationStore(layout.conversation_dir)
        assert store.get_undelivered() == {
            "dump.bin": "did not fit in the 25.0MB email size limit"
        }

    def test_delivery_failure_logged(self) -> None:
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.side_effect = RuntimeError("SMTP down")
        config = _make_schedule_config()
        result = _make_result()

        # Should not raise
        _deliver_via_email(adapter, "daily", config, result)

    def test_outbox_kept_when_delivery_fails(self, tmp_path: Path) -> None:
        """A failed send leaves the files for the next attempt."""
        adapter = MagicMock(spec=EmailChannelAdapter)
        adapter.send_new_message.side_effect = RuntimeError("SMTP down")
        config = _make_schedule_config()
        layout = _make_layout(tmp_path)
        (layout.outbox / "file.txt").write_text("content")
        result = _make_result(layout=layout)

        _deliver_via_email(adapter, "daily", config, result)

        assert [p.name for p in layout.outbox.iterdir()] == ["file.txt"]
