# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Delivery routing for scheduled task results.

Dispatches delivery to the appropriate channel adapter based on the
schedule's ``deliver.channel`` setting.  Currently only email delivery
is supported.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from airut.gateway.config import ScheduleConfig
from airut.gateway.email.adapter import EmailChannelAdapter
from airut.gateway.email.parsing import collect_outbox_files
from airut.gateway.service.message_processing import SandboxTaskResult


if TYPE_CHECKING:
    from airut.gateway.service.repo_handler import RepoHandler

logger = logging.getLogger(__name__)


def deliver_result(
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    result: SandboxTaskResult,
) -> None:
    """Deliver a scheduled task result via the configured channel.

    Looks up the adapter from ``repo_handler.adapters`` at delivery
    time (not cached), so adapter recreation during config reload does
    not invalidate the scheduler's state.

    Args:
        repo_handler: Repo handler with channel adapters.
        schedule_name: Name of the schedule.
        config: Schedule configuration.
        result: Sandbox execution result.
    """
    channel_type = config.deliver.channel
    adapter = repo_handler.adapters.get(channel_type)

    if adapter is None:
        logger.error(
            "Schedule '%s/%s': delivery channel '%s' not found",
            repo_handler.config.repo_id,
            schedule_name,
            channel_type,
        )
        return

    if isinstance(adapter, EmailChannelAdapter):
        _deliver_via_email(adapter, schedule_name, config, result)
    else:
        logger.error(
            "Schedule '%s/%s': unsupported delivery channel type: %s",
            repo_handler.config.repo_id,
            schedule_name,
            type(adapter).__name__,
        )


def _deliver_via_email(
    adapter: EmailChannelAdapter,
    schedule_name: str,
    config: ScheduleConfig,
    result: SandboxTaskResult,
) -> None:
    """Deliver result via email adapter's ``send_new_message()``."""
    display_name = config.subject or schedule_name
    subject = f"[ID:{result.conversation_id}] {display_name}"

    # Collect outbox files
    outbox_dir = result.layout.outbox
    attachments: list[tuple[str, bytes]] = []
    if outbox_dir.exists():
        attachments = collect_outbox_files(outbox_dir)

    # Build body with usage footer if available
    body = result.response_text
    if result.usage_stats and result.usage_stats.has_any():
        footer = result.usage_stats.format_summary()
        if footer:
            body = f"{body}\n\n*{footer}*"

    try:
        adapter.send_new_message(
            to=config.deliver.to,
            subject=subject,
            body=body,
            conversation_id=result.conversation_id,
            attachments=attachments,
        )
        logger.info(
            "Schedule '%s': delivered result to %s via email",
            schedule_name,
            config.deliver.to,
        )
    except Exception:
        logger.exception(
            "Schedule '%s': failed to deliver result to %s",
            schedule_name,
            config.deliver.to,
        )
