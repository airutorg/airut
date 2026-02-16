# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email gateway service package.

Provides the main email gateway service that monitors email, executes Claude
Code in containers, and replies with results.

The service has been modularized into the following components:
- gateway: Main EmailGatewayService orchestrator and entry point
- repo_handler: Per-repository handler (listener, auth, conversation mgmt)
- message_processing: Email message processing and Claude execution
- email_replies: Email reply sending (acknowledgments, errors, results)
- usage_stats: Usage statistics extraction from Claude output
"""

from airut.gateway.service.gateway import (
    EmailGatewayService,
    capture_version_info,
    main,
)
from airut.gateway.service.message_processing import (
    build_recovery_prompt,
    process_message,
)
from airut.gateway.service.repo_handler import RepoHandler
from airut.gateway.service.usage_stats import (
    UsageStats,
    extract_usage_stats,
)


__all__ = [
    # gateway
    "EmailGatewayService",
    "capture_version_info",
    "main",
    # repo_handler
    "RepoHandler",
    # message_processing
    "build_recovery_prompt",
    "process_message",
    # usage_stats
    "UsageStats",
    "extract_usage_stats",
]
