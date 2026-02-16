# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Gateway service package.

Provides the main gateway service that monitors messaging channels, executes
Claude Code in containers, and replies with results.

The service has been modularized into the following components:
- gateway: Main GatewayService orchestrator and entry point
- repo_handler: Per-repository handler (listener, auth, conversation mgmt)
- message_processing: Message processing and Claude execution
- usage_stats: Usage statistics extraction from Claude output
"""

from airut.gateway.service.gateway import (
    GatewayService,
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
    "GatewayService",
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
