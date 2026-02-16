# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel implementation for the gateway.

Provides Slack-specific protocol handling:
- SlackChannelAdapter: ChannelAdapter implementation for Slack
- SlackListener: Socket Mode listener
- SlackAuthorizer: Authorization rule evaluation
- SlackThreadStore: Thread-to-conversation persistence
- SlackChannelConfig: Configuration dataclass
"""
