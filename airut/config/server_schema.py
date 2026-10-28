# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Editor schemas for the server config's sections, at their YAML paths.

Shared by the dashboard config editor and ``airut check``'s config lint.
"""

from airut.config.editor_schema import EditorFieldSchema, schema_for_editor
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
)


def global_schema() -> list[EditorFieldSchema]:
    """Schema for the global (``GlobalConfig``) settings."""
    from airut.gateway.config import GlobalConfig

    return schema_for_editor(GlobalConfig, structure=YAML_GLOBAL_STRUCTURE)


def repo_schema(repo_id: str) -> list[EditorFieldSchema]:
    """Schema for a repo's ``RepoServerConfig`` fields (not channels)."""
    from airut.gateway.config import RepoServerConfig

    return schema_for_editor(
        RepoServerConfig,
        path_prefix=f"repos.{repo_id}",
        structure=YAML_REPO_STRUCTURE,
        exclude={"repo_id", "channels"},
    )


def email_schema(repo_id: str) -> list[EditorFieldSchema]:
    """Schema for a repo's email channel."""
    from airut.gateway.config import EmailChannelConfig

    return schema_for_editor(
        EmailChannelConfig,
        path_prefix=f"repos.{repo_id}.email",
        structure=YAML_EMAIL_STRUCTURE,
    )


def slack_schema(repo_id: str) -> list[EditorFieldSchema]:
    """Schema for a repo's Slack channel."""
    from airut.gateway.slack.config import SlackChannelConfig

    return schema_for_editor(
        SlackChannelConfig, path_prefix=f"repos.{repo_id}.slack"
    )
