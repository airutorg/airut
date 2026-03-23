# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor merge module."""

from typing import Any

from airut.config.schema import FieldSchema, schema_for_ui
from airut.config.source import YAML_GLOBAL_STRUCTURE
from airut.dashboard.config_editor.merge import (
    delete_nested,
    group_email_fields,
    group_fields,
    lookup_email_raw,
    lookup_global_raw,
    lookup_repo_raw,
    merge_email_fields,
    merge_global_fields,
    merge_repo_fields,
)
from airut.gateway.config import EmailChannelConfig, GlobalConfig


# ── Raw dict lookup helpers ─────────────────────────────────────────


class TestLookupGlobalRaw:
    def test_nested_path(self) -> None:
        raw = {"execution": {"max_concurrent": 8}}
        assert lookup_global_raw(raw, "max_concurrent_executions") == 8

    def test_top_level(self) -> None:
        raw = {"container_command": ["claude"]}
        assert lookup_global_raw(raw, "container_command") == ["claude"]

    def test_missing_nested(self) -> None:
        assert lookup_global_raw({}, "max_concurrent_executions") is None

    def test_missing_top_level(self) -> None:
        assert lookup_global_raw({}, "container_command") is None

    def test_intermediate_not_dict(self) -> None:
        raw = {"execution": "not_a_dict"}
        assert lookup_global_raw(raw, "max_concurrent_executions") is None


class TestLookupRepoRaw:
    def test_nested_path(self) -> None:
        raw_repo = {"git": {"repo_url": "https://example.com/repo.git"}}
        assert (
            lookup_repo_raw(raw_repo, "git_repo_url")
            == "https://example.com/repo.git"
        )

    def test_top_level(self) -> None:
        raw_repo = {"model": "sonnet"}
        assert lookup_repo_raw(raw_repo, "model") == "sonnet"

    def test_missing(self) -> None:
        assert lookup_repo_raw({}, "model") is None


class TestLookupEmailRaw:
    def test_simple_field(self) -> None:
        raw = {"imap_server": "imap.test.com"}
        assert lookup_email_raw(raw, "imap_server") == "imap.test.com"

    def test_nested_field(self) -> None:
        raw = {"imap": {"poll_interval": 30}}
        assert lookup_email_raw(raw, "poll_interval_seconds") == 30

    def test_missing(self) -> None:
        assert lookup_email_raw({}, "imap_server") is None

    def test_intermediate_not_dict(self) -> None:
        raw = {"imap": "not_a_dict"}
        assert lookup_email_raw(raw, "poll_interval_seconds") is None


# ── Field grouping ──────────────────────────────────────────────────


class TestGroupFields:
    def test_groups_by_structure(self) -> None:
        schema = schema_for_ui(GlobalConfig)
        groups = group_fields(schema, YAML_GLOBAL_STRUCTURE)

        group_names = [g[0] for g in groups]
        # Should have at least Execution and Dashboard groups
        assert "Execution" in group_names
        assert "Dashboard" in group_names

    def test_ungrouped_go_to_general(self) -> None:
        # Fields not in structure go to "General"
        field = FieldSchema(
            name="custom_field",
            type_name="str",
            default=None,
            required=False,
            doc="Test field",
            scope="task",
            secret=False,
        )
        groups = group_fields([field], YAML_GLOBAL_STRUCTURE)
        assert groups[0][0] == "General"
        assert groups[0][1] == [field]


class TestGroupEmailFields:
    def test_groups_email_fields(self) -> None:
        schema = schema_for_ui(EmailChannelConfig)
        groups = group_email_fields(schema)

        group_names = [g[0] for g in groups]
        assert "Connection" in group_names
        assert "Authentication" in group_names

    def test_unknown_field_goes_to_other(self) -> None:
        field = FieldSchema(
            name="unknown_field",
            type_name="str",
            default=None,
            required=False,
            doc="Unknown",
            scope="repo",
            secret=False,
        )
        groups = group_email_fields([field])
        assert groups[0][0] == "Other"


# ── Nested dict helpers ────────────────────────────────────────────


class TestDeleteNested:
    def test_deletes_leaf(self) -> None:
        target = {"a": {"b": {"c": 42}}}
        delete_nested(target, ("a", "b", "c"))
        assert target == {"a": {"b": {}}}

    def test_noop_if_missing(self) -> None:
        target: dict[str, Any] = {"a": {"b": 1}}
        delete_nested(target, ("x", "y"))
        assert target == {"a": {"b": 1}}

    def test_noop_if_intermediate_not_dict(self) -> None:
        target = {"a": "not_dict"}
        delete_nested(target, ("a", "b"))
        assert target == {"a": "not_dict"}


# ── Raw dict merging ───────────────────────────────────────────────


class TestMergeGlobalFields:
    def test_sets_nested_field(self) -> None:
        raw: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="max_concurrent_executions",
                type_name="int",
                default=4,
                required=False,
                doc="Max concurrent",
                scope="server",
                secret=False,
            )
        ]
        merge_global_fields(raw, {"max_concurrent_executions": 8}, schema)
        assert raw["execution"]["max_concurrent"] == 8

    def test_removes_cleared_optional(self) -> None:
        raw: dict[str, Any] = {"execution": {"max_concurrent": 8}}
        schema = [
            FieldSchema(
                name="max_concurrent_executions",
                type_name="int | None",
                default=4,
                required=False,
                doc="Max concurrent",
                scope="server",
                secret=False,
            )
        ]
        merge_global_fields(raw, {}, schema)
        assert "max_concurrent" not in raw.get("execution", {})

    def test_preserves_unedited_fields(self) -> None:
        raw: dict[str, Any] = {
            "execution": {"max_concurrent": 4},
            "some_other_key": "preserved",
        }
        schema = [
            FieldSchema(
                name="max_concurrent_executions",
                type_name="int",
                default=4,
                required=False,
                doc="Max concurrent",
                scope="server",
                secret=False,
            )
        ]
        merge_global_fields(raw, {"max_concurrent_executions": 8}, schema)
        assert raw["some_other_key"] == "preserved"

    def test_top_level_field(self) -> None:
        raw: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="container_command",
                type_name="list[str]",
                default=None,
                required=False,
                doc="Command",
                scope="server",
                secret=False,
            )
        ]
        merge_global_fields(raw, {"container_command": ["claude"]}, schema)
        assert raw["container_command"] == ["claude"]


class TestMergeRepoFields:
    def test_sets_field(self) -> None:
        raw_repo: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="model",
                type_name="str",
                default="opus",
                required=False,
                doc="Model",
                scope="task",
                secret=False,
            )
        ]
        merge_repo_fields(raw_repo, {"model": "sonnet"}, schema)
        assert raw_repo["model"] == "sonnet"

    def test_sets_nested_field(self) -> None:
        raw_repo: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="git_repo_url",
                type_name="str",
                default=None,
                required=True,
                doc="Git URL",
                scope="repo",
                secret=False,
            )
        ]
        merge_repo_fields(
            raw_repo, {"git_repo_url": "https://example.com"}, schema
        )
        assert raw_repo["git"]["repo_url"] == "https://example.com"

    def test_clears_optional(self) -> None:
        raw_repo: dict[str, Any] = {"model": "opus"}
        schema = [
            FieldSchema(
                name="model",
                type_name="str | None",
                default="opus",
                required=False,
                doc="Model",
                scope="task",
                secret=False,
            )
        ]
        merge_repo_fields(raw_repo, {}, schema)
        assert "model" not in raw_repo


class TestMergeEmailFields:
    def test_sets_field(self) -> None:
        raw_email: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="imap_server",
                type_name="str",
                default=None,
                required=True,
                doc="IMAP server",
                scope="repo",
                secret=False,
            )
        ]
        merge_email_fields(raw_email, {"imap_server": "imap.test.com"}, schema)
        assert raw_email["imap_server"] == "imap.test.com"

    def test_sets_nested_field(self) -> None:
        raw_email: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="poll_interval_seconds",
                type_name="int | None",
                default=30,
                required=False,
                doc="Poll interval",
                scope="repo",
                secret=False,
            )
        ]
        merge_email_fields(raw_email, {"poll_interval_seconds": 60}, schema)
        assert raw_email["imap"]["poll_interval"] == 60

    def test_clears_optional(self) -> None:
        raw_email: dict[str, Any] = {"username": "user@test.com"}
        schema = [
            FieldSchema(
                name="username",
                type_name="str | None",
                default=None,
                required=False,
                doc="Username",
                scope="repo",
                secret=False,
            )
        ]
        merge_email_fields(raw_email, {}, schema)
        assert "username" not in raw_email

    def test_clears_nested_optional(self) -> None:
        raw_email: dict[str, Any] = {"imap": {"poll_interval": 30}}
        schema = [
            FieldSchema(
                name="poll_interval_seconds",
                type_name="int | None",
                default=30,
                required=False,
                doc="Poll interval",
                scope="repo",
                secret=False,
            )
        ]
        merge_email_fields(raw_email, {}, schema)
        assert "poll_interval" not in raw_email.get("imap", {})

    def test_sets_non_structure_field(self) -> None:
        """Fields not in _YAML_EMAIL_STRUCTURE go to top level."""
        raw_email: dict[str, Any] = {}
        schema = [
            FieldSchema(
                name="smtp_require_auth",
                type_name="bool | None",
                default=None,
                required=False,
                doc="Require SMTP auth",
                scope="repo",
                secret=False,
            )
        ]
        merge_email_fields(raw_email, {"smtp_require_auth": True}, schema)
        assert raw_email["smtp_require_auth"] is True
