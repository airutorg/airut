# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor: EditorFieldSchema, schema_for_editor, EditBuffer."""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from airut.config.editor import (
    MISSING,
    EditBuffer,
    InMemoryConfigSource,
    schema_for_editor,
)
from airut.config.schema import Scope, meta
from airut.config.source import YAML_GLOBAL_STRUCTURE
from airut.yaml_env import EnvVar, VarRef
from tests.conftest import make_sample_raw as _make_sample_raw


# ── EditorFieldSchema tests ──────────────────────────────────────────


class TestSchemaForEditor:
    def test_scalar_str(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            host: str = field(
                default="localhost",
                metadata=meta("Host", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert len(schema) == 1
        fs = schema[0]
        assert fs.name == "host"
        assert fs.path == "host"
        assert fs.type_tag == "scalar"
        assert fs.python_type == "str"
        assert fs.default == "localhost"
        assert fs.required is False
        assert fs.doc == "Host"
        assert fs.scope == "server"

    def test_scalar_int(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            port: int = field(
                default=8080,
                metadata=meta("Port", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].python_type == "int"
        assert schema[0].env_eligible is True
        assert schema[0].var_eligible is True

    def test_scalar_bool(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            enabled: bool = field(
                default=True,
                metadata=meta("Enabled", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].env_eligible is False
        assert schema[0].var_eligible is False

    def test_required_field(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            host: str = field(metadata=meta("Host", Scope.SERVER))

        schema = schema_for_editor(Cfg)
        assert schema[0].required is True
        assert schema[0].default is MISSING

    def test_optional_field(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            url: str | None = field(
                default=None,
                metadata=meta("URL", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].required is False
        assert schema[0].python_type == "str"

    def test_nested_dataclass(self) -> None:
        @dataclass(frozen=True)
        class Inner:
            timeout: int = field(
                default=60,
                metadata=meta("Timeout", Scope.TASK),
            )

        @dataclass(frozen=True)
        class Cfg:
            limits: Inner | None = field(
                default=None,
                metadata=meta("Limits", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].type_tag == "nested"
        assert schema[0].nested_fields is not None
        assert len(schema[0].nested_fields) == 1
        assert schema[0].nested_fields[0].name == "timeout"

    def test_excludes_unannotated(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            host: str = field(
                default="localhost",
                metadata=meta("Host", Scope.SERVER),
            )
            internal: str = "computed"

        schema = schema_for_editor(Cfg)
        assert len(schema) == 1

    def test_structure_mapping(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            max_concurrent_executions: int = field(
                default=3,
                metadata=meta("Max", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg, structure=YAML_GLOBAL_STRUCTURE)
        assert schema[0].path == "execution.max_concurrent"

    def test_path_prefix(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            timeout: int = field(
                default=60,
                metadata=meta("Timeout", Scope.TASK),
            )

        schema = schema_for_editor(Cfg, path_prefix="repos.test")
        assert schema[0].path == "repos.test.timeout"

    def test_exclude_fields(self) -> None:
        """schema_for_editor with exclude omits matching field names."""

        @dataclass(frozen=True)
        class Cfg:
            name: str = field(metadata=meta("Name", Scope.SERVER))
            internal_id: str = field(metadata=meta("ID", Scope.SERVER))

        schema = schema_for_editor(Cfg, exclude={"internal_id"})
        names = {s.name for s in schema}
        assert "name" in names
        assert "internal_id" not in names


class TestSchemaForEditorTypeTags:
    """Tests for _type_tag_for covering all type tag branches."""

    def test_list_str(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            items: list[str] = field(
                default_factory=list,
                metadata=meta("Items", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].type_tag == "list_str"

    def test_dict_str_str(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            labels: dict[str, str] = field(
                default_factory=dict,
                metadata=meta("Labels", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].type_tag == "dict_str_str"

    def test_keyed_collection(self) -> None:
        @dataclass(frozen=True)
        class Item:
            name: str = field(
                default="",
                metadata=meta("Name", Scope.SERVER),
            )

        @dataclass(frozen=True)
        class Cfg:
            things: dict[str, Item] = field(
                default_factory=dict,
                metadata=meta("Things", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].type_tag == "keyed_collection"
        assert schema[0].item_class_name == "Item"
        assert schema[0].item_fields is not None
        assert len(schema[0].item_fields) == 1
        assert schema[0].item_fields[0].name == "name"

    def test_tagged_union_list(self) -> None:
        """Test tagged_union_list detection via TAGGED_UNION_RULES."""
        from airut.gateway.slack.config import SlackChannelConfig

        schema = schema_for_editor(SlackChannelConfig)
        by_name = {s.name: s for s in schema}
        assert "authorized" in by_name
        assert by_name["authorized"].type_tag == "tagged_union_list"
        assert by_name["authorized"].tagged_union_rules is not None

    def test_default_factory(self) -> None:
        @dataclass(frozen=True)
        class Cfg:
            items: list[str] = field(
                default_factory=list,
                metadata=meta("Items", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        assert schema[0].default == []
        assert schema[0].required is False

    def test_python_type_str_generic(self) -> None:
        """Non-type annotations produce str() representation."""

        @dataclass(frozen=True)
        class Cfg:
            items: list[str] = field(
                default_factory=list,
                metadata=meta("Items", Scope.SERVER),
            )

        schema = schema_for_editor(Cfg)
        # list[str] is a generic alias, not a plain type
        assert "list" in schema[0].python_type

    def test_nested_non_dataclass_returns_empty(self) -> None:
        """_get_nested_fields returns [] for non-dataclass types."""
        from airut.config.editor_schema import _get_nested_fields

        result = _get_nested_fields(str, "", None, "Test")
        assert result == []


class TestSchemaParserDefaults:
    def test_parser_defaults_applied(self) -> None:
        """PARSER_DEFAULTS injects defaults for EmailChannelConfig."""
        from airut.gateway.config import EmailChannelConfig

        schema = schema_for_editor(EmailChannelConfig)
        by_name = {s.name: s for s in schema}
        assert by_name["imap_port"].default == 993
        assert by_name["imap_port"].required is False
        assert by_name["smtp_port"].default == 587
        assert by_name["smtp_port"].required is False


class TestSchemaForEditorRealConfigs:
    def test_global_config(self) -> None:
        from airut.gateway.config import GlobalConfig

        schema = schema_for_editor(
            GlobalConfig, structure=YAML_GLOBAL_STRUCTURE
        )
        names = {s.name for s in schema}
        assert "max_concurrent_executions" in names
        assert "dashboard_enabled" in names
        assert "resource_limits" in names

        # Check path mapping
        by_name = {s.name: s for s in schema}
        assert (
            by_name["max_concurrent_executions"].path
            == "execution.max_concurrent"
        )
        assert by_name["dashboard_port"].path == "dashboard.port"
        assert by_name["upstream_dns"].path == "network.upstream_dns"
        assert by_name["container_command"].path == "container_command"

        # Resource limits is nested
        rl = by_name["resource_limits"]
        assert rl.type_tag == "nested"
        assert rl.nested_fields is not None
        assert len(rl.nested_fields) == 4

    def test_resource_limits(self) -> None:
        from airut.sandbox.types import ResourceLimits

        schema = schema_for_editor(ResourceLimits)
        names = {s.name for s in schema}
        assert "timeout" in names
        assert "memory" in names
        assert "cpus" in names
        assert "pids_limit" in names

        # All task scope
        for s in schema:
            assert s.scope == "task"

    def test_repo_server_config(self) -> None:
        from airut.config.source import YAML_REPO_STRUCTURE
        from airut.gateway.config import RepoServerConfig

        schema = schema_for_editor(
            RepoServerConfig,
            path_prefix="repos.my-project",
            structure=YAML_REPO_STRUCTURE,
            exclude={"repo_id"},
        )
        names = {s.name for s in schema}
        assert "repo_id" not in names
        assert "git_repo_url" in names
        assert "model" in names
        assert "effort" in names
        assert "network_sandbox_enabled" in names
        assert "resource_limits" in names

        # Check path mapping with prefix
        by_name = {s.name: s for s in schema}
        assert by_name["git_repo_url"].path == "repos.my-project.git.repo_url"
        assert by_name["model"].path == "repos.my-project.model"
        assert (
            by_name["network_sandbox_enabled"].path
            == "repos.my-project.network.sandbox_enabled"
        )

        # Resource limits is nested
        rl = by_name["resource_limits"]
        assert rl.type_tag == "nested"
        assert rl.nested_fields is not None


class TestSchemaForEditorChannels:
    def test_email_channel_config(self) -> None:
        from airut.config.source import YAML_EMAIL_STRUCTURE
        from airut.gateway.config import EmailChannelConfig

        schema = schema_for_editor(
            EmailChannelConfig,
            path_prefix="repos.my-project.email",
            structure=YAML_EMAIL_STRUCTURE,
        )
        names = {s.name for s in schema}
        assert "imap_server" in names
        assert "smtp_server" in names
        assert "password" in names
        assert "authorized_senders" in names

        by_name = {s.name: s for s in schema}
        assert (
            by_name["imap_server"].path == "repos.my-project.email.imap_server"
        )
        assert by_name["authorized_senders"].type_tag == "list_str"
        assert by_name["password"].secret is True

        # imap nested fields use YAML_EMAIL_STRUCTURE
        assert (
            by_name["imap_connect_retries"].path
            == "repos.my-project.email.imap.connect_retries"
        )

    def test_slack_channel_config(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        schema = schema_for_editor(
            SlackChannelConfig,
            path_prefix="repos.my-project.slack",
        )
        names = {s.name for s in schema}
        assert "bot_token" in names
        assert "app_token" in names
        assert "authorized" in names

        by_name = {s.name: s for s in schema}
        assert by_name["bot_token"].path == "repos.my-project.slack.bot_token"
        assert by_name["bot_token"].secret is True
        assert by_name["authorized"].type_tag == "tagged_union_list"
        assert by_name["authorized"].tagged_union_rules is not None
        assert len(by_name["authorized"].tagged_union_rules) == 3


# ── InMemoryConfigSource tests ───────────────────────────────────────


class TestInMemoryConfigSource:
    def test_load_returns_data(self) -> None:
        data = {"key": "value"}
        source = InMemoryConfigSource(data)
        assert source.load() == data

    def test_save_raises(self) -> None:
        source = InMemoryConfigSource({})
        with pytest.raises(NotImplementedError):
            source.save({})


# ── EditBuffer tests ─────────────────────────────────────────────────


class TestEditBufferCreate:
    def test_create_from_raw(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=5)
        assert buf.generation == 5
        assert buf.dirty is False

    def test_deep_copies_raw(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        # Modifying buffer should not affect original
        buf.set_field("dashboard.port", "literal", 9999)
        assert raw["dashboard"]["port"] == 5200

    def test_staleness_detection(self) -> None:
        buf = EditBuffer({}, generation=3)
        assert buf.is_stale(3) is False
        assert buf.is_stale(4) is True


class TestEditBufferSetField:
    def test_set_literal_scalar(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.set_field("dashboard.port", "literal", 5201)
        assert buf.raw["dashboard"]["port"] == 5201
        assert buf.dirty is True

    def test_set_env_field(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.set_field("dashboard.host", "env", "DASHBOARD_HOST")
        value = buf.raw["dashboard"]["host"]
        assert isinstance(value, EnvVar)
        assert value.var_name == "DASHBOARD_HOST"

    def test_set_var_field(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.set_field("dashboard.host", "var", "host_var")
        value = buf.raw["dashboard"]["host"]
        assert isinstance(value, VarRef)
        assert value.var_name == "host_var"

    def test_unset_field(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.set_field("dashboard.base_url", "literal", "http://example.com")
        assert "base_url" in buf.raw["dashboard"]
        buf.set_field("dashboard.base_url", "unset")
        assert "base_url" not in buf.raw["dashboard"]

    def test_unset_prunes_empty_parents(self) -> None:
        raw = {"a": {"b": {"c": "value"}}}
        buf = EditBuffer(raw, generation=0)
        buf.set_field("a.b.c", "unset")
        assert "a" not in buf.raw

    def test_set_creates_intermediate_dicts(self) -> None:
        buf = EditBuffer({}, generation=0)
        buf.set_field("a.b.c", "literal", "hello")
        assert buf.raw["a"]["b"]["c"] == "hello"

    def test_unset_nonexistent_is_safe(self) -> None:
        buf = EditBuffer({}, generation=0)
        buf.set_field("nonexistent.path", "unset")
        assert buf.dirty is True


class TestEditBufferDirty:
    def test_clean_after_create(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        assert buf.dirty is False

    def test_dirty_after_set(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.set_field("dashboard.port", "literal", 9999)
        assert buf.dirty is True

    def test_dirty_after_add(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.add_item("repos.test-repo.email.authorized_senders")
        assert buf.dirty is True

    def test_dirty_after_remove(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.remove_item("repos.test-repo.email.authorized_senders", index=0)
        assert buf.dirty is True


class TestEditBufferAddItem:
    def test_add_list_item(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.add_item("repos.test-repo.email.authorized_senders")
        senders = buf.raw["repos"]["test-repo"]["email"]["authorized_senders"]
        assert len(senders) == 2
        assert senders[-1] == ""

    def test_add_keyed_collection_item(self) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["masked_secrets"] = {}
        buf = EditBuffer(raw, generation=0)
        buf.add_item("repos.test-repo.masked_secrets", key="NEW_TOKEN")
        assert "NEW_TOKEN" in buf.raw["repos"]["test-repo"]["masked_secrets"]
        assert (
            buf.raw["repos"]["test-repo"]["masked_secrets"]["NEW_TOKEN"] == {}
        )

    def test_add_creates_list_if_missing(self) -> None:
        buf = EditBuffer({}, generation=0)
        buf.add_item("items")
        assert buf.raw["items"] == [""]

    def test_add_creates_dict_if_missing(self) -> None:
        buf = EditBuffer({}, generation=0)
        buf.add_item("collection", key="new")
        assert buf.raw["collection"] == {"new": {}}


class TestEditBufferRemoveItem:
    def test_remove_list_item(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.remove_item("repos.test-repo.email.authorized_senders", index=0)
        senders = buf.raw["repos"]["test-repo"]["email"]["authorized_senders"]
        assert len(senders) == 0

    def test_remove_keyed_item(self) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["masked_secrets"] = {"TOKEN": {"value": "x"}}
        buf = EditBuffer(raw, generation=0)
        buf.remove_item("repos.test-repo.masked_secrets", key="TOKEN")
        assert "TOKEN" not in buf.raw["repos"]["test-repo"]["masked_secrets"]

    def test_remove_path(self) -> None:
        """Remove an entire path (e.g., channel or repo)."""
        buf = EditBuffer(_make_sample_raw(), generation=0)
        buf.remove_item("repos.test-repo.email")
        assert "email" not in buf.raw["repos"]["test-repo"]

    def test_remove_nonexistent_is_safe(self) -> None:
        buf = EditBuffer({}, generation=0)
        buf.remove_item("nonexistent.path", key="x")
        buf.remove_item("nonexistent.path", index=5)
        buf.remove_item("nonexistent.path")
        assert buf.dirty is True

    def test_remove_list_out_of_range(self) -> None:
        raw = {"items": ["a", "b"]}
        buf = EditBuffer(raw, generation=0)
        buf.remove_item("items", index=99)
        assert len(buf.raw["items"]) == 2


class TestEditBufferGetValue:
    def test_get_existing(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        assert buf.get_value("dashboard.port") == 5200

    def test_get_missing(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        assert buf.get_value("nonexistent.path") is MISSING

    def test_get_nested(self) -> None:
        buf = EditBuffer(_make_sample_raw(), generation=0)
        assert buf.get_value("execution.max_concurrent") == 3


class TestEditBufferSetListItem:
    def test_set_list_item(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        buf.set_list_item(
            "repos.test-repo.email.authorized_senders", 0, "new@example.com"
        )
        assert buf.raw["repos"]["test-repo"]["email"]["authorized_senders"] == [
            "new@example.com"
        ]
        assert buf.dirty

    def test_set_list_item_out_of_range(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        buf.set_list_item("repos.test-repo.email.authorized_senders", 99, "bad")
        # Out-of-range should not modify
        assert not buf.dirty

    def test_set_list_item_non_list(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        buf.set_list_item("dashboard.port", 0, "bad")
        # Not a list, no modification
        assert not buf.dirty

    def test_set_list_item_missing_path(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        buf.set_list_item("nonexistent.path", 0, "bad")
        assert not buf.dirty


class TestEditBufferSetTaggedUnionItem:
    def test_set_tagged_union_item(self) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["slack"] = {
            "bot_token": "xoxb-test",
            "app_token": "xapp-test",
            "authorized": [{"workspace_members": True}],
        }
        buf = EditBuffer(raw, generation=0)
        buf.set_tagged_union_item(
            "repos.test-repo.slack.authorized", 0, "user_id", "U12345"
        )
        assert buf.raw["repos"]["test-repo"]["slack"]["authorized"] == [
            {"user_id": "U12345"}
        ]
        assert buf.dirty

    def test_set_tagged_union_item_bool(self) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["slack"] = {
            "bot_token": "xoxb-test",
            "app_token": "xapp-test",
            "authorized": [{"user_id": "U123"}],
        }
        buf = EditBuffer(raw, generation=0)
        buf.set_tagged_union_item(
            "repos.test-repo.slack.authorized", 0, "workspace_members", True
        )
        assert buf.raw["repos"]["test-repo"]["slack"]["authorized"] == [
            {"workspace_members": True}
        ]

    def test_set_tagged_union_item_out_of_range(self) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["slack"] = {
            "bot_token": "xoxb-test",
            "app_token": "xapp-test",
            "authorized": [],
        }
        buf = EditBuffer(raw, generation=0)
        buf.set_tagged_union_item(
            "repos.test-repo.slack.authorized", 0, "user_id", "U123"
        )
        assert not buf.dirty

    def test_set_tagged_union_item_missing_path(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        buf.set_tagged_union_item("nonexistent.path", 0, "key", "val")
        assert not buf.dirty


class TestEditBufferValidate:
    def test_validate_success(self) -> None:
        raw = _make_sample_raw()
        buf = EditBuffer(raw, generation=0)
        snapshot = buf.validate()
        assert snapshot.value.global_config.dashboard_port == 5200

    def test_validate_failure(self) -> None:
        raw = _make_sample_raw()
        # Remove all repos to trigger validation error
        raw["repos"] = {}
        buf = EditBuffer(raw, generation=0)
        with pytest.raises(Exception, match="At least one repo"):
            buf.validate()


# ── Atomic save tests ────────────────────────────────────────────────


class TestAtomicSave:
    def test_save_uses_atomic_rename(self, tmp_path: Path) -> None:
        from airut.config.source import YamlConfigSource

        config_path = tmp_path / "test.yaml"
        source = YamlConfigSource(config_path)
        source.save({"key": "value"})
        assert config_path.exists()
        # Temp file should not remain
        assert not config_path.with_suffix(".yaml.tmp").exists()

    def test_save_preserves_tags(self, tmp_path: Path) -> None:
        import yaml

        from airut.config.source import YamlConfigSource, make_env_loader

        config_path = tmp_path / "test.yaml"
        source = YamlConfigSource(config_path)
        source.save({"password": EnvVar("SECRET"), "ref": VarRef("my_var")})

        with open(config_path) as f:
            content = f.read()
        assert "!env" in content
        assert "!var" in content

        # Round-trip
        with open(config_path) as f:
            loaded = yaml.load(f, Loader=make_env_loader())
        assert isinstance(loaded["password"], EnvVar)
        assert isinstance(loaded["ref"], VarRef)
