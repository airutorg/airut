# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor schema introspection and form parsing."""

from typing import Any

import pytest

from airut.config.editor import build_editor_context, schema_for_editor
from airut.config.editor_form import (
    InMemoryConfigSource,
    detect_source,
    form_to_raw_dict,
    get_raw_value,
    get_source_ref,
)
from airut.config.snapshot import ConfigSnapshot
from airut.gateway.config import (
    EmailChannelConfig,
    GitHubAppCredential,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)
from airut.gateway.slack.config import SlackChannelConfig
from airut.sandbox.types import ResourceLimits
from airut.yaml_env import EnvVar, VarRef


class TestSchemaForEditor:
    """Tests for schema_for_editor()."""

    def test_global_config_fields(self) -> None:
        """All annotated GlobalConfig fields are in the editor schema."""
        from airut.config.source import YAML_GLOBAL_STRUCTURE

        schema = schema_for_editor(
            GlobalConfig, yaml_structure=YAML_GLOBAL_STRUCTURE
        )
        names = {f.name for f in schema}
        assert "max_concurrent_executions" in names
        assert "dashboard_enabled" in names
        assert "dashboard_port" in names
        assert "container_command" in names
        assert "resource_limits" in names

    def test_repo_config_fields(self) -> None:
        """All annotated RepoServerConfig fields are in the editor schema."""
        from airut.config.source import YAML_REPO_STRUCTURE

        schema = schema_for_editor(
            RepoServerConfig, yaml_structure=YAML_REPO_STRUCTURE
        )
        names = {f.name for f in schema}
        assert "repo_id" in names
        assert "git_repo_url" in names
        assert "model" in names
        assert "secrets" in names
        assert "masked_secrets" in names
        assert "signing_credentials" in names
        assert "github_app_credentials" in names

    def test_email_config_fields(self) -> None:
        """All annotated EmailChannelConfig fields are in the schema."""
        from airut.config.source import YAML_EMAIL_STRUCTURE

        schema = schema_for_editor(
            EmailChannelConfig, yaml_structure=YAML_EMAIL_STRUCTURE
        )
        names = {f.name for f in schema}
        assert "imap_server" in names
        assert "password" in names
        assert "authorized_senders" in names

    def test_slack_config_fields(self) -> None:
        """All annotated SlackChannelConfig fields are in the schema."""
        schema = schema_for_editor(SlackChannelConfig)
        names = {f.name for f in schema}
        assert "bot_token" in names
        assert "app_token" in names
        assert "authorized" in names

    def test_scalar_type_tag(self) -> None:
        """Scalar fields get type_tag='scalar'."""
        from airut.config.source import YAML_GLOBAL_STRUCTURE

        schema = schema_for_editor(
            GlobalConfig, yaml_structure=YAML_GLOBAL_STRUCTURE
        )
        by_name = {f.name: f for f in schema}
        assert by_name["max_concurrent_executions"].type_tag == "scalar"
        assert by_name["max_concurrent_executions"].python_type == "int"
        assert by_name["dashboard_enabled"].type_tag == "scalar"
        assert by_name["dashboard_enabled"].python_type == "bool"
        assert by_name["dashboard_host"].type_tag == "scalar"
        assert by_name["dashboard_host"].python_type == "str"

    def test_list_str_type_tag(self) -> None:
        """List[str] fields get type_tag='list_str'."""
        from airut.config.source import YAML_EMAIL_STRUCTURE

        schema = schema_for_editor(
            EmailChannelConfig, yaml_structure=YAML_EMAIL_STRUCTURE
        )
        by_name = {f.name: f for f in schema}
        assert by_name["authorized_senders"].type_tag == "list_str"

    def test_dict_str_str_type_tag(self) -> None:
        """dict[str, str] fields get type_tag='dict_str_str'."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["secrets"].type_tag == "dict_str_str"
        assert by_name["container_env"].type_tag == "dict_str_str"

    def test_keyed_collection_type_tag(self) -> None:
        """dict[str, <dataclass>] fields get type_tag='keyed_collection'."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["masked_secrets"].type_tag == "keyed_collection"
        assert by_name["masked_secrets"].item_class_name == "MaskedSecret"
        assert by_name["masked_secrets"].item_fields is not None

    def test_nested_type_tag(self) -> None:
        """Nested dataclass fields get type_tag='nested'."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["resource_limits"].type_tag == "nested"
        assert by_name["resource_limits"].nested_fields is not None
        nested_names = {
            f.name for f in by_name["resource_limits"].nested_fields
        }
        assert "timeout" in nested_names
        assert "memory" in nested_names
        assert "cpus" in nested_names

    def test_tagged_union_type_tag(self) -> None:
        """Tagged union fields get type_tag='tagged_union_list'."""
        schema = schema_for_editor(SlackChannelConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["authorized"].type_tag == "tagged_union_list"
        assert by_name["authorized"].tagged_union_rules is not None
        tags = [r[0] for r in by_name["authorized"].tagged_union_rules]
        assert "workspace_members" in tags
        assert "user_group" in tags
        assert "user_id" in tags

    def test_yaml_path_with_structure(self) -> None:
        """YAML paths use the structure mapping when provided."""
        from airut.config.source import YAML_GLOBAL_STRUCTURE

        schema = schema_for_editor(
            GlobalConfig, yaml_structure=YAML_GLOBAL_STRUCTURE
        )
        by_name = {f.name: f for f in schema}
        assert by_name["max_concurrent_executions"].yaml_path == (
            "execution",
            "max_concurrent",
        )
        assert by_name["dashboard_enabled"].yaml_path == (
            "dashboard",
            "enabled",
        )

    def test_yaml_path_without_structure(self) -> None:
        """YAML paths use field name when no structure mapping."""
        schema = schema_for_editor(SlackChannelConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["bot_token"].yaml_path == ("bot_token",)

    def test_yaml_path_with_prefix(self) -> None:
        """YAML paths include the prefix."""
        schema = schema_for_editor(
            SlackChannelConfig, prefix=("repos", "my-repo", "slack")
        )
        by_name = {f.name: f for f in schema}
        assert by_name["bot_token"].yaml_path == (
            "repos",
            "my-repo",
            "slack",
            "bot_token",
        )

    def test_required_field(self) -> None:
        """Required fields have required=True."""
        schema = schema_for_editor(EmailChannelConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["imap_server"].required is True

    def test_optional_field(self) -> None:
        """Optional fields have required=False."""
        schema = schema_for_editor(GlobalConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["dashboard_port"].required is False
        assert by_name["dashboard_port"].default == 5200

    def test_secret_field(self) -> None:
        """Secret fields have secret=True."""
        schema = schema_for_editor(EmailChannelConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["password"].secret is True
        assert by_name["imap_server"].secret is False

    def test_scope_values(self) -> None:
        """Scope values match FieldMeta."""
        schema = schema_for_editor(GlobalConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["max_concurrent_executions"].scope == "server"

        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["model"].scope == "task"
        assert by_name["git_repo_url"].scope == "repo"

    def test_env_var_eligibility(self) -> None:
        """Bool fields are not eligible for !env."""
        schema = schema_for_editor(GlobalConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["dashboard_enabled"].env_eligible is False
        assert by_name["dashboard_host"].env_eligible is True

    def test_var_eligibility(self) -> None:
        """Bool and numeric fields are not eligible for !var."""
        schema = schema_for_editor(GlobalConfig)
        by_name = {f.name: f for f in schema}
        assert by_name["dashboard_enabled"].var_eligible is False
        assert by_name["dashboard_port"].var_eligible is False
        assert by_name["dashboard_host"].var_eligible is True

    def test_masked_secret_item_fields(self) -> None:
        """MaskedSecret item_fields have correct sub-fields."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        ms = by_name["masked_secrets"]
        assert ms.item_class_name == "MaskedSecret"
        assert ms.item_fields is not None
        item_names = {f.name for f in ms.item_fields}
        assert "value" in item_names
        assert "scopes" in item_names
        assert "headers" in item_names
        assert "allow_foreign_credentials" in item_names

    def test_signing_credential_item_fields(self) -> None:
        """SigningCredential item_fields have correct sub-fields."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        sc = by_name["signing_credentials"]
        assert sc.item_class_name == "SigningCredential"
        assert sc.item_fields is not None
        item_names = {f.name for f in sc.item_fields}
        assert "access_key_id" in item_names
        assert "secret_access_key" in item_names
        assert "scopes" in item_names

    def test_github_app_item_fields(self) -> None:
        """GitHubAppCredential item_fields have correct sub-fields."""
        schema = schema_for_editor(RepoServerConfig)
        by_name = {f.name: f for f in schema}
        ga = by_name["github_app_credentials"]
        assert ga.item_class_name == "GitHubAppCredential"
        assert ga.item_fields is not None
        item_names = {f.name for f in ga.item_fields}
        assert "app_id" in item_names
        assert "private_key" in item_names
        assert "installation_id" in item_names
        assert "scopes" in item_names
        assert "base_url" in item_names

    def test_multiline_private_key(self) -> None:
        """private_key field is marked multiline."""
        schema = schema_for_editor(GitHubAppCredential)
        by_name = {f.name: f for f in schema}
        assert by_name["private_key"].multiline is True

    def test_resource_limits_nested(self) -> None:
        """ResourceLimits fields are exposed as nested fields."""
        schema = schema_for_editor(ResourceLimits)
        names = {f.name for f in schema}
        assert "timeout" in names
        assert "memory" in names
        assert "cpus" in names
        assert "pids_limit" in names


class TestFormToRawDict:
    """Tests for form_to_raw_dict()."""

    def test_empty_form(self) -> None:
        """Empty form produces empty dict."""
        result = form_to_raw_dict({})
        assert result == {}

    def test_literal_scalar(self) -> None:
        """Literal scalar values are set correctly."""
        result = form_to_raw_dict(
            {
                "execution.max_concurrent._source": "literal",
                "execution.max_concurrent._value": "5",
            }
        )
        assert result == {"execution": {"max_concurrent": 5}}

    def test_env_scalar(self) -> None:
        """!env values create EnvVar objects."""
        result = form_to_raw_dict(
            {
                "email.password._source": "env",
                "email.password._value": "EMAIL_PASS",
            }
        )
        assert isinstance(result["email"]["password"], EnvVar)
        assert result["email"]["password"].var_name == "EMAIL_PASS"

    def test_var_scalar(self) -> None:
        """!var values create VarRef objects."""
        result = form_to_raw_dict(
            {
                "email.password._source": "var",
                "email.password._value": "my_password",
            }
        )
        assert isinstance(result["email"]["password"], VarRef)
        assert result["email"]["password"].var_name == "my_password"

    def test_unset_excluded(self) -> None:
        """Unset fields are excluded from the dict."""
        result = form_to_raw_dict(
            {
                "execution.max_concurrent._source": "unset",
                "execution.max_concurrent._value": "5",
                "dashboard.host._source": "literal",
                "dashboard.host._value": "0.0.0.0",
            }
        )
        assert "execution" not in result
        assert result["dashboard"]["host"] == "0.0.0.0"

    def test_bool_coercion(self) -> None:
        """Boolean string values are coerced to bool."""
        result = form_to_raw_dict(
            {
                "dashboard.enabled._source": "literal",
                "dashboard.enabled._value": "true",
            }
        )
        assert result["dashboard"]["enabled"] is True

        result = form_to_raw_dict(
            {
                "dashboard.enabled._source": "literal",
                "dashboard.enabled._value": "false",
            }
        )
        assert result["dashboard"]["enabled"] is False

    def test_int_coercion(self) -> None:
        """Integer string values are coerced to int."""
        result = form_to_raw_dict(
            {
                "execution.max_concurrent._source": "literal",
                "execution.max_concurrent._value": "10",
            }
        )
        assert result["execution"]["max_concurrent"] == 10
        assert isinstance(result["execution"]["max_concurrent"], int)

    def test_float_coercion(self) -> None:
        """Float string values are coerced to float."""
        result = form_to_raw_dict(
            {
                "resource_limits.cpus._source": "literal",
                "resource_limits.cpus._value": "1.5",
            }
        )
        assert result["resource_limits"]["cpus"] == 1.5

    def test_generation_ignored(self) -> None:
        """_generation is ignored (starts with _)."""
        result = form_to_raw_dict({"_generation": "5"})
        assert result == {}

    def test_deeply_nested(self) -> None:
        """Multi-level nesting works."""
        result = form_to_raw_dict(
            {
                "repos.my-repo.email.imap_server._source": "literal",
                "repos.my-repo.email.imap_server._value": "mail.example.com",
            }
        )
        assert (
            result["repos"]["my-repo"]["email"]["imap_server"]
            == "mail.example.com"
        )


class TestRawValueHelpers:
    """Tests for get_raw_value, detect_source, get_source_ref."""

    def test_get_raw_value_found(self) -> None:
        raw = {"execution": {"max_concurrent": 5}}
        assert get_raw_value(raw, ("execution", "max_concurrent")) == 5

    def test_get_raw_value_missing(self) -> None:
        raw = {"execution": {}}
        assert get_raw_value(raw, ("execution", "max_concurrent")) is None

    def test_get_raw_value_none_raw(self) -> None:
        assert get_raw_value(None, ("foo",)) is None

    def test_detect_source_literal(self) -> None:
        assert detect_source("hello") == "literal"
        assert detect_source(42) == "literal"
        assert detect_source(True) == "literal"

    def test_detect_source_env(self) -> None:
        assert detect_source(EnvVar("FOO")) == "env"

    def test_detect_source_var(self) -> None:
        assert detect_source(VarRef("bar")) == "var"

    def test_detect_source_unset(self) -> None:
        assert detect_source(None) == "unset"

    def test_get_source_ref_env(self) -> None:
        assert get_source_ref(EnvVar("FOO")) == "FOO"

    def test_get_source_ref_var(self) -> None:
        assert get_source_ref(VarRef("bar")) == "bar"

    def test_get_source_ref_literal(self) -> None:
        assert get_source_ref("hello") == ""
        assert get_source_ref(42) == ""


class TestInMemoryConfigSource:
    """Tests for InMemoryConfigSource."""

    def test_load_returns_data(self) -> None:
        data = {"foo": "bar"}
        source = InMemoryConfigSource(data)
        assert source.load() == {"foo": "bar"}

    def test_save_raises(self) -> None:
        source = InMemoryConfigSource({})
        with pytest.raises(NotImplementedError):
            source.save({})


class TestBuildEditorContext:
    """Tests for build_editor_context()."""

    def _make_snapshot(self) -> ConfigSnapshot[ServerConfig]:
        """Create a minimal ServerConfig snapshot for testing."""
        email = EmailChannelConfig(
            imap_server="mail.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="secret",
            from_address="user@example.com",
            authorized_senders=["admin@example.com"],
            trusted_authserv_id="example.com",
        )
        repo = RepoServerConfig(
            repo_id="test-repo",
            git_repo_url="https://github.com/test/repo",
            channels={"email": email},
        )
        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test-repo": repo},
        )
        raw: dict[str, Any] = {
            "config_version": 2,
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/test/repo"},
                    "email": {
                        "imap_server": "mail.example.com",
                        "imap_port": 993,
                        "smtp_server": "smtp.example.com",
                        "smtp_port": 587,
                        "username": "user@example.com",
                        "password": "secret",
                        "from": "user@example.com",
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "example.com",
                    },
                }
            },
        }
        return ConfigSnapshot(
            config, frozenset({"global_config", "repos"}), raw=raw
        )

    def test_context_has_required_keys(self) -> None:
        """Editor context has all required template keys."""
        snapshot = self._make_snapshot()
        ctx = build_editor_context(snapshot, config_generation=1)
        assert "config" in ctx
        assert "raw" in ctx
        assert "global_schema" in ctx
        assert "repos" in ctx
        assert "config_generation" in ctx
        assert ctx["config_generation"] == 1
        assert "config_version" in ctx
        assert ctx["config_version"] == 2

    def test_global_schema_populated(self) -> None:
        """Global schema contains GlobalConfig fields."""
        snapshot = self._make_snapshot()
        ctx = build_editor_context(snapshot, config_generation=0)
        names = {f.name for f in ctx["global_schema"]}
        assert "max_concurrent_executions" in names

    def test_repo_context_populated(self) -> None:
        """Repo context has schema and channel info."""
        snapshot = self._make_snapshot()
        ctx = build_editor_context(snapshot, config_generation=0)
        assert len(ctx["repos"]) == 1
        repo_ctx = ctx["repos"][0]
        assert repo_ctx["repo_id"] == "test-repo"
        assert repo_ctx["has_email"] is True
        assert repo_ctx["has_slack"] is False
        assert repo_ctx["email_schema"] is not None
        # Slack schema is always built for the enable toggle
        assert repo_ctx["slack_schema"] is not None

    def test_context_with_slack_channel(self) -> None:
        """build_editor_context includes Slack schema when present."""
        slack = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=({"user_id": "U123"},),
        )
        repo = RepoServerConfig(
            repo_id="slack-repo",
            git_repo_url="https://github.com/test/repo",
            channels={"slack": slack},
        )
        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"slack-repo": repo},
        )
        raw: dict[str, Any] = {
            "config_version": 2,
            "repos": {
                "slack-repo": {
                    "git": {
                        "repo_url": "https://github.com/test/repo",
                    },
                    "slack": {
                        "bot_token": "xoxb-test",
                        "app_token": "xapp-test",
                    },
                }
            },
        }
        snapshot = ConfigSnapshot(
            config,
            frozenset({"global_config", "repos"}),
            raw=raw,
        )
        ctx = build_editor_context(snapshot, config_generation=0)
        repo_ctx = ctx["repos"][0]
        assert repo_ctx["has_slack"] is True
        assert repo_ctx["slack_schema"] is not None
        assert repo_ctx["has_email"] is False

    def test_fields_without_meta_skipped(self) -> None:
        """Fields without FieldMeta are excluded from schema."""
        import dataclasses

        from airut.config.schema import Scope, meta

        @dataclasses.dataclass
        class Mixed:
            annotated: str = dataclasses.field(
                metadata=meta("Has meta", Scope.SERVER),
            )
            plain: str = "no_meta"

        schema = schema_for_editor(Mixed)
        names = {f.name for f in schema}
        assert "annotated" in names
        assert "plain" not in names


class TestClassifyTypeEdgeCases:
    """Tests for _classify_type edge cases."""

    def test_bare_list_without_args(self) -> None:
        """Bare list type (no args) is classified as list_str."""
        from airut.config.editor import _classify_type

        tag, py_type, item = _classify_type(list, "Foo", "bar")
        assert tag == "list_str"

    def test_unknown_type_fallback(self) -> None:
        """Unknown type falls back to scalar with type name."""
        from airut.config.editor import _classify_type

        class CustomType:
            pass

        tag, py_type, item = _classify_type(CustomType, "Foo", "bar")
        assert tag == "scalar"
        assert py_type == "CustomType"

    def test_unknown_non_type_fallback(self) -> None:
        """Non-type annotation falls back to str()."""
        from airut.config.editor import _classify_type

        tag, py_type, item = _classify_type("some_string", "Foo", "bar")
        assert tag == "scalar"
        assert py_type == "some_string"


class TestFormToRawDictEdgeCases:
    """Edge case tests for form_to_raw_dict."""

    def test_unknown_source_skipped(self) -> None:
        """Unknown source values are skipped."""
        result = form_to_raw_dict(
            {
                "foo._source": "invalid_source",
                "foo._value": "bar",
            }
        )
        assert result == {}

    def test_list_items_converted(self) -> None:
        """Numeric keys are converted to list items."""
        result = form_to_raw_dict(
            {
                "senders.0._source": "literal",
                "senders.0._value": "a@b.com",
                "senders.1._source": "literal",
                "senders.1._value": "c@d.com",
            }
        )
        assert result == {"senders": ["a@b.com", "c@d.com"]}

    def test_path_conflict_overwritten(self) -> None:
        """If a path element conflicts, it is overwritten."""
        from airut.config.editor_form import _set_nested_path

        target: dict[str, Any] = {"a": "scalar_value"}
        _set_nested_path(target, ["a", "b"], "nested")
        assert target["a"] == {"b": "nested"}


class TestFormToRawDictDictEntries:
    """Tests for dict key-value form parsing."""

    def test_dict_entries_parsed(self) -> None:
        """Dict entries with key/value pairs are converted."""
        result = form_to_raw_dict(
            {
                "secrets.0.key": "API_KEY",
                "secrets.0.value._source": "literal",
                "secrets.0.value._value": "abc123",
                "secrets.1.key": "DB_PASS",
                "secrets.1.value._source": "env",
                "secrets.1.value._value": "DB_PASSWORD",
            }
        )
        from airut.yaml_env import EnvVar

        assert result["secrets"]["API_KEY"] == "abc123"
        assert isinstance(result["secrets"]["DB_PASS"], EnvVar)
        assert result["secrets"]["DB_PASS"].var_name == "DB_PASSWORD"


class TestFormToRawDictTaggedUnion:
    """Tests for tagged union form parsing."""

    def test_tagged_union_entries(self) -> None:
        """Tagged union items produce {tag: value} dicts."""
        result = form_to_raw_dict(
            {
                "authorized.0._tag": "user_id",
                "authorized.0._value": "U123",
                "authorized.1._tag": "workspace_members",
                "authorized.1._value": "true",
            }
        )
        items = result["authorized"]
        assert isinstance(items, list)
        assert len(items) == 2
        assert items[0] == {"user_id": "U123"}
        assert items[1] == {"workspace_members": True}


class TestFormToRawDictCollectionKeys:
    """Tests for keyed collection form parsing."""

    def test_collection_key_rename(self) -> None:
        """Collection entries are renamed from temp to user-supplied key."""
        result = form_to_raw_dict(
            {
                "repos.my-repo._key": "my-repo",
                "repos.my-repo.git.repo_url._source": "literal",
                "repos.my-repo.git.repo_url._value": "https://github.com/x/y",
            }
        )
        assert "my-repo" in result["repos"]
        assert result["repos"]["my-repo"]["git"]["repo_url"] == (
            "https://github.com/x/y"
        )

    def test_collection_new_entry_renamed(self) -> None:
        """New collection entries (_new_0) are renamed to user key."""
        result = form_to_raw_dict(
            {
                "repos._new_0._key": "new-repo",
                "repos._new_0.git.repo_url._source": "literal",
                "repos._new_0.git.repo_url._value": "https://github.com/a/b",
            }
        )
        assert "new-repo" in result["repos"]
        assert "_new_0" not in result["repos"]


class TestFormToRawDictDefensiveBranches:
    """Tests for defensive branches in form parsing helpers."""

    def test_key_without_dot_skipped(self) -> None:
        """Form keys without a dot separator are ignored."""
        result = form_to_raw_dict(
            {"nodot": "value", "a._source": "literal", "a._value": "x"}
        )
        assert result == {"a": "x"}

    def test_dict_key_path_too_short(self) -> None:
        """Dict key paths with fewer than 2 parts are ignored."""
        from airut.config.editor_form import _convert_dict_entries

        d: dict[str, Any] = {"x": "y"}
        _convert_dict_entries(d, {"single": "key"})
        assert d == {"x": "y"}

    def test_dict_entry_missing_parent(self) -> None:
        """Dict entries with missing parent path are skipped."""
        from airut.config.editor_form import _convert_dict_entries

        d: dict[str, Any] = {}
        _convert_dict_entries(d, {"missing.parent.0": "key"})
        assert d == {}

    def test_dict_entry_non_numeric_index(self) -> None:
        """Dict entries with non-numeric index are skipped."""
        from airut.config.editor_form import _convert_dict_entries

        d: dict[str, Any] = {"items": ["a", "b"]}
        _convert_dict_entries(d, {"items.abc": "key"})
        assert d == {"items": ["a", "b"]}

    def test_collection_key_path_too_short(self) -> None:
        """Collection key paths with fewer than 2 parts are ignored."""
        from airut.config.editor_form import _rename_collection_keys

        d: dict[str, Any] = {"x": "y"}
        _rename_collection_keys(d, {"single": "key"})
        assert d == {"x": "y"}

    def test_collection_missing_parent(self) -> None:
        """Collection entries with missing parent are skipped."""
        from airut.config.editor_form import _rename_collection_keys

        d: dict[str, Any] = {}
        _rename_collection_keys(d, {"missing.child": "key"})
        assert d == {}

    def test_collection_parent_not_dict(self) -> None:
        """Collection entries where parent is not a dict are skipped."""
        from airut.config.editor_form import _rename_collection_keys

        d: dict[str, Any] = {"items": "not_a_dict"}
        _rename_collection_keys(d, {"items.child": "key"})
        assert d == {"items": "not_a_dict"}

    def test_collection_key_sentinel_removed(self) -> None:
        """The _key sentinel is removed from renamed entries."""
        from airut.config.editor_form import _rename_collection_keys

        d: dict[str, Any] = {
            "repos": {"old": {"_key": "old", "url": "https://x"}},
        }
        _rename_collection_keys(d, {"repos.old": "new"})
        assert "new" in d["repos"]
        assert "_key" not in d["repos"]["new"]


class TestGetRawValueEdgeCases:
    """Edge case tests for get_raw_value."""

    def test_non_dict_in_path(self) -> None:
        """Returns None when path traverses a non-dict."""
        raw = {"a": "not_a_dict"}
        assert get_raw_value(raw, ("a", "b")) is None
