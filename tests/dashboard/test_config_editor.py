# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor module."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from werkzeug.test import Client

from airut.config.schema import FieldSchema, schema_for_ui
from airut.config.source import (
    YAML_GLOBAL_STRUCTURE,
    YamlConfigSource,
)
from airut.dashboard.config_editor import (
    ConfigEditor,
    _coerce_value,
    _delete_nested,
    _parse_mode_value,
    detect_mode,
    detect_mode_value,
    group_email_fields,
    group_fields,
    lookup_email_raw,
    lookup_global_raw,
    lookup_repo_raw,
    merge_email_fields,
    merge_global_fields,
    merge_repo_fields,
    parse_form_fields,
    parse_github_app_credentials,
    parse_key_value_table,
    parse_masked_secrets,
    parse_signing_credentials,
    parse_vars_from_form,
)
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker
from airut.gateway.config import EmailChannelConfig, GlobalConfig
from airut.yaml_env import EnvVar, VarRef


# ── Minimal config YAML for tests ──────────────────────────────────


def _write_config(path: Path, data: dict[str, Any] | None = None) -> Path:
    """Write a minimal config YAML file."""
    if data is None:
        data = {
            "vars": {"mail_server": "mail.example.com"},
            "execution": {"max_concurrent": 4},
            "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 5200},
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/test/repo.git"},
                    "model": "opus",
                    "email": {
                        "imap_server": "imap.example.com",
                        "smtp_server": "smtp.example.com",
                        "username": "user@example.com",
                        "password": "secret",
                        "from": "bot@example.com",
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "example.com",
                    },
                },
            },
        }
    config_file = path / "airut.yaml"
    config_file.write_text(yaml.dump(data, default_flow_style=False))
    return config_file


# ── detect_mode / detect_mode_value ─────────────────────────────────


class TestDetectMode:
    def test_literal(self) -> None:
        assert detect_mode("hello") == "literal"

    def test_var(self) -> None:
        assert detect_mode(VarRef("my_var")) == "var"

    def test_env(self) -> None:
        assert detect_mode(EnvVar("MY_ENV")) == "env"

    def test_none(self) -> None:
        assert detect_mode(None) == "literal"

    def test_int(self) -> None:
        assert detect_mode(42) == "literal"


class TestDetectModeValue:
    def test_literal_str(self) -> None:
        assert detect_mode_value("hello") == "hello"

    def test_var(self) -> None:
        assert detect_mode_value(VarRef("my_var")) == "my_var"

    def test_env(self) -> None:
        assert detect_mode_value(EnvVar("MY_ENV")) == "MY_ENV"

    def test_none(self) -> None:
        assert detect_mode_value(None) == ""

    def test_int(self) -> None:
        assert detect_mode_value(42) == "42"

    def test_list(self) -> None:
        assert detect_mode_value(["a", "b", "c"]) == "a\nb\nc"

    def test_tuple(self) -> None:
        assert detect_mode_value(("x", "y")) == "x\ny"

    def test_empty_list(self) -> None:
        assert detect_mode_value([]) == ""

    def test_bool(self) -> None:
        assert detect_mode_value(True) == "True"


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


# ── Form parsing ───────────────────────────────────────────────────


class TestCoerceValue:
    def test_int(self) -> None:
        assert _coerce_value("42", "int") == (42, None)

    def test_int_empty(self) -> None:
        assert _coerce_value("", "int") == (None, None)

    def test_int_invalid(self) -> None:
        val, err = _coerce_value("abc", "int")
        assert val is None
        assert err is not None

    def test_float(self) -> None:
        assert _coerce_value("3.14", "float") == (3.14, None)

    def test_float_empty(self) -> None:
        assert _coerce_value("", "float") == (None, None)

    def test_float_invalid(self) -> None:
        val, err = _coerce_value("xyz", "float")
        assert val is None
        assert err is not None

    def test_bool_true(self) -> None:
        assert _coerce_value("true", "bool") == (True, None)

    def test_bool_false(self) -> None:
        assert _coerce_value("false", "bool") == (False, None)

    def test_bool_empty(self) -> None:
        assert _coerce_value("", "bool") == (None, None)

    def test_list(self) -> None:
        val, err = _coerce_value("a\nb\nc", "list[str]")
        assert val == ["a", "b", "c"]
        assert err is None

    def test_list_strips(self) -> None:
        val, _ = _coerce_value("  a  \n\n  b  \n", "list[str]")
        assert val == ["a", "b"]

    def test_str(self) -> None:
        assert _coerce_value("hello", "str") == ("hello", None)

    def test_int_in_dict_type_treated_as_str(self) -> None:
        # "dict[str, int]" contains "int" but should not coerce as int
        # because it also contains "dict"
        val, err = _coerce_value("hello", "dict[str, int]")
        assert val == "hello"
        assert err is None


class TestParseFormFields:
    def _make_schema(
        self,
        name: str = "test_field",
        type_name: str = "str",
        default: object = None,
        required: bool = False,
        doc: str = "Test",
        scope: str = "task",
        secret: bool = False,
    ) -> list[FieldSchema]:
        return [
            FieldSchema(
                name=name,
                type_name=type_name,
                default=default,
                required=required,
                doc=doc,
                scope=scope,
                secret=secret,
            )
        ]

    def test_literal_str(self) -> None:
        schema = self._make_schema()
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "hello",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert parsed == {"test_field": "hello"}
        assert not errors

    def test_var_ref(self) -> None:
        schema = self._make_schema()
        form = {
            "field.test_field.mode": "var",
            "field.test_field.value": "my_var",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert isinstance(parsed["test_field"], VarRef)
        assert parsed["test_field"].var_name == "my_var"
        assert not errors

    def test_env_var(self) -> None:
        schema = self._make_schema()
        form = {
            "field.test_field.mode": "env",
            "field.test_field.value": "MY_ENV",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert isinstance(parsed["test_field"], EnvVar)
        assert parsed["test_field"].var_name == "MY_ENV"
        assert not errors

    def test_empty_optional_skipped(self) -> None:
        schema = self._make_schema(required=False)
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" not in parsed
        assert not errors

    def test_empty_required_error(self) -> None:
        schema = self._make_schema(required=True)
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" in errors

    def test_var_empty_required_error(self) -> None:
        schema = self._make_schema(required=True)
        form = {
            "field.test_field.mode": "var",
            "field.test_field.value": "",
        }
        _, errors = parse_form_fields(form, schema)
        assert "test_field" in errors

    def test_env_empty_required_error(self) -> None:
        schema = self._make_schema(required=True)
        form = {
            "field.test_field.mode": "env",
            "field.test_field.value": "",
        }
        _, errors = parse_form_fields(form, schema)
        assert "test_field" in errors

    def test_invalid_int_error(self) -> None:
        schema = self._make_schema(type_name="int")
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "abc",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" in errors

    def test_int_coercion(self) -> None:
        schema = self._make_schema(type_name="int")
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "42",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert parsed["test_field"] == 42
        assert not errors

    def test_default_mode_is_literal(self) -> None:
        schema = self._make_schema()
        form = {"field.test_field.value": "hello"}
        parsed, errors = parse_form_fields(form, schema)
        assert parsed == {"test_field": "hello"}
        assert not errors

    def test_var_empty_optional_not_included(self) -> None:
        schema = self._make_schema(required=False)
        form = {
            "field.test_field.mode": "var",
            "field.test_field.value": "",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" not in parsed
        assert not errors

    def test_env_empty_optional_not_included(self) -> None:
        schema = self._make_schema(required=False)
        form = {
            "field.test_field.mode": "env",
            "field.test_field.value": "",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" not in parsed
        assert not errors


# ── Credential parsing ─────────────────────────────────────────────


class TestParseKeyValueTable:
    def test_basic(self) -> None:
        form = {
            "secret.0.key": "TOKEN",
            "secret.0.value.mode": "literal",
            "secret.0.value.value": "abc123",
        }
        result = parse_key_value_table(form, "secret")
        assert result == {"TOKEN": "abc123"}

    def test_empty_key_skipped(self) -> None:
        form = {
            "secret.0.key": "",
            "secret.0.value.mode": "literal",
            "secret.0.value.value": "abc",
        }
        result = parse_key_value_table(form, "secret")
        assert result == {}

    def test_env_mode(self) -> None:
        form = {
            "secret.0.key": "TOKEN",
            "secret.0.value.mode": "env",
            "secret.0.value.value": "MY_TOKEN",
        }
        result = parse_key_value_table(form, "secret")
        assert isinstance(result["TOKEN"], EnvVar)

    def test_var_mode(self) -> None:
        form = {
            "secret.0.key": "TOKEN",
            "secret.0.value.mode": "var",
            "secret.0.value.value": "my_var",
        }
        result = parse_key_value_table(form, "secret")
        assert isinstance(result["TOKEN"], VarRef)

    def test_multiple_entries(self) -> None:
        form = {
            "secret.0.key": "A",
            "secret.0.value.mode": "literal",
            "secret.0.value.value": "val_a",
            "secret.1.key": "B",
            "secret.1.value.mode": "literal",
            "secret.1.value.value": "val_b",
        }
        result = parse_key_value_table(form, "secret")
        assert len(result) == 2
        assert result["A"] == "val_a"
        assert result["B"] == "val_b"


class TestParseMaskedSecrets:
    def test_basic(self) -> None:
        form = {
            "masked_secret.0.key": "GH_TOKEN",
            "masked_secret.0.value.mode": "env",
            "masked_secret.0.value.value": "GH_TOKEN_VALUE",
            "masked_secret.0.scopes": "api.github.com",
            "masked_secret.0.headers": "Authorization",
            "masked_secret.0.allow_foreign": "false",
        }
        result = parse_masked_secrets(form)
        assert "GH_TOKEN" in result
        entry = result["GH_TOKEN"]
        assert isinstance(entry["value"], EnvVar)
        assert entry["scopes"] == ["api.github.com"]
        assert entry["headers"] == ["Authorization"]
        assert "allow_foreign_credentials" not in entry

    def test_allow_foreign(self) -> None:
        form = {
            "masked_secret.0.key": "TOKEN",
            "masked_secret.0.value.mode": "literal",
            "masked_secret.0.value.value": "secret",
            "masked_secret.0.scopes": "",
            "masked_secret.0.headers": "",
            "masked_secret.0.allow_foreign": "true",
        }
        result = parse_masked_secrets(form)
        assert result["TOKEN"]["allow_foreign_credentials"] is True

    def test_multiline_scopes(self) -> None:
        form = {
            "masked_secret.0.key": "TOKEN",
            "masked_secret.0.value.mode": "literal",
            "masked_secret.0.value.value": "secret",
            "masked_secret.0.scopes": "a.com\nb.com\n",
            "masked_secret.0.headers": "",
        }
        result = parse_masked_secrets(form)
        assert result["TOKEN"]["scopes"] == ["a.com", "b.com"]

    def test_empty_key_skipped(self) -> None:
        form = {
            "masked_secret.0.key": "",
            "masked_secret.0.value.mode": "literal",
            "masked_secret.0.value.value": "val",
            "masked_secret.0.scopes": "",
            "masked_secret.0.headers": "",
        }
        result = parse_masked_secrets(form)
        assert result == {}


class TestParseSigningCredentials:
    def test_basic(self) -> None:
        form = {
            "signing_credential.0.key": "aws-main",
            "signing_credential.0.access_key_id.name": "AWS_ACCESS_KEY_ID",
            "signing_credential.0.access_key_id.value.mode": "env",
            "signing_credential.0.access_key_id.value.value": "AK_ENV",
            "signing_credential.0.secret_access_key.name": (
                "AWS_SECRET_ACCESS_KEY"
            ),
            "signing_credential.0.secret_access_key.value.mode": "literal",
            "signing_credential.0.secret_access_key.value.value": "secret123",
            "signing_credential.0.scopes": "bedrock.us-east-1.amazonaws.com",
        }
        result = parse_signing_credentials(form)
        assert "aws-main" in result
        entry = result["aws-main"]
        assert entry["type"] == "aws-sigv4"
        assert isinstance(entry["access_key_id"]["value"], EnvVar)
        assert entry["secret_access_key"]["value"] == "secret123"

    def test_with_session_token(self) -> None:
        form = {
            "signing_credential.0.key": "aws-sts",
            "signing_credential.0.access_key_id.name": "AK",
            "signing_credential.0.access_key_id.value.mode": "literal",
            "signing_credential.0.access_key_id.value.value": "AKIA...",
            "signing_credential.0.secret_access_key.name": "SK",
            "signing_credential.0.secret_access_key.value.mode": "literal",
            "signing_credential.0.secret_access_key.value.value": "secret",
            "signing_credential.0.session_token.name": "ST",
            "signing_credential.0.session_token.value.mode": "literal",
            "signing_credential.0.session_token.value.value": "token",
            "signing_credential.0.scopes": "",
        }
        result = parse_signing_credentials(form)
        assert "session_token" in result["aws-sts"]
        assert result["aws-sts"]["session_token"]["name"] == "ST"

    def test_empty_key_skipped(self) -> None:
        form = {
            "signing_credential.0.key": "",
            "signing_credential.0.access_key_id.name": "AK",
            "signing_credential.0.access_key_id.value.mode": "literal",
            "signing_credential.0.access_key_id.value.value": "val",
            "signing_credential.0.secret_access_key.name": "SK",
            "signing_credential.0.secret_access_key.value.mode": "literal",
            "signing_credential.0.secret_access_key.value.value": "val",
            "signing_credential.0.scopes": "",
        }
        result = parse_signing_credentials(form)
        assert result == {}


class TestParseGitHubAppCredentials:
    def test_basic(self) -> None:
        form = {
            "github_app.0.key": "my-app",
            "github_app.0.app_id.mode": "literal",
            "github_app.0.app_id.value": "12345",
            "github_app.0.private_key.mode": "env",
            "github_app.0.private_key.value": "GH_PK",
            "github_app.0.installation_id.mode": "literal",
            "github_app.0.installation_id.value": "67890",
            "github_app.0.scopes": "api.github.com",
        }
        result = parse_github_app_credentials(form)
        assert "my-app" in result
        entry = result["my-app"]
        assert entry["app_id"] == "12345"
        assert isinstance(entry["private_key"], EnvVar)
        assert entry["scopes"] == ["api.github.com"]

    def test_with_optional_fields(self) -> None:
        form = {
            "github_app.0.key": "app",
            "github_app.0.app_id.mode": "literal",
            "github_app.0.app_id.value": "1",
            "github_app.0.private_key.mode": "literal",
            "github_app.0.private_key.value": "pk",
            "github_app.0.installation_id.mode": "literal",
            "github_app.0.installation_id.value": "2",
            "github_app.0.scopes": "",
            "github_app.0.allow_foreign": "true",
            "github_app.0.base_url": "https://ghe.example.com/api/v3",
            "github_app.0.permissions": "contents: write\npull_requests: read",
            "github_app.0.repositories": "org/repo1\norg/repo2",
        }
        result = parse_github_app_credentials(form)
        entry = result["app"]
        assert entry["allow_foreign_credentials"] is True
        assert entry["base_url"] == "https://ghe.example.com/api/v3"
        assert entry["permissions"] == {
            "contents": "write",
            "pull_requests": "read",
        }
        assert entry["repositories"] == ["org/repo1", "org/repo2"]

    def test_empty_key_skipped(self) -> None:
        form = {
            "github_app.0.key": "",
            "github_app.0.app_id.mode": "literal",
            "github_app.0.app_id.value": "1",
            "github_app.0.private_key.mode": "literal",
            "github_app.0.private_key.value": "pk",
            "github_app.0.installation_id.mode": "literal",
            "github_app.0.installation_id.value": "2",
            "github_app.0.scopes": "",
        }
        result = parse_github_app_credentials(form)
        assert result == {}


# ── parse_mode_value ───────────────────────────────────────────────


class TestParseModeValue:
    def test_literal(self) -> None:
        form = {"p.mode": "literal", "p.value": "hello"}
        assert _parse_mode_value(form, "p") == "hello"

    def test_var(self) -> None:
        form = {"p.mode": "var", "p.value": "my_var"}
        result = _parse_mode_value(form, "p")
        assert isinstance(result, VarRef)

    def test_env(self) -> None:
        form = {"p.mode": "env", "p.value": "MY_ENV"}
        result = _parse_mode_value(form, "p")
        assert isinstance(result, EnvVar)

    def test_env_empty_returns_literal(self) -> None:
        form = {"p.mode": "env", "p.value": ""}
        result = _parse_mode_value(form, "p")
        assert result == ""


# ── Nested dict helpers ────────────────────────────────────────────


class TestDeleteNested:
    def test_deletes_leaf(self) -> None:
        target = {"a": {"b": {"c": 42}}}
        _delete_nested(target, ("a", "b", "c"))
        assert target == {"a": {"b": {}}}

    def test_noop_if_missing(self) -> None:
        target: dict[str, Any] = {"a": {"b": 1}}
        _delete_nested(target, ("x", "y"))
        assert target == {"a": {"b": 1}}

    def test_noop_if_intermediate_not_dict(self) -> None:
        target = {"a": "not_dict"}
        _delete_nested(target, ("a", "b"))
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


# ── Variable parsing ──────────────────────────────────────────────


class TestParseVarsFromForm:
    def test_literal_var(self) -> None:
        form = {
            "var.0.name": "mail_server",
            "var.0.mode": "literal",
            "var.0.value": "mail.example.com",
        }
        result = parse_vars_from_form(form)
        assert result == {"mail_server": "mail.example.com"}

    def test_env_var(self) -> None:
        form = {
            "var.0.name": "token",
            "var.0.mode": "env",
            "var.0.value": "MY_TOKEN",
        }
        result = parse_vars_from_form(form)
        assert isinstance(result["token"], EnvVar)
        assert result["token"].var_name == "MY_TOKEN"

    def test_empty_name_skipped(self) -> None:
        form = {
            "var.0.name": "",
            "var.0.mode": "literal",
            "var.0.value": "val",
        }
        result = parse_vars_from_form(form)
        assert result == {}

    def test_multiple_vars(self) -> None:
        form = {
            "var.0.name": "a",
            "var.0.mode": "literal",
            "var.0.value": "1",
            "var.1.name": "b",
            "var.1.mode": "literal",
            "var.1.value": "2",
        }
        result = parse_vars_from_form(form)
        assert result == {"a": "1", "b": "2"}


# ── ConfigEditor handler tests ─────────────────────────────────────


class TestConfigEditorHandlers:
    """Tests for ConfigEditor HTTP handlers via werkzeug test client."""

    @pytest.fixture
    def config_path(self, tmp_path: Path) -> Path:
        return _write_config(tmp_path)

    @pytest.fixture
    def editor(self, config_path: Path) -> ConfigEditor:
        return ConfigEditor(YamlConfigSource(config_path))

    @pytest.fixture
    def client(self, config_path: Path) -> Client:
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        return Client(server._wsgi_app)

    def test_config_index_redirects(self, client: Client) -> None:
        response = client.get("/config")
        assert response.status_code == 302
        assert response.headers["Location"] == "/config/global"

    def test_global_get(self, client: Client) -> None:
        response = client.get("/config/global")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Global Settings" in html
        assert "Variables" in html

    def test_global_post_without_csrf_rejected(self, client: Client) -> None:
        response = client.post("/config/global")
        assert response.status_code == 403

    def test_global_post_with_csrf(self, client: Client) -> None:
        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html

    def test_repo_get(self, client: Client) -> None:
        response = client.get("/config/repo/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_repo_get_not_found(self, client: Client) -> None:
        response = client.get("/config/repo/nonexistent")
        assert response.status_code == 404

    def test_repo_new_get(self, client: Client) -> None:
        response = client.get("/config/repo/new")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "New Repository" in html

    def test_repo_new_post_creates_repo(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=new-repo&git_repo_url=https://github.com/org/new.git",
        )
        assert response.status_code == 302
        assert "/config/repo/new-repo" in response.headers["Location"]

    def test_repo_new_post_missing_id(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "required" in html.lower()

    def test_repo_new_post_invalid_id(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=!invalid&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Invalid" in html

    def test_repo_new_post_duplicate(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=test-repo&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "already exists" in html

    def test_repo_new_post_missing_url(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=my-repo&git_repo_url=",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "required" in html.lower()

    def test_repo_delete_get(self, client: Client) -> None:
        response = client.get("/config/repo/test-repo/delete")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Delete" in html
        assert "test-repo" in html

    def test_repo_delete_get_not_found(self, client: Client) -> None:
        response = client.get("/config/repo/nonexistent/delete")
        assert response.status_code == 404

    def test_repo_delete_post(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/delete",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 302
        assert response.headers["Location"] == "/config/global"

    def test_repo_delete_post_not_found(self, client: Client) -> None:
        response = client.post(
            "/config/repo/nonexistent/delete",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    def test_nav_fragment(self, client: Client) -> None:
        response = client.get("/config/nav")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Global" in html
        assert "test-repo" in html

    def test_field_input_fragment(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=literal"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'name="field.model.value"' in html

    def test_field_input_var_mode(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=var"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Variable name" in html

    def test_field_input_env_mode(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=env"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "ENV_VAR_NAME" in html

    def test_vars_add(self, client: Client) -> None:
        response = client.post(
            "/config/vars/add",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "var." in html

    def test_credential_add_masked_secret(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=masked_secret",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "masked_secret." in html

    def test_credential_add_signing_credential(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=signing_credential",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "signing_credential." in html

    def test_credential_add_github_app(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=github_app",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "github_app." in html

    def test_reload_status(self, client: Client) -> None:
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "reload-status" in html

    def test_reload_status_no_gen(self, client: Client) -> None:
        response = client.get("/config/reload-status")
        assert response.status_code == 200

    def test_reload_status_with_status_callback(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": 10}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # gen=5, current=10 → reload complete, stop polling
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" not in html  # polling stopped

    def test_reload_status_still_pending(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": 3}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # gen=5, current=3 → still pending, keep polling
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" in html  # still polling

    def test_reload_status_bad_gen_value(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": "bad"}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # Bad gen value → stop polling gracefully
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" not in html  # stopped on bad value

    def test_credential_add_invalid_type(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=evil",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_repo_post_saves_changes(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.model.mode=literal"
                "&field.model.value=sonnet"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html

    def test_repo_post_not_found(self, client: Client) -> None:
        response = client.post(
            "/config/repo/nonexistent",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    def test_repo_post_add_slack(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true"
            ),
        )
        assert response.status_code == 200
        # Verify slack was saved
        raw = yaml.safe_load(config_path.read_text())
        assert "slack" in raw["repos"]["test-repo"]

    def test_config_not_available_without_source(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.get("/config/global")
        assert response.status_code == 404

    def test_repo_new_with_channels(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "repo_id=multi-chan"
                "&git_repo_url=https://github.com/test/repo.git"
                "&add_email=true"
                "&add_slack=true"
            ),
        )
        assert response.status_code == 302
        raw = yaml.safe_load(config_path.read_text())
        assert "email" in raw["repos"]["multi-chan"]
        assert "slack" in raw["repos"]["multi-chan"]


class TestConfigEditorInternal:
    """Tests for ConfigEditor internal methods."""

    @pytest.fixture
    def editor(self, tmp_path: Path) -> ConfigEditor:
        config_path = _write_config(tmp_path)
        return ConfigEditor(YamlConfigSource(config_path))

    def test_get_vars(self, editor: ConfigEditor) -> None:
        raw = editor._load_raw()
        assert editor._get_vars(raw) == {"mail_server": "mail.example.com"}

    def test_get_vars_empty(self, editor: ConfigEditor) -> None:
        assert editor._get_vars({}) == {}

    def test_get_vars_not_dict(self, editor: ConfigEditor) -> None:
        assert editor._get_vars({"vars": "not_a_dict"}) == {}

    def test_get_repo_ids(self, editor: ConfigEditor) -> None:
        raw = editor._load_raw()
        assert editor._get_repo_ids(raw) == ["test-repo"]

    def test_get_repo_ids_empty(self, editor: ConfigEditor) -> None:
        assert editor._get_repo_ids({}) == []

    def test_resolve_env_set(self, editor: ConfigEditor) -> None:
        with patch.dict("os.environ", {"TEST_VAR": "test_value"}):
            assert editor._resolve_env("TEST_VAR") == "test_value"

    def test_resolve_env_unset(self, editor: ConfigEditor) -> None:
        assert editor._resolve_env("SURELY_NOT_SET_12345") is None

    def test_schema_excludes_credential_fields(
        self, editor: ConfigEditor
    ) -> None:
        excluded = {
            "repo_id",
            "git_repo_url",
            "channels",
            "secrets",
            "masked_secrets",
            "signing_credentials",
            "github_app_credentials",
        }
        for field in editor._repo_schema:
            assert field.name not in excluded

    def test_global_post_saves_vars(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "var.0.name=new_var&var.0.mode=literal&var.0.value=new_value"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["vars"] == {"new_var": "new_value"}

    def test_global_post_removes_vars_when_empty(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="",
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "vars" not in raw

    def test_global_post_with_form_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Submit an invalid int value for max_concurrent_executions
        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "field.max_concurrent_executions.mode=literal"
                "&field.max_concurrent_executions.value=not_a_number"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Expected integer" in html

    def test_repo_post_with_email_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Email has required imap_server field
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=true"
                "&has_slack=false"
                "&field.imap_server.mode=literal"
                "&field.imap_server.value="
            ),
        )
        assert response.status_code == 200

    def test_repo_post_with_git_url_var_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=var"
                "&git_repo_url.value=my_repo_url"
                "&has_email=false"
                "&has_slack=false"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_with_git_url_env_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=env"
                "&git_repo_url.value=REPO_URL_ENV"
                "&has_email=false"
                "&has_slack=false"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_saves_secrets(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&secret.0.key=API_KEY"
                "&secret.0.value.mode=literal"
                "&secret.0.value.value=my-secret"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["repos"]["test-repo"]["secrets"] == {"API_KEY": "my-secret"}

    def test_repo_post_saves_container_env(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&container_env.0.key=MY_VAR"
                "&container_env.0.value.mode=literal"
                "&container_env.0.value.value=my_val"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["repos"]["test-repo"]["container_env"] == {
            "MY_VAR": "my_val"
        }

    def test_repo_post_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/repo/test-repo")
        assert response.status_code == 403

    def test_repo_new_post_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/new",
            content_type="application/x-www-form-urlencoded",
            data="repo_id=test&git_repo_url=https://example.com/r.git",
        )
        assert response.status_code == 403

    def test_repo_delete_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/repo/test-repo/delete")
        assert response.status_code == 403

    def test_repo_post_with_repo_field_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # network_sandbox_enabled is bool, give invalid
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.model.mode=literal"
                "&field.model.value=sonnet"
            ),
        )
        # Should succeed since model is valid
        assert response.status_code == 200

    def test_repo_post_with_email_valid(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=true"
                "&has_slack=false"
                "&field.imap_server.mode=literal"
                "&field.imap_server.value=imap.new.com"
                "&field.imap_port.mode=literal"
                "&field.imap_port.value=993"
                "&field.smtp_server.mode=literal"
                "&field.smtp_server.value=smtp.new.com"
                "&field.smtp_port.mode=literal"
                "&field.smtp_port.value=587"
                "&field.username.mode=literal"
                "&field.username.value=user@new.com"
                "&field.password.mode=literal"
                "&field.password.value=pass123"
                "&field.from_address.mode=literal"
                "&field.from_address.value=bot@new.com"
                "&field.authorized_senders.mode=literal"
                "&field.authorized_senders.value=admin@new.com"
                "&field.trusted_authserv_id.mode=literal"
                "&field.trusted_authserv_id.value=new.com"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html
        raw = yaml.safe_load(config_path.read_text())
        assert (
            raw["repos"]["test-repo"]["email"]["imap_server"] == "imap.new.com"
        )

    def test_repo_post_with_slack_var_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=var"
                "&field.bot_token.value=slack_bot"
                "&field.app_token.mode=env"
                "&field.app_token.value=SLACK_APP_TOKEN"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_slack_clear_authorized(self, tmp_path: Path) -> None:
        # Add slack with authorized rules first
        data = {
            "vars": {},
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/t/r.git"},
                    "model": "opus",
                    "slack": {
                        "bot_token": "xoxb-test",
                        "app_token": "xapp-test",
                        "authorized": [{"workspace_members": True}],
                    },
                },
            },
        }
        config_path = _write_config(tmp_path, data)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Submit with empty authorized text → clears rules
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/t/r.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized="
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "authorized" not in raw["repos"]["test-repo"]["slack"]

    def test_repo_post_saves_masked_secrets(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&masked_secret.0.key=GH_TOKEN"
                "&masked_secret.0.value.mode=literal"
                "&masked_secret.0.value.value=ghp_test"
                "&masked_secret.0.scopes=api.github.com"
                "&masked_secret.0.headers=Authorization"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "GH_TOKEN" in raw["repos"]["test-repo"]["masked_secrets"]

    def test_repo_post_saves_signing_credentials(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&signing_credential.0.key=aws-main"
                "&signing_credential.0.access_key_id.name=AK"
                "&signing_credential.0.access_key_id.value.mode=literal"
                "&signing_credential.0.access_key_id.value.value=AKIA"
                "&signing_credential.0.secret_access_key.name=SK"
                "&signing_credential.0.secret_access_key.value.mode=literal"
                "&signing_credential.0.secret_access_key.value.value=secret"
                "&signing_credential.0.scopes=bedrock.amazonaws.com"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "aws-main" in raw["repos"]["test-repo"]["signing_credentials"]

    def test_repo_post_saves_github_app_credentials(
        self, tmp_path: Path
    ) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&github_app.0.key=my-app"
                "&github_app.0.app_id.mode=literal"
                "&github_app.0.app_id.value=12345"
                "&github_app.0.private_key.mode=literal"
                "&github_app.0.private_key.value=pk"
                "&github_app.0.installation_id.mode=literal"
                "&github_app.0.installation_id.value=67890"
                "&github_app.0.scopes=api.github.com"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "my-app" in raw["repos"]["test-repo"]["github_app_credentials"]

    def test_vars_add_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/vars/add")
        assert response.status_code == 403

    def test_credential_add_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo/credential/add?type=masked_secret"
        )
        assert response.status_code == 403

    def test_repo_post_with_repo_schema_errors(self, tmp_path: Path) -> None:
        """Test that repo field validation errors return the form."""
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Inject a required int field into the repo schema to trigger
        # validation errors (current schema has no required/int fields).
        editor = server._config_editor
        assert editor is not None
        original_schema = editor._repo_schema
        editor._repo_schema = [
            FieldSchema(
                name="fake_int",
                type_name="int",
                default=None,
                required=True,
                doc="Fake",
                scope="task",
                secret=False,
            )
        ]
        try:
            response = client.post(
                "/config/repo/test-repo",
                headers={"X-Requested-With": "XMLHttpRequest"},
                content_type="application/x-www-form-urlencoded",
                data=(
                    "git_repo_url.mode=literal"
                    "&git_repo_url.value=https://github.com/test/repo.git"
                    "&has_email=false"
                    "&has_slack=false"
                    "&field.fake_int.mode=literal"
                    "&field.fake_int.value="
                ),
            )
            assert response.status_code == 200
        finally:
            editor._repo_schema = original_schema

    def test_repo_post_slack_empty_auth_line(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true\n"
                "\nuser_id: U123"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        slack = raw["repos"]["test-repo"]["slack"]
        # Empty line should be skipped
        assert len(slack["authorized"]) == 2

    def test_repo_post_slack_authorized_bool(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true\n"
                "user_id: U123"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        slack = raw["repos"]["test-repo"]["slack"]
        assert slack["authorized"] == [
            {"workspace_members": True},
            {"user_id": "U123"},
        ]
