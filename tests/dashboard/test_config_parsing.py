# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor parsing module."""

from airut.config.schema import FieldSchema
from airut.dashboard.config_editor.parsing import (
    coerce_value,
    detect_mode,
    detect_mode_value,
    parse_form_fields,
    parse_github_app_credentials,
    parse_key_value_table,
    parse_masked_secrets,
    parse_mode_value,
    parse_signing_credentials,
    parse_vars_from_form,
    remap_prefixed_fields,
)
from airut.yaml_env import EnvVar, VarRef


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


# ── Form parsing ───────────────────────────────────────────────────


class TestCoerceValue:
    def test_int(self) -> None:
        assert coerce_value("42", "int") == (42, None)

    def test_int_empty(self) -> None:
        assert coerce_value("", "int") == (None, None)

    def test_int_invalid(self) -> None:
        val, err = coerce_value("abc", "int")
        assert val is None
        assert err is not None

    def test_float(self) -> None:
        assert coerce_value("3.14", "float") == (3.14, None)

    def test_float_empty(self) -> None:
        assert coerce_value("", "float") == (None, None)

    def test_float_invalid(self) -> None:
        val, err = coerce_value("xyz", "float")
        assert val is None
        assert err is not None

    def test_bool_true(self) -> None:
        assert coerce_value("true", "bool") == (True, None)

    def test_bool_false(self) -> None:
        assert coerce_value("false", "bool") == (False, None)

    def test_bool_empty(self) -> None:
        assert coerce_value("", "bool") == (None, None)

    def test_list(self) -> None:
        val, err = coerce_value("a\nb\nc", "list[str]")
        assert val == ["a", "b", "c"]
        assert err is None

    def test_list_strips(self) -> None:
        val, _ = coerce_value("  a  \n\n  b  \n", "list[str]")
        assert val == ["a", "b"]

    def test_str(self) -> None:
        assert coerce_value("hello", "str") == ("hello", None)

    def test_int_in_dict_type_treated_as_str(self) -> None:
        val, err = coerce_value("hello", "dict[str, int]")
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

    def test_bool_empty_string(self) -> None:
        schema = self._make_schema(type_name="bool")
        form = {
            "field.test_field.mode": "literal",
            "field.test_field.value": "",
        }
        parsed, errors = parse_form_fields(form, schema)
        assert "test_field" not in parsed
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


# ── remap_prefixed_fields ──────────────────────────────────────────


class TestRemapPrefixedFields:
    def test_remaps_matching_keys(self) -> None:
        form = {
            "field.rl_timeout.mode": "literal",
            "field.rl_timeout.value": "300",
            "field.rl_memory.mode": "literal",
            "field.rl_memory.value": "1024",
        }
        result = remap_prefixed_fields(form, "rl_")
        assert result == {
            "field.timeout.mode": "literal",
            "field.timeout.value": "300",
            "field.memory.mode": "literal",
            "field.memory.value": "1024",
        }

    def test_ignores_non_matching_keys(self) -> None:
        form = {
            "field.model.mode": "literal",
            "field.model.value": "opus",
            "field.rl_timeout.mode": "literal",
            "field.rl_timeout.value": "300",
        }
        result = remap_prefixed_fields(form, "rl_")
        assert "field.model.mode" not in result
        assert result == {
            "field.timeout.mode": "literal",
            "field.timeout.value": "300",
        }

    def test_empty_form(self) -> None:
        assert remap_prefixed_fields({}, "rl_") == {}


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
        assert parse_mode_value(form, "p") == "hello"

    def test_var(self) -> None:
        form = {"p.mode": "var", "p.value": "my_var"}
        result = parse_mode_value(form, "p")
        assert isinstance(result, VarRef)

    def test_env(self) -> None:
        form = {"p.mode": "env", "p.value": "MY_ENV"}
        result = parse_mode_value(form, "p")
        assert isinstance(result, EnvVar)

    def test_env_empty_returns_literal(self) -> None:
        form = {"p.mode": "env", "p.value": ""}
        result = parse_mode_value(form, "p")
        assert result == ""


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
