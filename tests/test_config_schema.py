# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for declarative config schema metadata and introspection."""

import dataclasses
from dataclasses import dataclass, field

import pytest

from airut.config.schema import (
    _META_KEY,
    FieldMeta,
    Scope,
    get_field_meta,
    meta,
    schema_for_ui,
)


class TestScope:
    def test_values(self) -> None:
        assert Scope.SERVER.value == "server"
        assert Scope.REPO.value == "repo"
        assert Scope.TASK.value == "task"

    def test_all_scopes(self) -> None:
        assert len(Scope) == 3


class TestFieldMeta:
    def test_defaults(self) -> None:
        fm = FieldMeta(doc="test", scope=Scope.SERVER)
        assert fm.doc == "test"
        assert fm.scope == Scope.SERVER
        assert fm.secret is False
        assert fm.since_version == 1

    def test_custom_values(self) -> None:
        fm = FieldMeta(
            doc="a secret",
            scope=Scope.REPO,
            secret=True,
            since_version=3,
        )
        assert fm.secret is True
        assert fm.since_version == 3

    def test_frozen(self) -> None:
        fm = FieldMeta(doc="test", scope=Scope.TASK)
        with pytest.raises(dataclasses.FrozenInstanceError):
            fm.doc = "changed"  # type: ignore[misc]  # ty:ignore[invalid-assignment]


class TestMeta:
    def test_returns_dict_with_key(self) -> None:
        result = meta("description", Scope.SERVER)
        assert _META_KEY in result
        assert isinstance(result[_META_KEY], FieldMeta)

    def test_passes_kwargs(self) -> None:
        result = meta("secret field", Scope.REPO, secret=True, since_version=2)
        fm = result[_META_KEY]
        assert fm.secret is True
        assert fm.since_version == 2


class TestGetFieldMeta:
    def test_annotated_field(self) -> None:
        @dataclass
        class Config:
            host: str = field(
                default="localhost",
                metadata=meta("Server host", Scope.SERVER),
            )

        f = dataclasses.fields(Config)[0]
        fm = get_field_meta(f)
        assert fm is not None
        assert fm.doc == "Server host"
        assert fm.scope == Scope.SERVER

    def test_unannotated_field(self) -> None:
        @dataclass
        class Config:
            host: str = "localhost"

        f = dataclasses.fields(Config)[0]
        assert get_field_meta(f) is None


class TestSchemaForUI:
    def test_basic_extraction(self) -> None:
        @dataclass(frozen=True)
        class Config:
            host: str = field(
                default="localhost",
                metadata=meta("Server host", Scope.SERVER),
            )
            port: int = field(
                default=8080,
                metadata=meta("Server port", Scope.SERVER),
            )

        schema = schema_for_ui(Config)
        assert len(schema) == 2

        host_schema = schema[0]
        assert host_schema.name == "host"
        assert host_schema.type_name == "str"
        assert host_schema.default == "localhost"
        assert host_schema.required is False
        assert host_schema.doc == "Server host"
        assert host_schema.scope == "server"
        assert host_schema.secret is False

    def test_required_field(self) -> None:
        @dataclass(frozen=True)
        class Config:
            host: str = field(
                metadata=meta("Server host", Scope.SERVER),
            )

        schema = schema_for_ui(Config)
        assert len(schema) == 1
        assert schema[0].required is True
        assert schema[0].default is dataclasses.MISSING

    def test_secret_field(self) -> None:
        @dataclass(frozen=True)
        class Config:
            password: str = field(
                default="",
                metadata=meta("Password", Scope.REPO, secret=True),
            )

        schema = schema_for_ui(Config)
        assert schema[0].secret is True

    def test_excludes_unannotated_fields(self) -> None:
        @dataclass(frozen=True)
        class Config:
            host: str = field(
                default="localhost",
                metadata=meta("Server host", Scope.SERVER),
            )
            internal: str = "computed"

        schema = schema_for_ui(Config)
        assert len(schema) == 1
        assert schema[0].name == "host"

    def test_optional_type(self) -> None:
        @dataclass(frozen=True)
        class Config:
            url: str | None = field(
                default=None,
                metadata=meta("Optional URL", Scope.SERVER),
            )

        schema = schema_for_ui(Config)
        assert schema[0].type_name == "str | None"

    def test_factory_default(self) -> None:
        @dataclass(frozen=True)
        class Config:
            items: list[str] = field(
                default_factory=list,
                metadata=meta("Items", Scope.TASK),
            )

        schema = schema_for_ui(Config)
        assert schema[0].default == []
        assert schema[0].required is False

    def test_string_annotation_fallback(self) -> None:
        """Cover string annotation path in schema_for_ui."""
        from unittest.mock import patch

        @dataclass(frozen=True)
        class Config:
            host: str = field(
                default="localhost",
                metadata=meta("Host", Scope.SERVER),
            )

        # Simulate get_type_hints returning a string
        # (happens with forward refs that can't resolve)
        with patch(
            "airut.config.schema.typing.get_type_hints",
            return_value={"host": "str"},
        ):
            schema = schema_for_ui(Config)
        assert schema[0].type_name == "str"

    def test_multiple_scopes(self) -> None:
        @dataclass(frozen=True)
        class Config:
            a: int = field(default=1, metadata=meta("A", Scope.SERVER))
            b: int = field(default=2, metadata=meta("B", Scope.REPO))
            c: int = field(default=3, metadata=meta("C", Scope.TASK))

        schema = schema_for_ui(Config)
        scopes = [s.scope for s in schema]
        assert scopes == ["server", "repo", "task"]


class TestSchemaForUIWithRealConfigs:
    """Verify schema_for_ui works with the actual config classes."""

    def test_global_config(self) -> None:
        from airut.gateway.config import GlobalConfig

        schema = schema_for_ui(GlobalConfig)
        names = {s.name for s in schema}
        assert "max_concurrent_executions" in names
        assert "dashboard_enabled" in names
        assert "container_command" not in names  # hidden from UI

    def test_email_channel_config(self) -> None:
        from airut.gateway.config import (
            EmailAccountConfig,
            EmailAuthConfig,
            EmailChannelConfig,
            ImapConfig,
            SmtpConfig,
        )

        schema = schema_for_ui(EmailChannelConfig)
        names = {s.name for s in schema}
        # Top-level fields are the sub-dataclass names
        assert "account" in names
        assert "imap" in names
        assert "smtp" in names
        assert "auth" in names
        assert "microsoft_oauth2" in names

        # Verify sub-dataclass schemas work independently
        account_schema = schema_for_ui(EmailAccountConfig)
        account_names = {s.name for s in account_schema}
        assert "username" in account_names
        assert "from_address" in account_names
        assert "password" in account_names
        password = next(s for s in account_schema if s.name == "password")
        assert password.secret is True

        imap_schema = schema_for_ui(ImapConfig)
        imap_names = {s.name for s in imap_schema}
        assert "server" in imap_names
        assert "port" in imap_names

        smtp_schema = schema_for_ui(SmtpConfig)
        smtp_names = {s.name for s in smtp_schema}
        assert "server" in smtp_names
        assert "port" in smtp_names

        auth_schema = schema_for_ui(EmailAuthConfig)
        auth_names = {s.name for s in auth_schema}
        assert "authorized_senders" in auth_names
        assert "trusted_authserv_id" in auth_names

    def test_slack_channel_config(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        schema = schema_for_ui(SlackChannelConfig)
        names = {s.name for s in schema}
        assert "bot_token" in names
        assert "app_token" in names
        bot = next(s for s in schema if s.name == "bot_token")
        assert bot.secret is True

    def test_repo_server_config(self) -> None:
        from airut.gateway.config import RepoServerConfig

        schema = schema_for_ui(RepoServerConfig)
        names = {s.name for s in schema}
        assert "model" in names
        assert "effort" in names
        assert "resource_limits" in names
        # model should be TASK scope
        model = next(s for s in schema if s.name == "model")
        assert model.scope == "task"

    def test_resource_limits(self) -> None:
        from airut.sandbox.types import ResourceLimits

        schema = schema_for_ui(ResourceLimits)
        names = {s.name for s in schema}
        assert "timeout" in names
        assert "memory" in names
        assert "cpus" in names
        assert "pids_limit" in names
        # All should be TASK scope
        for s in schema:
            assert s.scope == "task"

    def test_masked_secret(self) -> None:
        from airut.gateway.config import MaskedSecret

        schema = schema_for_ui(MaskedSecret)
        names = {s.name for s in schema}
        assert names == {
            "value",
            "scopes",
            "headers",
            "allow_foreign_credentials",
        }
        # value is secret
        value_field = next(s for s in schema if s.name == "value")
        assert value_field.secret is True
        assert value_field.scope == "task"
        # allow_foreign_credentials has a default
        afc = next(s for s in schema if s.name == "allow_foreign_credentials")
        assert afc.required is False
        assert afc.default is False

    def test_signing_credential_field(self) -> None:
        from airut.gateway.config import SigningCredentialField

        schema = schema_for_ui(SigningCredentialField)
        names = {s.name for s in schema}
        assert names == {"name", "value"}
        value_field = next(s for s in schema if s.name == "value")
        assert value_field.secret is True
        name_field = next(s for s in schema if s.name == "name")
        assert name_field.secret is False

    def test_signing_credential(self) -> None:
        from airut.gateway.config import SigningCredential

        schema = schema_for_ui(SigningCredential)
        names = {s.name for s in schema}
        assert names == {
            "access_key_id",
            "secret_access_key",
            "session_token",
            "scopes",
        }
        # secret fields
        for name in ("access_key_id", "secret_access_key", "session_token"):
            f = next(s for s in schema if s.name == name)
            assert f.secret is True, f"{name} should be secret"
        # session_token is optional (has default None)
        st = next(s for s in schema if s.name == "session_token")
        assert st.required is False
        # scopes is required
        scopes = next(s for s in schema if s.name == "scopes")
        assert scopes.required is True

    def test_github_app_credential(self) -> None:
        from airut.gateway.config import GitHubAppCredential

        schema = schema_for_ui(GitHubAppCredential)
        names = {s.name for s in schema}
        assert names == {
            "app_id",
            "private_key",
            "installation_id",
            "scopes",
            "allow_foreign_credentials",
            "base_url",
            "permissions",
            "repositories",
        }
        # private_key is secret
        pk = next(s for s in schema if s.name == "private_key")
        assert pk.secret is True
        assert pk.scope == "task"
        # app_id is required, not secret
        app_id = next(s for s in schema if s.name == "app_id")
        assert app_id.required is True
        assert app_id.secret is False
        # base_url has a default
        base_url = next(s for s in schema if s.name == "base_url")
        assert base_url.default == "https://api.github.com"
        # All fields should be TASK scope
        for s in schema:
            assert s.scope == "task"
