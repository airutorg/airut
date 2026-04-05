# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for gateway configuration."""

from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.config import (
    CREDENTIAL_TYPE_GITHUB_APP,
    SIGNING_TYPE_AWS_SIGV4,
    ConfigError,
    EmailAccountConfig,
    EmailAuthConfig,
    EmailChannelConfig,
    GitHubAppCredential,
    GitHubAppEntry,
    GlobalConfig,
    ImapConfig,
    MaskedSecret,
    MicrosoftOAuth2Config,
    ReplacementEntry,
    RepoServerConfig,
    ResourceLimits,
    ServerConfig,
    SigningCredential,
    SigningCredentialEntry,
    SigningCredentialField,
    SmtpConfig,
    _build_task_env,
    _coerce_bool,
    _parse_resource_limits,
    _parse_slack_channel_config,
    _resolve,
    _resolve_github_app_credentials,
    _resolve_masked_secrets,
    _resolve_signing_credentials,
    _resolve_string_list,
    generate_github_app_surrogate,
    generate_session_token_surrogate,
    generate_surrogate,
    get_config_path,
    get_dotenv_path,
    get_storage_dir,
)
from airut.logging import SecretFilter
from airut.yaml_env import EnvVar, YamlValue, make_env_loader, raw_resolve


class TestRawResolve:
    """Tests for raw_resolve."""

    def test_literal_string(self) -> None:
        """Literal string values resolve to themselves."""
        assert raw_resolve("hello") == "hello"

    def test_none(self) -> None:
        """None resolves to None."""
        assert raw_resolve(None) is None

    def test_int(self) -> None:
        """Non-string values are stringified."""
        assert raw_resolve(42) == "42"

    def test_envvar_set(self) -> None:
        """EnvVar resolves to env value when set."""
        with patch.dict("os.environ", {"MY_VAR": "val"}):
            assert raw_resolve(EnvVar("MY_VAR")) == "val"

    def test_envvar_unset(self) -> None:
        """EnvVar resolves to None when env var is not set."""
        with patch.dict("os.environ", {}, clear=True):
            assert raw_resolve(EnvVar("MISSING")) is None

    def test_envvar_empty(self) -> None:
        """EnvVar set to empty string resolves to empty string."""
        with patch.dict("os.environ", {"EMPTY": ""}):
            assert raw_resolve(EnvVar("EMPTY")) == ""


class TestCoerceBool:
    """Tests for _coerce_bool."""

    def test_bool_passthrough(self) -> None:
        """Bool values pass through unchanged."""
        assert _coerce_bool(True) is True
        assert _coerce_bool(False) is False

    def test_truthy_strings(self) -> None:
        """Truthy string values are recognized."""
        for val in ("true", "True", "TRUE", "1", "yes", "on"):
            assert _coerce_bool(val) is True

    def test_falsy_strings(self) -> None:
        """Falsy string values are recognized."""
        for val in ("false", "False", "FALSE", "0", "no", "off"):
            assert _coerce_bool(val) is False

    def test_invalid_raises(self) -> None:
        """Invalid values raise ConfigError."""
        with pytest.raises(ConfigError, match="Cannot convert"):
            _coerce_bool("maybe")


class TestResolve:
    """Tests for the unified _resolve function."""

    def test_str_literal(self) -> None:
        """String literal resolves directly."""
        assert _resolve("hello", str) == "hello"

    def test_str_envvar(self) -> None:
        """String !env resolves from environment."""
        with patch.dict("os.environ", {"V": "val"}):
            assert _resolve(EnvVar("V"), str) == "val"

    def test_int_literal(self) -> None:
        """Int literal from YAML passes through."""
        assert _resolve(42, int) == 42

    def test_int_envvar(self) -> None:
        """Int !env resolves and coerces."""
        with patch.dict("os.environ", {"P": "993"}):
            assert _resolve(EnvVar("P"), int) == 993

    def test_bool_literal(self) -> None:
        """Bool literal from YAML passes through."""
        assert _resolve(True, bool) is True
        assert _resolve(False, bool) is False

    def test_bool_envvar(self) -> None:
        """Bool !env resolves string to bool."""
        with patch.dict("os.environ", {"B": "false"}):
            assert _resolve(EnvVar("B"), bool) is False
        with patch.dict("os.environ", {"B": "true"}):
            assert _resolve(EnvVar("B"), bool) is True

    def test_path_expanduser(self) -> None:
        """Path values get ~ expanded."""
        result = _resolve("~/data", Path)
        assert result == Path.home() / "data"

    def test_path_envvar(self) -> None:
        """Path !env resolves and expands."""
        with patch.dict("os.environ", {"D": "~/stuff"}):
            assert _resolve(EnvVar("D"), Path) == Path.home() / "stuff"

    def test_default_when_none(self) -> None:
        """Default returned when value is None."""
        assert _resolve(None, int, default=42) == 42

    def test_default_when_envvar_unset(self) -> None:
        """Default returned when !env var is unset."""
        with patch.dict("os.environ", {}, clear=True):
            assert _resolve(EnvVar("X"), str, default="fallback") == "fallback"

    def test_required_missing_literal(self) -> None:
        """Required raises ConfigError for missing literal."""
        with pytest.raises(ConfigError, match="'field' is missing"):
            _resolve(None, str, required="field")

    def test_required_missing_envvar(self) -> None:
        """Required raises ConfigError with env var name."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError, match="'MY_VAR' is not set"):
                _resolve(EnvVar("MY_VAR"), str, required="field")

    def test_optional_returns_none(self) -> None:
        """Optional (no default, no required) returns None."""
        assert _resolve(None, str) is None


# ---------------------------------------------------------------------------
# YAML loaders
# ---------------------------------------------------------------------------


class TestYamlLoader:
    """Tests for YAML !env tag loading."""

    def test_env_tag_parsed(self) -> None:
        """!env tags produce EnvVar objects."""
        import yaml

        loader = make_env_loader()
        result = yaml.load("key: !env MY_VAR", Loader=loader)
        assert isinstance(result["key"], EnvVar)
        assert result["key"].var_name == "MY_VAR"

    def test_plain_values_unchanged(self) -> None:
        """Plain values load normally."""
        import yaml

        loader = make_env_loader()
        result = yaml.load("key: hello", Loader=loader)
        assert result["key"] == "hello"


# ---------------------------------------------------------------------------
# _resolve_string_list
# ---------------------------------------------------------------------------


class TestResolveStringList:
    """Tests for _resolve_string_list."""

    def test_normal_list(self) -> None:
        """Normal list of strings is returned as-is."""
        result = _resolve_string_list(cast(YamlValue, ["a@b.com", "c@d.com"]))
        assert result == ["a@b.com", "c@d.com"]

    def test_none_without_required(self) -> None:
        """None returns empty list when not required."""
        result = _resolve_string_list(None)
        assert result == []

    def test_none_with_required_raises(self) -> None:
        """None raises ConfigError when required."""
        with pytest.raises(ConfigError, match="'test.field' is missing"):
            _resolve_string_list(None, required="test.field")

    def test_not_a_list_raises(self) -> None:
        """Non-list value raises ConfigError."""
        with pytest.raises(ConfigError, match="must be a list, got str"):
            _resolve_string_list("not-a-list", required="test.field")

    def test_empty_list_with_required_raises(self) -> None:
        """Empty list raises ConfigError when required."""
        with pytest.raises(ConfigError, match="'test.field' is empty"):
            _resolve_string_list([], required="test.field")

    def test_env_vars_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """!env vars in list are resolved."""
        monkeypatch.setenv("TEST_EMAIL", "env@test.com")
        result = _resolve_string_list(
            cast(YamlValue, [EnvVar("TEST_EMAIL"), "inline@test.com"])
        )
        assert result == ["env@test.com", "inline@test.com"]

    def test_empty_values_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty values (resolved or literal) are skipped."""
        monkeypatch.delenv("UNSET_VAR", raising=False)
        result = _resolve_string_list(
            cast(YamlValue, [EnvVar("UNSET_VAR"), "valid@test.com"])
        )
        assert result == ["valid@test.com"]


# ---------------------------------------------------------------------------
# GlobalConfig - direct construction
# ---------------------------------------------------------------------------


def test_global_config_defaults() -> None:
    """Test GlobalConfig with default values."""
    config = GlobalConfig()

    assert config.max_concurrent_executions == 3
    assert config.shutdown_timeout_seconds == 60
    assert config.conversation_max_age_days == 7
    assert config.image_prune is True
    assert config.dashboard_enabled is True
    assert config.dashboard_host == "127.0.0.1"
    assert config.dashboard_port == 5200
    assert config.dashboard_base_url is None
    assert config.container_command == "podman"
    assert config.upstream_dns is None


def test_global_config_with_custom_values() -> None:
    """Test GlobalConfig with custom values."""
    config = GlobalConfig(
        max_concurrent_executions=5,
        shutdown_timeout_seconds=120,
        conversation_max_age_days=30,
        image_prune=False,
        dashboard_enabled=False,
        dashboard_host="0.0.0.0",
        dashboard_port=8080,
        dashboard_base_url="https://dashboard.example.com",
        container_command="docker",
        upstream_dns="8.8.8.8",
    )

    assert config.max_concurrent_executions == 5
    assert config.shutdown_timeout_seconds == 120
    assert config.conversation_max_age_days == 30
    assert config.image_prune is False
    assert config.dashboard_enabled is False
    assert config.dashboard_host == "0.0.0.0"
    assert config.dashboard_port == 8080
    assert config.dashboard_base_url == "https://dashboard.example.com"
    assert config.container_command == "docker"
    assert config.upstream_dns == "8.8.8.8"


def test_global_config_invalid_max_concurrent() -> None:
    """Test GlobalConfig with invalid max concurrent executions."""
    with pytest.raises(
        ValueError, match="Max concurrent executions must be >= 1: 0"
    ):
        GlobalConfig(max_concurrent_executions=0)


def test_global_config_invalid_shutdown_timeout() -> None:
    """Test GlobalConfig with invalid shutdown timeout."""
    with pytest.raises(ValueError, match="Shutdown timeout must be >= 1s: 0"):
        GlobalConfig(shutdown_timeout_seconds=0)


def test_global_config_invalid_conversation_max_age() -> None:
    """Test GlobalConfig with invalid conversation max age."""
    with pytest.raises(
        ValueError, match="Conversation max age must be >= 1 day: 0"
    ):
        GlobalConfig(conversation_max_age_days=0)


# ---------------------------------------------------------------------------
# RepoServerConfig - direct construction
# ---------------------------------------------------------------------------


def _make_repo_server_config(
    master_repo: Path,
    tmp_path: Path,
    **overrides: Any,  # noqa: ANN401 - unpacked into mixed-type constructors
) -> RepoServerConfig:
    """Create a minimal RepoServerConfig for testing."""
    email_fields = {
        "imap_server",
        "imap_port",
        "smtp_server",
        "smtp_port",
        "account_username",
        "account_password",
        "account_from_address",
        "auth_authorized_senders",
        "auth_trusted_authserv_id",
        "imap_connect_retries",
        "imap_poll_interval_seconds",
        "imap_use_idle",
        "imap_idle_reconnect_interval_seconds",
        "smtp_require_auth",
        "auth_microsoft_internal_fallback",
        "microsoft_oauth2_tenant_id",
        "microsoft_oauth2_client_id",
        "microsoft_oauth2_client_secret",
    }
    email_defaults: dict[str, Any] = {
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "account_username": "test@example.com",
        "account_password": "secret123",
        "account_from_address": "Test <test@example.com>",
        "auth_authorized_senders": ["authorized@example.com"],
        "auth_trusted_authserv_id": "mx.example.com",
    }
    repo_defaults: dict[str, Any] = {
        "repo_id": "test",
        "git_repo_url": str(master_repo),
    }

    for key, value in overrides.items():
        if key in email_fields:
            email_defaults[key] = value
        else:
            repo_defaults[key] = value

    # Build sub-dataclass instances from flat email_defaults
    imap_kwargs: dict[str, Any] = {"server": email_defaults["imap_server"]}
    if "imap_port" in email_defaults:
        imap_kwargs["port"] = email_defaults["imap_port"]
    if "imap_connect_retries" in email_defaults:
        imap_kwargs["connect_retries"] = email_defaults["imap_connect_retries"]
    if "imap_poll_interval_seconds" in email_defaults:
        imap_kwargs["poll_interval"] = email_defaults[
            "imap_poll_interval_seconds"
        ]
    if "imap_use_idle" in email_defaults:
        imap_kwargs["use_idle"] = email_defaults["imap_use_idle"]
    if "imap_idle_reconnect_interval_seconds" in email_defaults:
        imap_kwargs["idle_reconnect_interval"] = email_defaults[
            "imap_idle_reconnect_interval_seconds"
        ]

    smtp_kwargs: dict[str, Any] = {"server": email_defaults["smtp_server"]}
    if "smtp_port" in email_defaults:
        smtp_kwargs["port"] = email_defaults["smtp_port"]
    if "smtp_require_auth" in email_defaults:
        smtp_kwargs["require_auth"] = email_defaults["smtp_require_auth"]

    account_kwargs: dict[str, Any] = {
        "username": email_defaults["account_username"],
        "from_address": email_defaults["account_from_address"],
    }
    if email_defaults.get("account_password") is not None:
        account_kwargs["password"] = email_defaults["account_password"]

    auth_kwargs: dict[str, Any] = {
        "authorized_senders": email_defaults["auth_authorized_senders"],
        "trusted_authserv_id": email_defaults["auth_trusted_authserv_id"],
    }
    if "auth_microsoft_internal_fallback" in email_defaults:
        auth_kwargs["microsoft_internal_fallback"] = email_defaults[
            "auth_microsoft_internal_fallback"
        ]

    microsoft_oauth2: MicrosoftOAuth2Config | None = None
    tenant_id = email_defaults.get("microsoft_oauth2_tenant_id")
    client_id = email_defaults.get("microsoft_oauth2_client_id")
    client_secret = email_defaults.get("microsoft_oauth2_client_secret")
    if tenant_id and client_id and client_secret:
        microsoft_oauth2 = MicrosoftOAuth2Config(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    elif tenant_id or client_id or client_secret:
        raise ValueError("microsoft_oauth2 requires all three fields")

    email_config = EmailChannelConfig(
        account=EmailAccountConfig(**account_kwargs),
        imap=ImapConfig(**imap_kwargs),
        smtp=SmtpConfig(**smtp_kwargs),
        auth=EmailAuthConfig(**auth_kwargs),
        microsoft_oauth2=microsoft_oauth2,
    )
    return RepoServerConfig(channels={"email": email_config}, **repo_defaults)


def test_repo_server_config_defaults(master_repo: Path, tmp_path: Path) -> None:
    """Test creating valid repo server configuration with defaults."""
    config = _make_repo_server_config(master_repo, tmp_path)

    assert config.repo_id == "test"
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.imap.server == "imap.example.com"
    assert email_ch.imap.port == 993
    assert email_ch.smtp.server == "smtp.example.com"
    assert email_ch.smtp.port == 587
    assert email_ch.account.username == "test@example.com"
    assert email_ch.account.password == "secret123"
    assert email_ch.auth.authorized_senders == ["authorized@example.com"]
    assert config.git_repo_url == str(master_repo)
    assert config.storage_dir == get_storage_dir("test")
    assert email_ch.imap.poll_interval == 60
    assert email_ch.imap.use_idle is True
    assert email_ch.imap.idle_reconnect_interval == 29 * 60
    assert config.secrets == {}


def test_repo_server_config_with_custom_defaults(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with custom default values."""
    config = _make_repo_server_config(
        master_repo,
        tmp_path,
        imap_poll_interval_seconds=30,
        imap_use_idle=False,
        imap_idle_reconnect_interval_seconds=1800,
    )

    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.imap.poll_interval == 30
    assert email_ch.imap.use_idle is False
    assert email_ch.imap.idle_reconnect_interval == 1800


def test_repo_server_config_secret_redaction(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test that password and secrets values are redacted."""
    password = "very_secret_password"
    api_key = "sk-test-key"

    # Clear any existing secrets
    SecretFilter._secrets.clear()

    _make_repo_server_config(
        master_repo,
        tmp_path,
        account_password=password,
        secrets={"ANTHROPIC_API_KEY": api_key},
    )

    # Verify password and secrets values were registered
    assert password in SecretFilter._secrets
    assert api_key in SecretFilter._secrets


def test_repo_server_config_masked_secret_redaction(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test that masked secret values are also redacted."""
    password = "test_password"
    masked_value = "ghp_masked_token_value"

    # Clear any existing secrets
    SecretFilter._secrets.clear()

    _make_repo_server_config(
        master_repo,
        tmp_path,
        account_password=password,
        masked_secrets={
            "GH_TOKEN": MaskedSecret(
                value=masked_value,
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        },
    )

    # Verify masked secret value was registered
    assert masked_value in SecretFilter._secrets


def test_email_channel_config_channel_type() -> None:
    """EmailChannelConfig.channel_type returns 'email'."""
    config = EmailChannelConfig(
        account=EmailAccountConfig(
            username="test@example.com",
            from_address="Test <test@example.com>",
            password="secret123",
        ),
        imap=ImapConfig(server="imap.example.com", port=993),
        smtp=SmtpConfig(server="smtp.example.com", port=587),
        auth=EmailAuthConfig(
            authorized_senders=["a@example.com"],
            trusted_authserv_id="mx.example.com",
        ),
    )
    assert config.channel_type == "email"


def test_email_channel_config_channel_detail() -> None:
    """EmailChannelConfig.channel_detail returns account.from_address."""
    config = EmailChannelConfig(
        account=EmailAccountConfig(
            username="test@example.com",
            from_address="Test <test@example.com>",
            password="secret123",
        ),
        imap=ImapConfig(server="imap.example.com", port=993),
        smtp=SmtpConfig(server="smtp.example.com", port=587),
        auth=EmailAuthConfig(
            authorized_senders=["a@example.com"],
            trusted_authserv_id="mx.example.com",
        ),
    )
    assert config.channel_detail == "Test <test@example.com>"


def test_repo_server_config_empty_channels() -> None:
    """RepoServerConfig rejects empty channels dict."""
    with pytest.raises(ValueError, match="at least one channel"):
        RepoServerConfig(
            repo_id="test",
            git_repo_url="https://example.com/r.git",
            channels={},
        )


def test_repo_server_config_unknown_channel_key() -> None:
    """RepoServerConfig rejects unrecognized channel keys."""
    mock_config = MagicMock(spec=EmailChannelConfig)
    mock_config.channel_info = "test"
    with pytest.raises(ValueError, match="unknown channel type"):
        RepoServerConfig(
            repo_id="test",
            git_repo_url="https://example.com/r.git",
            channels={"typo": mock_config},
        )


def test_repo_server_config_empty_repo_url(tmp_path: Path) -> None:
    """Test repo server configuration with empty repository URL."""
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    with pytest.raises(ValueError, match="repo_url cannot be empty"):
        RepoServerConfig(
            repo_id="test",
            git_repo_url="",
            channels={
                "email": EmailChannelConfig(
                    account=EmailAccountConfig(
                        username="test@example.com",
                        from_address="Test <test@example.com>",
                        password="secret123",
                    ),
                    imap=ImapConfig(server="imap.example.com", port=993),
                    smtp=SmtpConfig(server="smtp.example.com", port=587),
                    auth=EmailAuthConfig(
                        authorized_senders=["authorized@example.com"],
                        trusted_authserv_id="mx.example.com",
                    ),
                )
            },
        )


def test_repo_server_config_invalid_imap_port(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid IMAP port."""
    with pytest.raises(ValueError, match="Invalid IMAP port: 0"):
        _make_repo_server_config(master_repo, tmp_path, imap_port=0)
    with pytest.raises(ValueError, match="Invalid IMAP port: 70000"):
        _make_repo_server_config(master_repo, tmp_path, imap_port=70000)


def test_repo_server_config_invalid_smtp_port(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid SMTP port."""
    with pytest.raises(ValueError, match="Invalid SMTP port: 0"):
        _make_repo_server_config(master_repo, tmp_path, smtp_port=0)
    with pytest.raises(ValueError, match="Invalid SMTP port: 100000"):
        _make_repo_server_config(master_repo, tmp_path, smtp_port=100000)


def test_repo_server_config_invalid_imap_connect_retries(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid imap_connect_retries."""
    with pytest.raises(ValueError, match="connect_retries must be >= 1"):
        _make_repo_server_config(master_repo, tmp_path, imap_connect_retries=0)


def test_repo_server_config_invalid_poll_interval(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid poll interval."""
    with pytest.raises(ValueError, match="Poll interval must be >= 0.1s: 0"):
        _make_repo_server_config(
            master_repo, tmp_path, imap_poll_interval_seconds=0
        )


def test_repo_server_config_invalid_idle_reconnect_interval(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid IDLE reconnect interval."""
    with pytest.raises(
        ValueError, match="IDLE reconnect interval must be >= 60s"
    ):
        _make_repo_server_config(
            master_repo, tmp_path, imap_idle_reconnect_interval_seconds=30
        )


def test_repo_server_config_container_path_default(
    master_repo: Path, tmp_path: Path
) -> None:
    """container_path defaults to .airut/container."""
    config = _make_repo_server_config(master_repo, tmp_path)
    assert config.container_path == ".airut/container"


def test_repo_server_config_container_path_custom(
    master_repo: Path, tmp_path: Path
) -> None:
    """container_path accepts a custom relative path."""
    config = _make_repo_server_config(
        master_repo, tmp_path, container_path=".devcontainer"
    )
    assert config.container_path == ".devcontainer"


def test_repo_server_config_container_path_empty(
    master_repo: Path, tmp_path: Path
) -> None:
    """container_path rejects empty string."""
    with pytest.raises(ValueError, match="container_path cannot be empty"):
        _make_repo_server_config(master_repo, tmp_path, container_path="")


def test_repo_server_config_container_path_absolute(
    master_repo: Path, tmp_path: Path
) -> None:
    """container_path rejects absolute paths."""
    with pytest.raises(ValueError, match="must be a relative path"):
        _make_repo_server_config(
            master_repo, tmp_path, container_path="/etc/container"
        )


def test_repo_server_config_container_path_traversal(
    master_repo: Path, tmp_path: Path
) -> None:
    """container_path rejects paths with '..' traversal."""
    with pytest.raises(ValueError, match="must not contain"):
        _make_repo_server_config(
            master_repo, tmp_path, container_path="../escape/container"
        )


# ---------------------------------------------------------------------------
# Microsoft OAuth2 config
# ---------------------------------------------------------------------------


def test_repo_server_config_oauth2_defaults(
    master_repo: Path, tmp_path: Path
) -> None:
    """Microsoft OAuth2 defaults to None."""
    config = _make_repo_server_config(master_repo, tmp_path)
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.microsoft_oauth2 is None


def test_repo_server_config_oauth2_all_set(
    master_repo: Path, tmp_path: Path
) -> None:
    """All three OAuth2 fields set is valid."""
    config = _make_repo_server_config(
        master_repo,
        tmp_path,
        microsoft_oauth2_tenant_id="tenant-123",
        microsoft_oauth2_client_id="client-456",
        microsoft_oauth2_client_secret="secret-789",
    )
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.microsoft_oauth2 is not None
    assert email_ch.microsoft_oauth2.tenant_id == "tenant-123"
    assert email_ch.microsoft_oauth2.client_id == "client-456"
    assert email_ch.microsoft_oauth2.client_secret == "secret-789"


def test_repo_server_config_oauth2_partial_raises(
    master_repo: Path, tmp_path: Path
) -> None:
    """Partial OAuth2 config (only some fields set) raises ValueError."""
    with pytest.raises(ValueError, match="microsoft_oauth2 requires all three"):
        _make_repo_server_config(
            master_repo,
            tmp_path,
            microsoft_oauth2_tenant_id="tenant-123",
            # client_id and client_secret left as None
        )

    with pytest.raises(ValueError, match="microsoft_oauth2 requires all three"):
        _make_repo_server_config(
            master_repo,
            tmp_path,
            microsoft_oauth2_tenant_id="tenant-123",
            microsoft_oauth2_client_id="client-456",
            # client_secret left as None
        )


def test_repo_server_config_oauth2_secret_redaction(
    master_repo: Path, tmp_path: Path
) -> None:
    """OAuth2 client secret is registered for log redaction."""
    client_secret = "super-secret-oauth2-client-secret"
    SecretFilter._secrets.clear()

    _make_repo_server_config(
        master_repo,
        tmp_path,
        microsoft_oauth2_tenant_id="tenant-123",
        microsoft_oauth2_client_id="client-456",
        microsoft_oauth2_client_secret=client_secret,
    )

    assert client_secret in SecretFilter._secrets


# ---------------------------------------------------------------------------
# Microsoft internal auth fallback config
# ---------------------------------------------------------------------------


def test_repo_server_config_internal_auth_fallback_default(
    master_repo: Path, tmp_path: Path
) -> None:
    """microsoft_internal_fallback defaults to False."""
    config = _make_repo_server_config(master_repo, tmp_path)
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.auth.microsoft_internal_fallback is False


def test_repo_server_config_internal_auth_fallback_enabled(
    master_repo: Path, tmp_path: Path
) -> None:
    """microsoft_internal_fallback can be set to True."""
    config = _make_repo_server_config(
        master_repo,
        tmp_path,
        auth_microsoft_internal_fallback=True,
    )
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.auth.microsoft_internal_fallback is True


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# XDG path helpers
# ---------------------------------------------------------------------------


def test_get_config_path() -> None:
    """get_config_path returns XDG config directory."""
    path = get_config_path()
    assert path.name == "airut.yaml"
    assert path.parent.name == "airut"


def test_get_dotenv_path() -> None:
    """get_dotenv_path returns .env in XDG config directory."""
    path = get_dotenv_path()
    assert path.name == ".env"
    assert path.parent.name == "airut"


def test_get_storage_dir() -> None:
    """get_storage_dir returns directory keyed by repo_id."""
    path = get_storage_dir("my-repo")
    assert path.name == "my-repo"


def test_get_storage_dir_unique_per_repo() -> None:
    """Different repo_ids produce different storage dirs."""
    assert get_storage_dir("repo-a") != get_storage_dir("repo-b")


# ---------------------------------------------------------------------------
# ServerConfig.from_yaml
# ---------------------------------------------------------------------------

_MINIMAL_YAML = """\
repos:
  test:
    email:
      account:
        username: user@test.com
        password: plain_password
        from: "Test <test@example.com>"
      imap:
        server: imap.test.com
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - auth@test.com
        trusted_authserv_id: mx.test.com
    repo_url: {repo_url}
"""

_FULL_YAML = """\
execution:
  max_concurrent: 5
  shutdown_timeout: 90
  conversation_max_age_days: 30
  image_prune: false
dashboard:
  enabled: false
  host: 0.0.0.0
  port: 8080
  base_url: https://dashboard.example.com
container_command: docker
repos:
  test:
    email:
      account:
        username: user@test.com
        password: !env EMAIL_PASSWORD
        from: "Test <test@example.com>"
      imap:
        server: imap.test.com
        port: 143
        connect_retries: 5
        poll_interval: 45
        use_idle: false
        idle_reconnect_interval: 1800
      smtp:
        server: smtp.test.com
        port: 25
        require_auth: false
      auth:
        authorized_senders:
          - auth@test.com
        trusted_authserv_id: mx.test.com
    repo_url: {repo_url}
    secrets:
      GH_TOKEN: !env GH_TOKEN
      R2_ACCOUNT_ID: test-account
"""


class TestServerConfigValidation:
    """Tests for ServerConfig cross-repo validation."""

    def _repo(
        self,
        repo_id: str,
        tmp_path: Path,
        **overrides: Any,  # noqa: ANN401 - unpacked into mixed-type constructor
    ) -> RepoServerConfig:
        flat_defaults: dict[str, Any] = {
            "imap_server": "imap.example.com",
            "imap_port": 993,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "account_username": f"{repo_id}@example.com",
            "account_password": "secret",
            "account_from_address": f"<{repo_id}@example.com>",
            "auth_authorized_senders": ["auth@example.com"],
            "auth_trusted_authserv_id": "mx.example.com",
        }
        for k, v in overrides.items():
            if k in flat_defaults:
                flat_defaults[k] = v
        return RepoServerConfig(
            repo_id=repo_id,
            git_repo_url="https://example.com/repo.git",
            channels={
                "email": EmailChannelConfig(
                    account=EmailAccountConfig(
                        username=flat_defaults["account_username"],
                        from_address=flat_defaults["account_from_address"],
                        password=flat_defaults["account_password"],
                    ),
                    imap=ImapConfig(
                        server=flat_defaults["imap_server"],
                        port=flat_defaults["imap_port"],
                    ),
                    smtp=SmtpConfig(
                        server=flat_defaults["smtp_server"],
                        port=flat_defaults["smtp_port"],
                    ),
                    auth=EmailAuthConfig(
                        authorized_senders=flat_defaults[
                            "auth_authorized_senders"
                        ],
                        trusted_authserv_id=flat_defaults[
                            "auth_trusted_authserv_id"
                        ],
                    ),
                )
            },
        )

    def test_empty_repos_allowed(self, tmp_path: Path) -> None:
        """Empty repos is allowed (no config file / dashboard-only mode)."""
        config = ServerConfig(global_config=GlobalConfig(), repos={})
        assert len(config.repos) == 0

    def test_non_email_channel_skipped_in_inbox_check(
        self, tmp_path: Path
    ) -> None:
        """Non-EmailChannelConfig channels skip IMAP inbox validation.

        Even when keyed as "email", a channel that is not an
        EmailChannelConfig instance is skipped during inbox
        deduplication.  Validates the isinstance() guard in
        ServerConfig.__post_init__.
        """
        r1 = self._repo("a", tmp_path)
        # Build a RepoServerConfig then swap channels via
        # object.__setattr__ (frozen dataclass).
        r2 = self._repo("b", tmp_path, account_username="unique@example.com")
        mock_channel = MagicMock(spec=[])
        mock_channel.channel_type = "email"
        mock_channel.channel_info = "mock-imap"
        object.__setattr__(r2, "channels", {"email": mock_channel})
        # Should not raise — non-EmailChannelConfig is skipped
        ServerConfig(global_config=GlobalConfig(), repos={"a": r1, "b": r2})

    def test_duplicate_inbox_rejected(self, tmp_path: Path) -> None:
        """Two repos sharing the same IMAP inbox are rejected."""
        r1 = self._repo("a", tmp_path)
        r2 = self._repo("b", tmp_path, account_username="a@example.com")
        with pytest.raises(ConfigError, match="same IMAP inbox"):
            ServerConfig(global_config=GlobalConfig(), repos={"a": r1, "b": r2})


class TestFromYaml:
    """Tests for ServerConfig.from_yaml loading."""

    def test_minimal_config(self, master_repo: Path, tmp_path: Path) -> None:
        """Load minimal YAML with defaults."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]

        # Global config defaults
        assert config.global_config.max_concurrent_executions == 3
        assert config.global_config.shutdown_timeout_seconds == 60
        assert config.global_config.conversation_max_age_days == 7
        assert config.global_config.image_prune is True
        assert config.global_config.dashboard_enabled is True
        assert config.global_config.dashboard_host == "127.0.0.1"
        assert config.global_config.dashboard_port == 5200
        assert config.global_config.dashboard_base_url is None
        assert config.global_config.container_command == "podman"

        # Repo config
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.server == "imap.test.com"
        assert email_ch.imap.port == 993
        assert email_ch.smtp.port == 587
        assert email_ch.account.password == "plain_password"
        assert email_ch.imap.poll_interval == 60
        assert email_ch.imap.use_idle is True
        assert repo.secrets == {}

    def test_full_config(self, master_repo: Path, tmp_path: Path) -> None:
        """Load fully specified YAML."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_FULL_YAML.format(repo_url=master_repo))

        with patch.dict(
            "os.environ",
            {"EMAIL_PASSWORD": "env_pw", "GH_TOKEN": "ghp_tok"},
        ):
            config = ServerConfig.from_yaml(yaml_path).value

        repo = config.repos["test"]

        # Global config
        assert config.global_config.max_concurrent_executions == 5
        assert config.global_config.shutdown_timeout_seconds == 90
        assert config.global_config.conversation_max_age_days == 30
        assert config.global_config.image_prune is False
        assert config.global_config.dashboard_enabled is False
        assert config.global_config.dashboard_host == "0.0.0.0"
        assert config.global_config.dashboard_port == 8080
        assert (
            config.global_config.dashboard_base_url
            == "https://dashboard.example.com"
        )
        assert config.global_config.container_command == "docker"

        # Repo config
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.port == 143
        assert email_ch.smtp.port == 25
        assert email_ch.account.password == "env_pw"
        assert email_ch.smtp.require_auth is False
        assert email_ch.imap.connect_retries == 5
        assert email_ch.imap.poll_interval == 45
        assert email_ch.imap.use_idle is False
        assert email_ch.imap.idle_reconnect_interval == 1800
        assert repo.secrets == {
            "GH_TOKEN": "ghp_tok",
            "R2_ACCOUNT_ID": "test-account",
        }

    def test_global_resource_limits_migrated_to_vars(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Top-level resource_limits are migrated into vars."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "resource_limits:\n"
            + "  timeout: 3600\n"
            + "  memory: 8g\n"
            + "  cpus: 4\n"
            + "  pids_limit: 512\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        # After migration, resource limits resolve into repo config
        rl = config.repos["test"].resource_limits
        assert rl.timeout == 3600
        assert rl.memory == "8g"
        assert rl.cpus == 4
        assert rl.pids_limit == 512

    def test_network_sandbox_enabled_default(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """network_sandbox_enabled defaults to True when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].network_sandbox_enabled is True

    def test_network_sandbox_enabled_false(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """network.sandbox_enabled: false is parsed from server config."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    network:\n      sandbox_enabled: false\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].network_sandbox_enabled is False

    def test_model_default_opus(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Model defaults to 'opus' when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].model == "opus"

    def test_model_parsed(self, master_repo: Path, tmp_path: Path) -> None:
        """Model is parsed from server config."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo) + "    model: sonnet\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].model == "sonnet"

    def test_effort_default_none(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Effort defaults to None when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].effort is None

    def test_effort_parsed(self, master_repo: Path, tmp_path: Path) -> None:
        """Effort is parsed from server config."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo) + "    effort: medium\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].effort == "medium"

    def test_claude_version_parsed(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """claude_version is parsed from server config."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    claude_version: 1.2.3\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].claude_version == "1.2.3"

    def test_model_empty_string_falls_back_to_default(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Empty string model is treated as the default 'opus'."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo) + '    model: ""\n'
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        # Empty string is normalized to the default "opus"
        assert config.repos["test"].model == "opus"

    def test_effort_empty_string_normalized_to_none(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Empty string effort is normalized to None."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo) + '    effort: ""\n'
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].effort is None

    def test_container_path_default(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """container_path defaults to .airut/container when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].container_path == ".airut/container"

    def test_container_path_parsed(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """container_path is parsed from server config."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    container_path: .devcontainer\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].container_path == ".devcontainer"

    def test_schedule_parsed_from_yaml(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Schedules in YAML are parsed into ScheduleConfig."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    schedules:\n"
            + "      daily-review:\n"
            + "        cron: '0 9 * * 1-5'\n"
            + "        prompt: Review PRs\n"
            + "        deliver:\n"
            + "          channel: email\n"
            + "          to: user@example.com\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]
        assert "daily-review" in repo.schedules
        assert repo.schedules["daily-review"].prompt == "Review PRs"

    def test_schedule_defaults_channel_and_timezone(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Channel defaults to email, timezone defaults to None."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    schedules:\n"
            + "      nightly:\n"
            + "        cron: '0 2 * * *'\n"
            + "        prompt: Check status\n"
            + "        deliver:\n"
            + "          to: ops@example.com\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        sched = config.repos["test"].schedules["nightly"]
        assert sched.deliver.channel == "email"
        assert sched.timezone is None

    def test_schedule_non_dict_raises(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Non-dict schedule value raises ConfigError."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    schedules:\n"
            + "      bad-schedule: not-a-dict\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            ServerConfig.from_yaml(yaml_path)

    def test_missing_file(self, tmp_path: Path) -> None:
        """Raise ConfigError when file does not exist."""
        with pytest.raises(ConfigError, match="Config file not found"):
            ServerConfig.from_yaml(tmp_path / "nonexistent.yaml")

    def test_missing_required_field(self, tmp_path: Path) -> None:
        """Raise ConfigError when required field is missing."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            "repos:\n  test:\n    email:\n      imap:\n        server: test\n"
        )

        with pytest.raises(ConfigError, match=r"email\.account\.username"):
            ServerConfig.from_yaml(yaml_path)

    def test_missing_env_var(self, master_repo: Path, tmp_path: Path) -> None:
        """Raise ConfigError when !env var is not set on a required field."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            _MINIMAL_YAML.format(repo_url=master_repo).replace(
                "imap.test.com", "!env MISSING_VAR"
            )
        )

        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError, match="MISSING_VAR"):
                ServerConfig.from_yaml(yaml_path)

    def test_password_required_without_oauth2(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Password is required when OAuth2 is not configured."""
        yaml_content = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "        password: plain_password\n", ""
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with pytest.raises(
            ConfigError, match="email.account.password is required"
        ):
            ServerConfig.from_yaml(yaml_path)

    def test_secrets_skip_empty(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Secrets entries with unset !env vars are omitted."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo) + "    secrets:\n"
            "      PRESENT: value\n"
            "      MISSING: !env UNSET_VAR\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict("os.environ", {}, clear=True):
            config = ServerConfig.from_yaml(yaml_path).value

        assert config.repos["test"].secrets == {"PRESENT": "value"}

    def test_not_a_mapping(self, tmp_path: Path) -> None:
        """Raise ConfigError when YAML is not a mapping."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("- item1\n- item2\n")

        with pytest.raises(ConfigError, match="YAML mapping"):
            ServerConfig.from_yaml(yaml_path)

    def test_storage_dir_derived_from_repo_id(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """storage_dir is derived from repo_id via XDG state path."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]

        assert repo.storage_dir == get_storage_dir("test")

    def test_default_config_path(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """from_yaml with no path uses XDG config path."""
        xdg_dir = tmp_path / "xdg_config" / "airut"
        xdg_dir.mkdir(parents=True)
        yaml_path = xdg_dir / "airut.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        with patch(
            "airut.gateway.config.get_config_path",
            return_value=yaml_path,
        ):
            config = ServerConfig.from_yaml().value

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.server == "imap.test.com"

    def test_env_override_bool_field(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """!env works for bool fields like use_idle."""
        yaml_content = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "        server: imap.test.com\n",
            "        server: imap.test.com\n        use_idle: !env USE_IDLE\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict("os.environ", {"USE_IDLE": "false"}):
            config = ServerConfig.from_yaml(yaml_path).value

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.use_idle is False

    def test_env_override_int_field(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """!env works for int fields like poll_interval."""
        yaml_content = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "        server: imap.test.com\n",
            "        server: imap.test.com\n"
            "        poll_interval: !env POLL_INTERVAL\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict("os.environ", {"POLL_INTERVAL": "120"}):
            config = ServerConfig.from_yaml(yaml_path).value

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.poll_interval == 120

    def test_repos_not_a_mapping(self, tmp_path: Path) -> None:
        """Raise ConfigError when repos is not a mapping."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("repos:\n  - item1\n  - item2\n")
        with pytest.raises(ConfigError, match="'repos' must be a YAML mapping"):
            ServerConfig.from_yaml(yaml_path)

    def test_repo_entry_not_a_mapping(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Raise ConfigError when a repo entry is not a mapping."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("repos:\n  test: not-a-mapping\n")
        with pytest.raises(
            ConfigError, match="repos.test must be a YAML mapping"
        ):
            ServerConfig.from_yaml(yaml_path)

    def test_loads_dotenv(self, master_repo: Path, tmp_path: Path) -> None:
        """from_yaml calls load_dotenv_once before parsing."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        with patch("airut.config.source.load_dotenv_once") as mock_dotenv:
            ServerConfig.from_yaml(yaml_path)

        mock_dotenv.assert_called_once()

    def test_microsoft_oauth2_config(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Microsoft OAuth2 block is parsed from YAML."""
        # Insert microsoft_oauth2 block inside the email: section
        oauth2_block = (
            "      microsoft_oauth2:\n"
            "        tenant_id: my-tenant\n"
            "        client_id: my-client\n"
            "        client_secret: my-secret\n"
        )
        base = _MINIMAL_YAML.format(repo_url=master_repo)
        # Insert before the auth: block (at email: section level)
        yaml_content = base.replace(
            "      auth:\n",
            oauth2_block + "      auth:\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2 is not None
        assert email_ch.microsoft_oauth2.tenant_id == "my-tenant"
        assert email_ch.microsoft_oauth2.client_id == "my-client"
        assert email_ch.microsoft_oauth2.client_secret == "my-secret"

    def test_microsoft_oauth2_env_vars(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Microsoft OAuth2 fields support !env tags."""
        oauth2_block = (
            "      microsoft_oauth2:\n"
            "        tenant_id: !env AZURE_TENANT_ID\n"
            "        client_id: !env AZURE_CLIENT_ID\n"
            "        client_secret: !env AZURE_CLIENT_SECRET\n"
        )
        base = _MINIMAL_YAML.format(repo_url=master_repo)
        yaml_content = base.replace(
            "      auth:\n",
            oauth2_block + "      auth:\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict(
            "os.environ",
            {
                "AZURE_TENANT_ID": "env-tenant",
                "AZURE_CLIENT_ID": "env-client",
                "AZURE_CLIENT_SECRET": "env-secret",
            },
        ):
            config = ServerConfig.from_yaml(yaml_path).value

        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2 is not None
        assert email_ch.microsoft_oauth2.tenant_id == "env-tenant"
        assert email_ch.microsoft_oauth2.client_id == "env-client"
        assert email_ch.microsoft_oauth2.client_secret == "env-secret"

    def test_microsoft_oauth2_password_optional(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Password is not required when OAuth2 is configured."""
        oauth2_block = (
            "      microsoft_oauth2:\n"
            "        tenant_id: my-tenant\n"
            "        client_id: my-client\n"
            "        client_secret: my-secret\n"
        )
        # Remove password and add microsoft_oauth2 in the email section
        base = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "        password: plain_password\n", ""
        )
        yaml_content = base.replace(
            "      auth:\n",
            oauth2_block + "      auth:\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.account.password is None
        assert email_ch.microsoft_oauth2 is not None
        assert email_ch.microsoft_oauth2.tenant_id == "my-tenant"

    def test_microsoft_oauth2_absent_defaults_none(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Without microsoft_oauth2 block, fields default to None."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2 is None

    def test_internal_auth_fallback_from_yaml(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """microsoft_internal_fallback parsed from YAML."""
        base = _MINIMAL_YAML.format(repo_url=master_repo)
        yaml_content = base.replace(
            "        trusted_authserv_id: mx.test.com\n",
            "        trusted_authserv_id: mx.test.com\n"
            "        microsoft_internal_fallback: true\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.auth.microsoft_internal_fallback is True

    def test_internal_auth_fallback_default_false(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """microsoft_internal_auth_fallback defaults to False."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path).value
        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.auth.microsoft_internal_fallback is False

    def test_legacy_field_at_repo_level_rejected(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Legacy email fields at repo level produce a clear error."""
        yaml_content = (
            "repos:\n"
            "  test:\n"
            "    authorized_senders:\n"
            "      - user@example.com\n"
            "    email:\n"
            "      imap_server: imap.test.com\n"
            "      smtp_server: smtp.test.com\n"
            "      username: test@test.com\n"
            "      password: secret\n"
            '      from: "Test <test@test.com>"\n'
            "      trusted_authserv_id: mx.test.com\n"
            f"    repo_url: {master_repo}\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="must be nested under 'email:'"):
            ServerConfig.from_yaml(yaml_path)

    def test_missing_email_block_rejected(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Repo with no email block is rejected."""
        yaml_content = f"repos:\n  test:\n    repo_url: {master_repo}\n"
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="no channel configured"):
            ServerConfig.from_yaml(yaml_path)

    def test_legacy_field_detected_via_from_raw(self) -> None:
        """Legacy email fields caught by _from_raw (defense-in-depth)."""
        raw = {
            "config_version": 2,
            "repos": {
                "test": {
                    "authorized_senders": ["user@test.com"],
                    "email": {},
                    "repo_url": "/tmp/repo",
                },
            },
        }
        with pytest.raises(ConfigError, match="must be nested under 'email:'"):
            ServerConfig._from_raw(raw)


# ---------------------------------------------------------------------------
# ResourceLimits
# ---------------------------------------------------------------------------


class TestResourceLimits:
    """Tests for ResourceLimits dataclass."""

    def test_defaults_all_none(self) -> None:
        """Default ResourceLimits has all fields None."""
        rl = ResourceLimits()
        assert rl.timeout is None
        assert rl.memory is None
        assert rl.cpus is None
        assert rl.pids_limit is None

    def test_custom_values(self) -> None:
        """Custom values are preserved."""
        rl = ResourceLimits(timeout=600, memory="2g", cpus=4, pids_limit=256)
        assert rl.timeout == 600
        assert rl.memory == "2g"
        assert rl.cpus == 4
        assert rl.pids_limit == 256

    def test_invalid_timeout(self) -> None:
        """Timeout < 10 raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be >= 10s: 5"):
            ResourceLimits(timeout=5)

    def test_float_cpus(self) -> None:
        """Fractional CPU values are accepted."""
        rl = ResourceLimits(cpus=1.5)
        assert rl.cpus == 1.5

    def test_invalid_cpus(self) -> None:
        """CPUs < 0.01 raises ValueError."""
        with pytest.raises(ValueError, match="CPUs must be >= 0.01: 0"):
            ResourceLimits(cpus=0)

    def test_invalid_pids_limit(self) -> None:
        """PIDs limit < 1 raises ValueError."""
        with pytest.raises(ValueError, match="PIDs limit must be >= 1: 0"):
            ResourceLimits(pids_limit=0)

    def test_invalid_memory_format(self) -> None:
        """Invalid memory format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid memory limit"):
            ResourceLimits(memory="2x")

    def test_zero_memory(self) -> None:
        """Zero memory value raises ValueError."""
        with pytest.raises(ValueError, match="must be greater than zero"):
            ResourceLimits(memory="0m")

    def test_valid_memory_formats(self) -> None:
        """Various valid memory format strings."""
        for mem in ("512m", "2g", "1024k", "100b", "4G", "256M"):
            rl = ResourceLimits(memory=mem)
            assert rl.memory == mem


class TestParseResourceLimits:
    """Tests for _parse_resource_limits."""

    def test_none_input(self) -> None:
        """None returns None."""
        assert _parse_resource_limits(None) is None

    def test_empty_dict(self) -> None:
        """Empty dict returns None."""
        assert _parse_resource_limits({}) is None

    def test_full_block(self) -> None:
        """Full resource_limits block."""
        rl = _parse_resource_limits(
            {"timeout": 600, "memory": "2g", "cpus": 2, "pids_limit": 256}
        )
        assert rl is not None
        assert rl.timeout == 600
        assert rl.memory == "2g"
        assert rl.cpus == 2
        assert rl.pids_limit == 256

    def test_float_cpus(self) -> None:
        """Fractional cpus value is parsed correctly."""
        rl = _parse_resource_limits({"cpus": 1.5})
        assert rl is not None
        assert rl.cpus == 1.5

    def test_partial_block(self) -> None:
        """Partial block fills missing fields with None."""
        rl = _parse_resource_limits({"memory": "4g"})
        assert rl is not None
        assert rl.timeout is None
        assert rl.memory == "4g"
        assert rl.cpus is None
        assert rl.pids_limit is None


class TestRepoServerConfig:
    """Tests for RepoServerConfig new fields and defaults."""

    def test_model_defaults_to_opus(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Model defaults to 'opus'."""
        config = _make_repo_server_config(master_repo, tmp_path)
        assert config.model == "opus"

    def test_effort_defaults_to_none(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Effort defaults to None."""
        config = _make_repo_server_config(master_repo, tmp_path)
        assert config.effort is None

    def test_resource_limits_defaults(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Resource limits default to ResourceLimits()."""
        config = _make_repo_server_config(master_repo, tmp_path)
        assert config.resource_limits == ResourceLimits()

    def test_claude_version_defaults_to_latest(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """claude_version defaults to 'latest'."""
        config = _make_repo_server_config(master_repo, tmp_path)
        assert config.claude_version == "latest"

    def test_claude_version_valid(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Valid claude_version is accepted."""
        config = _make_repo_server_config(
            master_repo, tmp_path, claude_version="1.0.0"
        )
        assert config.claude_version == "1.0.0"

    def test_claude_version_invalid_raises(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Invalid claude_version raises ValueError."""
        with pytest.raises(ValueError, match="Invalid claude_version"):
            _make_repo_server_config(
                master_repo, tmp_path, claude_version="bad"
            )

    def test_custom_model(self, master_repo: Path, tmp_path: Path) -> None:
        """Custom model is preserved."""
        config = _make_repo_server_config(master_repo, tmp_path, model="sonnet")
        assert config.model == "sonnet"

    def test_custom_effort(self, master_repo: Path, tmp_path: Path) -> None:
        """Custom effort is preserved."""
        config = _make_repo_server_config(master_repo, tmp_path, effort="max")
        assert config.effort == "max"

    def test_custom_resource_limits(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Custom resource limits are preserved."""
        limits = ResourceLimits(timeout=600, memory="4g")
        config = _make_repo_server_config(
            master_repo, tmp_path, resource_limits=limits
        )
        assert config.resource_limits.timeout == 600
        assert config.resource_limits.memory == "4g"

    def test_no_container_env_field(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """container_env field no longer exists on RepoServerConfig."""
        config = _make_repo_server_config(master_repo, tmp_path)
        assert not hasattr(config, "container_env")


# ---------------------------------------------------------------------------
# _build_task_env
# ---------------------------------------------------------------------------


class TestBuildTaskEnv:
    """Tests for _build_task_env function."""

    def test_plain_secrets_inject_by_key(self) -> None:
        """Plain secrets are injected using their key as env var name."""
        secrets = {"API_KEY": "sk-test-123", "OTHER": "value"}
        result, replacement_map = _build_task_env(secrets, {}, {}, {})
        assert result == {"API_KEY": "sk-test-123", "OTHER": "value"}
        assert replacement_map == {}

    def test_masked_secrets_generate_surrogates_by_key(self) -> None:
        """Masked secrets generate surrogates using key as env var name."""
        masked = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _build_task_env({}, masked, {}, {})

        assert "GH_TOKEN" in result
        surrogate = result["GH_TOKEN"]
        assert surrogate.startswith("ghp_")
        assert surrogate != "ghp_realtoken"
        assert surrogate in replacement_map
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.real_value == "ghp_realtoken"

    def test_signing_credentials_generate_surrogates_by_field_name(
        self,
    ) -> None:
        """Signing credentials inject by field .name, not by credential key."""
        signing_creds = {
            "AWS_PROD": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="AWS_ACCESS_KEY_ID", value="AKIAIOSFODNN7EXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="AWS_SECRET_ACCESS_KEY", value="secretkey"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            )
        }
        result, replacement_map = _build_task_env({}, {}, signing_creds, {})

        # Env var names come from field .name, not credential key
        assert "AWS_ACCESS_KEY_ID" in result
        assert "AWS_SECRET_ACCESS_KEY" in result
        assert "AWS_PROD" not in result

        surrogate_key = result["AWS_ACCESS_KEY_ID"]
        assert surrogate_key.startswith("AKIA")
        assert surrogate_key in replacement_map

    def test_github_app_credentials_generate_surrogates_by_key(self) -> None:
        """GitHub App credentials inject by credential key."""
        gh_creds = {
            "GH_TOKEN": GitHubAppCredential(
                app_id="Iv23li",
                private_key="key",
                installation_id=12345,
                scopes=frozenset(["api.github.com"]),
            )
        }
        result, replacement_map = _build_task_env({}, {}, {}, gh_creds)

        assert "GH_TOKEN" in result
        surrogate = result["GH_TOKEN"]
        assert surrogate.startswith("ghs_")
        assert surrogate in replacement_map
        assert isinstance(replacement_map[surrogate], GitHubAppEntry)

    def test_priority_ordering(self) -> None:
        """Higher-priority pools win over lower-priority for same key."""
        # All pools have a "TOKEN" key — signing > github_app > masked > plain
        signing_creds = {
            "AWS": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="TOKEN", value="AKIAIOSFODNN7EXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="AWS_SECRET", value="secret"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            )
        }
        gh_creds = {
            "TOKEN": GitHubAppCredential(
                app_id="app",
                private_key="key",
                installation_id=123,
                scopes=frozenset(["api.github.com"]),
            )
        }
        masked = {
            "TOKEN": MaskedSecret(
                value="masked_val",
                scopes=frozenset(["api.example.com"]),
                headers=("Authorization",),
            )
        }
        plain = {"TOKEN": "plain_val"}

        result, replacement_map = _build_task_env(
            plain, masked, signing_creds, gh_creds
        )

        # Signing credential wins — TOKEN comes from signing field .name
        surrogate = result["TOKEN"]
        assert surrogate.startswith("AKIA")

    def test_empty_values_skipped_in_plain_secrets(self) -> None:
        """Plain secrets with empty string values are skipped."""
        secrets = {"EMPTY": "", "PRESENT": "val"}
        result, _ = _build_task_env(secrets, {}, {}, {})
        assert "EMPTY" not in result
        assert result["PRESENT"] == "val"

    def test_empty_string_masked_secret_preserved(self) -> None:
        """Masked secret with empty string value is preserved."""
        masked = {
            "TOKEN": MaskedSecret(
                value="",
                scopes=frozenset(["api.example.com"]),
                headers=("*",),
            )
        }
        result, replacement_map = _build_task_env({}, masked, {}, {})
        # Empty string is a valid configured value
        assert result["TOKEN"] == ""
        assert replacement_map == {}

    def test_signing_credential_duplicate_field_name_skipped(self) -> None:
        """Second signing credential with same field name is skipped."""
        signing_creds = {
            "AWS_PROD": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="AWS_ACCESS_KEY_ID", value="AKIAIOSFODNN7EXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="AWS_SECRET_ACCESS_KEY", value="secret1"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            ),
            "AWS_STAGING": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="AWS_ACCESS_KEY_ID", value="AKIASECONDKEYEXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="AWS_SECRET_ACCESS_KEY", value="secret2"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            ),
        }
        result, _ = _build_task_env({}, {}, signing_creds, {})

        # First credential's values win; second is skipped
        assert "AWS_ACCESS_KEY_ID" in result
        assert "AWS_SECRET_ACCESS_KEY" in result

    def test_signing_credential_field_name_collision_within_cred(self) -> None:
        """Field name collision within a credential skips the duplicate."""
        # Two credentials where the second's secret_access_key.name collides
        # with the first's access_key_id.name (cross-credential field collision)
        signing_creds = {
            "CRED_A": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="AWS_KEY", value="AKIAIOSFODNN7EXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="SHARED_NAME", value="secret_a"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            ),
            "CRED_B": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="OTHER_KEY", value="AKIAOTHERKEYSEXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="SHARED_NAME", value="secret_b"
                ),
                session_token=None,
                scopes=frozenset(["*.amazonaws.com"]),
            ),
        }
        result, _ = _build_task_env({}, {}, signing_creds, {})

        # Both credentials' access_key_ids are present
        assert "AWS_KEY" in result
        assert "OTHER_KEY" in result
        # SHARED_NAME comes from the first credential only
        assert "SHARED_NAME" in result

    def test_all_empty_returns_empty(self) -> None:
        """All-empty inputs return empty results."""
        result, replacement_map = _build_task_env({}, {}, {}, {})
        assert result == {}
        assert replacement_map == {}


class TestRepoServerConfigBuildTaskEnv:
    """Tests for RepoServerConfig.build_task_env method."""

    def test_integration_full_config(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """build_task_env integrates all credential pools."""
        config = _make_repo_server_config(
            master_repo,
            tmp_path,
            secrets={"API_KEY": "sk-test-123"},
            masked_secrets={
                "GH_TOKEN": MaskedSecret(
                    value="ghp_realtoken",
                    scopes=frozenset(["api.github.com"]),
                    headers=("Authorization",),
                )
            },
        )

        env, replacement_map = config.build_task_env()

        # Plain secret injected
        assert env["API_KEY"] == "sk-test-123"
        # Masked secret has surrogate
        assert env["GH_TOKEN"] != "ghp_realtoken"
        assert env["GH_TOKEN"].startswith("ghp_")
        assert env["GH_TOKEN"] in replacement_map

    def test_build_task_env_unique_surrogates(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Each call to build_task_env generates fresh surrogates."""
        config = _make_repo_server_config(
            master_repo,
            tmp_path,
            masked_secrets={
                "TOKEN": MaskedSecret(
                    value="ghp_realtoken",
                    scopes=frozenset(["api.github.com"]),
                    headers=("Authorization",),
                )
            },
        )

        env1, _ = config.build_task_env()
        env2, _ = config.build_task_env()

        # Different calls should produce different surrogates
        assert env1["TOKEN"] != env2["TOKEN"]


# ---------------------------------------------------------------------------
# RepoServerConfig parsing from YAML (resource_limits, model)
# ---------------------------------------------------------------------------


class TestRepoServerConfigFromYaml:
    """Tests for resource_limits and model in YAML parsing."""

    def test_resource_limits_parsed_from_repo(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """resource_limits block is parsed from repo section."""
        yaml_content = (
            _MINIMAL_YAML.format(repo_url=master_repo)
            + "    resource_limits:\n"
            + "      timeout: 600\n"
            + "      memory: 2g\n"
            + "      cpus: 2\n"
            + "      pids_limit: 128\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        config = ServerConfig.from_yaml(yaml_path).value
        rl = config.repos["test"].resource_limits
        assert rl.timeout == 600
        assert rl.memory == "2g"
        assert rl.cpus == 2
        assert rl.pids_limit == 128

    def test_resource_limits_defaults_when_absent(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """resource_limits defaults to ResourceLimits() when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].resource_limits == ResourceLimits()

    def test_model_defaults_to_opus(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Model defaults to 'opus' when not specified in YAML."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert config.repos["test"].model == "opus"


class TestFromYamlVars:
    """Tests for !var resolution through ServerConfig.from_yaml."""

    def test_var_resolves_in_repo(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """!var references in repo config resolve from vars: section."""
        yaml_content = f"""\
vars:
  mail: imap.test.com
  smtp: smtp.test.com
repos:
  test:
    email:
      account:
        username: user
        password: plain_password
        from: "T <t@e.com>"
      imap:
        server: !var mail
      smtp:
        server: !var smtp
      auth:
        authorized_senders:
          - a@b.com
        trusted_authserv_id: mx
    repo_url: {master_repo}
"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        snapshot = ServerConfig.from_yaml(yaml_path)
        config = snapshot.value
        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap.server == "imap.test.com"
        assert email_ch.smtp.server == "smtp.test.com"

    def test_snapshot_has_raw(self, master_repo: Path, tmp_path: Path) -> None:
        """from_yaml returns snapshot with raw document preserved."""
        yaml_content = f"""\
vars:
  mail: imap.test.com
repos:
  test:
    email:
      account:
        username: user
        password: pw
        from: "T <t@e.com>"
      imap:
        server: !var mail
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - a@b.com
        trusted_authserv_id: mx
    repo_url: {master_repo}
"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        snapshot = ServerConfig.from_yaml(yaml_path)

        assert snapshot.raw is not None
        assert "vars" in snapshot.raw
        assert snapshot.raw["vars"]["mail"] == "imap.test.com"

    def test_undefined_var_raises(self, tmp_path: Path) -> None:
        """Referencing an undefined var raises ConfigError."""
        yaml_content = """\
repos:
  test:
    email:
      account:
        username: user
        password: pw
        from: "T <t@e.com>"
      imap:
        server: !var undefined_server
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - a@b.com
        trusted_authserv_id: mx
    repo_url: https://example.com/repo.git
"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="undefined variable"):
            ServerConfig.from_yaml(yaml_path)

    def test_no_vars_section_works(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Config without vars: works (backwards compatible)."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path).value
        assert "test" in config.repos


# ---------------------------------------------------------------------------
# generate_surrogate
# ---------------------------------------------------------------------------


class TestGenerateSurrogate:
    """Tests for generate_surrogate."""

    def test_preserves_length(self) -> None:
        """Surrogate has same length as original."""
        original = "abc123XYZ"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)

    def test_preserves_ghp_prefix(self) -> None:
        """GitHub personal access token prefix is preserved."""
        original = "ghp_aBcD1234567890eFgHiJkL"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("ghp_")
        assert len(surrogate) == len(original)

    def test_preserves_sk_ant_prefix(self) -> None:
        """Anthropic API key prefix is preserved."""
        original = "sk-ant-api03-abcdef1234567890"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("sk-ant-")
        assert len(surrogate) == len(original)

    def test_preserves_charset_alphanumeric(self) -> None:
        """Alphanumeric charset is detected and used."""
        original = "aAbBcC123"
        for _ in range(10):  # Multiple runs to check randomness
            surrogate = generate_surrogate(original)
            # Should only contain alphanumerics (since original has no special)
            assert surrogate.isalnum()
            assert len(surrogate) == len(original)

    def test_includes_special_chars_when_present(self) -> None:
        """Special chars in original allow special chars in surrogate."""
        original = "abc-def_ghi"
        surrogates = {generate_surrogate(original) for _ in range(50)}
        # With many samples, should see special chars
        has_special = any("-" in s or "_" in s for s in surrogates)
        assert has_special

    def test_different_each_time(self) -> None:
        """Surrogates are random (different each time)."""
        original = "ghp_abcdefghijklmnopqrstuvwxyz1234"
        surrogates = {generate_surrogate(original) for _ in range(10)}
        # Should be at least 5 unique values (allowing some collisions)
        assert len(surrogates) >= 5

    def test_empty_suffix_uses_fallback_charset(self) -> None:
        """Empty suffix after prefix uses fallback charset."""
        # A prefix with nothing after it - suffix_len is 0
        original = "ghp_"
        surrogate = generate_surrogate(original)
        # Should still be exactly the prefix (length 4, empty suffix)
        assert surrogate == "ghp_"
        assert len(surrogate) == len(original)


# ---------------------------------------------------------------------------
# _resolve_masked_secrets
# ---------------------------------------------------------------------------


class TestResolveMaskedSecrets:
    """Tests for _resolve_masked_secrets."""

    def test_empty_mapping(self) -> None:
        """Empty mapping returns empty dict."""
        result = _resolve_masked_secrets({}, "repos.test")
        assert result == {}

    def test_basic_masked_secret(self) -> None:
        """Parses basic masked secret with value, scopes, and headers."""
        raw = {
            "GH_TOKEN": {
                "value": "ghp_real_token",
                "scopes": ["api.github.com", "*.githubusercontent.com"],
                "headers": ["Authorization"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert "GH_TOKEN" in result
        assert result["GH_TOKEN"].value == "ghp_real_token"
        assert result["GH_TOKEN"].scopes == frozenset(
            ["api.github.com", "*.githubusercontent.com"]
        )
        assert result["GH_TOKEN"].headers == ("Authorization",)

    def test_none_value_skipped(self) -> None:
        """None/null value is silently skipped."""
        raw = {
            "GH_TOKEN": {
                "value": None,
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result == {}

    def test_empty_string_value_preserved(self) -> None:
        """Empty string value is preserved (intentionally empty)."""
        raw = {
            "GH_TOKEN": {
                "value": "",
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert "GH_TOKEN" in result
        assert result["GH_TOKEN"].value == ""

    def test_not_a_mapping_raises(self) -> None:
        """Non-mapping value raises ConfigError."""
        raw = {"GH_TOKEN": "just a string"}
        with pytest.raises(ConfigError, match="must be a mapping"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_missing_scopes_raises(self) -> None:
        """Missing scopes raises ConfigError."""
        raw = {"GH_TOKEN": {"value": "secret", "headers": ["Authorization"]}}
        with pytest.raises(ConfigError, match="scopes is required"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_empty_scopes_raises(self) -> None:
        """Empty scopes list raises ConfigError."""
        raw = {
            "GH_TOKEN": {
                "value": "secret",
                "scopes": [],
                "headers": ["Authorization"],
            }
        }
        with pytest.raises(ConfigError, match="scopes cannot be empty"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_scopes_not_list_raises(self) -> None:
        """Non-list scopes raises ConfigError."""
        raw = {
            "GH_TOKEN": {
                "value": "secret",
                "scopes": "api.github.com",
                "headers": ["Authorization"],
            }
        }
        with pytest.raises(ConfigError, match="scopes must be a list"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_custom_headers(self) -> None:
        """Parses optional custom headers."""
        raw = {
            "API_KEY": {
                "value": "secret",
                "scopes": ["api.example.com"],
                "headers": ["X-Custom-Header", "X-Api-Key"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result["API_KEY"].headers == ("X-Custom-Header", "X-Api-Key")

    def test_headers_not_list_raises(self) -> None:
        """Non-list headers raises ConfigError."""
        raw = {
            "API_KEY": {
                "value": "secret",
                "scopes": ["api.example.com"],
                "headers": "X-Api-Key",  # Should be a list
            }
        }
        with pytest.raises(ConfigError, match="headers must be a list"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_empty_headers_raises(self) -> None:
        """Empty headers list raises ConfigError."""
        raw = {
            "API_KEY": {
                "value": "secret",
                "scopes": ["api.example.com"],
                "headers": [],
            }
        }
        with pytest.raises(ConfigError, match="headers cannot be empty"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_missing_headers_raises(self) -> None:
        """Missing headers raises ConfigError."""
        raw = {
            "API_KEY": {
                "value": "secret",
                "scopes": ["api.example.com"],
            }
        }
        with pytest.raises(ConfigError, match="headers is required"):
            _resolve_masked_secrets(raw, "repos.test")

    def test_wildcard_headers(self) -> None:
        """Headers can use fnmatch wildcards like '*'."""
        raw = {
            "API_KEY": {
                "value": "secret",
                "scopes": ["api.example.com"],
                "headers": ["*"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result["API_KEY"].headers == ("*",)

    def test_allow_foreign_credentials_default_false(self) -> None:
        """allow_foreign_credentials defaults to False."""
        raw = {
            "GH_TOKEN": {
                "value": "ghp_real",
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result["GH_TOKEN"].allow_foreign_credentials is False

    def test_allow_foreign_credentials_true(self) -> None:
        """allow_foreign_credentials can be set to True."""
        raw = {
            "GH_TOKEN": {
                "value": "ghp_real",
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
                "allow_foreign_credentials": True,
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result["GH_TOKEN"].allow_foreign_credentials is True

    def test_allow_foreign_credentials_explicit_false(self) -> None:
        """allow_foreign_credentials can be explicitly set to False."""
        raw = {
            "GH_TOKEN": {
                "value": "ghp_real",
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
                "allow_foreign_credentials": False,
            }
        }
        result = _resolve_masked_secrets(raw, "repos.test")
        assert result["GH_TOKEN"].allow_foreign_credentials is False


# ---------------------------------------------------------------------------
# Masked secrets in task env resolution
# ---------------------------------------------------------------------------


class TestMaskedSecretResolution:
    """Tests for masked secrets in _build_task_env."""

    def test_masked_secret_generates_surrogate(self) -> None:
        """Masked secret generates surrogate in task env."""
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken1234",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _build_task_env({}, masked_secrets, {}, {})

        # task env should have a surrogate, not the real value
        assert "GH_TOKEN" in result
        assert result["GH_TOKEN"] != "ghp_realtoken1234"
        assert result["GH_TOKEN"].startswith("ghp_")

        # replacement_map should have the mapping
        surrogate = result["GH_TOKEN"]
        assert surrogate in replacement_map
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.real_value == "ghp_realtoken1234"
        assert "api.github.com" in entry.scopes
        assert entry.headers == ("Authorization",)

    def test_masked_secret_with_custom_headers(self) -> None:
        """Custom headers are passed through to replacement_map."""
        masked_secrets = {
            "API_KEY": MaskedSecret(
                value="secret_value",
                scopes=frozenset(["api.example.com"]),
                headers=("X-Custom-Header",),
            )
        }
        result, replacement_map = _build_task_env({}, masked_secrets, {}, {})

        surrogate = result["API_KEY"]
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.headers == ("X-Custom-Header",)

    def test_masked_secret_takes_priority_over_plain(self) -> None:
        """Masked secret is used even if plain secret exists."""
        plain_secrets = {"GH_TOKEN": "plain_value"}
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="masked_value",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _build_task_env(
            plain_secrets, masked_secrets, {}, {}
        )

        # Should use masked secret, not plain
        assert result["GH_TOKEN"] != "plain_value"
        assert result["GH_TOKEN"] != "masked_value"
        assert len(replacement_map) == 1

    def test_plain_secret_used_when_not_masked(self) -> None:
        """Plain secret is used when no masked secret exists."""
        plain_secrets = {"API_KEY": "plain_key"}
        result, replacement_map = _build_task_env(plain_secrets, {}, {}, {})

        assert result == {"API_KEY": "plain_key"}
        assert replacement_map == {}

    def test_mixed_masked_and_plain(self) -> None:
        """Mix of masked and plain secrets works correctly."""
        plain_secrets = {"API_KEY": "plain_api_key"}
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_secret",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _build_task_env(
            plain_secrets, masked_secrets, {}, {}
        )

        # GH_TOKEN should be masked, API_KEY should be plain
        assert result["GH_TOKEN"] != "ghp_secret"
        assert result["API_KEY"] == "plain_api_key"
        assert len(replacement_map) == 1

    def test_allow_foreign_credentials_threaded_to_replacement(self) -> None:
        """allow_foreign_credentials is passed through to ReplacementEntry."""
        masked_secrets = {
            "TOKEN": MaskedSecret(
                value="secret_value",
                scopes=frozenset(["api.example.com"]),
                headers=("Authorization",),
                allow_foreign_credentials=True,
            )
        }
        result, replacement_map = _build_task_env({}, masked_secrets, {}, {})

        surrogate = result["TOKEN"]
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.allow_foreign_credentials is True

    def test_allow_foreign_credentials_default_in_replacement(self) -> None:
        """Default allow_foreign_credentials=False passes through."""
        masked_secrets = {
            "TOKEN": MaskedSecret(
                value="secret_value",
                scopes=frozenset(["api.example.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _build_task_env({}, masked_secrets, {}, {})

        surrogate = result["TOKEN"]
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.allow_foreign_credentials is False


# ---------------------------------------------------------------------------
# ReplacementEntry
# ---------------------------------------------------------------------------


class TestReplacementEntry:
    """Tests for ReplacementEntry."""

    def test_to_dict(self) -> None:
        """to_dict produces expected JSON-serializable format."""
        entry = ReplacementEntry(
            real_value="secret123",
            scopes=("api.github.com", "*.example.com"),
            headers=("Authorization",),
        )
        d = entry.to_dict()
        assert d == {
            "value": "secret123",
            "scopes": ["api.github.com", "*.example.com"],
            "headers": ["Authorization"],
        }

    def test_to_dict_with_wildcard_headers(self) -> None:
        """to_dict includes wildcard headers."""
        entry = ReplacementEntry(
            real_value="secret123",
            scopes=("api.github.com",),
            headers=("*",),
        )
        d = entry.to_dict()
        assert d == {
            "value": "secret123",
            "scopes": ["api.github.com"],
            "headers": ["*"],
        }

    def test_to_dict_with_multiple_headers(self) -> None:
        """to_dict includes multiple header patterns."""
        entry = ReplacementEntry(
            real_value="secret123",
            scopes=("api.github.com",),
            headers=("Authorization", "X-Api-*"),
        )
        d = entry.to_dict()
        assert d == {
            "value": "secret123",
            "scopes": ["api.github.com"],
            "headers": ["Authorization", "X-Api-*"],
        }

    def test_to_dict_omits_allow_foreign_when_false(self) -> None:
        """to_dict omits allow_foreign_credentials when False (default)."""
        entry = ReplacementEntry(
            real_value="secret",
            scopes=("example.com",),
            headers=("Authorization",),
        )
        d = entry.to_dict()
        assert "allow_foreign_credentials" not in d

    def test_to_dict_includes_allow_foreign_when_true(self) -> None:
        """to_dict includes allow_foreign_credentials when True."""
        entry = ReplacementEntry(
            real_value="secret",
            scopes=("example.com",),
            headers=("Authorization",),
            allow_foreign_credentials=True,
        )
        d = entry.to_dict()
        assert d["allow_foreign_credentials"] is True


# ---------------------------------------------------------------------------
# generate_session_token_surrogate
# ---------------------------------------------------------------------------


class TestGenerateSessionTokenSurrogate:
    """Tests for generate_session_token_surrogate."""

    def test_fixed_length(self) -> None:
        """Surrogate is always 512 characters."""
        surrogate = generate_session_token_surrogate()
        assert len(surrogate) == 512

    def test_alphanumeric(self) -> None:
        """Surrogate contains only alphanumeric characters."""
        surrogate = generate_session_token_surrogate()
        assert surrogate.isalnum()

    def test_different_each_time(self) -> None:
        """Surrogates are random."""
        surrogates = {generate_session_token_surrogate() for _ in range(10)}
        assert len(surrogates) >= 5


# ---------------------------------------------------------------------------
# AWS access key ID prefix preservation
# ---------------------------------------------------------------------------


class TestAwsKeyIdSurrogate:
    """Tests for AWS key ID surrogate generation."""

    def test_akia_prefix_preserved(self) -> None:
        """AKIA prefix is preserved in surrogate."""
        original = "AKIAIOSFODNN7EXAMPLE"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("AKIA")
        assert len(surrogate) == len(original)

    def test_asia_prefix_preserved(self) -> None:
        """ASIA prefix is preserved in surrogate."""
        original = "ASIAIOSFODNN7EXAMPLE"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("ASIA")
        assert len(surrogate) == len(original)


# ---------------------------------------------------------------------------
# SigningCredentialEntry
# ---------------------------------------------------------------------------


class TestSigningCredentialEntry:
    """Tests for SigningCredentialEntry."""

    def test_to_dict(self) -> None:
        """to_dict produces expected JSON-serializable format."""
        entry = SigningCredentialEntry(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token=None,
            surrogate_session_token=None,
            scopes=("*.amazonaws.com",),
        )
        d = entry.to_dict()
        assert d == {
            "type": SIGNING_TYPE_AWS_SIGV4,
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "session_token": None,
            "surrogate_session_token": None,
            "scopes": ["*.amazonaws.com"],
        }

    def test_to_dict_with_session_token(self) -> None:
        """to_dict includes session token when present."""
        entry = SigningCredentialEntry(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="secret",
            session_token="real-session-token",
            surrogate_session_token="surrogate-session-token",
            scopes=("*.amazonaws.com",),
        )
        d = entry.to_dict()
        assert d["session_token"] == "real-session-token"
        assert d["surrogate_session_token"] == "surrogate-session-token"


# ---------------------------------------------------------------------------
# _resolve_signing_credentials
# ---------------------------------------------------------------------------


class TestResolveSigningCredentials:
    """Tests for _resolve_signing_credentials."""

    def test_empty_mapping(self) -> None:
        """Empty mapping returns empty dict."""
        result = _resolve_signing_credentials({}, "repos.test")
        assert result == {}

    def test_basic_signing_credential(self) -> None:
        """Parses basic signing credential with name/value fields."""
        raw = {
            "AWS_PROD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIAIOSFODNN7EXAMPLE",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "wJalrXUtnFEMI",
                },
                "scopes": ["*.amazonaws.com"],
            }
        }
        result = _resolve_signing_credentials(raw, "repos.test")
        assert "AWS_PROD" in result
        cred = result["AWS_PROD"]
        assert cred.access_key_id.name == "AWS_ACCESS_KEY_ID"
        assert cred.access_key_id.value == "AKIAIOSFODNN7EXAMPLE"
        assert cred.secret_access_key.value == "wJalrXUtnFEMI"
        assert cred.session_token is None
        assert "*.amazonaws.com" in cred.scopes

    def test_with_session_token(self) -> None:
        """Parses credential with session token."""
        raw = {
            "AWS_TEMP": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "ASIAIOSFODNN7EXAMPLE",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "session_token": {
                    "name": "AWS_SESSION_TOKEN",
                    "value": "token123",
                },
                "scopes": ["*.amazonaws.com"],
            }
        }
        result = _resolve_signing_credentials(raw, "repos.test")
        assert result["AWS_TEMP"].session_token is not None
        assert result["AWS_TEMP"].session_token.value == "token123"

    def test_invalid_type_raises(self) -> None:
        """Invalid type raises ConfigError."""
        raw = {
            "BAD": {
                "type": "hmac-sha512",
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIA",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="must be 'aws-sigv4'"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_missing_key_id_raises(self) -> None:
        """Missing access_key_id raises ConfigError."""
        raw = {
            "BAD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="access_key_id is required"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_missing_secret_key_raises(self) -> None:
        """Missing secret_access_key raises ConfigError."""
        raw = {
            "BAD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIA",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="secret_access_key is required"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_missing_scopes_raises(self) -> None:
        """Missing scopes raises ConfigError."""
        raw = {
            "BAD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIA",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
            }
        }
        with pytest.raises(ConfigError, match="scopes is required"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_empty_scopes_raises(self) -> None:
        """Empty scopes raises ConfigError."""
        raw = {
            "BAD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIA",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": [],
            }
        }
        with pytest.raises(ConfigError, match="scopes cannot be empty"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_not_a_mapping_raises(self) -> None:
        """Non-mapping value raises ConfigError."""
        raw = {"BAD": "just a string"}
        with pytest.raises(ConfigError, match="must be a mapping"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_scopes_not_list_raises(self) -> None:
        """Non-list scopes raises ConfigError."""
        raw = {
            "BAD": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIA",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": "*.amazonaws.com",
            }
        }
        with pytest.raises(ConfigError, match="scopes must be a list"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_env_var_resolution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """!env vars are resolved in signing credential field values."""
        from airut.yaml_env import EnvVar

        monkeypatch.setenv("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")
        monkeypatch.setenv("AWS_SECRET", "secretkey")
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": EnvVar("AWS_KEY"),
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": EnvVar("AWS_SECRET"),
                },
                "scopes": ["*.amazonaws.com"],
            }
        }
        result = _resolve_signing_credentials(raw, "repos.test")
        assert result["AWS"].access_key_id.value == "AKIAIOSFODNN7EXAMPLE"
        assert result["AWS"].secret_access_key.value == "secretkey"

    def test_missing_field_name_raises(self) -> None:
        """Field without name raises ConfigError."""
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {"value": "AKIA"},
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="name is required"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_non_mapping_field_raises(self) -> None:
        """Flat string field raises ConfigError."""
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": "AKIA",
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="must be a mapping"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_empty_required_field_value_raises(self) -> None:
        """Required field with name but empty value raises ConfigError."""
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "scopes": ["*"],
            }
        }
        with pytest.raises(ConfigError, match="value is required"):
            _resolve_signing_credentials(raw, "repos.test")

    def test_empty_optional_session_token_returns_none(self) -> None:
        """Optional session_token with empty value returns None."""
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": "AKIAIOSFODNN7EXAMPLE",
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": "secret",
                },
                "session_token": {
                    "name": "AWS_SESSION_TOKEN",
                    "value": "",
                },
                "scopes": ["*.amazonaws.com"],
            }
        }
        result = _resolve_signing_credentials(raw, "repos.test")
        assert result["AWS"].session_token is None


# ---------------------------------------------------------------------------
# Signing credential resolution in _build_task_env
# ---------------------------------------------------------------------------


class TestSigningCredentialResolution:
    """Tests for signing credentials in _build_task_env."""

    def _make_signing_cred(
        self,
        key_id: str = "AKIAIOSFODNN7EXAMPLE",
        secret: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: str | None = None,
    ) -> SigningCredential:
        return SigningCredential(
            access_key_id=SigningCredentialField(
                name="AWS_ACCESS_KEY_ID", value=key_id
            ),
            secret_access_key=SigningCredentialField(
                name="AWS_SECRET_ACCESS_KEY", value=secret
            ),
            session_token=(
                SigningCredentialField(
                    name="AWS_SESSION_TOKEN", value=session_token
                )
                if session_token
                else None
            ),
            scopes=frozenset(["*.amazonaws.com"]),
        )

    def test_basic_signing_credential_resolution(self) -> None:
        """Signing credential fields generate surrogates by field name."""
        signing_creds = {"AWS_PROD": self._make_signing_cred()}

        result, replacement_map = _build_task_env({}, {}, signing_creds, {})

        # Container env should have surrogates
        assert result["AWS_ACCESS_KEY_ID"].startswith("AKIA")
        assert result["AWS_ACCESS_KEY_ID"] != "AKIAIOSFODNN7EXAMPLE"
        assert result["AWS_SECRET_ACCESS_KEY"] != (
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        # Replacement map should have a SigningCredentialEntry
        surrogate_key_id = result["AWS_ACCESS_KEY_ID"]
        assert surrogate_key_id in replacement_map
        entry = replacement_map[surrogate_key_id]
        assert isinstance(entry, SigningCredentialEntry)
        assert entry.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert entry.secret_access_key == (
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

    def test_with_session_token(self) -> None:
        """Session token generates fixed-length surrogate."""
        signing_creds = {
            "AWS": self._make_signing_cred(session_token="real-token-value")
        }

        result, replacement_map = _build_task_env({}, {}, signing_creds, {})

        # Session token surrogate should be 512 chars
        assert len(result["AWS_SESSION_TOKEN"]) == 512

        # Entry should have real and surrogate session tokens
        surrogate_key_id = result["AWS_ACCESS_KEY_ID"]
        entry = replacement_map[surrogate_key_id]
        assert isinstance(entry, SigningCredentialEntry)
        assert entry.session_token == "real-token-value"
        assert entry.surrogate_session_token == result["AWS_SESSION_TOKEN"]

    def test_no_session_token_skipped(self) -> None:
        """Credential without session_token produces no session_token env."""
        signing_creds = {"AWS": self._make_signing_cred()}

        result, replacement_map = _build_task_env({}, {}, signing_creds, {})

        # session_token is None, so no env var for it
        assert "AWS_SESSION_TOKEN" not in result
        surrogate_key_id = result["AWS_ACCESS_KEY_ID"]
        entry = replacement_map[surrogate_key_id]
        assert isinstance(entry, SigningCredentialEntry)
        assert entry.session_token is None
        assert entry.surrogate_session_token is None

    def test_mixed_signing_and_masked(self) -> None:
        """Signing credentials coexist with masked secrets."""
        signing_creds = {"AWS": self._make_signing_cred()}
        masked = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_real",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }

        result, replacement_map = _build_task_env({}, masked, signing_creds, {})

        # Both should be in replacement map
        assert len(replacement_map) == 2
        assert result["GH_TOKEN"].startswith("ghp_")
        assert result["AWS_ACCESS_KEY_ID"].startswith("AKIA")


# ---------------------------------------------------------------------------
# RepoServerConfig with signing_credentials
# ---------------------------------------------------------------------------


class TestRepoServerConfigSigningCredentials:
    """Tests for RepoServerConfig with signing_credentials."""

    def test_signing_credential_redaction(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Signing credential values are redacted in logs."""
        SecretFilter._secrets.clear()

        _make_repo_server_config(
            master_repo,
            tmp_path,
            signing_credentials={
                "AWS": SigningCredential(
                    access_key_id=SigningCredentialField(
                        name="AWS_ACCESS_KEY_ID",
                        value="AKIAIOSFODNN7EXAMPLE",
                    ),
                    secret_access_key=SigningCredentialField(
                        name="AWS_SECRET_ACCESS_KEY",
                        value="wJalrXUtnFEMI",
                    ),
                    session_token=SigningCredentialField(
                        name="AWS_SESSION_TOKEN",
                        value="session123",
                    ),
                    scopes=frozenset(["*.amazonaws.com"]),
                )
            },
        )

        assert "AKIAIOSFODNN7EXAMPLE" in SecretFilter._secrets
        assert "wJalrXUtnFEMI" in SecretFilter._secrets
        assert "session123" in SecretFilter._secrets

    def test_signing_credential_redaction_no_token(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Signing credential without session token redacts key+secret."""
        SecretFilter._secrets.clear()

        _make_repo_server_config(
            master_repo,
            tmp_path,
            signing_credentials={
                "AWS": SigningCredential(
                    access_key_id=SigningCredentialField(
                        name="AWS_ACCESS_KEY_ID",
                        value="AKIAIOSFODNN7EXAMPLE",
                    ),
                    secret_access_key=SigningCredentialField(
                        name="AWS_SECRET_ACCESS_KEY",
                        value="wJalrXUtnFEMI",
                    ),
                    session_token=None,
                    scopes=frozenset(["*.amazonaws.com"]),
                )
            },
        )

        assert "AKIAIOSFODNN7EXAMPLE" in SecretFilter._secrets
        assert "wJalrXUtnFEMI" in SecretFilter._secrets


# ---------------------------------------------------------------------------
# Slack channel config parsing
# ---------------------------------------------------------------------------


class TestParseSlackChannelConfig:
    def test_basic_parsing(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        raw = {
            "bot_token": "xoxb-test-slack-token-1",
            "app_token": "xapp-test-slack-token-1",
            "authorized": [{"workspace_members": True}],
        }
        config = _parse_slack_channel_config(raw, "repos.test")
        assert isinstance(config, SlackChannelConfig)
        assert config.bot_token == "xoxb-test-slack-token-1"
        assert config.app_token == "xapp-test-slack-token-1"
        assert config.authorized == ({"workspace_members": True},)

    def test_user_id_rule(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        raw = {
            "bot_token": "xoxb-test-slack-token-2",
            "app_token": "xapp-test-slack-token-2",
            "authorized": [{"user_id": "U12345678"}],
        }
        config = _parse_slack_channel_config(raw, "repos.test")
        assert isinstance(config, SlackChannelConfig)
        assert config.authorized == ({"user_id": "U12345678"},)

    def test_user_group_rule(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        raw = {
            "bot_token": "xoxb-test-slack-token-3",
            "app_token": "xapp-test-slack-token-3",
            "authorized": [{"user_group": "engineering"}],
        }
        config = _parse_slack_channel_config(raw, "repos.test")
        assert isinstance(config, SlackChannelConfig)
        assert config.authorized == ({"user_group": "engineering"},)

    def test_missing_bot_token_raises(self) -> None:
        raw = {
            "app_token": "xapp-test-slack-token-4",
            "authorized": [{"workspace_members": True}],
        }
        with pytest.raises(ConfigError, match="bot_token"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_missing_app_token_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-5",
            "authorized": [{"workspace_members": True}],
        }
        with pytest.raises(ConfigError, match="app_token"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_missing_authorized_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-6",
            "app_token": "xapp-test-slack-token-6",
        }
        with pytest.raises(ConfigError, match="authorized is required"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_empty_authorized_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-7",
            "app_token": "xapp-test-slack-token-7",
            "authorized": [],
        }
        with pytest.raises(ConfigError, match="cannot be empty"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_authorized_not_list_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-8",
            "app_token": "xapp-test-slack-token-8",
            "authorized": "not_a_list",
        }
        with pytest.raises(ConfigError, match="must be a list"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_invalid_rule_key_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-9",
            "app_token": "xapp-test-slack-token-9",
            "authorized": [{"invalid_key": "value"}],
        }
        with pytest.raises(ConfigError, match="unknown rule type"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_multi_key_rule_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-10",
            "app_token": "xapp-test-slack-token-10",
            "authorized": [{"workspace_members": True, "user_id": "U123"}],
        }
        with pytest.raises(ConfigError, match="single-key"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_env_var_resolution(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        with patch.dict("os.environ", {"SLACK_BOT_CFG": "xoxb-env-token"}):
            raw = {
                "bot_token": EnvVar("SLACK_BOT_CFG"),
                "app_token": "xapp-test-slack-token-11",
                "authorized": [{"workspace_members": True}],
            }
            config = _parse_slack_channel_config(raw, "repos.test")
            assert isinstance(config, SlackChannelConfig)
            assert config.bot_token == "xoxb-env-token"

    def test_multiple_rules(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        raw = {
            "bot_token": "xoxb-test-slack-token-12",
            "app_token": "xapp-test-slack-token-12",
            "authorized": [
                {"workspace_members": True},
                {"user_group": "eng"},
                {"user_id": "U123"},
            ],
        }
        config = _parse_slack_channel_config(raw, "repos.test")
        assert isinstance(config, SlackChannelConfig)
        assert len(config.authorized) == 3

    def test_null_user_id_value_raises(self) -> None:
        raw = {
            "bot_token": "xoxb-test-slack-token-13",
            "app_token": "xapp-test-slack-token-13",
            "authorized": [{"user_id": None}],
        }
        with pytest.raises(ConfigError, match="value is required"):
            _parse_slack_channel_config(raw, "repos.test")

    def test_workspace_members_false_warns(self) -> None:
        from unittest.mock import patch

        raw = {
            "bot_token": "xoxb-test-slack-token-wmf",
            "app_token": "xapp-test-slack-token-wmf",
            "authorized": [{"workspace_members": False}],
        }
        with patch("airut.gateway.config.logger") as mock_logger:
            config = _parse_slack_channel_config(raw, "repos.test")

        mock_logger.warning.assert_any_call(
            "%s.slack.authorized[%d]: workspace_members: false "
            "has no effect (rule never matches); remove it or "
            "set to true",
            "repos.test",
            0,
        )
        assert config.authorized == ({"workspace_members": False},)


def test_repo_server_config_slack_channel(
    master_repo: Path, tmp_path: Path
) -> None:
    """ServerConfig.from_yaml parses a Slack channel block."""
    from airut.gateway.slack.config import SlackChannelConfig

    yaml_text = f"""\
repos:
  test-slack:
    slack:
      bot_token: xoxb-test-slack-token-sv
      app_token: xapp-test-slack-token-sv
      authorized:
        - workspace_members: true
    repo_url: {master_repo.as_uri()}
"""
    config_path = tmp_path / "airut.yaml"
    config_path.write_text(yaml_text)

    server = ServerConfig.from_yaml(config_path).value
    repo = server.repos["test-slack"]
    assert "slack" in repo.channels
    slack_config = repo.channels["slack"]
    assert isinstance(slack_config, SlackChannelConfig)
    assert slack_config.bot_token == "xoxb-test-slack-token-sv"


def test_repo_server_config_dual_channel(
    master_repo: Path, tmp_path: Path
) -> None:
    """A repo can have both email and Slack channels simultaneously."""
    from airut.gateway.slack.config import SlackChannelConfig

    yaml_text = f"""\
repos:
  dual:
    email:
      account:
        username: user@test.com
        password: pass123
        from: "Bot <bot@test.com>"
      imap:
        server: imap.test.com
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - auth@test.com
        trusted_authserv_id: mx.test.com
    slack:
      bot_token: xoxb-test-slack-token-dual
      app_token: xapp-test-slack-token-dual
      authorized:
        - workspace_members: true
    repo_url: {master_repo.as_uri()}
"""
    config_path = tmp_path / "airut.yaml"
    config_path.write_text(yaml_text)

    server = ServerConfig.from_yaml(config_path).value
    repo = server.repos["dual"]
    assert len(repo.channels) == 2
    assert "email" in repo.channels
    assert "slack" in repo.channels
    assert isinstance(repo.channels["email"], EmailChannelConfig)
    assert isinstance(repo.channels["slack"], SlackChannelConfig)


# ---------------------------------------------------------------------------
# GitHub App Credentials
# ---------------------------------------------------------------------------


class TestGitHubAppCredential:
    """Tests for GitHubAppCredential dataclass."""

    def test_create_minimal(self) -> None:
        """Creates GitHubAppCredential with required fields only."""
        cred = GitHubAppCredential(
            app_id="Iv23liXyz",
            private_key=(
                "-----BEGIN RSA PRIVATE KEY-----"
                "\ntest\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            installation_id=12345,
            scopes=frozenset(["api.github.com"]),
        )
        assert cred.app_id == "Iv23liXyz"
        assert cred.installation_id == 12345
        assert cred.base_url == "https://api.github.com"
        assert cred.allow_foreign_credentials is False
        assert cred.permissions is None
        assert cred.repositories is None

    def test_create_with_optional_fields(self) -> None:
        """Creates GitHubAppCredential with all fields."""
        cred = GitHubAppCredential(
            app_id="Iv23liXyz",
            private_key="key",
            installation_id=12345,
            scopes=frozenset(["api.github.com", "*.githubusercontent.com"]),
            allow_foreign_credentials=True,
            base_url="https://github.example.com/api/v3",
            permissions={"contents": "write"},
            repositories=("my-repo",),
        )
        assert cred.allow_foreign_credentials is True
        assert cred.base_url == "https://github.example.com/api/v3"
        assert cred.permissions == {"contents": "write"}
        assert cred.repositories == ("my-repo",)

    def test_frozen(self) -> None:
        """GitHubAppCredential is immutable."""
        cred = GitHubAppCredential(
            app_id="app",
            private_key="key",
            installation_id=123,
            scopes=frozenset(["api.github.com"]),
        )
        with pytest.raises(AttributeError):
            cred.app_id = "other"  # ty:ignore[invalid-assignment]


class TestGitHubAppEntry:
    """Tests for GitHubAppEntry dataclass."""

    def test_to_dict_minimal(self) -> None:
        """Serializes with required fields."""
        entry = GitHubAppEntry(
            app_id="Iv23liXyz",
            private_key="key",
            installation_id=12345,
            base_url="https://api.github.com",
            scopes=("api.github.com",),
        )
        d = entry.to_dict()
        assert d["type"] == CREDENTIAL_TYPE_GITHUB_APP
        assert d["app_id"] == "Iv23liXyz"
        assert d["private_key"] == "key"
        assert d["installation_id"] == 12345
        assert d["base_url"] == "https://api.github.com"
        assert d["scopes"] == ["api.github.com"]
        assert "allow_foreign_credentials" not in d
        assert "permissions" not in d
        assert "repositories" not in d

    def test_to_dict_with_optional_fields(self) -> None:
        """Serializes with optional permissions and repositories."""
        entry = GitHubAppEntry(
            app_id="Iv23liXyz",
            private_key="key",
            installation_id=12345,
            base_url="https://api.github.com",
            scopes=("api.github.com",),
            allow_foreign_credentials=True,
            permissions={"contents": "write"},
            repositories=("my-repo", "other-repo"),
        )
        d = entry.to_dict()
        assert d["allow_foreign_credentials"] is True
        assert d["permissions"] == {"contents": "write"}
        assert d["repositories"] == ["my-repo", "other-repo"]

    def test_frozen(self) -> None:
        """GitHubAppEntry is immutable."""
        entry = GitHubAppEntry(
            app_id="app",
            private_key="key",
            installation_id=123,
            base_url="https://api.github.com",
            scopes=("api.github.com",),
        )
        with pytest.raises(AttributeError):
            entry.app_id = "other"  # ty:ignore[invalid-assignment]


class TestGenerateGitHubAppSurrogate:
    """Tests for generate_github_app_surrogate function."""

    def test_prefix(self) -> None:
        """Surrogate starts with ghs_ prefix."""
        surrogate = generate_github_app_surrogate()
        assert surrogate.startswith("ghs_")

    def test_length(self) -> None:
        """Surrogate is 40 characters total (4 prefix + 36 random)."""
        surrogate = generate_github_app_surrogate()
        assert len(surrogate) == 40

    def test_alphanumeric_suffix(self) -> None:
        """Suffix is alphanumeric."""
        surrogate = generate_github_app_surrogate()
        suffix = surrogate[4:]
        assert suffix.isalnum()

    def test_different_each_time(self) -> None:
        """Each call produces a different surrogate."""
        s1 = generate_github_app_surrogate()
        s2 = generate_github_app_surrogate()
        assert s1 != s2


class TestResolveGitHubAppCredentials:
    """Tests for _resolve_github_app_credentials function."""

    def test_valid_config(self) -> None:
        """Parses a valid GitHub App credential config."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23liXyz",
                "private_key": (
                    "-----BEGIN RSA PRIVATE KEY-----"
                    "\ntest\n"
                    "-----END RSA PRIVATE KEY-----"
                ),
                "installation_id": 12345,
                "scopes": [
                    "api.github.com",
                    "*.githubusercontent.com",
                ],
            }
        }
        result = _resolve_github_app_credentials(raw, "repos.test")

        assert "GH_TOKEN" in result
        cred = result["GH_TOKEN"]
        assert cred.app_id == "Iv23liXyz"
        assert cred.installation_id == 12345
        assert "api.github.com" in cred.scopes
        assert cred.base_url == "https://api.github.com"

    def test_with_all_optional_fields(self) -> None:
        """Parses config with all optional fields."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23liXyz",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
                "allow_foreign_credentials": True,
                "base_url": "https://github.example.com/api/v3",
                "permissions": {"contents": "write", "pull_requests": "write"},
                "repositories": ["my-repo"],
            }
        }
        result = _resolve_github_app_credentials(raw, "repos.test")

        cred = result["GH_TOKEN"]
        assert cred.allow_foreign_credentials is True
        assert cred.base_url == "https://github.example.com/api/v3"
        assert cred.permissions == {
            "contents": "write",
            "pull_requests": "write",
        }
        assert cred.repositories == ("my-repo",)

    def test_missing_app_id_raises(self) -> None:
        """Raises ConfigError when app_id is missing."""
        raw = {
            "GH_TOKEN": {
                "private_key": "key",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
            }
        }
        with pytest.raises(ConfigError, match="app_id is required"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_missing_private_key_raises(self) -> None:
        """Raises ConfigError when private_key is missing."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
            }
        }
        with pytest.raises(ConfigError, match="private_key is required"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_missing_installation_id_raises(self) -> None:
        """Raises ConfigError when installation_id is missing."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "scopes": ["api.github.com"],
            }
        }
        with pytest.raises(ConfigError, match="installation_id.* is missing"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_missing_scopes_raises(self) -> None:
        """Raises ConfigError when scopes is missing."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
            }
        }
        with pytest.raises(ConfigError, match="scopes is required"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_empty_scopes_raises(self) -> None:
        """Raises ConfigError when scopes is empty."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": [],
            }
        }
        with pytest.raises(ConfigError, match="scopes cannot be empty"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_scopes_not_list_raises(self) -> None:
        """Raises ConfigError when scopes is not a list."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": "api.github.com",
            }
        }
        with pytest.raises(ConfigError, match="scopes must be a list"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_non_mapping_raises(self) -> None:
        """Raises ConfigError when entry is not a mapping."""
        raw = {"GH_TOKEN": "not-a-mapping"}
        with pytest.raises(ConfigError, match="must be a mapping"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_non_numeric_installation_id_raises(self) -> None:
        """Raises ValueError when installation_id is not numeric."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": "abc",
                "scopes": ["api.github.com"],
            }
        }
        with pytest.raises(ValueError, match="invalid literal"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_http_base_url_raises(self) -> None:
        """Raises ConfigError when base_url uses HTTP instead of HTTPS."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
                "base_url": "http://github.example.com/api/v3",
            }
        }
        with pytest.raises(ConfigError, match="base_url must use HTTPS"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_invalid_permissions_type_raises(self) -> None:
        """Raises ConfigError when permissions is not a mapping."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
                "permissions": "not-a-mapping",
            }
        }
        with pytest.raises(ConfigError, match="permissions must be a mapping"):
            _resolve_github_app_credentials(raw, "repos.test")

    def test_invalid_repositories_type_raises(self) -> None:
        """Raises ConfigError when repositories is not a list."""
        raw = {
            "GH_TOKEN": {
                "app_id": "Iv23li",
                "private_key": "key",
                "installation_id": 12345,
                "scopes": ["api.github.com"],
                "repositories": "not-a-list",
            }
        }
        with pytest.raises(ConfigError, match="repositories must be a list"):
            _resolve_github_app_credentials(raw, "repos.test")


class TestBuildTaskEnvGitHubApp:
    """Tests for GitHub App credential resolution in _build_task_env."""

    def _make_github_app_cred(
        self,
        *,
        app_id: str = "Iv23liXyz",
        private_key: str = "test-key",
        installation_id: int = 12345,
    ) -> GitHubAppCredential:
        return GitHubAppCredential(
            app_id=app_id,
            private_key=private_key,
            installation_id=installation_id,
            scopes=frozenset(["api.github.com"]),
        )

    def test_github_app_generates_ghs_surrogate(self) -> None:
        """GitHub App credential generates a ghs_ prefixed surrogate."""
        gh_creds = {"GH_TOKEN": self._make_github_app_cred()}

        result, replacement_map = _build_task_env({}, {}, {}, gh_creds)

        surrogate = result["GH_TOKEN"]
        assert surrogate.startswith("ghs_")
        assert len(surrogate) == 40

    def test_github_app_adds_entry_to_replacement_map(self) -> None:
        """GitHub App credential adds GitHubAppEntry to replacement map."""
        gh_creds = {"GH_TOKEN": self._make_github_app_cred()}

        result, replacement_map = _build_task_env({}, {}, {}, gh_creds)

        surrogate = result["GH_TOKEN"]
        assert surrogate in replacement_map
        entry = replacement_map[surrogate]
        assert isinstance(entry, GitHubAppEntry)
        assert entry.app_id == "Iv23liXyz"
        assert entry.private_key == "test-key"
        assert entry.installation_id == 12345
        assert entry.base_url == "https://api.github.com"

    def test_github_app_priority_over_masked_secrets(self) -> None:
        """GitHub App credential takes priority over masked secret."""
        gh_creds = {"GH_TOKEN": self._make_github_app_cred()}
        masked = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }

        result, replacement_map = _build_task_env({}, masked, {}, gh_creds)

        surrogate = result["GH_TOKEN"]
        assert surrogate.startswith("ghs_")
        assert isinstance(replacement_map[surrogate], GitHubAppEntry)

    def test_github_app_with_permissions_and_repos(self) -> None:
        """GitHub App entry includes permissions and repositories."""
        cred = GitHubAppCredential(
            app_id="Iv23li",
            private_key="key",
            installation_id=123,
            scopes=frozenset(["api.github.com"]),
            permissions={"contents": "write"},
            repositories=("my-repo",),
        )

        result, replacement_map = _build_task_env(
            {}, {}, {}, {"GH_TOKEN": cred}
        )

        surrogate = result["GH_TOKEN"]
        entry = replacement_map[surrogate]
        assert isinstance(entry, GitHubAppEntry)
        assert entry.permissions == {"contents": "write"}
        assert entry.repositories == ("my-repo",)

    def test_signing_credential_priority_over_github_app(self) -> None:
        """Signing credential takes priority over GitHub App credential."""
        gh_creds = {
            "AWS_ACCESS_KEY_ID": self._make_github_app_cred(app_id="conflict")
        }
        signing_creds = {
            "AWS_PROD": SigningCredential(
                access_key_id=SigningCredentialField(
                    name="AWS_ACCESS_KEY_ID", value="AKIAIOSFODNN7EXAMPLE"
                ),
                secret_access_key=SigningCredentialField(
                    name="AWS_SECRET_ACCESS_KEY", value="secret"
                ),
                session_token=None,
                scopes=frozenset(["s3.amazonaws.com"]),
            )
        }

        result, replacement_map = _build_task_env(
            {},
            {},
            signing_creds,
            gh_creds,
        )

        surrogate = result["AWS_ACCESS_KEY_ID"]
        # Should be signing credential, not GitHub App
        assert surrogate.startswith("AKIA")


class TestRepoServerConfigGitHubApp:
    """Tests for GitHub App credentials in RepoServerConfig."""

    def test_registers_private_key_for_redaction(self) -> None:
        """Private key is registered with SecretFilter."""
        SecretFilter.clear_secrets()
        config = RepoServerConfig(
            repo_id="test",
            git_repo_url="https://github.com/test/repo.git",
            channels={"email": MagicMock(channel_info="test")},
            github_app_credentials={
                "GH_TOKEN": GitHubAppCredential(
                    app_id="Iv23li",
                    private_key="super-secret-key",
                    installation_id=123,
                    scopes=frozenset(["api.github.com"]),
                )
            },
        )
        assert config is not None
        assert "super-secret-key" in SecretFilter._secrets


# ── Schedule config tests ─────────────────────────────────────────────


class TestScheduleConfig:
    """Tests for ScheduleConfig and ScheduleDelivery."""

    def test_prompt_mode(self) -> None:
        from airut.gateway.config import ScheduleConfig, ScheduleDelivery

        config = ScheduleConfig(
            cron="0 9 * * 1-5",
            deliver=ScheduleDelivery(channel="email", to="user@example.com"),
            prompt="Review PRs",
        )
        assert config.prompt == "Review PRs"
        assert config.trigger_command is None
        assert config.timezone is None
        assert config.output_limit == 102400

    def test_script_mode(self) -> None:
        from airut.gateway.config import ScheduleConfig, ScheduleDelivery

        config = ScheduleConfig(
            cron="0 2 * * *",
            deliver=ScheduleDelivery(channel="email", to="ops@example.com"),
            trigger_command="./check.sh --verbose",
            trigger_timeout=300,
        )
        assert config.prompt is None
        assert config.trigger_command == "./check.sh --verbose"
        assert config.trigger_timeout == 300

    def test_overrides(self) -> None:
        from airut.gateway.config import ScheduleConfig, ScheduleDelivery

        config = ScheduleConfig(
            cron="0 9 * * *",
            deliver=ScheduleDelivery(channel="email", to="a@b.com"),
            prompt="test",
            model="sonnet",
            effort="high",
            timezone="Europe/Helsinki",
            output_limit=204800,
        )
        assert config.model == "sonnet"
        assert config.effort == "high"
        assert config.timezone == "Europe/Helsinki"
        assert config.output_limit == 204800


class TestScheduleConfigParsing:
    """Tests for _parse_schedule_config and RepoServerConfig validation."""

    def _make_repo_config(self, **schedule_raw: dict) -> "RepoServerConfig":
        from airut.gateway.config import (
            RepoServerConfig,
            ScheduleConfig,
            ScheduleDelivery,
        )

        schedules = {}
        for name, raw in schedule_raw.items():
            schedules[name] = ScheduleConfig(
                cron=raw.get("cron", "0 9 * * *"),
                deliver=ScheduleDelivery(
                    channel=raw.get("channel", "email"),
                    to=raw.get("to", "user@example.com"),
                ),
                prompt=raw.get("prompt"),
                trigger_command=raw.get("trigger_command"),
                timezone=raw.get("timezone", "UTC"),
            )

        return RepoServerConfig(
            repo_id="test",
            git_repo_url="https://github.com/test/repo.git",
            channels={"email": MagicMock(channel_info="test")},
            schedules=schedules,
        )

    def test_valid_prompt_schedule(self) -> None:
        config = self._make_repo_config(daily={"prompt": "Review PRs"})
        assert "daily" in config.schedules

    def test_missing_both_prompt_and_trigger(self) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            self._make_repo_config(bad={})

    def test_both_prompt_and_trigger(self) -> None:
        with pytest.raises(ValueError, match="mutually exclusive"):
            self._make_repo_config(
                bad={
                    "prompt": "test",
                    "trigger_command": "./check.sh",
                }
            )

    def test_invalid_delivery_channel(self) -> None:
        with pytest.raises(ValueError, match="does not match"):
            self._make_repo_config(bad={"prompt": "test", "channel": "slack"})

    def test_invalid_cron(self) -> None:
        with pytest.raises(ValueError, match="invalid expression"):
            self._make_repo_config(
                bad={"prompt": "test", "cron": "invalid cron"}
            )

    def test_invalid_timezone(self) -> None:
        with pytest.raises(ValueError, match="invalid timezone"):
            self._make_repo_config(
                bad={"prompt": "test", "timezone": "Invalid/Zone"}
            )


class TestParseScheduleConfigFromYAML:
    """Tests for _parse_schedule_config from raw YAML dicts."""

    def test_parse_prompt_mode(self) -> None:
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 9 * * 1-5",
            "prompt": "Review PRs",
            "deliver": {"channel": "email", "to": "user@example.com"},
        }
        config = _parse_schedule_config("daily", raw, "repos.test")
        assert config.cron == "0 9 * * 1-5"
        assert config.prompt == "Review PRs"
        assert config.trigger_command is None
        assert config.deliver.channel == "email"
        assert config.deliver.to == "user@example.com"

    def test_parse_script_mode(self) -> None:
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 2 * * *",
            "trigger_command": "./check.sh --verbose",
            "trigger_timeout": 300,
            "deliver": {"channel": "email", "to": "ops@example.com"},
            "output_limit": 204800,
        }
        config = _parse_schedule_config("nightly", raw, "repos.test")
        assert config.trigger_command == "./check.sh --verbose"
        assert config.trigger_timeout == 300
        assert config.output_limit == 204800

    def test_parse_with_overrides(self) -> None:
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 9 * * *",
            "prompt": "test",
            "deliver": {"channel": "email", "to": "a@b.com"},
            "timezone": "Europe/Helsinki",
            "model": "sonnet",
            "effort": "high",
        }
        config = _parse_schedule_config("test", raw, "repos.test")
        assert config.timezone == "Europe/Helsinki"
        assert config.model == "sonnet"
        assert config.effort == "high"

    def test_parse_missing_cron(self) -> None:
        from airut.gateway.config import ConfigError, _parse_schedule_config

        raw = {
            "prompt": "test",
            "deliver": {"channel": "email", "to": "a@b.com"},
        }
        with pytest.raises(ConfigError, match="cron"):
            _parse_schedule_config("test", raw, "repos.test")

    def test_parse_missing_deliver(self) -> None:
        from airut.gateway.config import ConfigError, _parse_schedule_config

        raw = {
            "cron": "0 9 * * *",
            "prompt": "test",
        }
        with pytest.raises(ConfigError, match="deliver"):
            _parse_schedule_config("test", raw, "repos.test")

    def test_parse_subject_override(self) -> None:
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 9 * * 1-5",
            "prompt": "Review PRs",
            "subject": "Weekly PR Summary",
            "deliver": {"channel": "email", "to": "user@example.com"},
        }
        config = _parse_schedule_config("weekly-prs", raw, "repos.test")
        assert config.subject == "Weekly PR Summary"

    def test_parse_subject_defaults_to_none(self) -> None:
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 9 * * 1-5",
            "prompt": "Review PRs",
            "deliver": {"channel": "email", "to": "user@example.com"},
        }
        config = _parse_schedule_config("daily", raw, "repos.test")
        assert config.subject is None

    def test_parse_trigger_timeout_without_command(self) -> None:
        """trigger_timeout without trigger_command parses fine.

        Validation catches the missing trigger_command at RepoServerConfig
        level (neither prompt nor trigger_command set).
        """
        from airut.gateway.config import _parse_schedule_config

        raw = {
            "cron": "0 9 * * *",
            "trigger_timeout": 300,
            "deliver": {"channel": "email", "to": "a@b.com"},
        }
        config = _parse_schedule_config("test", raw, "repos.test")
        assert config.trigger_command is None
        assert config.trigger_timeout == 300
