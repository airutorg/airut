# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email gateway configuration."""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.config import (
    SIGNING_TYPE_AWS_SIGV4,
    ConfigError,
    EmailChannelConfig,
    GlobalConfig,
    MaskedSecret,
    ReplacementEntry,
    RepoConfig,
    RepoServerConfig,
    ServerConfig,
    SigningCredential,
    SigningCredentialEntry,
    SigningCredentialField,
    _coerce_bool,
    _EnvVar,
    _make_loader,
    _make_repo_loader,
    _raw_resolve,
    _resolve,
    _resolve_container_env,
    _resolve_masked_secrets,
    _resolve_signing_credentials,
    _resolve_string_list,
    _SecretRef,
    generate_session_token_surrogate,
    generate_surrogate,
    get_config_path,
    get_dotenv_path,
    get_storage_dir,
)
from airut.logging import SecretFilter


class TestRawResolve:
    """Tests for _raw_resolve."""

    def test_literal_string(self) -> None:
        """Literal string values resolve to themselves."""
        assert _raw_resolve("hello") == "hello"

    def test_none(self) -> None:
        """None resolves to None."""
        assert _raw_resolve(None) is None

    def test_int(self) -> None:
        """Non-string values are stringified."""
        assert _raw_resolve(42) == "42"

    def test_envvar_set(self) -> None:
        """EnvVar resolves to env value when set."""
        with patch.dict("os.environ", {"MY_VAR": "val"}):
            assert _raw_resolve(_EnvVar("MY_VAR")) == "val"

    def test_envvar_unset(self) -> None:
        """EnvVar resolves to None when env var is not set."""
        with patch.dict("os.environ", {}, clear=True):
            assert _raw_resolve(_EnvVar("MISSING")) is None

    def test_envvar_empty(self) -> None:
        """EnvVar set to empty string resolves to empty string."""
        with patch.dict("os.environ", {"EMPTY": ""}):
            assert _raw_resolve(_EnvVar("EMPTY")) == ""


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
            assert _resolve(_EnvVar("V"), str) == "val"

    def test_int_literal(self) -> None:
        """Int literal from YAML passes through."""
        assert _resolve(42, int) == 42

    def test_int_envvar(self) -> None:
        """Int !env resolves and coerces."""
        with patch.dict("os.environ", {"P": "993"}):
            assert _resolve(_EnvVar("P"), int) == 993

    def test_bool_literal(self) -> None:
        """Bool literal from YAML passes through."""
        assert _resolve(True, bool) is True
        assert _resolve(False, bool) is False

    def test_bool_envvar(self) -> None:
        """Bool !env resolves string to bool."""
        with patch.dict("os.environ", {"B": "false"}):
            assert _resolve(_EnvVar("B"), bool) is False
        with patch.dict("os.environ", {"B": "true"}):
            assert _resolve(_EnvVar("B"), bool) is True

    def test_path_expanduser(self) -> None:
        """Path values get ~ expanded."""
        result = _resolve("~/data", Path)
        assert result == Path.home() / "data"

    def test_path_envvar(self) -> None:
        """Path !env resolves and expands."""
        with patch.dict("os.environ", {"D": "~/stuff"}):
            assert _resolve(_EnvVar("D"), Path) == Path.home() / "stuff"

    def test_default_when_none(self) -> None:
        """Default returned when value is None."""
        assert _resolve(None, int, default=42) == 42

    def test_default_when_envvar_unset(self) -> None:
        """Default returned when !env var is unset."""
        with patch.dict("os.environ", {}, clear=True):
            assert _resolve(_EnvVar("X"), str, default="fallback") == "fallback"

    def test_required_missing_literal(self) -> None:
        """Required raises ConfigError for missing literal."""
        with pytest.raises(ConfigError, match="'field' is missing"):
            _resolve(None, str, required="field")

    def test_required_missing_envvar(self) -> None:
        """Required raises ConfigError with env var name."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError, match="'MY_VAR' is not set"):
                _resolve(_EnvVar("MY_VAR"), str, required="field")

    def test_optional_returns_none(self) -> None:
        """Optional (no default, no required) returns None."""
        assert _resolve(None, str) is None


# ---------------------------------------------------------------------------
# YAML loaders
# ---------------------------------------------------------------------------


class TestYamlLoader:
    """Tests for YAML !env tag loading."""

    def test_env_tag_parsed(self) -> None:
        """!env tags produce _EnvVar objects."""
        import yaml

        loader = _make_loader()
        result = yaml.load("key: !env MY_VAR", Loader=loader)
        assert isinstance(result["key"], _EnvVar)
        assert result["key"].var_name == "MY_VAR"

    def test_plain_values_unchanged(self) -> None:
        """Plain values load normally."""
        import yaml

        loader = _make_loader()
        result = yaml.load("key: hello", Loader=loader)
        assert result["key"] == "hello"


class TestRepoYamlLoader:
    """Tests for repo config YAML loader."""

    def test_secret_tag_parsed(self) -> None:
        """!secret tags produce _SecretRef objects."""
        import yaml

        loader = _make_repo_loader()
        result = yaml.load("key: !secret MY_SECRET", Loader=loader)
        assert isinstance(result["key"], _SecretRef)
        assert result["key"].name == "MY_SECRET"

    def test_env_tag_rejected(self) -> None:
        """!env tags raise ConfigError in repo config."""
        import yaml

        loader = _make_repo_loader()
        with pytest.raises(ConfigError, match="!env tags are not allowed"):
            yaml.load("key: !env MY_VAR", Loader=loader)

    def test_plain_values_unchanged(self) -> None:
        """Plain values load normally."""
        import yaml

        loader = _make_repo_loader()
        result = yaml.load("key: hello", Loader=loader)
        assert result["key"] == "hello"


# ---------------------------------------------------------------------------
# _resolve_string_list
# ---------------------------------------------------------------------------


class TestResolveStringList:
    """Tests for _resolve_string_list."""

    def test_normal_list(self) -> None:
        """Normal list of strings is returned as-is."""
        result = _resolve_string_list(["a@b.com", "c@d.com"])
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
            [_EnvVar("TEST_EMAIL"), "inline@test.com"]
        )
        assert result == ["env@test.com", "inline@test.com"]

    def test_empty_values_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty values (resolved or literal) are skipped."""
        monkeypatch.delenv("UNSET_VAR", raising=False)
        result = _resolve_string_list([_EnvVar("UNSET_VAR"), "valid@test.com"])
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
    master_repo: Path, tmp_path: Path, **overrides: object
) -> RepoServerConfig:
    """Create a minimal RepoServerConfig for testing.

    Email-specific overrides go into the EmailChannelConfig; repo-level
    overrides (repo_id, git_repo_url, secrets, masked_secrets, etc.) stay
    on RepoServerConfig.
    """
    email_fields = {
        "imap_server",
        "imap_port",
        "smtp_server",
        "smtp_port",
        "username",
        "password",
        "from_address",
        "authorized_senders",
        "trusted_authserv_id",
        "poll_interval_seconds",
        "use_imap_idle",
        "idle_reconnect_interval_seconds",
        "smtp_require_auth",
        "microsoft_internal_auth_fallback",
        "microsoft_oauth2_tenant_id",
        "microsoft_oauth2_client_id",
        "microsoft_oauth2_client_secret",
    }
    email_defaults: dict[str, object] = {
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "username": "test@example.com",
        "password": "secret123",
        "from_address": "Test <test@example.com>",
        "authorized_senders": ["authorized@example.com"],
        "trusted_authserv_id": "mx.example.com",
    }
    repo_defaults: dict[str, object] = {
        "repo_id": "test",
        "git_repo_url": str(master_repo),
    }

    for key, value in overrides.items():
        if key in email_fields:
            email_defaults[key] = value
        else:
            repo_defaults[key] = value

    email_config = EmailChannelConfig(**email_defaults)  # type: ignore[arg-type]
    return RepoServerConfig(channels={"email": email_config}, **repo_defaults)  # type: ignore[arg-type]


def test_repo_server_config_defaults(master_repo: Path, tmp_path: Path) -> None:
    """Test creating valid repo server configuration with defaults."""
    config = _make_repo_server_config(master_repo, tmp_path)

    assert config.repo_id == "test"
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.imap_server == "imap.example.com"
    assert email_ch.imap_port == 993
    assert email_ch.smtp_server == "smtp.example.com"
    assert email_ch.smtp_port == 587
    assert email_ch.username == "test@example.com"
    assert email_ch.password == "secret123"
    assert email_ch.authorized_senders == ["authorized@example.com"]
    assert config.git_repo_url == str(master_repo)
    assert config.storage_dir == get_storage_dir("test")
    assert email_ch.poll_interval_seconds == 60
    assert email_ch.use_imap_idle is True
    assert email_ch.idle_reconnect_interval_seconds == 29 * 60
    assert config.secrets == {}


def test_repo_server_config_with_custom_defaults(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with custom default values."""
    config = _make_repo_server_config(
        master_repo,
        tmp_path,
        poll_interval_seconds=30,
        use_imap_idle=False,
        idle_reconnect_interval_seconds=1800,
    )

    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.poll_interval_seconds == 30
    assert email_ch.use_imap_idle is False
    assert email_ch.idle_reconnect_interval_seconds == 1800


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
        password=password,
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
        password=password,
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
        imap_server="imap.example.com",
        imap_port=993,
        smtp_server="smtp.example.com",
        smtp_port=587,
        username="test@example.com",
        password="secret123",
        from_address="Test <test@example.com>",
        authorized_senders=["a@example.com"],
        trusted_authserv_id="mx.example.com",
    )
    assert config.channel_type == "email"


def test_repo_server_config_empty_channels() -> None:
    """RepoServerConfig rejects empty channels dict."""
    with pytest.raises(ValueError, match="at least one channel"):
        RepoServerConfig(
            repo_id="test",
            git_repo_url="https://example.com/r.git",
            channels={},
        )


def test_repo_server_config_empty_repo_url(tmp_path: Path) -> None:
    """Test repo server configuration with empty repository URL."""
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    with pytest.raises(ValueError, match="git.repo_url cannot be empty"):
        RepoServerConfig(
            repo_id="test",
            git_repo_url="",
            channels={
                "email": EmailChannelConfig(
                    imap_server="imap.example.com",
                    imap_port=993,
                    smtp_server="smtp.example.com",
                    smtp_port=587,
                    username="test@example.com",
                    password="secret123",
                    from_address="Test <test@example.com>",
                    authorized_senders=["authorized@example.com"],
                    trusted_authserv_id="mx.example.com",
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


def test_repo_server_config_invalid_poll_interval(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid poll interval."""
    with pytest.raises(ValueError, match="Poll interval must be >= 1s: 0"):
        _make_repo_server_config(master_repo, tmp_path, poll_interval_seconds=0)


def test_repo_server_config_invalid_idle_reconnect_interval(
    master_repo: Path, tmp_path: Path
) -> None:
    """Test repo server configuration with invalid IDLE reconnect interval."""
    with pytest.raises(
        ValueError, match="IDLE reconnect interval must be >= 60s"
    ):
        _make_repo_server_config(
            master_repo, tmp_path, idle_reconnect_interval_seconds=30
        )


# ---------------------------------------------------------------------------
# Microsoft OAuth2 config
# ---------------------------------------------------------------------------


def test_repo_server_config_oauth2_defaults(
    master_repo: Path, tmp_path: Path
) -> None:
    """Microsoft OAuth2 fields default to None."""
    config = _make_repo_server_config(master_repo, tmp_path)
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.microsoft_oauth2_tenant_id is None
    assert email_ch.microsoft_oauth2_client_id is None
    assert email_ch.microsoft_oauth2_client_secret is None


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
    assert email_ch.microsoft_oauth2_tenant_id == "tenant-123"
    assert email_ch.microsoft_oauth2_client_id == "client-456"
    assert email_ch.microsoft_oauth2_client_secret == "secret-789"


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
    """microsoft_internal_auth_fallback defaults to False."""
    config = _make_repo_server_config(master_repo, tmp_path)
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.microsoft_internal_auth_fallback is False


def test_repo_server_config_internal_auth_fallback_enabled(
    master_repo: Path, tmp_path: Path
) -> None:
    """microsoft_internal_auth_fallback can be set to True."""
    config = _make_repo_server_config(
        master_repo,
        tmp_path,
        microsoft_internal_auth_fallback=True,
    )
    email_ch = config.channels["email"]
    assert isinstance(email_ch, EmailChannelConfig)
    assert email_ch.microsoft_internal_auth_fallback is True


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
      imap_server: imap.test.com
      smtp_server: smtp.test.com
      username: user@test.com
      password: plain_password
      from: "Test <test@example.com>"
      authorized_senders:
        - auth@test.com
      trusted_authserv_id: mx.test.com
    git:
      repo_url: {repo_url}
"""

_FULL_YAML = """\
execution:
  max_concurrent: 5
  shutdown_timeout: 90
  conversation_max_age_days: 30
dashboard:
  enabled: false
  host: 0.0.0.0
  port: 8080
  base_url: https://dashboard.example.com
container_command: docker
repos:
  test:
    email:
      imap_server: imap.test.com
      imap_port: 143
      smtp_server: smtp.test.com
      smtp_port: 25
      username: user@test.com
      password: !env EMAIL_PASSWORD
      from: "Test <test@example.com>"
      authorized_senders:
        - auth@test.com
      trusted_authserv_id: mx.test.com
      imap:
        poll_interval: 45
        use_idle: false
        idle_reconnect_interval: 1800
    git:
      repo_url: {repo_url}
    secrets:
      GH_TOKEN: !env GH_TOKEN
      R2_ACCOUNT_ID: test-account
"""


class TestServerConfigValidation:
    """Tests for ServerConfig cross-repo validation."""

    def _repo(
        self, repo_id: str, tmp_path: Path, **overrides: object
    ) -> RepoServerConfig:
        email_defaults: dict[str, object] = {
            "imap_server": "imap.example.com",
            "imap_port": 993,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": f"{repo_id}@example.com",
            "password": "secret",
            "from_address": f"<{repo_id}@example.com>",
            "authorized_senders": ["auth@example.com"],
            "trusted_authserv_id": "mx.example.com",
        }
        email_overrides = {
            k: v for k, v in overrides.items() if k in email_defaults
        }
        email_defaults.update(email_overrides)
        return RepoServerConfig(
            repo_id=repo_id,
            git_repo_url="https://example.com/repo.git",
            channels={"email": EmailChannelConfig(**email_defaults)},  # type: ignore[arg-type]
        )

    def test_empty_repos_rejected(self, tmp_path: Path) -> None:
        """At least one repo must be configured."""
        with pytest.raises(ConfigError, match="At least one repo"):
            ServerConfig(global_config=GlobalConfig(), repos={})

    def test_non_email_channel_skipped_in_inbox_check(
        self, tmp_path: Path
    ) -> None:
        """Non-email channels are skipped during IMAP inbox validation."""
        r1 = self._repo("a", tmp_path)
        # Simulate a non-email channel config
        mock_channel = MagicMock(spec=[])
        mock_channel.channel_type = "slack"
        mock_channel.channel_info = "slack-channel"
        r2 = RepoServerConfig(
            repo_id="b",
            git_repo_url="https://example.com/repo.git",
            channels={"slack": mock_channel},
        )
        # Should not raise — the non-email repo is skipped
        ServerConfig(global_config=GlobalConfig(), repos={"a": r1, "b": r2})

    def test_duplicate_inbox_rejected(self, tmp_path: Path) -> None:
        """Two repos sharing the same IMAP inbox are rejected."""
        r1 = self._repo("a", tmp_path)
        r2 = self._repo("b", tmp_path, username="a@example.com")
        with pytest.raises(ConfigError, match="same IMAP inbox"):
            ServerConfig(global_config=GlobalConfig(), repos={"a": r1, "b": r2})


class TestFromYaml:
    """Tests for ServerConfig.from_yaml loading."""

    def test_minimal_config(self, master_repo: Path, tmp_path: Path) -> None:
        """Load minimal YAML with defaults."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]

        # Global config defaults
        assert config.global_config.max_concurrent_executions == 3
        assert config.global_config.shutdown_timeout_seconds == 60
        assert config.global_config.conversation_max_age_days == 7
        assert config.global_config.dashboard_enabled is True
        assert config.global_config.dashboard_host == "127.0.0.1"
        assert config.global_config.dashboard_port == 5200
        assert config.global_config.dashboard_base_url is None
        assert config.global_config.container_command == "podman"

        # Repo config
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap_server == "imap.test.com"
        assert email_ch.imap_port == 993
        assert email_ch.smtp_port == 587
        assert email_ch.password == "plain_password"
        assert email_ch.poll_interval_seconds == 60
        assert email_ch.use_imap_idle is True
        assert repo.secrets == {}

    def test_full_config(self, master_repo: Path, tmp_path: Path) -> None:
        """Load fully specified YAML."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_FULL_YAML.format(repo_url=master_repo))

        with patch.dict(
            "os.environ",
            {"EMAIL_PASSWORD": "env_pw", "GH_TOKEN": "ghp_tok"},
        ):
            config = ServerConfig.from_yaml(yaml_path)

        repo = config.repos["test"]

        # Global config
        assert config.global_config.max_concurrent_executions == 5
        assert config.global_config.shutdown_timeout_seconds == 90
        assert config.global_config.conversation_max_age_days == 30
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
        assert email_ch.imap_port == 143
        assert email_ch.smtp_port == 25
        assert email_ch.password == "env_pw"
        assert email_ch.poll_interval_seconds == 45
        assert email_ch.use_imap_idle is False
        assert email_ch.idle_reconnect_interval_seconds == 1800
        assert repo.secrets == {
            "GH_TOKEN": "ghp_tok",
            "R2_ACCOUNT_ID": "test-account",
        }

    def test_network_sandbox_enabled_default(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """network_sandbox_enabled defaults to True when not specified."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))
        config = ServerConfig.from_yaml(yaml_path)
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
        config = ServerConfig.from_yaml(yaml_path)
        assert config.repos["test"].network_sandbox_enabled is False

    def test_missing_file(self, tmp_path: Path) -> None:
        """Raise ConfigError when file does not exist."""
        with pytest.raises(ConfigError, match="Config file not found"):
            ServerConfig.from_yaml(tmp_path / "nonexistent.yaml")

    def test_missing_required_field(self, tmp_path: Path) -> None:
        """Raise ConfigError when required field is missing."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            "repos:\n  test:\n    email:\n      imap_server: test\n"
        )

        with pytest.raises(ConfigError, match="email.smtp_server"):
            ServerConfig.from_yaml(yaml_path)

    def test_missing_env_var(self, master_repo: Path, tmp_path: Path) -> None:
        """Raise ConfigError when !env var is not set."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            _MINIMAL_YAML.format(repo_url=master_repo).replace(
                "plain_password", "!env MISSING_VAR"
            )
        )

        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError, match="MISSING_VAR"):
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
            config = ServerConfig.from_yaml(yaml_path)

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

        config = ServerConfig.from_yaml(yaml_path)
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
            config = ServerConfig.from_yaml()

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.imap_server == "imap.test.com"

    def test_env_override_bool_field(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """!env works for bool fields like use_idle."""
        yaml_content = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "      trusted_authserv_id: mx.test.com\n",
            "      trusted_authserv_id: mx.test.com\n"
            "      imap:\n        use_idle: !env USE_IDLE\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict("os.environ", {"USE_IDLE": "false"}):
            config = ServerConfig.from_yaml(yaml_path)

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.use_imap_idle is False

    def test_env_override_int_field(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """!env works for int fields like poll_interval."""
        yaml_content = _MINIMAL_YAML.format(repo_url=master_repo).replace(
            "      trusted_authserv_id: mx.test.com\n",
            "      trusted_authserv_id: mx.test.com\n"
            "      imap:\n        poll_interval: !env POLL_INTERVAL\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        with patch.dict("os.environ", {"POLL_INTERVAL": "120"}):
            config = ServerConfig.from_yaml(yaml_path)

        email_ch = config.repos["test"].channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.poll_interval_seconds == 120

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

        with patch("airut.gateway.config.load_dotenv_once") as mock_dotenv:
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
        # Insert after the from: line (last line of email: section)
        yaml_content = base.replace(
            '      from: "Test <test@example.com>"\n',
            '      from: "Test <test@example.com>"\n' + oauth2_block,
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2_tenant_id == "my-tenant"
        assert email_ch.microsoft_oauth2_client_id == "my-client"
        assert email_ch.microsoft_oauth2_client_secret == "my-secret"

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
            '      from: "Test <test@example.com>"\n',
            '      from: "Test <test@example.com>"\n' + oauth2_block,
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
            config = ServerConfig.from_yaml(yaml_path)

        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2_tenant_id == "env-tenant"
        assert email_ch.microsoft_oauth2_client_id == "env-client"
        assert email_ch.microsoft_oauth2_client_secret == "env-secret"

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
            "      password: plain_password\n", ""
        )
        yaml_content = base.replace(
            '      from: "Test <test@example.com>"\n',
            '      from: "Test <test@example.com>"\n' + oauth2_block,
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.password == ""
        assert email_ch.microsoft_oauth2_tenant_id == "my-tenant"

    def test_microsoft_oauth2_absent_defaults_none(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Without microsoft_oauth2 block, fields default to None."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]

        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_oauth2_tenant_id is None
        assert email_ch.microsoft_oauth2_client_id is None
        assert email_ch.microsoft_oauth2_client_secret is None

    def test_internal_auth_fallback_from_yaml(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """microsoft_internal_auth_fallback parsed from YAML."""
        base = _MINIMAL_YAML.format(repo_url=master_repo)
        yaml_content = base.replace(
            "      trusted_authserv_id: mx.test.com\n",
            "      trusted_authserv_id: mx.test.com\n"
            "      microsoft_internal_auth_fallback: true\n",
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_internal_auth_fallback is True

    def test_internal_auth_fallback_default_false(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """microsoft_internal_auth_fallback defaults to False."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(_MINIMAL_YAML.format(repo_url=master_repo))

        config = ServerConfig.from_yaml(yaml_path)
        repo = config.repos["test"]
        email_ch = repo.channels["email"]
        assert isinstance(email_ch, EmailChannelConfig)
        assert email_ch.microsoft_internal_auth_fallback is False

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
            "    git:\n"
            f"      repo_url: {master_repo}\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="must be nested under 'email:'"):
            ServerConfig.from_yaml(yaml_path)

    def test_missing_email_block_rejected(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """Repo with no email block is rejected."""
        yaml_content = (
            f"repos:\n  test:\n    git:\n      repo_url: {master_repo}\n"
        )
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml_content)
        with pytest.raises(ConfigError, match="no channel configured"):
            ServerConfig.from_yaml(yaml_path)


# ---------------------------------------------------------------------------
# RepoConfig
# ---------------------------------------------------------------------------


class TestRepoConfigDirect:
    """Tests for direct RepoConfig construction."""

    def test_defaults(self) -> None:
        """Defaults are sensible."""
        rc = RepoConfig()
        assert rc.default_model == "opus"
        assert rc.timeout == 300
        assert rc.network_sandbox_enabled is True
        assert rc.container_env == {}

    def test_custom_values(self) -> None:
        """Custom values are preserved."""
        rc = RepoConfig(
            default_model="sonnet",
            timeout=600,
            network_sandbox_enabled=False,
            container_env={"KEY": "val"},
        )
        assert rc.default_model == "sonnet"
        assert rc.timeout == 600
        assert rc.network_sandbox_enabled is False
        assert rc.container_env == {"KEY": "val"}

    def test_invalid_timeout(self) -> None:
        """Timeout < 10 raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be >= 10s: 5"):
            RepoConfig(timeout=5)

    def test_container_env_redaction(self) -> None:
        """Container env values are registered for log redaction."""
        SecretFilter._secrets.clear()
        RepoConfig(container_env={"SECRET": "my-secret-val"})
        assert "my-secret-val" in SecretFilter._secrets


class TestRepoConfigFromRaw:
    """Tests for RepoConfig._from_raw."""

    def test_minimal(self) -> None:
        """Minimal repo config with defaults."""
        raw: dict = {}
        rc, replacement_map = RepoConfig._from_raw(raw, {}, {})
        assert rc.default_model == "opus"
        assert rc.timeout == 300
        assert rc.network_sandbox_enabled is True
        assert rc.container_env == {}
        assert replacement_map == {}

    def test_full(self) -> None:
        """Full repo config with all fields."""
        raw = {
            "default_model": "sonnet",
            "timeout": 6000,
            "network": {"sandbox_enabled": False},
            "container_env": {
                "INLINE": "value",
                "FROM_SERVER": _SecretRef("GH_TOKEN"),
            },
        }
        secrets = {"GH_TOKEN": "ghp_tok"}
        rc, replacement_map = RepoConfig._from_raw(raw, secrets, {})
        assert rc.default_model == "sonnet"
        assert rc.timeout == 6000
        assert rc.network_sandbox_enabled is False
        assert rc.container_env == {
            "INLINE": "value",
            "FROM_SERVER": "ghp_tok",
        }
        assert replacement_map == {}

    def test_server_sandbox_false_overrides_repo_true(self) -> None:
        """Server sandbox_enabled=false disables even when repo is true."""
        raw: dict = {}
        rc, _ = RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=False)
        assert rc.network_sandbox_enabled is False

    def test_repo_sandbox_false_overrides_server_true(self) -> None:
        """Repo sandbox_enabled=false disables even when server is true."""
        raw = {"network": {"sandbox_enabled": False}}
        rc, _ = RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=True)
        assert rc.network_sandbox_enabled is False

    def test_both_sandbox_false(self) -> None:
        """Both false results in disabled."""
        raw = {"network": {"sandbox_enabled": False}}
        rc, _ = RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=False)
        assert rc.network_sandbox_enabled is False

    def test_both_sandbox_true(self) -> None:
        """Both true results in enabled."""
        raw: dict = {}
        rc, _ = RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=True)
        assert rc.network_sandbox_enabled is True

    def test_server_sandbox_default_is_true(self) -> None:
        """server_sandbox_enabled defaults to True when not passed."""
        raw: dict = {}
        rc, _ = RepoConfig._from_raw(raw, {}, {})
        assert rc.network_sandbox_enabled is True

    def test_warning_logged_when_server_disables_sandbox(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning logged when server config disables sandbox."""
        raw: dict = {}
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=False)
        assert "sandbox disabled" in caplog.text.lower()
        assert "server=False" in caplog.text
        assert "repo=True" in caplog.text

    def test_warning_logged_when_repo_disables_sandbox(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning logged when repo config disables sandbox."""
        raw = {"network": {"sandbox_enabled": False}}
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=True)
        assert "sandbox disabled" in caplog.text.lower()
        assert "server=True" in caplog.text
        assert "repo=False" in caplog.text

    def test_warning_logged_when_both_disable_sandbox(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning logged when both sides disable sandbox."""
        raw = {"network": {"sandbox_enabled": False}}
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=False)
        assert "sandbox disabled" in caplog.text.lower()
        assert "server=False" in caplog.text
        assert "repo=False" in caplog.text

    def test_no_warning_when_sandbox_enabled(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No warning when sandbox is enabled."""
        raw: dict = {}
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(raw, {}, {}, server_sandbox_enabled=True)
        assert "sandbox disabled" not in caplog.text.lower()

    def test_warning_logged_when_sandbox_disabled_with_masked_secrets(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning when sandbox disabled but masked secrets are configured."""
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken1234",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        raw = {
            "container_env": {"GH_TOKEN": _SecretRef("GH_TOKEN")},
        }
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(
                raw, {}, masked_secrets, server_sandbox_enabled=False
            )
        assert "masked secrets are configured" in caplog.text

    def test_no_masked_warning_when_sandbox_enabled(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No masked secrets warning when sandbox is enabled."""
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken1234",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        raw = {
            "container_env": {"GH_TOKEN": _SecretRef("GH_TOKEN")},
        }
        with caplog.at_level(logging.WARNING, logger="airut.gateway.config"):
            RepoConfig._from_raw(
                raw, {}, masked_secrets, server_sandbox_enabled=True
            )
        assert "masked secrets are configured" not in caplog.text


class TestRepoConfigFromMirror:
    """Tests for RepoConfig.from_mirror."""

    def test_loads_from_mirror(self) -> None:
        """Loads and parses config from git mirror."""
        mirror = MagicMock()
        mirror.read_file.return_value = "default_model: sonnet\ntimeout: 600\n"
        rc, replacement_map = RepoConfig.from_mirror(mirror, {})
        mirror.read_file.assert_called_once_with(".airut/airut.yaml")
        assert rc.default_model == "sonnet"
        assert replacement_map == {}

    def test_mirror_read_error(self) -> None:
        """Mirror read failure raises ConfigError."""
        mirror = MagicMock()
        mirror.read_file.side_effect = RuntimeError("not found")
        with pytest.raises(ConfigError, match="Failed to read repo config"):
            RepoConfig.from_mirror(mirror, {})

    def test_env_tag_rejected(self) -> None:
        """!env tags in repo config raise ConfigError."""
        mirror = MagicMock()
        mirror.read_file.return_value = "timeout: !env MY_TIMEOUT\n"
        with pytest.raises(ConfigError, match="!env tags are not allowed"):
            RepoConfig.from_mirror(mirror, {})

    def test_not_a_mapping(self) -> None:
        """Non-mapping YAML raises ConfigError."""
        mirror = MagicMock()
        mirror.read_file.return_value = "- item1\n- item2\n"
        with pytest.raises(ConfigError, match="YAML mapping"):
            RepoConfig.from_mirror(mirror, {})

    def test_secret_resolved(self) -> None:
        """!secret tags resolve from server secrets pool."""
        mirror = MagicMock()
        mirror.read_file.return_value = (
            "container_env:\n  MY_KEY: !secret SERVER_KEY\n"
        )
        rc, _ = RepoConfig.from_mirror(mirror, {"SERVER_KEY": "secret-val"})
        assert rc.container_env == {"MY_KEY": "secret-val"}

    def test_unknown_secret_raises(self) -> None:
        """Unknown !secret reference raises ConfigError."""
        mirror = MagicMock()
        mirror.read_file.return_value = (
            "container_env:\n  MY_KEY: !secret UNKNOWN\n"
        )
        with pytest.raises(ConfigError, match="!secret 'UNKNOWN' not found"):
            RepoConfig.from_mirror(mirror, {})

    def test_optional_secret_missing_skipped(self) -> None:
        """!secret? tag with missing secret is silently skipped."""
        mirror = MagicMock()
        mirror.read_file.return_value = (
            "container_env:\n  MY_KEY: !secret? MISSING\n"
        )
        rc, _ = RepoConfig.from_mirror(mirror, {})
        assert rc.container_env == {}

    def test_optional_secret_present_resolved(self) -> None:
        """!secret? tag with present secret is resolved."""
        mirror = MagicMock()
        mirror.read_file.return_value = (
            "container_env:\n  MY_KEY: !secret? SERVER_KEY\n"
        )
        rc, _ = RepoConfig.from_mirror(mirror, {"SERVER_KEY": "secret-val"})
        assert rc.container_env == {"MY_KEY": "secret-val"}

    def test_secret_empty_string_resolved(self) -> None:
        """!secret tag with empty string value resolves successfully."""
        mirror = MagicMock()
        mirror.read_file.return_value = (
            "container_env:\n  MY_KEY: !secret SERVER_KEY\n"
        )
        rc, _ = RepoConfig.from_mirror(mirror, {"SERVER_KEY": ""})
        assert rc.container_env == {"MY_KEY": ""}

    def test_secret_tag_outside_container_env_raises(self) -> None:
        """!secret tag outside container_env raises ConfigError."""
        mirror = MagicMock()
        mirror.read_file.return_value = "default_model: !secret MODEL\n"
        with pytest.raises(ConfigError, match="!secret.*outside container_env"):
            RepoConfig.from_mirror(mirror, {"MODEL": "sonnet"})

    def test_optional_secret_tag_outside_container_env_raises(self) -> None:
        """!secret? tag outside container_env raises ConfigError."""
        mirror = MagicMock()
        mirror.read_file.return_value = "timeout: !secret? TIMEOUT\n"
        with pytest.raises(ConfigError, match="!secret.*outside container_env"):
            RepoConfig.from_mirror(mirror, {})

    def test_secret_tag_in_nested_list_raises(self) -> None:
        """!secret tag nested inside a list outside container_env raises."""
        mirror = MagicMock()
        mirror.read_file.return_value = "extra:\n  - !secret NESTED_SECRET\n"
        with pytest.raises(ConfigError, match="!secret.*outside container_env"):
            RepoConfig.from_mirror(mirror, {"NESTED_SECRET": "val"})

    def test_server_sandbox_override(self) -> None:
        """server_sandbox_enabled=False overrides repo default."""
        mirror = MagicMock()
        mirror.read_file.return_value = "default_model: opus\n"
        rc, _ = RepoConfig.from_mirror(mirror, {}, server_sandbox_enabled=False)
        assert rc.network_sandbox_enabled is False

    def test_server_sandbox_default_true(self) -> None:
        """server_sandbox_enabled defaults to True."""
        mirror = MagicMock()
        mirror.read_file.return_value = "default_model: opus\n"
        rc, _ = RepoConfig.from_mirror(mirror, {})
        assert rc.network_sandbox_enabled is True


# ---------------------------------------------------------------------------
# _resolve_container_env
# ---------------------------------------------------------------------------


class TestResolveContainerEnv:
    """Tests for _resolve_container_env."""

    def test_inline_values(self) -> None:
        """Inline string values pass through."""
        result, replacement_map = _resolve_container_env({"K": "v"}, {}, {})
        assert result == {"K": "v"}
        assert replacement_map == {}

    def test_secret_refs(self) -> None:
        """SecretRef values resolve from server secrets."""
        result, replacement_map = _resolve_container_env(
            {"K": _SecretRef("S")}, {"S": "val"}, {}
        )
        assert result == {"K": "val"}
        assert replacement_map == {}

    def test_missing_secret_raises(self) -> None:
        """Missing secret raises ConfigError."""
        with pytest.raises(ConfigError, match="not found"):
            _resolve_container_env({"K": _SecretRef("S")}, {}, {})

    def test_empty_values_skipped(self) -> None:
        """Empty inline values are skipped."""
        result, _ = _resolve_container_env({"K": None}, {}, {})
        assert result == {}

    def test_empty_string_secret_resolved(self) -> None:
        """Secret configured with empty string is a valid value."""
        result, _ = _resolve_container_env(
            {"K": _SecretRef("S")}, {"S": ""}, {}
        )
        assert result == {"K": ""}

    def test_missing_required_secret_not_in_pool_raises(self) -> None:
        """Required !secret for name absent from server pool raises."""
        with pytest.raises(ConfigError, match="not found"):
            _resolve_container_env(
                {"K": _SecretRef("NOPE")}, {"OTHER": "v"}, {}
            )

    def test_optional_secret_empty_string_resolved(self) -> None:
        """Optional !secret? with empty string value resolves it."""
        result, _ = _resolve_container_env(
            {"K": _SecretRef("S", optional=True)}, {"S": ""}, {}
        )
        assert result == {"K": ""}

    def test_optional_secret_missing_skipped(self) -> None:
        """Missing optional secret (!secret?) is silently skipped."""
        result, _ = _resolve_container_env(
            {"K": _SecretRef("S", optional=True)}, {}, {}
        )
        assert result == {}

    def test_optional_secret_present_resolved(self) -> None:
        """Present optional secret (!secret?) is resolved normally."""
        result, _ = _resolve_container_env(
            {"K": _SecretRef("S", optional=True)}, {"S": "val"}, {}
        )
        assert result == {"K": "val"}

    def test_mixed_required_optional_secrets(self) -> None:
        """Mix of required and optional secrets works correctly."""
        raw = {
            "REQ": _SecretRef("REQUIRED"),
            "OPT_PRESENT": _SecretRef("OPTIONAL_A", optional=True),
            "OPT_MISSING": _SecretRef("OPTIONAL_B", optional=True),
        }
        secrets = {"REQUIRED": "req-val", "OPTIONAL_A": "opt-val"}
        result, _ = _resolve_container_env(raw, secrets, {})
        # Required + present optional resolved; missing optional skipped
        assert result == {"REQ": "req-val", "OPT_PRESENT": "opt-val"}

    def test_empty_string_masked_secret_resolved(self) -> None:
        """Masked secret with empty string value is resolved."""
        masked = {
            "S": MaskedSecret(
                value="",
                scopes=frozenset(["api.example.com"]),
                headers=("*",),
            )
        }
        # Empty string is still a valid configured value — should be set
        result, rmap = _resolve_container_env(
            {"K": _SecretRef("S")}, {}, masked
        )
        assert result == {"K": ""}
        assert rmap == {}

    def test_missing_masked_required_secret_raises(self) -> None:
        """Required !secret absent from masked pool and plain pool raises."""
        masked = {
            "OTHER": MaskedSecret(
                value="val",
                scopes=frozenset(["api.example.com"]),
                headers=("*",),
            )
        }
        with pytest.raises(ConfigError, match="not found"):
            _resolve_container_env({"K": _SecretRef("NOPE")}, {}, masked)


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


# ---------------------------------------------------------------------------
# Masked secrets in container_env resolution
# ---------------------------------------------------------------------------


class TestMaskedSecretResolution:
    """Tests for masked secrets in _resolve_container_env."""

    def test_masked_secret_generates_surrogate(self) -> None:
        """Masked secret generates surrogate in container_env."""
        raw_env = {"GH_TOKEN": _SecretRef("GH_TOKEN")}
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_realtoken1234",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _resolve_container_env(
            raw_env, {}, masked_secrets
        )

        # container_env should have a surrogate, not the real value
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
        raw_env = {"API_KEY": _SecretRef("API_KEY")}
        masked_secrets = {
            "API_KEY": MaskedSecret(
                value="secret_value",
                scopes=frozenset(["api.example.com"]),
                headers=("X-Custom-Header",),
            )
        }
        result, replacement_map = _resolve_container_env(
            raw_env, {}, masked_secrets
        )

        surrogate = result["API_KEY"]
        entry = replacement_map[surrogate]
        assert isinstance(entry, ReplacementEntry)
        assert entry.headers == ("X-Custom-Header",)

    def test_masked_secret_takes_priority_over_plain(self) -> None:
        """Masked secret is used even if plain secret exists."""
        raw_env = {"GH_TOKEN": _SecretRef("GH_TOKEN")}
        plain_secrets = {"GH_TOKEN": "plain_value"}
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="masked_value",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _resolve_container_env(
            raw_env, plain_secrets, masked_secrets
        )

        # Should use masked secret, not plain
        assert result["GH_TOKEN"] != "plain_value"
        assert result["GH_TOKEN"] != "masked_value"
        assert len(replacement_map) == 1

    def test_plain_secret_used_when_not_masked(self) -> None:
        """Plain secret is used when no masked secret exists."""
        raw_env = {"API_KEY": _SecretRef("API_KEY")}
        plain_secrets = {"API_KEY": "plain_key"}
        result, replacement_map = _resolve_container_env(
            raw_env, plain_secrets, {}
        )

        assert result == {"API_KEY": "plain_key"}
        assert replacement_map == {}

    def test_mixed_masked_and_plain(self) -> None:
        """Mix of masked and plain secrets works correctly."""
        raw_env = {
            "GH_TOKEN": _SecretRef("GH_TOKEN"),
            "API_KEY": _SecretRef("API_KEY"),
        }
        plain_secrets = {"API_KEY": "plain_api_key"}
        masked_secrets = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_secret",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }
        result, replacement_map = _resolve_container_env(
            raw_env, plain_secrets, masked_secrets
        )

        # GH_TOKEN should be masked, API_KEY should be plain
        assert result["GH_TOKEN"] != "ghp_secret"
        assert result["API_KEY"] == "plain_api_key"
        assert len(replacement_map) == 1


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
        from airut.gateway.config import _EnvVar

        monkeypatch.setenv("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")
        monkeypatch.setenv("AWS_SECRET", "secretkey")
        raw = {
            "AWS": {
                "type": SIGNING_TYPE_AWS_SIGV4,
                "access_key_id": {
                    "name": "AWS_ACCESS_KEY_ID",
                    "value": _EnvVar("AWS_KEY"),
                },
                "secret_access_key": {
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "value": _EnvVar("AWS_SECRET"),
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
# Signing credential resolution in _resolve_container_env
# ---------------------------------------------------------------------------


class TestSigningCredentialResolution:
    """Tests for signing credentials in _resolve_container_env."""

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
        """Signing credential fields generate surrogates via !secret."""
        raw_env = {
            "AWS_ACCESS_KEY_ID": _SecretRef("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": _SecretRef("AWS_SECRET_ACCESS_KEY"),
        }
        signing_creds = {"AWS_PROD": self._make_signing_cred()}

        result, replacement_map = _resolve_container_env(
            raw_env, {}, {}, signing_credentials=signing_creds
        )

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
        raw_env = {
            "AWS_ACCESS_KEY_ID": _SecretRef("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": _SecretRef("AWS_SECRET_ACCESS_KEY"),
            "AWS_SESSION_TOKEN": _SecretRef("AWS_SESSION_TOKEN"),
        }
        signing_creds = {
            "AWS": self._make_signing_cred(session_token="real-token-value")
        }

        result, replacement_map = _resolve_container_env(
            raw_env, {}, {}, signing_credentials=signing_creds
        )

        # Session token surrogate should be 512 chars
        assert len(result["AWS_SESSION_TOKEN"]) == 512

        # Entry should have real and surrogate session tokens
        surrogate_key_id = result["AWS_ACCESS_KEY_ID"]
        entry = replacement_map[surrogate_key_id]
        assert isinstance(entry, SigningCredentialEntry)
        assert entry.session_token == "real-token-value"
        assert entry.surrogate_session_token == result["AWS_SESSION_TOKEN"]

    def test_optional_session_token_skipped(self) -> None:
        """Missing session token with !secret? is silently skipped."""
        raw_env = {
            "AWS_ACCESS_KEY_ID": _SecretRef("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": _SecretRef("AWS_SECRET_ACCESS_KEY"),
            "AWS_SESSION_TOKEN": _SecretRef("AWS_SESSION_TOKEN", optional=True),
        }
        signing_creds = {"AWS": self._make_signing_cred()}

        result, replacement_map = _resolve_container_env(
            raw_env, {}, {}, signing_credentials=signing_creds
        )

        # session_token is None, so !secret? resolves to nothing; secret name
        # falls through to plain secrets where it's also not found; optional
        # so silently skipped.
        assert "AWS_SESSION_TOKEN" not in result
        surrogate_key_id = result["AWS_ACCESS_KEY_ID"]
        entry = replacement_map[surrogate_key_id]
        assert isinstance(entry, SigningCredentialEntry)
        assert entry.session_token is None
        assert entry.surrogate_session_token is None

    def test_missing_key_id_mapping_raises(self) -> None:
        """Referencing only secret_access_key without key_id raises."""
        raw_env = {
            "AWS_SECRET": _SecretRef("AWS_SECRET_ACCESS_KEY"),
        }
        signing_creds = {"AWS": self._make_signing_cred()}

        with pytest.raises(ConfigError, match="access_key_id.*not mapped"):
            _resolve_container_env(
                raw_env, {}, {}, signing_credentials=signing_creds
            )

    def test_unknown_secret_name_falls_through(self) -> None:
        """Secret name not matching any signing field falls through."""
        raw_env = {
            "AWS_ACCESS_KEY_ID": _SecretRef("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": _SecretRef("AWS_SECRET_ACCESS_KEY"),
            "OTHER": _SecretRef("NONEXISTENT_SECRET", optional=True),
        }
        signing_creds = {"AWS": self._make_signing_cred()}

        result, _ = _resolve_container_env(
            raw_env, {}, {}, signing_credentials=signing_creds
        )

        # NONEXISTENT_SECRET is not in any pool; optional, so silently skipped.
        assert "OTHER" not in result

    def test_mixed_signing_and_masked(self) -> None:
        """Signing credentials coexist with masked secrets."""
        raw_env = {
            "AWS_ACCESS_KEY_ID": _SecretRef("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": _SecretRef("AWS_SECRET_ACCESS_KEY"),
            "GH_TOKEN": _SecretRef("GH_TOKEN"),
        }
        signing_creds = {"AWS": self._make_signing_cred()}
        masked = {
            "GH_TOKEN": MaskedSecret(
                value="ghp_real",
                scopes=frozenset(["api.github.com"]),
                headers=("Authorization",),
            )
        }

        result, replacement_map = _resolve_container_env(
            raw_env, {}, masked, signing_credentials=signing_creds
        )

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
