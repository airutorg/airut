# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox_cli.py -- CLI entry point for airut-sandbox."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airut.sandbox.secrets import (
    MaskedSecret,
    PreparedSecrets,
    SecretReplacements,
)
from airut.sandbox.types import (
    CommandResult,
    ResourceLimits,
)
from airut.sandbox_cli import (
    EXIT_INFRA_ERROR,
    EXIT_TIMEOUT,
    _build_container_env,
    _execute,
    _install_signal_handlers,
    _load_allowlist,
    _load_config,
    _map_exit_code,
    _parse_args,
    _parse_env,
    _parse_masked_secrets,
    _parse_mount,
    _parse_network_sandbox,
    _parse_pass_env,
    _parse_resource_limits,
    _parse_signing_credentials,
    _require_env,
    _run,
    _setup_logging,
    _setup_network_log,
    main,
)
from airut.yaml_env import EnvVar


# -------------------------------------------------------------------
# _parse_args
# -------------------------------------------------------------------


class TestParseArgs:
    """Tests for CLI argument parsing."""

    def test_run_with_double_dash_separator(self) -> None:
        """Arguments split on -- with command after."""
        args = _parse_args(["run", "--", "ls", "-la"])
        assert args.subcommand == "run"
        assert args.command == ["ls", "-la"]

    def test_run_without_double_dash(self) -> None:
        """No -- means empty command list."""
        args = _parse_args(["run"])
        assert args.subcommand == "run"
        assert args.command == []

    def test_no_subcommand(self) -> None:
        """No subcommand returns None."""
        args = _parse_args([])
        assert args.subcommand is None
        assert args.command == []

    def test_run_all_options(self, tmp_path: Path) -> None:
        """All CLI options are parsed correctly."""
        config = tmp_path / "config.yaml"
        config.touch()
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.touch()
        context = tmp_path / "context"
        context.mkdir()
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.touch()
        netlog = tmp_path / "net.log"

        args = _parse_args(
            [
                "run",
                "--config",
                str(config),
                "--dockerfile",
                str(dockerfile),
                "--context-dir",
                str(context),
                "--allowlist",
                str(allowlist),
                "--timeout",
                "300",
                "--container-command",
                "docker",
                "--mount",
                "/src:/dst",
                "--mount",
                "/a:/b:ro",
                "--network-log",
                str(netlog),
                "--verbose",
                "--",
                "echo",
                "hello",
            ]
        )
        assert args.subcommand == "run"
        assert args.config == config
        assert args.dockerfile == dockerfile
        assert args.context_dir == context
        assert args.allowlist == allowlist
        assert args.timeout == 300
        assert args.container_command == "docker"
        assert args.mount == ["/src:/dst", "/a:/b:ro"]
        assert args.network_log == netlog
        assert args.verbose is True
        assert args.command == ["echo", "hello"]

    def test_debug_flag(self) -> None:
        """Debug flag is parsed correctly."""
        args = _parse_args(["run", "--debug", "--", "cmd"])
        assert args.debug is True

    def test_log_flag(self, tmp_path: Path) -> None:
        """--log flag is parsed correctly."""
        log_path = tmp_path / "sandbox.log"
        args = _parse_args(["run", "--log", str(log_path), "--", "cmd"])
        assert args.log == log_path

    def test_defaults(self) -> None:
        """Default values are None/False/[]."""
        args = _parse_args(["run", "--", "cmd"])
        assert args.config is None
        assert args.dockerfile is None
        assert args.context_dir is None
        assert args.allowlist is None
        assert args.timeout is None
        assert args.container_command is None
        assert args.mount == []
        assert args.network_log is None
        assert args.log is None
        assert args.verbose is False
        assert args.debug is False

    def test_double_dash_no_command(self) -> None:
        """Double dash with nothing after yields empty command."""
        args = _parse_args(["run", "--"])
        assert args.command == []


# -------------------------------------------------------------------
# _setup_logging
# -------------------------------------------------------------------


class TestSetupLogging:
    """Tests for logging configuration."""

    def _cleanup_root_logger(self) -> None:
        """Remove handlers added by _setup_logging from root logger."""
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
            h.close()

    def test_default_level(self) -> None:
        """Default level is ERROR (quiet by default)."""
        _setup_logging()
        try:
            root = logging.getLogger()
            assert root.level == logging.ERROR
        finally:
            self._cleanup_root_logger()

    def test_verbose_level(self) -> None:
        """Verbose enables INFO level."""
        _setup_logging(verbose=True)
        try:
            root = logging.getLogger()
            assert root.level == logging.INFO
        finally:
            self._cleanup_root_logger()

    def test_debug_level(self) -> None:
        """Debug enables DEBUG level."""
        _setup_logging(debug=True)
        try:
            root = logging.getLogger()
            assert root.level == logging.DEBUG
        finally:
            self._cleanup_root_logger()

    def test_debug_overrides_verbose(self) -> None:
        """Debug takes precedence over verbose."""
        _setup_logging(verbose=True, debug=True)
        try:
            root = logging.getLogger()
            assert root.level == logging.DEBUG
        finally:
            self._cleanup_root_logger()

    def test_stream_is_stderr(self) -> None:
        """Default output goes to stderr via StreamHandler."""
        _setup_logging()
        try:
            root = logging.getLogger()
            handler = root.handlers[-1]
            assert isinstance(handler, logging.StreamHandler)
            assert handler.stream is sys.stderr
        finally:
            self._cleanup_root_logger()

    def test_log_file(self, tmp_path: Path) -> None:
        """--log PATH writes to a file via FileHandler."""
        log_path = tmp_path / "sandbox.log"
        _setup_logging(log_file=log_path)
        try:
            root = logging.getLogger()
            handler = root.handlers[-1]
            assert isinstance(handler, logging.FileHandler)
            assert Path(handler.baseFilename) == log_path.resolve()
        finally:
            self._cleanup_root_logger()

    def test_log_file_creates_parents(self, tmp_path: Path) -> None:
        """--log PATH creates parent directories."""
        log_path = tmp_path / "deep" / "nested" / "sandbox.log"
        _setup_logging(log_file=log_path)
        try:
            assert log_path.parent.exists()
        finally:
            self._cleanup_root_logger()

    def test_log_file_appends(self, tmp_path: Path) -> None:
        """--log PATH appends to existing file."""
        log_path = tmp_path / "sandbox.log"
        log_path.write_text("existing content\n")
        _setup_logging(log_file=log_path)
        try:
            root = logging.getLogger()
            handler = root.handlers[-1]
            assert isinstance(handler, logging.FileHandler)
            assert handler.mode == "a"
        finally:
            self._cleanup_root_logger()


# -------------------------------------------------------------------
# _require_env
# -------------------------------------------------------------------


class TestRequireEnv:
    """Tests for env var resolution with fail-closed behavior."""

    def test_plain_string(self) -> None:
        """Plain strings are returned as-is."""
        assert _require_env("hello", "path") == "hello"

    def test_integer_value(self) -> None:
        """Non-string values are stringified."""
        assert _require_env(42, "path") == "42"

    def test_env_var_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvVar resolves when the env var is set."""
        monkeypatch.setenv("MY_VAR", "secret-value")
        result = _require_env(EnvVar("MY_VAR"), "path.to.field")
        assert result == "secret-value"

    def test_env_var_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvVar raises _ConfigError when env var is not set."""
        monkeypatch.delenv("MISSING_VAR", raising=False)
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="environment variable"):
            _require_env(EnvVar("MISSING_VAR"), "some.path")

    def test_none_value(self) -> None:
        """None value raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="value is missing"):
            _require_env(None, "some.path")


# -------------------------------------------------------------------
# _load_config
# -------------------------------------------------------------------


class TestLoadConfig:
    """Tests for YAML config file loading."""

    def test_missing_file_returns_defaults(self, tmp_path: Path) -> None:
        """Missing config file returns default config."""
        config = _load_config(tmp_path / "nonexistent.yaml")
        assert config.env == {}
        assert config.pass_env == []
        assert config.masked_secrets == []
        assert config.signing_credentials == []
        assert config.network_sandbox is True
        assert config.resource_limits == ResourceLimits()

    def test_empty_file_returns_defaults(self, tmp_path: Path) -> None:
        """Empty YAML file returns default config."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("")
        config = _load_config(cfg_file)
        assert config.env == {}
        assert config.network_sandbox is True

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        """Invalid YAML raises _ConfigError."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(": :\n  :\n[invalid")
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="Invalid YAML"):
            _load_config(cfg_file)

    def test_non_mapping_raises(self, tmp_path: Path) -> None:
        """Non-mapping YAML root raises _ConfigError."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("- item1\n- item2")
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="must be a YAML mapping"):
            _load_config(cfg_file)

    def test_full_config(self, tmp_path: Path) -> None:
        """Complete config is parsed correctly."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "env:\n"
            "  FOO: bar\n"
            "pass_env:\n"
            "  - HOME\n"
            "network_sandbox: false\n"
            "resource_limits:\n"
            "  timeout: 120\n"
            "  memory: 2g\n"
        )
        config = _load_config(cfg_file)
        assert config.env == {"FOO": "bar"}
        assert config.pass_env == ["HOME"]
        assert config.network_sandbox is False
        assert config.resource_limits.timeout == 120
        assert config.resource_limits.memory == "2g"


# -------------------------------------------------------------------
# _parse_env
# -------------------------------------------------------------------


class TestParseEnv:
    """Tests for static env parsing."""

    def test_none_returns_empty(self) -> None:
        """None returns empty dict."""
        assert _parse_env(None) == {}

    def test_valid_mapping(self) -> None:
        """Dict values are stringified."""
        result = _parse_env({"KEY": "val", "NUM": 42})
        assert result == {"KEY": "val", "NUM": "42"}

    def test_env_var_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvVar values are resolved from host environment."""
        monkeypatch.setenv("MY_VAR", "hello")
        result = _parse_env({"KEY": EnvVar("MY_VAR")})
        assert result == {"KEY": "hello"}

    def test_env_var_missing_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing EnvVar raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        monkeypatch.delenv("MISSING_VAR", raising=False)
        with pytest.raises(_ConfigError, match="environment variable"):
            _parse_env({"KEY": EnvVar("MISSING_VAR")})

    def test_non_mapping_raises(self) -> None:
        """Non-dict raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="'env' must be a mapping"):
            _parse_env(["not", "a", "dict"])


# -------------------------------------------------------------------
# _parse_pass_
# -------------------------------------------------------------------


class TestParsePassEnv:
    """Tests for pass_env parsing."""

    def test_none_returns_empty(self) -> None:
        """None returns empty list."""
        assert _parse_pass_env(None) == []

    def test_valid_list(self) -> None:
        """List items are stringified."""
        result = _parse_pass_env(["HOME", "PATH"])
        assert result == ["HOME", "PATH"]

    def test_non_list_raises(self) -> None:
        """Non-list raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="'pass_env' must be a list"):
            _parse_pass_env({"not": "a list"})


# -------------------------------------------------------------------
# _parse_masked_secrets
# -------------------------------------------------------------------


class TestParseMaskedSecrets:
    """Tests for masked secrets parsing."""

    def test_none_returns_empty(self) -> None:
        """None returns empty list."""
        assert _parse_masked_secrets(None) == []

    def test_non_mapping_raises(self) -> None:
        """Non-dict raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(
            _ConfigError, match="'masked_secrets' must be a mapping"
        ):
            _parse_masked_secrets(["not", "a", "dict"])

    def test_entry_not_mapping_raises(self) -> None:
        """Non-dict entry raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="must be a mapping"):
            _parse_masked_secrets({"MY_TOKEN": "string_not_dict"})

    def test_missing_scopes_raises(self) -> None:
        """Missing scopes raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "headers": ["Authorization"],
                    }
                }
            )

    def test_empty_scopes_raises(self) -> None:
        """Empty scopes list raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "scopes": [],
                        "headers": ["Authorization"],
                    }
                }
            )

    def test_missing_headers_raises(self) -> None:
        """Missing headers raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="headers must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "scopes": ["api.example.com"],
                    }
                }
            )

    def test_empty_headers_raises(self) -> None:
        """Empty headers list raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="headers must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "scopes": ["api.example.com"],
                        "headers": [],
                    }
                }
            )

    def test_valid_secret(self) -> None:
        """Valid masked secret is parsed correctly."""
        result = _parse_masked_secrets(
            {
                "MY_TOKEN": {
                    "value": "secret123",
                    "scopes": ["api.example.com"],
                    "headers": ["Authorization"],
                }
            }
        )
        assert len(result) == 1
        assert result[0] == MaskedSecret(
            env_var="MY_TOKEN",
            real_value="secret123",
            scopes=("api.example.com",),
            headers=("Authorization",),
        )

    def test_value_with_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvVar value is resolved from environment."""
        monkeypatch.setenv("SECRET_VAR", "resolved-secret")
        result = _parse_masked_secrets(
            {
                "MY_TOKEN": {
                    "value": EnvVar("SECRET_VAR"),
                    "scopes": ["*.example.com"],
                    "headers": ["Authorization", "X-Api-Key"],
                }
            }
        )
        assert result[0].real_value == "resolved-secret"
        assert result[0].scopes == ("*.example.com",)
        assert result[0].headers == ("Authorization", "X-Api-Key")

    def test_allow_foreign_credentials_true(self) -> None:
        """allow_foreign_credentials: true is parsed and propagated."""
        result = _parse_masked_secrets(
            {
                "CF_TOKEN": {
                    "value": "cf-secret",
                    "scopes": ["api.cloudflare.com"],
                    "headers": ["Authorization"],
                    "allow_foreign_credentials": True,
                }
            }
        )
        assert len(result) == 1
        assert result[0].allow_foreign_credentials is True

    def test_allow_foreign_credentials_false(self) -> None:
        """allow_foreign_credentials: false is parsed explicitly."""
        result = _parse_masked_secrets(
            {
                "MY_TOKEN": {
                    "value": "secret",
                    "scopes": ["api.example.com"],
                    "headers": ["Authorization"],
                    "allow_foreign_credentials": False,
                }
            }
        )
        assert result[0].allow_foreign_credentials is False

    def test_allow_foreign_credentials_absent_defaults_false(self) -> None:
        """Omitted allow_foreign_credentials defaults to False."""
        result = _parse_masked_secrets(
            {
                "MY_TOKEN": {
                    "value": "secret",
                    "scopes": ["api.example.com"],
                    "headers": ["Authorization"],
                }
            }
        )
        assert result[0].allow_foreign_credentials is False

    def test_scopes_not_list_raises(self) -> None:
        """Non-list scopes raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "scopes": "not-a-list",
                        "headers": ["Authorization"],
                    }
                }
            )

    def test_headers_not_list_raises(self) -> None:
        """Non-list headers raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="headers must be a non-empty"):
            _parse_masked_secrets(
                {
                    "MY_TOKEN": {
                        "value": "secret",
                        "scopes": ["api.example.com"],
                        "headers": "not-a-list",
                    }
                }
            )


# -------------------------------------------------------------------
# _parse_signing_credentials
# -------------------------------------------------------------------


class TestParseSigningCredentials:
    """Tests for signing credential parsing."""

    def test_none_returns_empty(self) -> None:
        """None returns empty list."""
        assert _parse_signing_credentials(None) == []

    def test_non_mapping_raises(self) -> None:
        """Non-dict raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(
            _ConfigError,
            match="'signing_credentials' must be a mapping",
        ):
            _parse_signing_credentials(["not", "a", "dict"])

    def test_entry_not_mapping_raises(self) -> None:
        """Non-dict entry raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="must be a mapping"):
            _parse_signing_credentials({"aws": "string_not_dict"})

    def test_invalid_type_raises(self) -> None:
        """Wrong type field raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="type must be 'aws-sigv4'"):
            _parse_signing_credentials(
                {
                    "aws": {
                        "type": "aws-sigv2",
                        "access_key_id": "AKIATEST",
                        "secret_access_key": "secret",
                        "scopes": ["bedrock.us-east-1.amazonaws.com"],
                    }
                }
            )

    def test_missing_type_raises(self) -> None:
        """Missing type field raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="type must be 'aws-sigv4'"):
            _parse_signing_credentials(
                {
                    "aws": {
                        "access_key_id": "AKIATEST",
                        "secret_access_key": "secret",
                        "scopes": ["bedrock.us-east-1.amazonaws.com"],
                    }
                }
            )

    def test_missing_scopes_raises(self) -> None:
        """Missing scopes raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_signing_credentials(
                {
                    "aws": {
                        "type": "aws-sigv4",
                        "access_key_id": "AKIATEST",
                        "secret_access_key": "secret",
                    }
                }
            )

    def test_empty_scopes_raises(self) -> None:
        """Empty scopes raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_signing_credentials(
                {
                    "aws": {
                        "type": "aws-sigv4",
                        "access_key_id": "AKIATEST",
                        "secret_access_key": "secret",
                        "scopes": [],
                    }
                }
            )

    def test_valid_credential_plain_strings(self) -> None:
        """Plain string credentials use default env var names."""
        result = _parse_signing_credentials(
            {
                "aws": {
                    "type": "aws-sigv4",
                    "access_key_id": "AKIATEST123",
                    "secret_access_key": "secret123",
                    "scopes": ["bedrock.us-east-1.amazonaws.com"],
                }
            }
        )
        assert len(result) == 1
        cred = result[0]
        assert cred.access_key_id_env_var == "AWS_ACCESS_KEY_ID"
        assert cred.access_key_id == "AKIATEST123"
        assert cred.secret_access_key_env_var == "AWS_SECRET_ACCESS_KEY"
        assert cred.secret_access_key == "secret123"
        assert cred.session_token_env_var is None
        assert cred.session_token is None
        assert cred.scopes == ("bedrock.us-east-1.amazonaws.com",)

    def test_valid_credential_with_env_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """EnvVar values resolve env var names from the tag."""
        monkeypatch.setenv("MY_ACCESS_KEY", "AKIATEST456")
        monkeypatch.setenv("MY_SECRET_KEY", "secret456")
        result = _parse_signing_credentials(
            {
                "aws": {
                    "type": "aws-sigv4",
                    "access_key_id": EnvVar("MY_ACCESS_KEY"),
                    "secret_access_key": EnvVar("MY_SECRET_KEY"),
                    "scopes": ["*.amazonaws.com"],
                }
            }
        )
        cred = result[0]
        assert cred.access_key_id_env_var == "MY_ACCESS_KEY"
        assert cred.access_key_id == "AKIATEST456"
        assert cred.secret_access_key_env_var == "MY_SECRET_KEY"
        assert cred.secret_access_key == "secret456"

    def test_credential_with_session_token_plain(self) -> None:
        """Session token as plain string uses default env var name."""
        result = _parse_signing_credentials(
            {
                "aws": {
                    "type": "aws-sigv4",
                    "access_key_id": "ASIATEST789",
                    "secret_access_key": "secret789",
                    "session_token": "token789",
                    "scopes": ["s3.amazonaws.com"],
                }
            }
        )
        cred = result[0]
        assert cred.session_token_env_var == "AWS_SESSION_TOKEN"
        assert cred.session_token == "token789"

    def test_credential_with_session_token_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Session token as EnvVar resolves from env."""
        monkeypatch.setenv("MY_SESSION_TOKEN", "session-token-value")
        result = _parse_signing_credentials(
            {
                "aws": {
                    "type": "aws-sigv4",
                    "access_key_id": "ASIATEST",
                    "secret_access_key": "secret",
                    "session_token": EnvVar("MY_SESSION_TOKEN"),
                    "scopes": ["s3.amazonaws.com"],
                }
            }
        )
        cred = result[0]
        assert cred.session_token_env_var == "MY_SESSION_TOKEN"
        assert cred.session_token == "session-token-value"

    def test_scopes_not_list_raises(self) -> None:
        """Non-list scopes raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="scopes must be a non-empty"):
            _parse_signing_credentials(
                {
                    "aws": {
                        "type": "aws-sigv4",
                        "access_key_id": "AKIATEST",
                        "secret_access_key": "secret",
                        "scopes": "not-a-list",
                    }
                }
            )


# -------------------------------------------------------------------
# _parse_network_sandbox
# -------------------------------------------------------------------


class TestParseNetworkSandbox:
    """Tests for network_sandbox bool parsing."""

    def test_none_returns_true(self) -> None:
        """Default is True when unspecified."""
        assert _parse_network_sandbox(None) is True

    def test_bool_true(self) -> None:
        """Native bool True passes through."""
        assert _parse_network_sandbox(True) is True

    def test_bool_false(self) -> None:
        """Native bool False passes through."""
        assert _parse_network_sandbox(False) is False

    @pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE", "Yes"])
    def test_truthy_strings(self, value: str) -> None:
        """Various truthy strings return True."""
        assert _parse_network_sandbox(value) is True

    @pytest.mark.parametrize(
        "value", ["false", "0", "no", "off", "FALSE", "No"]
    )
    def test_falsy_strings(self, value: str) -> None:
        """Various falsy strings return False."""
        assert _parse_network_sandbox(value) is False

    def test_invalid_string_raises(self) -> None:
        """Invalid string raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="must be a boolean"):
            _parse_network_sandbox("maybe")


# -------------------------------------------------------------------
# _parse_resource_limits
# -------------------------------------------------------------------


class TestParseResourceLimits:
    """Tests for resource limits parsing."""

    def test_none_returns_defaults(self) -> None:
        """None returns default ResourceLimits."""
        result = _parse_resource_limits(None)
        assert result == ResourceLimits()

    def test_non_mapping_raises(self) -> None:
        """Non-dict raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(
            _ConfigError, match="'resource_limits' must be a mapping"
        ):
            _parse_resource_limits("not-a-dict")

    def test_all_fields(self) -> None:
        """All fields are parsed with correct types."""
        result = _parse_resource_limits(
            {
                "timeout": 600,
                "memory": "4g",
                "cpus": 2.5,
                "pids_limit": 100,
            }
        )
        assert result.timeout == 600
        assert result.memory == "4g"
        assert result.cpus == 2.5
        assert result.pids_limit == 100

    def test_partial_fields(self) -> None:
        """Missing fields remain None."""
        result = _parse_resource_limits({"timeout": 120})
        assert result.timeout == 120
        assert result.memory is None
        assert result.cpus is None
        assert result.pids_limit is None

    def test_empty_dict(self) -> None:
        """Empty dict returns defaults."""
        result = _parse_resource_limits({})
        assert result == ResourceLimits()

    def test_string_timeout_converted_to_int(self) -> None:
        """String timeout is converted to int."""
        result = _parse_resource_limits({"timeout": "300"})
        assert result.timeout == 300

    def test_string_cpus_converted_to_float(self) -> None:
        """String cpus is converted to float."""
        result = _parse_resource_limits({"cpus": "1.5"})
        assert result.cpus == 1.5

    def test_string_pids_limit_converted_to_int(self) -> None:
        """String pids_limit is converted to int."""
        result = _parse_resource_limits({"pids_limit": "50"})
        assert result.pids_limit == 50

    def test_invalid_timeout_raises(self) -> None:
        """Non-numeric timeout raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="invalid value"):
            _parse_resource_limits({"timeout": "fast"})


# -------------------------------------------------------------------
# _parse_mount
# -------------------------------------------------------------------


class TestParseMount:
    """Tests for mount string parsing."""

    def test_src_dst(self) -> None:
        """SRC:DST mount is parsed correctly."""
        mount = _parse_mount("/host/path:/container/path")
        assert mount.host_path == Path("/host/path").resolve()
        assert mount.container_path == "/container/path"
        assert mount.read_only is False

    def test_src_dst_ro(self) -> None:
        """SRC:DST:ro mount is parsed correctly."""
        mount = _parse_mount("/host/path:/container/path:ro")
        assert mount.host_path == Path("/host/path").resolve()
        assert mount.container_path == "/container/path"
        assert mount.read_only is True

    def test_invalid_format_one_part(self) -> None:
        """Single component raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="Invalid mount format"):
            _parse_mount("/only/one/part")

    def test_invalid_format_four_parts(self) -> None:
        """Four components raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="Invalid mount format"):
            _parse_mount("/a:/b:ro:extra")

    def test_three_parts_not_ro(self) -> None:
        """Three components with third != 'ro' raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="Invalid mount format"):
            _parse_mount("/a:/b:rw")


# -------------------------------------------------------------------
# _setup_network_log
# -------------------------------------------------------------------


class TestSetupNetworkLog:
    """Tests for network log file setup."""

    def test_with_user_path(self, tmp_path: Path) -> None:
        """User-specified path is resolved and touched."""
        user_path = tmp_path / "logs" / "network.log"
        log_path, cleanup = _setup_network_log(user_path)

        try:
            # User path is created
            assert user_path.exists()
            # log_path matches resolved user path
            assert log_path == user_path.resolve()
        finally:
            cleanup()

        # User file persists after cleanup
        assert user_path.exists()

    def test_without_user_path(self) -> None:
        """No user path creates temp file, cleaned up on exit."""
        log_path, cleanup = _setup_network_log(None)

        try:
            assert log_path.exists()
            assert "airut-netlog-" in str(log_path)
        finally:
            cleanup()

        assert not log_path.exists()

    def test_cleanup_default_removes_log_file(self) -> None:
        """Default cleanup removes temp log file."""
        log_path, cleanup = _setup_network_log(None)

        try:
            # Simulate proxy creating log data
            log_path.write_text("some log data")
        finally:
            cleanup()

        assert not log_path.exists()

    def test_with_user_path_parent_created(self, tmp_path: Path) -> None:
        """Parent directories for user path are created."""
        user_path = tmp_path / "deep" / "nested" / "dir" / "net.log"
        log_path, cleanup = _setup_network_log(user_path)

        try:
            assert user_path.parent.exists()
        finally:
            cleanup()


# -------------------------------------------------------------------
# _load_allowlist
# -------------------------------------------------------------------


class TestLoadAllowlist:
    """Tests for allowlist loading."""

    def test_sandbox_disabled(self, tmp_path: Path) -> None:
        """Returns None when network sandbox is disabled."""
        result = _load_allowlist(
            tmp_path / "allowlist.yaml", network_sandbox=False
        )
        assert result is None

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """Missing file returns empty allowlist."""
        result = _load_allowlist(
            tmp_path / "nonexistent.yaml", network_sandbox=True
        )
        assert result is not None
        assert result.domains == ()
        assert result.url_patterns == ()

    def test_valid_file(self, tmp_path: Path) -> None:
        """Valid allowlist file is parsed correctly."""
        allowlist_path = tmp_path / "allowlist.yaml"
        allowlist_path.write_text(
            "domains:\n"
            "  - api.example.com\n"
            "url_prefixes:\n"
            "  - host: pypi.org\n"
            "    methods: [GET]\n"
        )
        result = _load_allowlist(allowlist_path, network_sandbox=True)
        assert result is not None
        assert len(result.domains) == 1
        assert result.domains[0].host == "api.example.com"

    def test_invalid_file_raises(self, tmp_path: Path) -> None:
        """Invalid YAML in allowlist raises _ConfigError."""
        from airut.sandbox_cli import _ConfigError

        allowlist_path = tmp_path / "allowlist.yaml"
        allowlist_path.write_bytes(b"[invalid: yaml: :")
        with pytest.raises(_ConfigError, match="Invalid allowlist"):
            _load_allowlist(allowlist_path, network_sandbox=True)


# -------------------------------------------------------------------
# _build_container_env
# -------------------------------------------------------------------


class TestBuildContainerEnv:
    """Tests for container environment building."""

    def test_static_env(self) -> None:
        """Static env vars are included."""
        from airut.sandbox_cli import _SandboxCliConfig

        config = _SandboxCliConfig(env={"FOO": "bar", "BAZ": "qux"})
        prepared = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )
        result = _build_container_env(config, prepared)
        assert result.variables == {"FOO": "bar", "BAZ": "qux"}

    def test_pass_env_from_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pass_env picks up host environment variables."""
        from airut.sandbox_cli import _SandboxCliConfig

        monkeypatch.setenv("PASS_ME", "value123")
        monkeypatch.delenv("MISSING", raising=False)
        config = _SandboxCliConfig(pass_env=["PASS_ME", "MISSING"])
        prepared = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )
        result = _build_container_env(config, prepared)
        assert result.variables == {"PASS_ME": "value123"}

    def test_prepared_secrets_override(self) -> None:
        """Prepared secrets override earlier values."""
        from airut.sandbox_cli import _SandboxCliConfig

        config = _SandboxCliConfig(env={"TOKEN": "static"})
        prepared = PreparedSecrets(
            env_vars={"TOKEN": "surrogate"},
            replacements=SecretReplacements(),
        )
        result = _build_container_env(config, prepared)
        assert result.variables["TOKEN"] == "surrogate"

    def test_merge_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Merge order: static < pass_env < prepared secrets."""
        from airut.sandbox_cli import _SandboxCliConfig

        monkeypatch.setenv("MY_VAR", "from-host")
        config = _SandboxCliConfig(
            env={"MY_VAR": "from-static", "OTHER": "static"},
            pass_env=["MY_VAR"],
        )
        prepared = PreparedSecrets(
            env_vars={"MY_VAR": "from-prepared"},
            replacements=SecretReplacements(),
        )
        result = _build_container_env(config, prepared)
        assert result.variables["MY_VAR"] == "from-prepared"
        assert result.variables["OTHER"] == "static"


# -------------------------------------------------------------------
# _install_signal_handlers
# -------------------------------------------------------------------


class TestInstallSignalHandlers:
    """Tests for signal handler installation."""

    def test_installs_handlers_for_command_task(self) -> None:
        """Signal handlers installed for real CommandTask."""
        from airut.sandbox.task import CommandTask

        mock_task = MagicMock(spec=CommandTask)
        with patch("airut.sandbox_cli.signal.signal") as mock_signal:
            _install_signal_handlers(mock_task)

            assert mock_signal.call_count == 2
            calls = mock_signal.call_args_list
            signal_numbers = {c[0][0] for c in calls}
            assert signal.SIGTERM in signal_numbers
            assert signal.SIGINT in signal_numbers

    def test_handler_calls_stop(self) -> None:
        """Installed handler calls task.stop() on signal."""
        from airut.sandbox.task import CommandTask

        mock_task = MagicMock(spec=CommandTask)
        handlers: dict[int, object] = {}

        def capture_handler(signum: int, handler: object) -> None:
            handlers[signum] = handler

        with patch(
            "airut.sandbox_cli.signal.signal", side_effect=capture_handler
        ):
            _install_signal_handlers(mock_task)

        # Call the SIGTERM handler
        handler = handlers[signal.SIGTERM]
        handler(signal.SIGTERM, None)  # type: ignore[operator]
        mock_task.stop.assert_called_once()

    def test_skips_non_command_task(self) -> None:
        """Non-CommandTask instances are silently skipped."""
        mock_task = MagicMock()  # Not spec'd as CommandTask
        with patch("airut.sandbox_cli.signal.signal") as mock_signal:
            _install_signal_handlers(mock_task)
            mock_signal.assert_not_called()


# -------------------------------------------------------------------
# _map_exit_code
# -------------------------------------------------------------------


class TestMapExitCode:
    """Tests for exit code mapping."""

    def test_normal_exit(self) -> None:
        """Normal exit code passes through."""
        result = CommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            duration_ms=100,
            timed_out=False,
        )
        assert _map_exit_code(result) == 0

    def test_nonzero_exit(self) -> None:
        """Non-zero exit code passes through."""
        result = CommandResult(
            exit_code=1,
            stdout="",
            stderr="",
            duration_ms=100,
            timed_out=False,
        )
        assert _map_exit_code(result) == 1

    def test_timeout_returns_124(self) -> None:
        """Timeout returns EXIT_TIMEOUT (124)."""
        result = CommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            duration_ms=30000,
            timed_out=True,
        )
        assert _map_exit_code(result) == EXIT_TIMEOUT

    def test_oom_exit_137_warns(self) -> None:
        """Exit code 137 logs OOM warning and returns 137."""
        result = CommandResult(
            exit_code=137,
            stdout="",
            stderr="",
            duration_ms=100,
            timed_out=False,
        )
        with patch("airut.sandbox_cli.logger") as mock_logger:
            code = _map_exit_code(result)
            assert code == 137
            mock_logger.warning.assert_called_once()
            assert "OOM" in mock_logger.warning.call_args[0][0]

    def test_timeout_takes_priority_over_exit_code(self) -> None:
        """Timeout is checked before exit code."""
        result = CommandResult(
            exit_code=137,
            stdout="",
            stderr="",
            duration_ms=30000,
            timed_out=True,
        )
        assert _map_exit_code(result) == EXIT_TIMEOUT


# -------------------------------------------------------------------
# _execute
# -------------------------------------------------------------------


class TestExecute:
    """Tests for the main execution orchestration."""

    def _make_args(
        self,
        command: list[str] | None = None,
        tmp_path: Path | None = None,
        **overrides: object,
    ) -> argparse.Namespace:
        """Create a minimal args Namespace for testing _execute."""
        defaults = {
            "command": command if command is not None else ["echo", "hello"],
            "dockerfile": None,
            "context_dir": None,
            "allowlist": None,
            "timeout": None,
            "container_command": None,
            "mount": [],
            "network_log": None,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_no_command_returns_infra_error(self) -> None:
        """Empty command returns EXIT_INFRA_ERROR."""
        args = self._make_args(command=[])
        from airut.sandbox_cli import _SandboxCliConfig

        result = _execute(args, _SandboxCliConfig())
        assert result == EXIT_INFRA_ERROR

    def test_missing_dockerfile_returns_infra_error(
        self, tmp_path: Path
    ) -> None:
        """Missing Dockerfile returns EXIT_INFRA_ERROR."""
        from airut.sandbox_cli import _SandboxCliConfig

        args = self._make_args(
            dockerfile=tmp_path / "nonexistent" / "Dockerfile"
        )
        result = _execute(args, _SandboxCliConfig())
        assert result == EXIT_INFRA_ERROR

    def test_invalid_mount_returns_infra_error(self, tmp_path: Path) -> None:
        """Invalid mount format returns EXIT_INFRA_ERROR."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        args = self._make_args(
            dockerfile=dockerfile, mount=["invalid-mount-format"]
        )
        result = _execute(args, _SandboxCliConfig(network_sandbox=False))
        assert result == EXIT_INFRA_ERROR

    def test_invalid_allowlist_returns_infra_error(
        self, tmp_path: Path
    ) -> None:
        """Invalid allowlist returns EXIT_INFRA_ERROR."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        allowlist_path = tmp_path / "bad.yaml"
        allowlist_path.write_bytes(b"[invalid: yaml: :")
        args = self._make_args(dockerfile=dockerfile, allowlist=allowlist_path)
        result = _execute(args, _SandboxCliConfig(network_sandbox=True))
        assert result == EXIT_INFRA_ERROR

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_successful_execution(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Successful execution returns command exit code."""
        from airut.sandbox_cli import _SandboxCliConfig

        # Set up Dockerfile
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        # Mock prepare_secrets
        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        # Mock sandbox
        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "test-image:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="hello\n",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        result = _execute(args, _SandboxCliConfig(network_sandbox=False))

        assert result == 0
        mock_sandbox.startup.assert_called_once()
        mock_sandbox.ensure_image.assert_called_once()
        mock_sandbox.create_command_task.assert_called_once()
        mock_task.execute.assert_called_once()
        mock_sandbox.shutdown.assert_called_once()

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_sandbox_error_returns_infra_error(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Sandbox exception returns EXIT_INFRA_ERROR."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.startup.side_effect = RuntimeError("podman not found")

        args = self._make_args(dockerfile=dockerfile)
        result = _execute(args, _SandboxCliConfig(network_sandbox=False))

        assert result == EXIT_INFRA_ERROR

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_timeout_override(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """CLI --timeout overrides config timeout."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        config = _SandboxCliConfig(
            resource_limits=ResourceLimits(timeout=600, memory="2g")
        )
        args = self._make_args(dockerfile=dockerfile, timeout=120)
        _execute(args, config)

        # Verify the resource_limits passed have overridden timeout
        create_call = mock_sandbox.create_command_task.call_args
        resource_limits = create_call.kwargs["resource_limits"]
        assert resource_limits.timeout == 120
        assert resource_limits.memory == "2g"

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_container_command_default_podman(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Default container command is podman."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        from airut.sandbox import SandboxConfig

        mock_sandbox_cls.assert_called_once_with(
            SandboxConfig(
                container_command="podman", resource_prefix="airut-cli"
            )
        )

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_container_command_override(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Custom container command is passed through."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(
            dockerfile=dockerfile, container_command="docker"
        )
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        from airut.sandbox import SandboxConfig

        mock_sandbox_cls.assert_called_once_with(
            SandboxConfig(
                container_command="docker", resource_prefix="airut-cli"
            )
        )

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_network_sandbox_enabled(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Network sandbox config is passed when enabled."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        allowlist_path = tmp_path / "allowlist.yaml"
        allowlist_path.write_text("domains:\n  - api.example.com\n")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile, allowlist=allowlist_path)
        _execute(args, _SandboxCliConfig(network_sandbox=True))

        create_call = mock_sandbox.create_command_task.call_args
        network_sandbox = create_call.kwargs["network_sandbox"]
        assert network_sandbox is not None
        assert network_sandbox.allowlist is not None
        assert network_sandbox.allowlist.domains[0].host == "api.example.com"

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_network_sandbox_disabled(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Network sandbox config is None when disabled."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        create_call = mock_sandbox.create_command_task.call_args
        assert create_call.kwargs["network_sandbox"] is None

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_context_files_loaded(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Context directory files (excluding Dockerfile) are loaded."""
        from airut.sandbox_cli import _SandboxCliConfig

        context = tmp_path / "context"
        context.mkdir()
        dockerfile = context / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        (context / "requirements.txt").write_bytes(b"flask\n")
        # Create a subdirectory that should be ignored (is_file check)
        (context / "subdir").mkdir()

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile, context_dir=context)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        ensure_image_call = mock_sandbox.ensure_image.call_args
        context_files = ensure_image_call[0][1]
        assert "requirements.txt" in context_files
        assert "Dockerfile" not in context_files
        assert "subdir" not in context_files

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_context_dir_defaults_to_dockerfile_parent(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Context dir defaults to Dockerfile's parent directory."""
        from airut.sandbox_cli import _SandboxCliConfig

        container_dir = tmp_path / "container"
        container_dir.mkdir()
        dockerfile = container_dir / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        (container_dir / "extra.sh").write_bytes(b"#!/bin/sh\necho hi\n")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        ensure_image_call = mock_sandbox.ensure_image.call_args
        context_files = ensure_image_call[0][1]
        assert "extra.sh" in context_files

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_cwd_mount_inserted_first(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """CWD is mounted as first mount at /workspace."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(
            dockerfile=dockerfile,
            mount=["/extra:/extra"],
        )
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        create_call = mock_sandbox.create_command_task.call_args
        mounts = create_call.kwargs["mounts"]
        assert mounts[0].container_path == "/workspace"
        assert len(mounts) == 2
        assert mounts[1].container_path == "/extra"

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_passthrough_entrypoint(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """ensure_image is called with passthrough_entrypoint=True."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        ensure_image_call = mock_sandbox.ensure_image.call_args
        assert ensure_image_call.kwargs["passthrough_entrypoint"] is True

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_context_dir_not_existing(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Non-existent context dir yields empty context files."""
        from airut.sandbox_cli import _SandboxCliConfig

        # Place Dockerfile in tmp_path, but set context_dir to non-existent
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        nonexistent_ctx = tmp_path / "no-such-dir"

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(
            dockerfile=dockerfile, context_dir=nonexistent_ctx
        )
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        ensure_image_call = mock_sandbox.ensure_image.call_args
        context_files = ensure_image_call[0][1]
        assert context_files == {}

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_network_log_cleanup_on_oserror(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """OSError during network log cleanup is suppressed."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.startup.side_effect = RuntimeError("fail")

        args = self._make_args(dockerfile=dockerfile)
        # Just verify it doesn't raise even with network sandbox enabled
        # and a broken state
        result = _execute(args, _SandboxCliConfig(network_sandbox=True))
        assert result == EXIT_INFRA_ERROR

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_shutdown_called_on_error_during_image_build(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Sandbox is shut down even when ensure_image fails."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.side_effect = RuntimeError("build failed")

        args = self._make_args(dockerfile=dockerfile)
        result = _execute(args, _SandboxCliConfig(network_sandbox=False))

        assert result == EXIT_INFRA_ERROR
        mock_sandbox.shutdown.assert_called_once()

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_shutdown_exception_does_not_swallow_exit_code(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Shutdown error does not override the command's exit code."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task
        mock_sandbox.shutdown.side_effect = RuntimeError("shutdown failed")

        args = self._make_args(dockerfile=dockerfile)
        result = _execute(args, _SandboxCliConfig(network_sandbox=False))

        # Exit code from task.execute (0) is preserved, not EXIT_INFRA_ERROR
        assert result == 0
        mock_sandbox.shutdown.assert_called_once()

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_network_log_with_user_path(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Network log user path is forwarded correctly."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        net_log = tmp_path / "net.log"

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile, network_log=net_log)
        _execute(args, _SandboxCliConfig(network_sandbox=True))

        create_call = mock_sandbox.create_command_task.call_args
        network_log_path = create_call.kwargs["network_log_path"]
        assert network_log_path == net_log.resolve()

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_verbose_sets_airut_verbose_env(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Verbose flag injects AIRUT_VERBOSE=1 into container env."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile, verbose=True)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        create_call = mock_sandbox.create_command_task.call_args
        env = create_call.kwargs["env"]
        assert env.variables["AIRUT_VERBOSE"] == "1"

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_debug_sets_airut_verbose_env(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Debug flag also injects AIRUT_VERBOSE=1 into container env."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile, debug=True)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        create_call = mock_sandbox.create_command_task.call_args
        env = create_call.kwargs["env"]
        assert env.variables["AIRUT_VERBOSE"] == "1"

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_no_verbose_omits_airut_verbose_env(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Without verbose, AIRUT_VERBOSE is not in container env."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        args = self._make_args(dockerfile=dockerfile)
        _execute(args, _SandboxCliConfig(network_sandbox=False))

        create_call = mock_sandbox.create_command_task.call_args
        env = create_call.kwargs["env"]
        assert "AIRUT_VERBOSE" not in env.variables


# -------------------------------------------------------------------
# _run
# -------------------------------------------------------------------


class TestRun:
    """Tests for the top-level CLI runner."""

    def test_no_subcommand_returns_infra_error(self) -> None:
        """No subcommand yields EXIT_INFRA_ERROR."""
        with patch("airut.sandbox_cli._setup_logging"):
            result = _run([])
        assert result == EXIT_INFRA_ERROR

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_config_error_returns_infra_error(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Config error yields EXIT_INFRA_ERROR."""
        from airut.sandbox_cli import _ConfigError

        mock_load_config.side_effect = _ConfigError("bad config")
        with patch("airut.sandbox_cli._setup_logging"):
            result = _run(["run", "--", "echo"])
        assert result == EXIT_INFRA_ERROR
        mock_execute.assert_not_called()

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_successful_run_delegates_to_execute(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Successful run delegates to _execute."""
        from airut.sandbox_cli import _SandboxCliConfig

        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging"):
            result = _run(["run", "--", "echo", "hello"])
        assert result == 0
        mock_execute.assert_called_once()

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_custom_config_path(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Custom --config path is passed to _load_config."""
        from airut.sandbox_cli import _SandboxCliConfig

        config_path = tmp_path / "custom.yaml"
        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging"):
            _run(
                [
                    "run",
                    "--config",
                    str(config_path),
                    "--",
                    "echo",
                ]
            )

        mock_load_config.assert_called_once_with(config_path)

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_default_config_path(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Default config path is .airut/sandbox.yaml."""
        from airut.sandbox_cli import _SandboxCliConfig

        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging"):
            _run(["run", "--", "echo"])

        mock_load_config.assert_called_once_with(Path(".airut/sandbox.yaml"))

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_verbose_passed_to_setup_logging(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Verbose flag is passed to _setup_logging."""
        from airut.sandbox_cli import _SandboxCliConfig

        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging") as mock_logging:
            _run(["run", "--verbose", "--", "echo"])
            mock_logging.assert_called_once_with(
                verbose=True, debug=False, log_file=None
            )

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_debug_passed_to_setup_logging(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Debug flag is passed to _setup_logging."""
        from airut.sandbox_cli import _SandboxCliConfig

        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging") as mock_logging:
            _run(["run", "--debug", "--", "echo"])
            mock_logging.assert_called_once_with(
                verbose=False, debug=True, log_file=None
            )

    @patch("airut.sandbox_cli._execute")
    @patch("airut.sandbox_cli._load_config")
    def test_log_file_passed_to_setup_logging(
        self,
        mock_load_config: MagicMock,
        mock_execute: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--log path is passed to _setup_logging."""
        from airut.sandbox_cli import _SandboxCliConfig

        log_path = tmp_path / "sandbox.log"
        mock_load_config.return_value = _SandboxCliConfig()
        mock_execute.return_value = 0

        with patch("airut.sandbox_cli._setup_logging") as mock_logging:
            _run(["run", "--log", str(log_path), "--", "echo"])
            mock_logging.assert_called_once_with(
                verbose=False, debug=False, log_file=log_path
            )


# -------------------------------------------------------------------
# main
# -------------------------------------------------------------------


class TestMain:
    """Tests for the entry point."""

    @patch("airut.sandbox_cli._run")
    def test_main_calls_sys_exit(self, mock_run: MagicMock) -> None:
        """main() calls sys.exit with _run's return value."""
        mock_run.return_value = 42
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 42
        mock_run.assert_called_once_with(sys.argv[1:])

    @patch("airut.sandbox_cli._run")
    def test_main_exit_zero(self, mock_run: MagicMock) -> None:
        """main() exits 0 on success."""
        mock_run.return_value = 0
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0


# -------------------------------------------------------------------
# _SandboxCliConfig dataclass
# -------------------------------------------------------------------


class TestSandboxCliConfig:
    """Tests for the _SandboxCliConfig dataclass."""

    def test_defaults(self) -> None:
        """Default config values."""
        from airut.sandbox_cli import _SandboxCliConfig

        config = _SandboxCliConfig()
        assert config.env == {}
        assert config.pass_env == []
        assert config.masked_secrets == []
        assert config.signing_credentials == []
        assert config.network_sandbox is True
        assert config.resource_limits == ResourceLimits()

    def test_frozen(self) -> None:
        """Config is immutable (frozen dataclass)."""
        from airut.sandbox_cli import _SandboxCliConfig

        config = _SandboxCliConfig()
        with pytest.raises(AttributeError):
            config.network_sandbox = False  # type: ignore[misc]


# -------------------------------------------------------------------
# _ConfigError
# -------------------------------------------------------------------


class TestConfigError:
    """Tests for the _ConfigError exception class."""

    def test_is_exception(self) -> None:
        """_ConfigError is an Exception."""
        from airut.sandbox_cli import _ConfigError

        err = _ConfigError("test message")
        assert isinstance(err, Exception)
        assert str(err) == "test message"


# -------------------------------------------------------------------
# Integration-style tests for _load_config with !env
# -------------------------------------------------------------------


class TestRunIntegration:
    """Integration-style tests calling _run without mocking _execute.

    These tests exercise code paths through _run -> _execute that the
    isolated unit tests miss due to coverage tracing limitations.
    """

    def test_no_command_after_double_dash(self) -> None:
        """_run with empty command reaches _execute early return."""
        with patch("airut.sandbox_cli._setup_logging"):
            result = _run(["run", "--"])
        assert result == EXIT_INFRA_ERROR

    def test_unknown_subcommand_branch(self) -> None:
        """Unknown subcommand triggers the else branch in _run."""
        with patch("airut.sandbox_cli._setup_logging"):
            with patch("airut.sandbox_cli._parse_args") as mock_parse:
                mock_parse.return_value = argparse.Namespace(
                    subcommand="unknown",
                    verbose=False,
                    debug=False,
                    command=[],
                )
                result = _run(["unknown", "--", "cmd"])
        assert result == EXIT_INFRA_ERROR

    @patch("airut.sandbox_cli.Sandbox")
    @patch("airut.sandbox_cli.prepare_secrets")
    @patch("airut.sandbox_cli._install_signal_handlers")
    def test_network_log_cleanup_oserror_suppressed(
        self,
        mock_signal_handlers: MagicMock,
        mock_prepare: MagicMock,
        mock_sandbox_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """OSError during network_log_cleanup is silently caught."""
        from airut.sandbox_cli import _SandboxCliConfig

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")

        mock_prepare.return_value = PreparedSecrets(
            env_vars={}, replacements=SecretReplacements()
        )

        mock_sandbox = MagicMock()
        mock_sandbox_cls.return_value = mock_sandbox
        mock_sandbox.ensure_image.return_value = "img:latest"

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(
            return_value=CommandResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=50,
                timed_out=False,
            )
        )
        mock_sandbox.create_command_task.return_value = mock_task

        # Patch _setup_network_log to return a cleanup that raises OSError
        def bad_cleanup() -> None:
            raise OSError("disk full")

        with patch(
            "airut.sandbox_cli._setup_network_log",
            return_value=(tmp_path / "net.log", bad_cleanup),
        ):
            args = argparse.Namespace(
                command=["echo", "hi"],
                dockerfile=dockerfile,
                context_dir=None,
                allowlist=None,
                timeout=None,
                container_command=None,
                mount=[],
                network_log=tmp_path / "net.log",
            )
            result = _execute(args, _SandboxCliConfig(network_sandbox=True))

        assert result == 0


class TestLoadConfigWithEnvTag:
    """Tests for config loading with !env tag resolution."""

    def test_env_tag_resolved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """!env tags in config are resolved from environment."""
        monkeypatch.setenv("MY_SECRET", "secret-value-123")
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "masked_secrets:\n"
            "  TOKEN:\n"
            "    value: !env MY_SECRET\n"
            "    scopes:\n"
            "      - api.example.com\n"
            "    headers:\n"
            "      - Authorization\n"
        )
        config = _load_config(cfg_file)
        assert len(config.masked_secrets) == 1
        assert config.masked_secrets[0].real_value == "secret-value-123"

    def test_env_tag_missing_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing !env var raises _ConfigError."""
        monkeypatch.delenv("UNSET_VAR", raising=False)
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "masked_secrets:\n"
            "  TOKEN:\n"
            "    value: !env UNSET_VAR\n"
            "    scopes:\n"
            "      - api.example.com\n"
            "    headers:\n"
            "      - Authorization\n"
        )
        from airut.sandbox_cli import _ConfigError

        with pytest.raises(_ConfigError, match="environment variable"):
            _load_config(cfg_file)

    def test_signing_credentials_with_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signing credentials with !env tags are resolved."""
        monkeypatch.setenv("AWS_AKI", "AKIATEST")
        monkeypatch.setenv("AWS_SAK", "secretkey")
        monkeypatch.setenv("AWS_ST", "sessiontoken")
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "signing_credentials:\n"
            "  aws:\n"
            "    type: aws-sigv4\n"
            "    access_key_id: !env AWS_AKI\n"
            "    secret_access_key: !env AWS_SAK\n"
            "    session_token: !env AWS_ST\n"
            "    scopes:\n"
            "      - bedrock.us-east-1.amazonaws.com\n"
        )
        config = _load_config(cfg_file)
        assert len(config.signing_credentials) == 1
        cred = config.signing_credentials[0]
        assert cred.access_key_id == "AKIATEST"
        assert cred.secret_access_key == "secretkey"
        assert cred.session_token == "sessiontoken"
        assert cred.access_key_id_env_var == "AWS_AKI"
        assert cred.secret_access_key_env_var == "AWS_SAK"
        assert cred.session_token_env_var == "AWS_ST"

    def test_allow_foreign_credentials_from_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """allow_foreign_credentials flows through YAML loading."""
        monkeypatch.setenv("CF_TOKEN_VAL", "cf-secret-123")
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "masked_secrets:\n"
            "  CF_TOKEN:\n"
            "    value: !env CF_TOKEN_VAL\n"
            "    scopes:\n"
            "      - api.cloudflare.com\n"
            "    headers:\n"
            "      - Authorization\n"
            "    allow_foreign_credentials: true\n"
        )
        config = _load_config(cfg_file)
        assert len(config.masked_secrets) == 1
        assert config.masked_secrets[0].allow_foreign_credentials is True
