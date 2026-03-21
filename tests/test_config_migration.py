# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config schema migration."""

from typing import Any

import pytest

from airut.config.migration import (
    CURRENT_CONFIG_VERSION,
    MIGRATIONS,
    _migrate_v1_to_v2,
    apply_migrations,
)
from airut.gateway.config import ConfigError


class TestMigrateV1ToV2:
    def test_clean_config_passes(self) -> None:
        raw: dict[str, Any] = {
            "repos": {
                "my-repo": {
                    "email": {
                        "authorized_senders": ["user@example.com"],
                        "trusted_authserv_id": "mx.example.com",
                    }
                }
            }
        }
        result = _migrate_v1_to_v2(raw)
        assert result is raw  # No copy needed for clean configs

    def test_detects_authorized_senders_at_repo_level(self) -> None:
        raw: dict[str, Any] = {
            "repos": {
                "my-repo": {
                    "authorized_senders": ["user@example.com"],
                    "email": {},
                }
            }
        }
        with pytest.raises(ConfigError, match="authorized_senders"):
            _migrate_v1_to_v2(raw)

    def test_detects_trusted_authserv_id_at_repo_level(self) -> None:
        raw: dict[str, Any] = {
            "repos": {
                "my-repo": {
                    "trusted_authserv_id": "mx.example.com",
                    "email": {},
                }
            }
        }
        with pytest.raises(ConfigError, match="trusted_authserv_id"):
            _migrate_v1_to_v2(raw)

    def test_detects_multiple_legacy_fields(self) -> None:
        raw: dict[str, Any] = {
            "repos": {
                "my-repo": {
                    "authorized_senders": ["user@example.com"],
                    "imap": {"poll_interval": 30},
                    "email": {},
                }
            }
        }
        with pytest.raises(
            ConfigError,
            match="authorized_senders.*imap|imap.*authorized_senders",
        ):
            _migrate_v1_to_v2(raw)

    def test_no_repos_key(self) -> None:
        raw: dict[str, Any] = {"execution": {"max_concurrent": 5}}
        result = _migrate_v1_to_v2(raw)
        assert result == raw

    def test_empty_repos(self) -> None:
        raw: dict[str, Any] = {"repos": {}}
        result = _migrate_v1_to_v2(raw)
        assert result == raw

    def test_skips_non_dict_repos(self) -> None:
        raw: dict[str, Any] = {"repos": {"bad": "not-a-dict"}}
        result = _migrate_v1_to_v2(raw)
        assert result == raw

    def test_idempotent(self) -> None:
        raw: dict[str, Any] = {
            "repos": {
                "my-repo": {
                    "email": {
                        "authorized_senders": ["user@example.com"],
                    }
                }
            }
        }
        result1 = _migrate_v1_to_v2(raw)
        result2 = _migrate_v1_to_v2(result1)
        assert result1 == result2


class TestApplyMigrations:
    def test_already_current(self) -> None:
        raw: dict[str, Any] = {
            "config_version": CURRENT_CONFIG_VERSION,
            "repos": {},
        }
        result = apply_migrations(raw)
        assert result["config_version"] == CURRENT_CONFIG_VERSION

    def test_missing_version_defaults_to_1(self) -> None:
        raw: dict[str, Any] = {"repos": {}}
        result = apply_migrations(raw)
        assert result["config_version"] == CURRENT_CONFIG_VERSION

    def test_stamps_current_version(self) -> None:
        raw: dict[str, Any] = {"config_version": 1, "repos": {}}
        result = apply_migrations(raw)
        assert result["config_version"] == CURRENT_CONFIG_VERSION

    def test_invalid_version_type(self) -> None:
        raw: dict[str, Any] = {"config_version": "abc"}
        with pytest.raises(ConfigError, match="Invalid config_version"):
            apply_migrations(raw)

    def test_zero_version(self) -> None:
        raw: dict[str, Any] = {"config_version": 0}
        with pytest.raises(ConfigError, match="positive integer"):
            apply_migrations(raw)

    def test_future_version(self) -> None:
        raw: dict[str, Any] = {"config_version": CURRENT_CONFIG_VERSION + 1}
        with pytest.raises(ConfigError, match="newer than supported"):
            apply_migrations(raw)

    def test_migration_chain(self) -> None:
        # Ensure all migrations from 1 to current are defined
        for v in range(1, CURRENT_CONFIG_VERSION):
            assert v in MIGRATIONS, f"Missing migration from v{v} to v{v + 1}"

    def test_missing_migration_function(self) -> None:
        """Raise if a migration step has no function defined."""
        from unittest.mock import patch

        with patch(
            "airut.config.migration.MIGRATIONS",
            {},
        ):
            raw: dict[str, Any] = {"config_version": 1}
            with pytest.raises(ConfigError, match="No migration defined"):
                apply_migrations(raw)

    def test_v1_migration_raises_on_legacy_fields(self) -> None:
        raw: dict[str, Any] = {
            "config_version": 1,
            "repos": {
                "test": {
                    "authorized_senders": ["user@example.com"],
                    "email": {},
                }
            },
        }
        with pytest.raises(ConfigError, match="authorized_senders"):
            apply_migrations(raw)
