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
    _migrate_v2_to_v3,
    _migrate_v3_to_v4,
    apply_migrations,
    unique_var_name,
)
from airut.gateway.config import ConfigError
from airut.yaml_env import VarRef


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


class TestUniqueVarName:
    def test_no_collision(self) -> None:
        assert unique_var_name("foo", set()) == "foo"

    def test_no_collision_with_other_names(self) -> None:
        assert unique_var_name("foo", {"bar", "baz"}) == "foo"

    def test_collision_adds_suffix(self) -> None:
        assert unique_var_name("foo", {"foo"}) == "foo_2"

    def test_collision_skips_taken_suffixes(self) -> None:
        assert unique_var_name("foo", {"foo", "foo_2", "foo_3"}) == "foo_4"

    def test_collision_finds_gap(self) -> None:
        assert unique_var_name("foo", {"foo", "foo_2"}) == "foo_3"


class TestMigrateV2ToV3:
    def test_no_global_resource_limits(self) -> None:
        """No top-level resource_limits → no-op."""
        raw: dict[str, Any] = {"repos": {"r": {"email": {}}}}
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result
        assert "vars" not in result

    def test_empty_global_resource_limits(self) -> None:
        """Empty resource_limits block is removed."""
        raw: dict[str, Any] = {
            "resource_limits": {},
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result
        assert "vars" not in result

    def test_none_global_resource_limits(self) -> None:
        """None resource_limits is removed."""
        raw: dict[str, Any] = {
            "resource_limits": None,
            "repos": {},
        }
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result

    def test_extracts_all_fields(self) -> None:
        """All resource limit fields are extracted into vars."""
        raw: dict[str, Any] = {
            "resource_limits": {
                "timeout": 7200,
                "memory": "8g",
                "cpus": 4,
                "pids_limit": 1024,
            },
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result
        assert result["vars"] == {
            "default_resource_timeout": 7200,
            "default_resource_memory": "8g",
            "default_resource_cpus": 4,
            "default_resource_pids_limit": 1024,
        }

    def test_injects_var_refs_into_repos(self) -> None:
        """Repos without explicit sub-fields get !var refs."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 3600, "memory": "4g"},
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        repo_limits = result["repos"]["r"]["resource_limits"]
        assert repo_limits["timeout"] == VarRef("default_resource_timeout")
        assert repo_limits["memory"] == VarRef("default_resource_memory")

    def test_repo_explicit_field_preserved(self) -> None:
        """Repo-level explicit values are not overwritten with !var."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 7200, "memory": "8g"},
            "repos": {
                "r": {
                    "email": {},
                    "resource_limits": {"timeout": 3600},
                }
            },
        }
        result = _migrate_v2_to_v3(raw)
        repo_limits = result["repos"]["r"]["resource_limits"]
        assert repo_limits["timeout"] == 3600  # kept
        assert repo_limits["memory"] == VarRef("default_resource_memory")

    def test_partial_global_limits(self) -> None:
        """Only set global fields are extracted; others are skipped."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 600},
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        assert result["vars"] == {"default_resource_timeout": 600}
        repo_limits = result["repos"]["r"]["resource_limits"]
        assert repo_limits["timeout"] == VarRef("default_resource_timeout")
        assert "memory" not in repo_limits

    def test_extends_existing_vars(self) -> None:
        """Existing vars: section is extended, not replaced."""
        raw: dict[str, Any] = {
            "vars": {"my_key": "my_value"},
            "resource_limits": {"timeout": 100},
            "repos": {},
        }
        result = _migrate_v2_to_v3(raw)
        assert result["vars"]["my_key"] == "my_value"
        assert result["vars"]["default_resource_timeout"] == 100

    def test_collision_avoidance(self) -> None:
        """Variable name collision adds a suffix."""
        raw: dict[str, Any] = {
            "vars": {"default_resource_timeout": "user_value"},
            "resource_limits": {"timeout": 100},
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        # Original var preserved
        assert result["vars"]["default_resource_timeout"] == "user_value"
        # New var gets suffix
        assert result["vars"]["default_resource_timeout_2"] == 100
        # Repo refs point to the suffixed name
        repo_limits = result["repos"]["r"]["resource_limits"]
        assert repo_limits["timeout"] == VarRef("default_resource_timeout_2")

    def test_multiple_repos(self) -> None:
        """Multiple repos all get !var refs for unset fields."""
        raw: dict[str, Any] = {
            "resource_limits": {"cpus": 2},
            "repos": {
                "a": {"email": {}},
                "b": {"email": {}, "resource_limits": {"cpus": 8}},
            },
        }
        result = _migrate_v2_to_v3(raw)
        assert result["repos"]["a"]["resource_limits"]["cpus"] == VarRef(
            "default_resource_cpus"
        )
        # b had explicit cpus=8, should be preserved
        assert result["repos"]["b"]["resource_limits"]["cpus"] == 8

    def test_no_repos_key(self) -> None:
        """Missing repos: key doesn't crash."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 100},
        }
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result
        assert result["vars"] == {"default_resource_timeout": 100}

    def test_skips_non_dict_repos(self) -> None:
        """Non-dict repo entries are skipped."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 100},
            "repos": {"bad": "not-a-dict"},
        }
        result = _migrate_v2_to_v3(raw)
        assert result["repos"]["bad"] == "not-a-dict"

    def test_skips_non_dict_repo_limits(self) -> None:
        """Non-dict resource_limits in a repo is skipped."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 100},
            "repos": {"r": {"email": {}, "resource_limits": "bad"}},
        }
        result = _migrate_v2_to_v3(raw)
        # Bad repo limits left alone
        assert result["repos"]["r"]["resource_limits"] == "bad"

    def test_idempotent(self) -> None:
        """Running the migration twice produces the same result."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": 7200, "memory": "8g"},
            "repos": {
                "r": {"email": {}, "resource_limits": {"timeout": 3600}},
            },
        }
        result1 = _migrate_v2_to_v3(raw)
        result2 = _migrate_v2_to_v3(result1)
        assert result1 == result2

    def test_null_field_values_skipped(self) -> None:
        """Fields set to None in global limits are not extracted."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": None, "memory": "4g"},
            "repos": {"r": {"email": {}}},
        }
        result = _migrate_v2_to_v3(raw)
        assert "default_resource_timeout" not in result["vars"]
        assert result["vars"] == {"default_resource_memory": "4g"}

    def test_all_null_field_values(self) -> None:
        """All None values in global limits → no vars created."""
        raw: dict[str, Any] = {
            "resource_limits": {"timeout": None, "memory": None},
            "repos": {},
        }
        result = _migrate_v2_to_v3(raw)
        assert "resource_limits" not in result
        assert "vars" not in result

    def test_malformed_vars_section(self) -> None:
        """Non-dict vars: section → resource_limits removed, vars kept."""
        raw: dict[str, Any] = {
            "vars": "not-a-dict",
            "resource_limits": {"timeout": 100},
            "repos": {},
        }
        result = _migrate_v2_to_v3(raw)
        # Malformed vars left for validation to catch
        assert result["vars"] == "not-a-dict"
        # resource_limits still removed
        assert "resource_limits" not in result

    def test_full_chain_v2_to_v3(self) -> None:
        """apply_migrations runs v2→v3 for config_version: 2."""
        raw: dict[str, Any] = {
            "config_version": 2,
            "resource_limits": {"timeout": 600},
            "repos": {"r": {"email": {}}},
        }
        result = apply_migrations(raw)
        assert result["config_version"] == CURRENT_CONFIG_VERSION
        assert "resource_limits" not in result
        assert result["vars"]["default_resource_timeout"] == 600


class TestMigrateV3ToV4:
    def test_no_email_block(self) -> None:
        """No email block → no-op."""
        raw: dict[str, Any] = {"repos": {"r": {"git": {"repo_url": "x"}}}}
        result = _migrate_v3_to_v4(raw)
        assert result == raw

    def test_non_dict_email(self) -> None:
        """Non-dict email value is left alone."""
        raw: dict[str, Any] = {"repos": {"r": {"email": "not-a-dict"}}}
        result = _migrate_v3_to_v4(raw)
        assert result["repos"]["r"]["email"] == "not-a-dict"

    def test_moves_flat_keys_into_subsections(self) -> None:
        """Flat email keys are moved into account/imap/smtp/auth."""
        raw: dict[str, Any] = {
            "repos": {
                "r": {
                    "email": {
                        "username": "user@example.com",
                        "password": "secret",
                        "from": "bot@example.com",
                        "imap_server": "imap.example.com",
                        "imap_port": 993,
                        "smtp_server": "smtp.example.com",
                        "smtp_port": 587,
                        "smtp_require_auth": True,
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "mx.example.com",
                        "microsoft_internal_auth_fallback": True,
                    }
                }
            }
        }
        result = _migrate_v3_to_v4(raw)
        email = result["repos"]["r"]["email"]

        assert email["account"] == {
            "username": "user@example.com",
            "password": "secret",
            "from": "bot@example.com",
        }
        assert email["imap"]["server"] == "imap.example.com"
        assert email["imap"]["port"] == 993
        assert email["smtp"] == {
            "server": "smtp.example.com",
            "port": 587,
            "require_auth": True,
        }
        assert email["auth"] == {
            "authorized_senders": ["admin@example.com"],
            "trusted_authserv_id": "mx.example.com",
            "microsoft_internal_fallback": True,
        }

        # Flat keys removed
        for key in (
            "username",
            "password",
            "from",
            "imap_server",
            "imap_port",
            "smtp_server",
            "smtp_port",
            "smtp_require_auth",
            "authorized_senders",
            "trusted_authserv_id",
            "microsoft_internal_auth_fallback",
        ):
            assert key not in email

    def test_preserves_existing_imap_nested_keys(self) -> None:
        """Existing imap: sub-keys (connect_retries, etc.) stay."""
        raw: dict[str, Any] = {
            "repos": {
                "r": {
                    "email": {
                        "imap_server": "imap.example.com",
                        "imap": {
                            "connect_retries": 5,
                            "poll_interval": 30,
                            "use_idle": True,
                            "idle_reconnect_interval": 600,
                        },
                    }
                }
            }
        }
        result = _migrate_v3_to_v4(raw)
        imap = result["repos"]["r"]["email"]["imap"]
        assert imap["server"] == "imap.example.com"
        assert imap["connect_retries"] == 5
        assert imap["poll_interval"] == 30
        assert imap["use_idle"] is True
        assert imap["idle_reconnect_interval"] == 600

    def test_preserves_microsoft_oauth2(self) -> None:
        """microsoft_oauth2: section is already nested and unchanged."""
        raw: dict[str, Any] = {
            "repos": {
                "r": {
                    "email": {
                        "microsoft_oauth2": {
                            "tenant_id": "t",
                            "client_id": "c",
                            "client_secret": "s",
                        },
                    }
                }
            }
        }
        result = _migrate_v3_to_v4(raw)
        assert result["repos"]["r"]["email"]["microsoft_oauth2"] == {
            "tenant_id": "t",
            "client_id": "c",
            "client_secret": "s",
        }

    def test_no_repos_key(self) -> None:
        """Missing repos: key doesn't crash."""
        raw: dict[str, Any] = {"execution": {"max_concurrent": 5}}
        result = _migrate_v3_to_v4(raw)
        assert result == raw

    def test_non_dict_repos(self) -> None:
        """Non-dict repos: is left alone."""
        raw: dict[str, Any] = {"repos": "not-a-dict"}
        result = _migrate_v3_to_v4(raw)
        assert result["repos"] == "not-a-dict"

    def test_skips_non_dict_repo(self) -> None:
        """Non-dict repo entries are skipped."""
        raw: dict[str, Any] = {"repos": {"bad": "not-a-dict"}}
        result = _migrate_v3_to_v4(raw)
        assert result["repos"]["bad"] == "not-a-dict"

    def test_partial_keys(self) -> None:
        """Only present flat keys are moved; missing keys are ignored."""
        raw: dict[str, Any] = {
            "repos": {
                "r": {
                    "email": {
                        "username": "user@example.com",
                        "imap_server": "imap.example.com",
                    }
                }
            }
        }
        result = _migrate_v3_to_v4(raw)
        email = result["repos"]["r"]["email"]
        assert email["account"] == {"username": "user@example.com"}
        assert email["imap"]["server"] == "imap.example.com"
        assert "smtp" not in email
        assert "auth" not in email

    def test_idempotent(self) -> None:
        """Running the migration twice produces the same result."""
        raw: dict[str, Any] = {
            "repos": {
                "r": {
                    "email": {
                        "username": "user@example.com",
                        "imap_server": "imap.example.com",
                        "authorized_senders": ["admin@example.com"],
                    }
                }
            }
        }
        result1 = _migrate_v3_to_v4(raw)
        result2 = _migrate_v3_to_v4(result1)
        assert result1 == result2

    def test_multiple_repos(self) -> None:
        """All repos are migrated."""
        raw: dict[str, Any] = {
            "repos": {
                "a": {"email": {"username": "a@example.com"}},
                "b": {"email": {"username": "b@example.com"}},
            }
        }
        result = _migrate_v3_to_v4(raw)
        assert result["repos"]["a"]["email"]["account"]["username"] == (
            "a@example.com"
        )
        assert result["repos"]["b"]["email"]["account"]["username"] == (
            "b@example.com"
        )

    def test_full_chain_v3_to_v4(self) -> None:
        """apply_migrations runs v3→v4 for config_version: 3."""
        raw: dict[str, Any] = {
            "config_version": 3,
            "repos": {
                "r": {
                    "email": {
                        "username": "user@example.com",
                        "imap_server": "imap.example.com",
                        "authorized_senders": ["admin@example.com"],
                    }
                }
            },
        }
        result = apply_migrations(raw)
        assert result["config_version"] == CURRENT_CONFIG_VERSION
        email = result["repos"]["r"]["email"]
        assert email["account"]["username"] == "user@example.com"
        assert email["imap"]["server"] == "imap.example.com"
        assert email["auth"]["authorized_senders"] == ["admin@example.com"]
