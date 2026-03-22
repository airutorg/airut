# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Schema migration for server configuration.

Each config file carries a ``config_version`` integer (defaults to ``1``
when absent).  On load, migrations are applied sequentially from the
file's version to ``CURRENT_CONFIG_VERSION``.

Migration functions operate on raw dicts (pre-resolution) and must be
idempotent.  Security-sensitive migrations raise ``ConfigError`` instead
of silently transforming.
"""

import logging
from collections.abc import Callable
from typing import Any

from airut.gateway.config import ConfigError


logger = logging.getLogger(__name__)

#: Current schema version.  Bump when adding a migration.
CURRENT_CONFIG_VERSION: int = 2


def _migrate_v1_to_v2(raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate v1 -> v2: detect legacy email field placement.

    Security-critical: refuses to auto-migrate ``authorized_senders``
    and other email-specific fields found at the repo level.  The user
    must manually move them under ``email:``.

    Args:
        raw: Raw config dict.

    Returns:
        The config dict (unmodified if no legacy fields found).

    Raises:
        ConfigError: If legacy email fields are found at repo level.
    """
    legacy_fields = {
        "authorized_senders",
        "trusted_authserv_id",
        "microsoft_internal_auth_fallback",
        "imap",
    }

    repos = raw.get("repos", {})
    if not isinstance(repos, dict):
        return raw
    for repo_id, repo in repos.items():
        if not isinstance(repo, dict):
            continue
        found = sorted(legacy_fields & repo.keys())
        if found:
            listed = ", ".join(f"'{k}'" for k in found)
            raise ConfigError(
                f"repos.{repo_id}: {listed} must be nested under "
                f"'email:'. See config/airut.example.yaml."
            )

    return raw


#: Migration functions keyed by the version they migrate FROM.
#: Each takes a raw dict and returns the transformed raw dict.
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_v1_to_v2,
}


def apply_migrations(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply all pending migrations to a raw config dict.

    Reads ``config_version`` from the dict (defaults to ``1`` if
    absent), applies migrations sequentially up to
    ``CURRENT_CONFIG_VERSION``, and stamps the result with the current
    version.

    Args:
        raw: Raw config dict as loaded from the config source.

    Returns:
        Migrated config dict with ``config_version`` set to current.

    Raises:
        ConfigError: If a migration fails or version is unsupported.
    """
    version = raw.get("config_version", 1)

    if not isinstance(version, int) or version < 1:
        raise ConfigError(
            f"Invalid config_version: {version!r} (must be a positive integer)"
        )

    if version > CURRENT_CONFIG_VERSION:
        raise ConfigError(
            f"Config version {version} is newer than supported "
            f"version {CURRENT_CONFIG_VERSION}. "
            f"Please update Airut."
        )

    if version < CURRENT_CONFIG_VERSION:
        logger.info(
            "Migrating config from version %d to %d",
            version,
            CURRENT_CONFIG_VERSION,
        )

    while version < CURRENT_CONFIG_VERSION:
        migration = MIGRATIONS.get(version)
        if migration is None:
            raise ConfigError(
                f"No migration defined for config_version {version} -> "
                f"{version + 1}"
            )
        raw = migration(raw)
        version += 1

    raw["config_version"] = CURRENT_CONFIG_VERSION
    return raw
