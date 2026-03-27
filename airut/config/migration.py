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
CURRENT_CONFIG_VERSION: int = 4


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


def unique_var_name(
    desired: str,
    existing: set[str],
) -> str:
    """Return *desired* if not in *existing*, else append a numeric suffix.

    Tries ``desired``, then ``desired_2``, ``desired_3``, etc. until a
    name not in *existing* is found.  Useful for migrations that
    auto-create variables without colliding with user-defined ones.

    Args:
        desired: Preferred variable name.
        existing: Set of variable names already in use.

    Returns:
        A name guaranteed not to be in *existing*.
    """
    if desired not in existing:
        return desired
    n = 2
    while f"{desired}_{n}" in existing:
        n += 1
    return f"{desired}_{n}"


#: Resource limit sub-fields eligible for variable extraction.
_RESOURCE_LIMIT_FIELDS = ("timeout", "memory", "cpus", "pids_limit")


def _migrate_v2_to_v3(raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate v2 -> v3: extract global resource_limits into variables.

    Moves top-level ``resource_limits`` values into the ``vars:`` section
    and injects ``!var`` references into repos that did not explicitly set
    the corresponding sub-field.  After migration the top-level
    ``resource_limits`` key is removed.

    This is a non-security structural migration — safe to auto-transform.

    Args:
        raw: Raw config dict.

    Returns:
        The transformed config dict.
    """
    from airut.yaml_env import VarRef

    global_limits = raw.get("resource_limits")
    if not isinstance(global_limits, dict) or not global_limits:
        # Nothing to migrate: no top-level resource_limits set.
        # Remove the key if present (could be None or empty dict).
        raw.pop("resource_limits", None)
        return raw

    # Collect fields that have values set in the global block.
    fields_to_extract: dict[str, Any] = {}
    for field_name in _RESOURCE_LIMIT_FIELDS:
        if (
            field_name in global_limits
            and global_limits[field_name] is not None
        ):
            fields_to_extract[field_name] = global_limits[field_name]

    if not fields_to_extract:
        raw.pop("resource_limits", None)
        return raw

    # Build or extend the vars: section.
    vars_section = raw.get("vars")
    if vars_section is None:
        vars_section = {}
        raw["vars"] = vars_section
    elif not isinstance(vars_section, dict):
        # Malformed vars: section — leave untouched, validation will catch.
        # Still remove the old key so it doesn't linger.
        raw.pop("resource_limits", None)
        return raw

    existing_vars = set(vars_section.keys())

    # Create a variable for each global resource limit field.
    # var_map: field_name -> variable_name
    var_map: dict[str, str] = {}
    for field_name, value in fields_to_extract.items():
        desired = f"default_resource_{field_name}"
        var_name = unique_var_name(desired, existing_vars)
        vars_section[var_name] = value
        existing_vars.add(var_name)
        var_map[field_name] = var_name

    # Inject !var references into repos that don't explicitly set
    # the corresponding sub-field.
    repos = raw.get("repos", {})
    if isinstance(repos, dict):
        for repo in repos.values():
            if not isinstance(repo, dict):
                continue
            repo_limits = repo.get("resource_limits")
            if repo_limits is None:
                repo_limits = {}
                repo["resource_limits"] = repo_limits
            elif not isinstance(repo_limits, dict):
                continue

            for field_name, var_name in var_map.items():
                if field_name not in repo_limits:
                    repo_limits[field_name] = VarRef(var_name)

    # Remove the top-level resource_limits block.
    raw.pop("resource_limits", None)

    return raw


#: Mapping from old flat email YAML keys to their new nested location.
#: Each entry is (old_key, new_section, new_key).  Keys already under
#: ``imap:`` or ``microsoft_oauth2:`` are handled separately.
_V4_EMAIL_MOVES: list[tuple[str, str, str]] = [
    ("username", "account", "username"),
    ("password", "account", "password"),
    ("from", "account", "from"),
    ("imap_server", "imap", "server"),
    ("imap_port", "imap", "port"),
    ("smtp_server", "smtp", "server"),
    ("smtp_port", "smtp", "port"),
    ("smtp_require_auth", "smtp", "require_auth"),
    ("authorized_senders", "auth", "authorized_senders"),
    ("trusted_authserv_id", "auth", "trusted_authserv_id"),
    ("microsoft_internal_auth_fallback", "auth", "microsoft_internal_fallback"),
]


def _migrate_v3_to_v4(raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate v3 -> v4: reorganize email fields into subsections.

    Restructures the flat ``email:`` block into nested subsections:
    ``account:``, ``imap:``, ``smtp:``, ``auth:``.  The
    ``microsoft_oauth2:`` section is already nested and stays unchanged.

    This is a non-security structural migration — field values are
    preserved unchanged, only the nesting changes.

    Args:
        raw: Raw config dict.

    Returns:
        The transformed config dict.
    """
    repos = raw.get("repos", {})
    if not isinstance(repos, dict):
        return raw

    for repo in repos.values():
        if not isinstance(repo, dict):
            continue
        email = repo.get("email")
        if not isinstance(email, dict):
            continue

        # Move flat top-level keys into their new sections
        for old_key, section, new_key in _V4_EMAIL_MOVES:
            if old_key in email:
                email.setdefault(section, {})[new_key] = email.pop(old_key)

    return raw


#: Migration functions keyed by the version they migrate FROM.
#: Each takes a raw dict and returns the transformed raw dict.
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_v1_to_v2,
    2: _migrate_v2_to_v3,
    3: _migrate_v3_to_v4,
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
