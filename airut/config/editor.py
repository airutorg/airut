# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor logic for the web dashboard.

Provides JSON-safe encoding/decoding of ``EnvVar``/``VarRef`` tags,
validation through the full config pipeline, scope-grouped diffing,
and atomic file save with backup management.
"""

import copy
import dataclasses
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from airut.config.migration import apply_migrations
from airut.config.schema import Scope, get_field_meta
from airut.config.source import make_tag_dumper
from airut.config.vars import resolve_var_refs, resolve_vars_section
from airut.gateway.config import (
    ConfigError,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)
from airut.yaml_env import EnvVar, VarRef


logger = logging.getLogger(__name__)

#: Maximum number of backup files to keep.
_MAX_BACKUPS = 5


@dataclass(frozen=True)
class FieldChange:
    """A single changed field in the config diff.

    Attributes:
        field: Field name.
        doc: Human-readable description from FieldMeta.
        old: Previous value.
        new: New value.
        repo: Repo name for per-repo fields, None for global.
    """

    field: str
    doc: str
    old: object
    new: object
    repo: str | None


@dataclass(frozen=True)
class PreviewResult:
    """Result of a config preview (validation + diff).

    Attributes:
        valid: Whether the edited config is valid.
        error: Validation error message (None if valid).
        diff: Changes grouped by scope name (None if invalid).
        warnings: Advisory messages (e.g. server-scope restart warning).
    """

    valid: bool
    error: str | None
    diff: dict[str, list[FieldChange]] | None
    warnings: list[str]


def raw_to_json(raw: dict[str, Any]) -> dict[str, Any]:
    """Encode ``EnvVar``/``VarRef`` as JSON-safe ``__tag__`` dicts.

    Recursively walks the raw config dict and replaces ``EnvVar`` and
    ``VarRef`` objects with ``{"__tag__": "env", "name": "..."}`` and
    ``{"__tag__": "var", "name": "..."}`` respectively.

    Args:
        raw: Raw config dict with ``EnvVar``/``VarRef`` objects.

    Returns:
        New dict with tags encoded as JSON-safe markers.
    """
    return cast(dict[str, Any], _encode_value(raw))


def _encode_value(value: object) -> object:
    """Recursively encode EnvVar/VarRef objects."""
    if isinstance(value, EnvVar):
        return {"__tag__": "env", "name": value.var_name}
    if isinstance(value, VarRef):
        return {"__tag__": "var", "name": value.var_name}
    if isinstance(value, dict):
        return {k: _encode_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_value(v) for v in value]
    return value


def json_to_raw(data: dict[str, Any]) -> dict[str, Any]:
    """Decode ``__tag__`` dicts back to ``EnvVar``/``VarRef`` objects.

    Inverse of :func:`raw_to_json`.

    Args:
        data: JSON dict with ``__tag__`` markers.

    Returns:
        New dict with ``EnvVar``/``VarRef`` objects restored.
    """
    return cast(dict[str, Any], _decode_value(data))


def _decode_value(value: object) -> object:
    """Recursively decode __tag__ dicts."""
    if isinstance(value, dict):
        d = cast(dict[str, Any], value)
        tag = d.get("__tag__")
        if tag == "env" and "name" in d and len(d) == 2:
            return EnvVar(str(d["name"]))
        if tag == "var" and "name" in d and len(d) == 2:
            return VarRef(str(d["name"]))
        return {k: _decode_value(v) for k, v in d.items()}
    if isinstance(value, list):
        return [_decode_value(v) for v in value]
    return value


def validate_raw(raw: dict[str, Any]) -> ServerConfig:
    """Run full validation pipeline on a raw config dict.

    Replicates the ``ServerConfig.from_source()`` pipeline without
    requiring a ``ConfigSource``: apply_migrations -> deepcopy ->
    resolve_vars_section -> resolve_var_refs -> _from_raw.

    Args:
        raw: Raw config dict (with ``EnvVar``/``VarRef`` objects).

    Returns:
        The resolved ``ServerConfig``.

    Raises:
        ConfigError: If validation fails at any stage.
    """
    raw = apply_migrations(copy.deepcopy(raw))
    resolved = copy.deepcopy(raw)
    vars_table = resolve_vars_section(resolved)
    resolved = resolve_var_refs(resolved, vars_table)
    return ServerConfig._from_raw(resolved)


def preview_changes(
    current_config: ServerConfig,
    edited_json: dict[str, Any],
) -> PreviewResult:
    """Validate edited config and compute scope-grouped diff.

    Uses the two-level diff strategy: global field-by-field comparison
    + per-repo field-by-field comparison with ``get_field_meta()`` for
    scope classification.

    Args:
        current_config: Currently active resolved ``ServerConfig``.
        edited_json: Edited config as JSON dict (with ``__tag__`` markers).

    Returns:
        ``PreviewResult`` with validation status and diff.
    """
    edited_raw = json_to_raw(edited_json)

    try:
        new_config = validate_raw(edited_raw)
    except (ConfigError, ValueError) as e:
        return PreviewResult(valid=False, error=str(e), diff=None, warnings=[])

    changes: dict[str, list[FieldChange]] = {
        "server": [],
        "repo": [],
        "task": [],
    }
    warnings: list[str] = []

    # 1. Global config: compare field by field
    _diff_global(
        current_config.global_config, new_config.global_config, changes
    )

    # 2. Per-repo: compare field by field
    current_repos = current_config.repos
    new_repos = new_config.repos

    for repo_id in sorted(set(current_repos.keys()) | set(new_repos.keys())):
        if repo_id not in current_repos:
            changes["repo"].append(
                FieldChange(
                    field="(repository)",
                    doc=f"Repository '{repo_id}' added",
                    old=None,
                    new=repo_id,
                    repo=repo_id,
                )
            )
            continue
        if repo_id not in new_repos:
            changes["repo"].append(
                FieldChange(
                    field="(repository)",
                    doc=f"Repository '{repo_id}' removed",
                    old=repo_id,
                    new=None,
                    repo=repo_id,
                )
            )
            continue
        _diff_repo(current_repos[repo_id], new_repos[repo_id], repo_id, changes)

    if changes["server"]:
        warnings.append(
            "server-scope changes require service restart or idle period"
        )

    # Check if there are no changes at all
    has_changes = any(changes[scope] for scope in changes)
    if not has_changes:
        return PreviewResult(valid=True, error=None, diff=changes, warnings=[])

    return PreviewResult(
        valid=True, error=None, diff=changes, warnings=warnings
    )


def _diff_global(
    current: GlobalConfig,
    new: GlobalConfig,
    changes: dict[str, list[FieldChange]],
) -> None:
    """Compare GlobalConfig fields and add changes to the appropriate scope."""
    for f in dataclasses.fields(current):
        fm = get_field_meta(f)
        old_val = getattr(current, f.name)
        new_val = getattr(new, f.name)
        if old_val != new_val:
            scope_name = fm.scope.value if fm else Scope.SERVER.value
            doc = fm.doc if fm else f.name
            changes[scope_name].append(
                FieldChange(
                    field=f.name, doc=doc, old=old_val, new=new_val, repo=None
                )
            )


def _diff_repo(
    current: RepoServerConfig,
    new: RepoServerConfig,
    repo_id: str,
    changes: dict[str, list[FieldChange]],
) -> None:
    """Compare RepoServerConfig fields and add changes."""
    for f in dataclasses.fields(current):
        fm = get_field_meta(f)
        old_val = getattr(current, f.name)
        new_val = getattr(new, f.name)
        if old_val != new_val:
            scope_name = fm.scope.value if fm else Scope.REPO.value
            doc = fm.doc if fm else f.name
            changes[scope_name].append(
                FieldChange(
                    field=f.name,
                    doc=doc,
                    old=old_val,
                    new=new_val,
                    repo=repo_id,
                )
            )


def backup_config(source_path: Path) -> Path:
    """Create a timestamped backup of the config file.

    Keeps the latest ``_MAX_BACKUPS`` backups and prunes older ones.

    Args:
        source_path: Path to the config file to back up.

    Returns:
        Path to the created backup file.
    """
    timestamp = int(time.time() * 1000)
    backup_path = source_path.with_suffix(f".{timestamp}.bak")
    backup_path.write_bytes(source_path.read_bytes())

    # Prune old backups
    pattern = f"{source_path.stem}.*.bak"
    backups = sorted(source_path.parent.glob(pattern))
    while len(backups) > _MAX_BACKUPS:
        oldest = backups.pop(0)
        oldest.unlink()

    logger.info("Config backup created: %s", backup_path.name)
    return backup_path


def atomic_save(
    raw: dict[str, Any],
    target_path: Path,
) -> None:
    """Write config dict to YAML using atomic write-to-temp-then-rename.

    Creates a temporary file in the same directory, writes YAML with
    tag representers, then renames atomically.  The inotify watcher
    detects the ``MOVED_TO`` event.

    Args:
        raw: Raw config dict (with ``EnvVar``/``VarRef`` objects).
        target_path: Path to the config file.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target_path.parent),
        prefix=f".{target_path.stem}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(
                raw,
                f,
                Dumper=make_tag_dumper(),
                default_flow_style=False,
                sort_keys=False,
            )
        os.rename(str(tmp_path), str(target_path))
    except BaseException:
        # Clean up temp file on any error
        if tmp_path.exists():
            tmp_path.unlink()
        raise
