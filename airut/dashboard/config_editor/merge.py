# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Raw dict lookup, merge, and field grouping for the config editor.

Provides helpers for navigating and updating nested YAML dicts using
the ``YAML_*_STRUCTURE`` mappings from ``airut.config.source``.
"""

from typing import Any

from airut.config.schema import FieldSchema
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
    set_nested,
)


# ── Raw dict lookup ──────────────────────────────────────────────────


def lookup_raw(
    raw: dict[str, Any],
    field_name: str,
    structure: dict[str, tuple[str, ...]],
) -> object:
    """Look up a field value from a raw YAML dict using a structure mapping."""
    path = structure.get(field_name)
    if path is not None:
        d: Any = raw
        for key in path:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d
    return raw.get(field_name)


def lookup_global_raw(
    raw: dict[str, Any],
    field_name: str,
) -> object:
    """Look up a GlobalConfig field value from the raw YAML dict."""
    return lookup_raw(raw, field_name, YAML_GLOBAL_STRUCTURE)


def lookup_repo_raw(
    raw_repo: dict[str, Any],
    field_name: str,
) -> object:
    """Look up a RepoServerConfig field value from its raw YAML dict."""
    return lookup_raw(raw_repo, field_name, YAML_REPO_STRUCTURE)


def lookup_email_raw(
    raw_email: dict[str, Any],
    field_name: str,
) -> object:
    """Look up an EmailChannelConfig field from the raw email YAML dict."""
    return lookup_raw(raw_email, field_name, YAML_EMAIL_STRUCTURE)


# ── Nested dict helpers ──────────────────────────────────────────────


def delete_nested(
    target: dict[str, Any],
    path: tuple[str, ...],
) -> None:
    """Delete a value from a nested dict (no-op if missing)."""
    for key in path[:-1]:
        if not isinstance(target, dict) or key not in target:
            return
        target = target[key]
    if isinstance(target, dict):
        target.pop(path[-1], None)


# ── Field merging ────────────────────────────────────────────────────


def merge_fields(
    raw: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
    structure: dict[str, tuple[str, ...]],
) -> None:
    """Merge parsed config fields into a raw dict using a structure mapping.

    Fields present in ``parsed`` are set; fields in ``schema`` but
    absent from ``parsed`` are removed (user cleared them).
    """
    for field in schema:
        path = structure.get(field.name)
        if field.name in parsed:
            if path:
                set_nested(raw, path, parsed[field.name])
            else:
                raw[field.name] = parsed[field.name]
        elif not field.required:
            if path:
                delete_nested(raw, path)
            else:
                raw.pop(field.name, None)


def merge_global_fields(
    raw: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed global config fields into the raw YAML dict."""
    merge_fields(raw, parsed, schema, YAML_GLOBAL_STRUCTURE)


def merge_repo_fields(
    raw_repo: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed repo config fields into the raw repo dict."""
    merge_fields(raw_repo, parsed, schema, YAML_REPO_STRUCTURE)


def merge_email_fields(
    raw_email: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed email config fields into the raw email dict."""
    merge_fields(raw_email, parsed, schema, YAML_EMAIL_STRUCTURE)


# ── Field grouping ───────────────────────────────────────────────────


def group_fields(
    schema: list[FieldSchema],
    structure: dict[str, tuple[str, ...]],
) -> list[tuple[str, list[FieldSchema]]]:
    """Group schema fields by their YAML nesting structure.

    Fields sharing the same first path element are grouped.  Fields
    not in the structure mapping go into a "General" group.

    Returns a list of ``(group_name, fields)`` tuples in order of
    first appearance.
    """
    groups: dict[str, list[FieldSchema]] = {}
    order: list[str] = []

    for field in schema:
        path = structure.get(field.name)
        if path and len(path) > 1:
            group = path[0].replace("_", " ").title()
        else:
            group = "General"
        if group not in groups:
            groups[group] = []
            order.append(group)
        groups[group].append(field)

    return [(g, groups[g]) for g in order]


#: Custom grouping for email channel fields (flat YAML, so
#: YAML_EMAIL_STRUCTURE doesn't produce good groups).
_EMAIL_FIELD_GROUPS: dict[str, str] = {
    "imap_server": "Connection",
    "imap_port": "Connection",
    "smtp_server": "Connection",
    "smtp_port": "Connection",
    "username": "Authentication",
    "password": "Authentication",
    "authorized_senders": "Authentication",
    "trusted_authserv_id": "Authentication",
    "smtp_require_auth": "Authentication",
    "microsoft_internal_auth_fallback": "Authentication",
    "from_address": "Display",
    "poll_interval_seconds": "Polling",
    "use_imap_idle": "Polling",
    "idle_reconnect_interval_seconds": "Polling",
    "microsoft_oauth2_tenant_id": "Microsoft OAuth2",
    "microsoft_oauth2_client_id": "Microsoft OAuth2",
    "microsoft_oauth2_client_secret": "Microsoft OAuth2",
}


def group_email_fields(
    schema: list[FieldSchema],
) -> list[tuple[str, list[FieldSchema]]]:
    """Group email config fields using custom grouping table."""
    groups: dict[str, list[FieldSchema]] = {}
    order: list[str] = []

    for field in schema:
        group = _EMAIL_FIELD_GROUPS.get(field.name, "Other")
        if group not in groups:
            groups[group] = []
            order.append(group)
        groups[group].append(field)

    return [(g, groups[g]) for g in order]
