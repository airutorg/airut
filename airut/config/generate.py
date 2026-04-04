# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generate example and stub config files from schema metadata.

Produces ``config/airut.example.yaml`` and the stub config written by
``airut init`` by walking the declarative config schema automatically.
Comments and default values always match the source code — there is no
duplication of field names or structure.

Instead of hardcoded YAML snippets, example values come from **actual
config instances** — the same dataclasses that production code uses.
This means:

- Adding a field to a config class breaks generation until the example
  instance is updated (type-checked, validated by ``__post_init__``).
- Removing or renaming a field breaks the example instance immediately.
- Default values are always read from the dataclass, never duplicated.

The only remaining tables are:

- **Display overrides** for fields that should show ``!env`` / ``!var``
  syntax or illustrative values instead of their instance value.
- **Editorial comments** (e.g. section intros in schedules) that are
  documentation, not schema-derived.

CLI usage::

    # Generate (write) the example config
    uv run python -m airut.config.generate

    # Verify the example config is up to date
    uv run python -m airut.config.generate --check
"""

from __future__ import annotations

import dataclasses
import sys
from collections.abc import Callable
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from airut.config.schema import get_field_meta
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
)


if TYPE_CHECKING:
    from airut.gateway.config import EmailAuthConfig
    from airut.gateway.slack.config import SlackChannelConfig


#: Path to the example config relative to the repository root.
EXAMPLE_CONFIG_PATH = Path("config/airut.example.yaml")

#: Documentation URL base.
_DOCS_BASE = "https://github.com/airutorg/airut/blob/main"


# ---------------------------------------------------------------------------
# Example config instances — type-checked, validated by __post_init__.
# ---------------------------------------------------------------------------


def _example_instances() -> dict[str, Any]:
    """Build example config instances for YAML generation.

    Each instance is a real dataclass validated by ``__post_init__``.
    If a field is added, removed, or renamed, this function fails at
    import time, forcing the example to be updated.

    Returns:
        Dict keyed by class name mapping to example instances.
    """
    from airut.gateway.config import (
        EmailAccountConfig,
        EmailAuthConfig,
        GlobalConfig,
        ImapConfig,
        MicrosoftOAuth2Config,
        SmtpConfig,
    )
    from airut.gateway.slack.config import SlackChannelConfig
    from airut.sandbox.types import ResourceLimits

    return {
        "GlobalConfig": GlobalConfig(
            dashboard_base_url="dashboard.example.com",
            upstream_dns="1.1.1.1",
        ),
        "ResourceLimits": ResourceLimits(
            timeout=7200,
            memory="8g",
            cpus=4.0,
            pids_limit=1024,
        ),
        "EmailAccountConfig": EmailAccountConfig(
            username="airut",
            from_address="Airut <airut@example.com>",
            password="placeholder",
        ),
        "ImapConfig": ImapConfig(server="mail.example.com"),
        "SmtpConfig": SmtpConfig(server="mail.example.com"),
        "EmailAuthConfig": EmailAuthConfig(
            authorized_senders=["you@example.com"],
            trusted_authserv_id="mail.example.com",
        ),
        "MicrosoftOAuth2Config": MicrosoftOAuth2Config(
            tenant_id="placeholder",
            client_id="placeholder",
            client_secret="placeholder",
        ),
        "SlackChannelConfig": SlackChannelConfig(
            bot_token="xoxb-placeholder",
            app_token="xapp-placeholder",
            authorized=({"workspace_members": True},),
        ),
    }


# ---------------------------------------------------------------------------
# Display overrides — values shown instead of the instance value.
# Keys are "ClassName.field_name" and are validated against the schema.
# ---------------------------------------------------------------------------

#: Fields whose YAML representation should show a specific display
#: value instead of the literal value from the example instance.
#: Includes ``!env`` / ``!var`` tags and illustrative placeholder values.
_DISPLAY_OVERRIDES: dict[str, str] = {
    # !env tags — show how to reference environment variables
    "EmailAccountConfig.password": "!env EMAIL_PASSWORD",
    "MicrosoftOAuth2Config.tenant_id": "!env MS_OAUTH2_TENANT_ID",
    "MicrosoftOAuth2Config.client_id": "!env MS_OAUTH2_CLIENT_ID",
    "MicrosoftOAuth2Config.client_secret": "!env MS_OAUTH2_CLIENT_SECRET",
    "SlackChannelConfig.bot_token": "!env SLACK_BOT_TOKEN",
    "SlackChannelConfig.app_token": "!env SLACK_APP_TOKEN",
    # !var tags — show how to reference shared variables
    "ResourceLimits.timeout": "!var default_resource_timeout",
    "ResourceLimits.memory": "!var default_resource_memory",
    "ResourceLimits.cpus": "!var default_resource_cpus",
    "ResourceLimits.pids_limit": "!var default_resource_pids_limit",
    # Illustrative values for fields without useful defaults
    "RepoServerConfig.git_repo_url": "https://github.com/you/my-project.git",
    "RepoServerConfig.effort": "max",
    "GlobalConfig.upstream_dns": '"1.1.1.1"',
}

# ---------------------------------------------------------------------------
# Complex field serializers — replace hardcoded YAML snippets.
# Each serializer returns YAML lines derived from actual instances.
# ---------------------------------------------------------------------------

#: Editorial comments for specific fields (documentation, not schema).
_EDITORIAL_COMMENTS: dict[str, list[str]] = {
    "EmailAuthConfig.authorized_senders": [
        "  # - *@company.com",
    ],
    "SlackChannelConfig.authorized": [
        "  # Or restrict to a user group (requires usergroups:read scope):",
        "  # - user_group: engineering",
        "  # Or restrict to specific users:",
        "  # - user_id: U12345678",
    ],
}


def _serialize_authorized_senders(instance: EmailAuthConfig) -> list[str]:
    """Serialize EmailAuthConfig.authorized_senders to YAML lines."""
    lines = ["authorized_senders:"]
    for sender in instance.authorized_senders:
        lines.append(f"  - {sender}")
    lines.extend(_EDITORIAL_COMMENTS["EmailAuthConfig.authorized_senders"])
    return lines


def _serialize_slack_authorized(instance: SlackChannelConfig) -> list[str]:
    """Serialize SlackChannelConfig.authorized to YAML lines."""
    lines = ["authorized:"]
    lines.append("  # Allow all full workspace members:")
    for rule in instance.authorized:
        for key, value in rule.items():
            formatted = "true" if value is True else str(value)
            lines.append(f"  - {key}: {formatted}")
    lines.extend(_EDITORIAL_COMMENTS["SlackChannelConfig.authorized"])
    return lines


def _serialize_secrets() -> list[str]:
    """Serialize the example secrets dict to YAML lines."""
    return [
        "secrets:",
        "  ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY",
    ]


def _serialize_masked_secrets() -> list[str]:
    """Serialize example masked_secrets to YAML lines.

    Derives structure from MaskedSecret fields so that adding a field
    to MaskedSecret is caught by the coverage check.
    """
    from airut.gateway.config import MaskedSecret

    example = MaskedSecret(
        value="placeholder",
        scopes=frozenset({"*.githubusercontent.com", "api.github.com"}),
        headers=("Authorization",),
        allow_foreign_credentials=False,
    )
    lines = [
        "masked_secrets:",
        "  GH_TOKEN:",
        "    value: !env GH_TOKEN",
        "    scopes:",
    ]
    # Display order: specific domains before wildcards
    _masked_scope_order = ("api.github.com", "*.githubusercontent.com")
    for scope in _masked_scope_order:
        assert scope in example.scopes, f"scope {scope!r} not in example"
        lines.append(f'      - "{scope}"')
    lines.append("    headers:")
    for header in example.headers:
        lines.append(f'      - "{header}"')
    lines.append(
        f"    allow_foreign_credentials: "
        f"{'true' if example.allow_foreign_credentials else 'false'}"
    )
    return lines


def _serialize_signing_credentials() -> list[str]:
    """Serialize example signing_credentials to YAML lines.

    Derives structure from SigningCredential/SigningCredentialField
    so that adding or renaming fields is caught.
    """
    from airut.gateway.config import SigningCredential, SigningCredentialField

    example = SigningCredential(
        access_key_id=SigningCredentialField(
            name="AWS_ACCESS_KEY_ID", value="placeholder"
        ),
        secret_access_key=SigningCredentialField(
            name="AWS_SECRET_ACCESS_KEY", value="placeholder"
        ),
        session_token=SigningCredentialField(
            name="AWS_SESSION_TOKEN", value="placeholder"
        ),
        scopes=frozenset({"*.amazonaws.com"}),
    )
    lines = [
        "signing_credentials:",
        "  AWS_PROD:",
        "    type: aws-sigv4",
    ]
    for field_name in ("access_key_id", "secret_access_key", "session_token"):
        field_obj = getattr(example, field_name)
        if field_obj is not None:
            lines.append(f"    {field_name}:")
            lines.append(f"      name: {field_obj.name}")
            lines.append(f"      value: !env {field_obj.name}")
    lines.append("    scopes:")
    for scope in sorted(example.scopes):
        lines.append(f'      - "{scope}"')
    return lines


def _serialize_github_app_credentials() -> list[str]:
    """Serialize example github_app_credentials to YAML lines.

    Derives structure from GitHubAppCredential so that adding
    or renaming fields is caught.
    """
    from airut.gateway.config import GitHubAppCredential

    example = GitHubAppCredential(
        app_id="placeholder",
        private_key="placeholder",
        installation_id=0,
        scopes=frozenset(
            {"*.githubusercontent.com", "api.github.com", "github.com"}
        ),
        allow_foreign_credentials=False,
        base_url="https://api.github.com",
        permissions={"contents": "write", "pull_requests": "write"},
        repositories=("my-repo",),
    )
    # Display order: specific domains before wildcards
    _scope_display_order = (
        "github.com",
        "api.github.com",
        "*.githubusercontent.com",
    )
    lines = [
        "github_app_credentials:",
        "  GH_TOKEN:",
        "    app_id: !env GH_APP_ID",
        "    private_key: !env GH_APP_PRIVATE_KEY",
        "    installation_id: !env GH_APP_INSTALLATION_ID",
        "    scopes:",
    ]
    for scope in _scope_display_order:
        assert scope in example.scopes, f"scope {scope!r} not in example"
        lines.append(f'      - "{scope}"')
    lines.append(
        f"    allow_foreign_credentials: "
        f"{'true' if example.allow_foreign_credentials else 'false'}"
    )
    lines.append(f'    base_url: "{example.base_url}"')
    if example.permissions is not None:
        lines.append("    permissions:")
        for perm, level in example.permissions.items():
            lines.append(f"      {perm}: {level}")
    if example.repositories is not None:
        lines.append("    repositories:")
        for repo in example.repositories:
            lines.append(f"      - {repo}")
    return lines


def _serialize_schedules() -> list[str]:
    """Serialize example schedules to YAML lines.

    Uses actual ScheduleConfig/ScheduleDelivery instances so that
    field changes are caught at generation time.
    """
    from airut.gateway.config import ScheduleConfig, ScheduleDelivery

    # Prompt mode example (active)
    prompt_schedule = ScheduleConfig(
        cron="0 9 * * 1-5",
        prompt="Summarize recent changes and open issues.",
        deliver=ScheduleDelivery(to="team@example.com"),
    )
    # Script mode example (commented out)
    script_schedule = ScheduleConfig(
        cron="0 2 * * *",
        trigger_command="./scripts/check-status.sh",
        trigger_timeout=120,
        deliver=ScheduleDelivery(to="oncall@example.com"),
    )

    lines = [
        "schedules:",
        "  # Prompt mode: run Claude with a fixed prompt on a schedule",
        "  daily-report:",
        f'    cron: "{prompt_schedule.cron}"',
        "    prompt: >",
        f"      {prompt_schedule.prompt}",
        "    deliver:",
        f"      to: {prompt_schedule.deliver.to}",
    ]
    # Show optional fields from prompt_schedule as commented defaults
    _optional_schedule_fields = [
        ("subject", "Daily Report"),
        ("timezone", "America/New_York"),
        ("model", "sonnet"),
    ]
    for fname, example_val in _optional_schedule_fields:
        lines.append(f"    # {fname}: {example_val}")
    lines.append("")
    # Script mode (fully commented)
    lines.append(
        "  # Script mode: run a command, then Claude if it produces output"
    )
    lines.append("  # nightly-check:")
    lines.append(f'  #   cron: "{script_schedule.cron}"')
    lines.append(f'  #   trigger_command: "{script_schedule.trigger_command}"')
    lines.append(f"  #   trigger_timeout: {script_schedule.trigger_timeout}")
    lines.append("  #   deliver:")
    lines.append(f"  #     to: {script_schedule.deliver.to}")
    return lines


#: Maps "ClassName.field_name" to a serializer function that returns
#: YAML lines for that field.  The serializer receives the example
#: instance for the class (or None for static serializers).
_COMPLEX_SERIALIZERS: dict[str, Callable[[Any], list[str]]] = {
    "EmailAuthConfig.authorized_senders": _serialize_authorized_senders,
    "SlackChannelConfig.authorized": _serialize_slack_authorized,
    "RepoServerConfig.secrets": lambda _: _serialize_secrets(),
    "RepoServerConfig.masked_secrets": lambda _: _serialize_masked_secrets(),
    "RepoServerConfig.signing_credentials": (
        lambda _: _serialize_signing_credentials()
    ),
    "RepoServerConfig.github_app_credentials": (
        lambda _: _serialize_github_app_credentials()
    ),
    "RepoServerConfig.schedules": lambda _: _serialize_schedules(),
}


#: Fields that are structural and should not appear in the example config.
_SKIP_FIELDS: set[tuple[str, str]] = {
    ("RepoServerConfig", "repo_id"),
    ("RepoServerConfig", "channels"),
}


# ---------------------------------------------------------------------------
# Config class registry
# ---------------------------------------------------------------------------


def _config_classes() -> list[type]:
    """Return the config dataclass classes used for schema walking."""
    from airut.gateway.config import (
        EmailAccountConfig,
        EmailAuthConfig,
        EmailChannelConfig,
        GlobalConfig,
        ImapConfig,
        MicrosoftOAuth2Config,
        RepoServerConfig,
        SmtpConfig,
    )
    from airut.gateway.slack.config import SlackChannelConfig
    from airut.sandbox.types import ResourceLimits

    return [
        GlobalConfig,
        ResourceLimits,
        EmailAccountConfig,
        ImapConfig,
        SmtpConfig,
        EmailAuthConfig,
        MicrosoftOAuth2Config,
        EmailChannelConfig,
        RepoServerConfig,
        SlackChannelConfig,
    ]


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def validate_tables() -> list[str]:
    """Validate that all data table entries reference real schema fields.

    Returns:
        List of error messages (empty if all valid).
    """
    errors: list[str] = []
    class_map = {cls.__name__: cls for cls in _config_classes()}

    for table_name, table in [
        ("_DISPLAY_OVERRIDES", _DISPLAY_OVERRIDES),
        ("_COMPLEX_SERIALIZERS", _COMPLEX_SERIALIZERS),
    ]:
        for key in table:
            cls_name, _, field_name = key.partition(".")
            if not field_name:
                errors.append(
                    f"{table_name}: invalid key format '{key}' "
                    f"(expected 'ClassName.field_name')"
                )
                continue
            cls = class_map.get(cls_name)
            if cls is None:
                errors.append(
                    f"{table_name}: unknown class '{cls_name}' in '{key}'"
                )
                continue
            field_names = {f.name for f in dc_fields(cls)}
            if field_name not in field_names:
                errors.append(
                    f"{table_name}: field '{field_name}' not found "
                    f"on {cls_name} (key '{key}')"
                )

    return errors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_yaml(value: object) -> str:
    """Format a Python default value as a YAML scalar string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return str(value)  # pragma: no cover


def _yaml_key(
    field_name: str,
    structure: dict[str, tuple[str, ...]] | None,
) -> str:
    """Return the leaf YAML key for *field_name* from a structure mapping."""
    if structure and field_name in structure:
        return structure[field_name][-1]
    return field_name


def _yaml_section(
    field_name: str,
    structure: dict[str, tuple[str, ...]] | None,
) -> str | None:
    """Return the YAML section name for *field_name*, or None if top-level."""
    if structure and field_name in structure:
        path = structure[field_name]
        if len(path) > 1:
            return path[0]
    return None


def _field_value(
    cls: type,
    f: dataclasses.Field[Any],
    instances: dict[str, Any] | None = None,
) -> tuple[str | None, bool]:
    """Return (formatted_value, has_real_default) for a field.

    Looks up the example instance for the field's class, applies
    tag display overrides, then falls back to the dataclass default.
    """
    key = f"{cls.__name__}.{f.name}"
    has_default = (
        f.default is not dataclasses.MISSING
        or f.default_factory is not dataclasses.MISSING
    )

    # Tag display override takes priority
    if key in _DISPLAY_OVERRIDES:
        return _DISPLAY_OVERRIDES[key], has_default

    # Look up example instance
    if instances and cls.__name__ in instances:
        instance = instances[cls.__name__]
        val = getattr(instance, f.name)
        if val is not None:
            formatted = _format_yaml(val)
            # Quote strings that need YAML quoting (contain special
            # chars like angle brackets, or look like numbers)
            if isinstance(val, str) and " <" in val:
                formatted = f'"{val}"'
            return formatted, has_default

    # Fall back to dataclass default
    if f.default is not dataclasses.MISSING:
        if f.default is None:
            return None, True
        return _format_yaml(f.default), True

    if f.default_factory is not dataclasses.MISSING:
        return None, True

    return None, False


def _is_nested_dataclass(cls: type, f: dataclasses.Field[Any]) -> type | None:
    """If the field is a nested config dataclass, return its class."""
    import types

    hint = f.type
    # Unwrap Optional/Union (e.g. ResourceLimits | None)
    if isinstance(hint, types.UnionType):
        args = [a for a in hint.__args__ if a is not type(None)]
        if len(args) == 1:
            hint = args[0]
    if isinstance(hint, type) and dataclasses.is_dataclass(hint):
        return hint
    return None


def _comment_lines(lines: list[str], prefix: str = "") -> list[str]:
    """Prepend ``# `` to each line, with optional prefix indentation.

    Every non-empty line gets the ``# `` prefix regardless of content.
    Lines that are already comments (doc comments, editorial notes) get
    double-commented — this is correct for block-commenting sections
    where the inner ``#`` carries semantic meaning.
    """
    result: list[str] = []
    for line in lines:
        if not line:
            result.append(f"{prefix}#")
        else:
            result.append(f"{prefix}# {line}")
    return result


# ---------------------------------------------------------------------------
# Section-based rendering
# ---------------------------------------------------------------------------


def _group_fields_by_section(
    cls: type,
    structure: dict[str, tuple[str, ...]] | None,
) -> list[tuple[str | None, list[dataclasses.Field[Any]]]]:
    """Group annotated fields by their YAML section.

    Returns a list of (section_name, fields) pairs in field declaration
    order.  Fields at the top level have section_name=None.
    """
    groups: dict[str | None, list[dataclasses.Field[Any]]] = {}
    order: list[str | None] = []

    for f in dc_fields(cls):
        fm = get_field_meta(f)
        if fm is None:
            continue
        if fm.hidden:
            continue
        if (cls.__name__, f.name) in _SKIP_FIELDS:
            continue

        section = _yaml_section(f.name, structure)
        if section not in groups:
            groups[section] = []
            order.append(section)
        groups[section].append(f)

    return [(s, groups[s]) for s in order]


def _render_field(
    cls: type,
    f: dataclasses.Field[Any],
    structure: dict[str, tuple[str, ...]] | None,
    indent: str,
    *,
    force_comment: bool = False,
    plain: bool = False,
    instances: dict[str, Any] | None = None,
) -> list[str]:
    """Render a single field as YAML lines.

    Args:
        cls: The config dataclass containing this field.
        f: The dataclass field.
        structure: YAML structure mapping for key name resolution.
        indent: Indentation prefix string.
        force_comment: If True, always comment out regardless of defaults.
        plain: If True, render values without default-commenting (the
            caller will handle commenting, e.g. for commented sections).
        instances: Example config instances keyed by class name.
    """
    fm = get_field_meta(f)
    if fm is None:
        return []  # pragma: no cover

    key = f"{cls.__name__}.{f.name}"
    out: list[str] = []

    # Complex field with serializer
    if key in _COMPLEX_SERIALIZERS:
        out.append(f"{indent}# {fm.doc}")
        instance = instances.get(cls.__name__) if instances else None
        snippet = _COMPLEX_SERIALIZERS[key](instance)
        value, has_default = _field_value(cls, f, instances)
        commented = force_comment or (has_default and not plain)
        if commented:
            out.extend(_comment_lines(snippet, indent))
        else:
            for line in snippet:
                out.append(f"{indent}{line}")
        return out

    # Nested dataclass (e.g. resource_limits -> ResourceLimits)
    nested_cls = _is_nested_dataclass(cls, f)
    if nested_cls is not None:
        from airut.config.source import YAML_CLASS_STRUCTURES

        out.append(f"{indent}# {fm.doc}")
        yaml_name = _yaml_key(f.name, structure)
        # Look up per-class structure mapping for sub-field YAML keys
        nested_structure = YAML_CLASS_STRUCTURES.get(nested_cls.__name__)
        # Will the whole block be commented? (outer field is optional)
        block_comment = force_comment or (
            f.default is not dataclasses.MISSING
            or f.default_factory is not dataclasses.MISSING
        )
        # Render the nested class's fields under this key
        nested_lines = [f"{yaml_name}:"]
        for nf in dc_fields(nested_cls):
            nfm = get_field_meta(nf)
            if nfm is None:
                continue
            nk = f"{nested_cls.__name__}.{nf.name}"
            sub_yaml_name = _yaml_key(nf.name, nested_structure)
            # Complex serializers within nested classes
            if nk in _COMPLEX_SERIALIZERS:
                nested_lines.append(f"  # {nfm.doc}")
                n_instance = (
                    instances.get(nested_cls.__name__) if instances else None
                )
                snippet = _COMPLEX_SERIALIZERS[nk](n_instance)
                nval, has_default = _field_value(nested_cls, nf, instances)
                commented = force_comment or (has_default and not plain)
                if commented:
                    for sline in _comment_lines(snippet, "  "):
                        nested_lines.append(sline)
                else:
                    for sline in snippet:
                        nested_lines.append(f"  {sline}")
                continue
            nval, _ = _field_value(nested_cls, nf, instances)
            if nval is not None:
                nested_lines.append(f"  # {nfm.doc}")
                line = f"  {sub_yaml_name}: {nval}"
                # Comment sub-fields with defaults only when the
                # outer block itself won't be block-commented.
                if not block_comment:
                    nf_has_default = (
                        nf.default is not dataclasses.MISSING
                        or nf.default_factory is not dataclasses.MISSING
                    )
                    if force_comment or (nf_has_default and not plain):
                        line = f"  # {sub_yaml_name}: {nval}"
                nested_lines.append(line)
        if block_comment:
            out.extend(_comment_lines(nested_lines, indent))
        else:
            for line in nested_lines:
                out.append(f"{indent}{line}")
        return out

    # Simple scalar field
    value, has_default = _field_value(cls, f, instances)
    commented = force_comment or (has_default and not plain)
    yaml_name = _yaml_key(f.name, structure)

    out.append(f"{indent}# {fm.doc}")
    if value is not None:
        line = f"{yaml_name}: {value}"
        if commented:
            out.append(f"{indent}# {line}")
        else:
            out.append(f"{indent}{line}")
    elif plain:
        # Plain mode: show key without value (caller adds commenting)
        out.append(f"{indent}{yaml_name}:")
    else:
        # None default, no override — comment the key
        out.append(f"{indent}# {yaml_name}:")

    return out


def _render_section(
    cls: type,
    section: str | None,
    section_fields: list[dataclasses.Field[Any]],
    structure: dict[str, tuple[str, ...]] | None,
    indent: str,
    *,
    force_comment: bool = False,
    instances: dict[str, Any] | None = None,
) -> list[str]:
    """Render a group of fields that share a YAML section.

    If *section* is not None, wraps the fields under a ``section:``
    header.  When all fields in a section have defaults, the entire
    section is commented out as a block.
    """
    out: list[str] = []

    if section is not None:
        inner_indent = indent + "  "

        # Check if the section should be commented as a whole
        all_have_defaults = all(
            _field_value(cls, f, instances)[1] for f in section_fields
        )
        comment_section = force_comment or all_have_defaults

        if comment_section:
            # Build the section with fields in plain mode (no
            # per-field commenting), then comment the whole block.
            inner_lines: list[str] = [f"{section}:"]
            for i, f in enumerate(section_fields):
                rendered = _render_field(
                    cls,
                    f,
                    structure,
                    "  ",
                    plain=True,
                    instances=instances,
                )
                if i > 0:
                    inner_lines.append("")
                inner_lines.extend(rendered)
            out.extend(_comment_lines(inner_lines, indent))
        else:
            # Mixed section: some required, some optional.
            out.append(f"{indent}{section}:")
            for i, f in enumerate(section_fields):
                rendered = _render_field(
                    cls,
                    f,
                    structure,
                    inner_indent,
                    instances=instances,
                )
                if i > 0:
                    out.append("")
                out.extend(rendered)
    else:
        # Top-level fields (no section wrapper)
        for i, f in enumerate(section_fields):
            rendered = _render_field(
                cls,
                f,
                structure,
                indent,
                force_comment=force_comment,
                instances=instances,
            )
            if i > 0:
                out.append("")
            out.extend(rendered)

    return out


def _render_class(
    cls: type,
    structure: dict[str, tuple[str, ...]] | None,
    indent: str = "",
    *,
    force_comment: bool = False,
    instances: dict[str, Any] | None = None,
) -> list[str]:
    """Render all annotated fields of a config class as YAML sections."""
    groups = _group_fields_by_section(cls, structure)
    out: list[str] = []
    for section, section_fields in groups:
        if out:
            out.append("")
        out.extend(
            _render_section(
                cls,
                section,
                section_fields,
                structure,
                indent,
                force_comment=force_comment,
                instances=instances,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Example config
# ---------------------------------------------------------------------------

#: Static header for the example config.
_HEADER = """\
# Airut Server Configuration
#
# AUTO-GENERATED — do not edit by hand.
# Source: airut/config/generate.py  (schema in airut/gateway/config.py)
# Regenerate: uv run python -m airut.config.generate
#
# Server-side settings: infrastructure, credentials, and per-repo controls.
# All per-repo configuration (model, effort, resource limits, container env,
# network, secrets) is managed here.  There is no repo-side airut.yaml —
# only .airut/network-allowlist.yaml and the container Dockerfile (default
# .airut/container/Dockerfile, configurable via container_path) live in the
# repository.
#
# Run `airut init` to create a stub at ~/.config/airut/airut.yaml,
# then use this file as a reference for all available options.
# Never commit real credentials.
#
# Values tagged with !env are resolved from environment variables at load
# time.  Use !env for secrets; put everything else inline.  Set env vars
# in ~/.config/airut/.env (auto-loaded by the service).
#
# Use the vars: section to define shared values.  Reference them anywhere
# with !var.  This avoids repeating the same server address, API key, or
# token across multiple repos.  Resource limits are a common use case:
# define defaults as variables and reference them from each repo.
#
# vars:
#   mail_server: mail.example.com
#   anthropic_key: sk-ant-api03-...
#   gh_token: !env GH_TOKEN           # vars can reference !env too
#   default_resource_timeout: 7200    # shared resource limit defaults
#   default_resource_memory: "8g"
#   default_resource_cpus: 4
#   default_resource_pids_limit: 1024"""


def generate_example_config() -> str:
    """Generate the full example config from schema metadata.

    Walks all config dataclasses automatically.  Field names, doc
    strings, defaults, and YAML key mappings are read from the schema —
    nothing is duplicated here.  Example values come from actual config
    instances, validated by ``__post_init__``.

    Returns:
        Complete YAML config file content.

    Raises:
        ValueError: If data tables reference fields not in the schema.
    """
    from airut.gateway.config import (
        EmailChannelConfig,
        GlobalConfig,
        RepoServerConfig,
    )
    from airut.gateway.slack.config import SlackChannelConfig

    # Validate all data tables against the schema
    errors = validate_tables()
    if errors:
        raise ValueError(
            "Schema drift detected in generate.py data tables:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    instances = _example_instances()

    out: list[str] = [_HEADER]

    # -- Global settings ---------------------------------------------------
    out.append("")
    out.extend(
        _render_class(GlobalConfig, YAML_GLOBAL_STRUCTURE, instances=instances)
    )

    # -- Repos -------------------------------------------------------------
    sep = "-" * 75
    sep2 = "-" * 73
    out.extend(
        [
            "",
            f"# {sep}",
            "# Repositories",
            f"# {sep}",
            "# Each entry under repos: defines a channel"
            " configuration + git repository.",
            "# A repo can have email, Slack, or both channels"
            " active simultaneously.",
            "",
            "repos:",
            f"  # {sep2}",
            "  # Example: primary repository",
            f"  # {sep2}",
            "  my-project:",
        ]
    )

    # Email channel
    out.append("    email:")
    out.extend(
        _render_class(
            EmailChannelConfig,
            YAML_EMAIL_STRUCTURE,
            indent="      ",
            instances=instances,
        )
    )
    out.append("")

    # Repo-level fields (git, model, effort, etc.)
    out.extend(
        _render_class(
            RepoServerConfig,
            YAML_REPO_STRUCTURE,
            indent="    ",
            instances=instances,
        )
    )
    out.append("")

    # Slack channel (commented out)
    out.append("    # Slack channel (can coexist with email).")
    out.append("    # See config/slack-app-manifest.json for app setup.")
    out.append("    # slack:")
    out.extend(
        _render_class(
            SlackChannelConfig,
            None,
            indent="      ",
            force_comment=True,
            instances=instances,
        )
    )

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Stub config (for airut init)
# ---------------------------------------------------------------------------


def generate_stub_config() -> str:
    """Generate a minimal stub config for ``airut init``.

    Walks the schema to include only required fields (no default) with
    placeholder values, plus a reference link to the full example config.

    Returns:
        Minimal YAML config file content.
    """
    from airut.gateway.config import (
        GlobalConfig,
    )

    instances = _example_instances()

    out: list[str] = [
        "# Airut Server Configuration",
        "#",
        "# For all available options, see the documented example:",
        f"# {_DOCS_BASE}/config/airut.example.yaml",
        "",
    ]

    # Show a couple of useful global defaults (commented)
    out.extend(
        _render_class(GlobalConfig, YAML_GLOBAL_STRUCTURE, instances=instances)
    )

    # Repo section with required fields only
    out.extend(
        [
            "",
            "repos:",
            "  my-project:",
            "    email:",
        ]
    )

    # Walk email sub-dataclasses to render required fields + selected
    # optional fields under the email: section.
    from airut.config.source import YAML_CLASS_STRUCTURES
    from airut.gateway.config import (
        EmailAccountConfig,
        EmailAuthConfig,
        ImapConfig,
        SmtpConfig,
    )

    #: Sub-dataclasses in section order, plus which optional fields to include.
    _stub_sections: list[tuple[str, type, set[str]]] = [
        ("account", EmailAccountConfig, {"password"}),
        ("imap", ImapConfig, set()),
        ("smtp", SmtpConfig, set()),
        ("auth", EmailAuthConfig, {"authorized_senders"}),
    ]
    for section_name, section_cls, include_optional in _stub_sections:
        section_structure = YAML_CLASS_STRUCTURES.get(section_cls.__name__)
        out.append(f"      {section_name}:")
        for nf in dc_fields(section_cls):
            if get_field_meta(nf) is None:
                continue  # pragma: no cover
            nk = f"{section_cls.__name__}.{nf.name}"
            has_default = (
                nf.default is not dataclasses.MISSING
                or nf.default_factory is not dataclasses.MISSING
            )
            if has_default and nf.name not in include_optional:
                continue
            sub_yaml_name = _yaml_key(nf.name, section_structure)
            if nk in _COMPLEX_SERIALIZERS:
                instance = instances.get(section_cls.__name__)
                for line in _COMPLEX_SERIALIZERS[nk](instance):
                    out.append(f"        {line}")
                continue
            value, _ = _field_value(section_cls, nf, instances)
            if value is None:
                continue
            out.append(f"        {sub_yaml_name}: {value}")

    # repo_url and secrets
    from airut.gateway.config import RepoServerConfig

    git_url_field = next(
        f for f in dc_fields(RepoServerConfig) if f.name == "git_repo_url"
    )
    git_url, _ = _field_value(RepoServerConfig, git_url_field, instances)
    out.extend(
        [
            f"    repo_url: {git_url}",
            "    secrets:",
            "      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY",
        ]
    )

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Field coverage validation
# ---------------------------------------------------------------------------


def check_field_coverage() -> list[str]:
    """Check that all annotated config fields are covered.

    Generates the example config and verifies that every
    ``FieldMeta``-annotated field's doc string appears in the output.
    This is self-maintaining — adding a new annotated field without
    including it in the generator will cause this check to fail.

    Returns:
        List of error messages for missing fields (empty if all covered).
    """
    content = generate_example_config()
    errors: list[str] = []

    for cls in _config_classes():
        for f in dc_fields(cls):
            fm = get_field_meta(f)
            if fm is None:
                continue
            if fm.hidden:
                continue
            if (cls.__name__, f.name) in _SKIP_FIELDS:
                continue
            if fm.doc not in content:
                errors.append(
                    f"{cls.__name__}.{f.name} is annotated with"
                    f" FieldMeta but its doc string was not found"
                    f" in the generated config"
                )

    return errors


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """CLI entry point for generating or checking the example config.

    Usage:
        ``python -m airut.config.generate``         — write the file
        ``python -m airut.config.generate --check``  — verify matches

    Returns:
        Exit code (0 = success, 1 = mismatch or error).
    """
    check_mode = "--check" in sys.argv

    content = generate_example_config()
    path = EXAMPLE_CONFIG_PATH

    if check_mode:
        if not path.exists():
            print(f"Missing: {path}")
            return 1
        actual = path.read_text()
        if actual != content:
            print(f"Out of date: {path}")
            print("Run: uv run python -m airut.config.generate")
            return 1
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
