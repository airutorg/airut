# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generate example and stub config files from schema metadata.

Produces ``config/airut.example.yaml`` and the stub config written by
``airut init`` by walking the declarative config schema automatically.
Comments and default values always match the source code — there is no
duplication of field names or structure.

The only hardcoded data are:

- **Example values** for optional fields that lack defaults (e.g.
  ``ResourceLimits.memory`` defaults to ``None``; we show ``"8g"`` as
  an illustrative value).
- **Example snippets** for complex (non-scalar) fields whose YAML
  representation cannot be derived from the type alone.
- **Placeholder values** for required fields (e.g. ``mail.example.com``).

All three tables are validated against the actual schema at generation
time — if a referenced field no longer exists, generation fails.

CLI usage::

    # Generate (write) the example config
    uv run python -m airut.config.generate

    # Verify the example config is up to date
    uv run python -m airut.config.generate --check
"""

from __future__ import annotations

import dataclasses
import sys
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Any

from airut.config.schema import get_field_meta
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
)


#: Path to the example config relative to the repository root.
EXAMPLE_CONFIG_PATH = Path("config/airut.example.yaml")

#: Documentation URL base.
_DOCS_BASE = "https://github.com/airutorg/airut/blob/main"


# ---------------------------------------------------------------------------
# Data tables — the ONLY schema-adjacent data in this module.
# Keys are "ClassName.field_name" and are validated against the real schema.
# ---------------------------------------------------------------------------

#: Placeholder or illustrative values for fields that lack useful defaults.
#: Required fields need placeholders; optional None-default fields need
#: illustrative example values.  Every entry is validated at generation time.
_EXAMPLE_VALUES: dict[str, str] = {
    # Required field placeholders — email sub-dataclasses
    "ImapConfig.server": "mail.example.com",
    "SmtpConfig.server": "mail.example.com",
    "EmailAccountConfig.username": "airut",
    "EmailAccountConfig.from_address": '"Airut <airut@example.com>"',
    "EmailAuthConfig.trusted_authserv_id": "mail.example.com",
    # Optional email overrides (illustrative)
    "EmailAccountConfig.password": "!env EMAIL_PASSWORD",
    # Microsoft OAuth2 (optional block, all fields required within)
    "MicrosoftOAuth2Config.tenant_id": "!env MS_OAUTH2_TENANT_ID",
    "MicrosoftOAuth2Config.client_id": "!env MS_OAUTH2_CLIENT_ID",
    "MicrosoftOAuth2Config.client_secret": "!env MS_OAUTH2_CLIENT_SECRET",
    # Slack
    "SlackChannelConfig.bot_token": "!env SLACK_BOT_TOKEN",
    "SlackChannelConfig.app_token": "!env SLACK_APP_TOKEN",
    # Repo
    "RepoServerConfig.git_repo_url": "https://github.com/you/my-project.git",
    # Optional None-default overrides (illustrative)
    "GlobalConfig.dashboard_base_url": "dashboard.example.com",
    "GlobalConfig.upstream_dns": '"1.1.1.1"',
    "ResourceLimits.timeout": "!var default_resource_timeout",
    "ResourceLimits.memory": "!var default_resource_memory",
    "ResourceLimits.cpus": "!var default_resource_cpus",
    "ResourceLimits.pids_limit": "!var default_resource_pids_limit",
    "RepoServerConfig.effort": "max",
}

#: Example YAML snippets for complex (non-scalar) fields.
#: Each entry is a list of YAML lines rendered verbatim at the field's
#: indentation level.  Keys are validated against the actual schema.
_COMPLEX_EXAMPLES: dict[str, list[str]] = {
    "EmailAuthConfig.authorized_senders": [
        "authorized_senders:",
        "  - you@example.com",
        "  # - *@company.com",
    ],
    "SlackChannelConfig.authorized": [
        "authorized:",
        "  # Allow all full workspace members:",
        "  - workspace_members: true",
        "  # Or restrict to a user group (requires usergroups:read scope):",
        "  # - user_group: engineering",
        "  # Or restrict to specific users:",
        "  # - user_id: U12345678",
    ],
    "RepoServerConfig.secrets": [
        "secrets:",
        "  ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY",
    ],
    "RepoServerConfig.masked_secrets": [
        "masked_secrets:",
        "  GH_TOKEN:",
        "    value: !env GH_TOKEN",
        "    scopes:",
        '      - "api.github.com"',
        '      - "*.githubusercontent.com"',
        "    headers:",
        '      - "Authorization"',
        "    allow_foreign_credentials: false",
    ],
    "RepoServerConfig.signing_credentials": [
        "signing_credentials:",
        "  AWS_PROD:",
        "    type: aws-sigv4",
        "    access_key_id:",
        "      name: AWS_ACCESS_KEY_ID",
        "      value: !env AWS_ACCESS_KEY_ID",
        "    secret_access_key:",
        "      name: AWS_SECRET_ACCESS_KEY",
        "      value: !env AWS_SECRET_ACCESS_KEY",
        "    session_token:",
        "      name: AWS_SESSION_TOKEN",
        "      value: !env AWS_SESSION_TOKEN",
        "    scopes:",
        '      - "*.amazonaws.com"',
    ],
    "RepoServerConfig.github_app_credentials": [
        "github_app_credentials:",
        "  GH_TOKEN:",
        "    app_id: !env GH_APP_ID",
        "    private_key: !env GH_APP_PRIVATE_KEY",
        "    installation_id: !env GH_APP_INSTALLATION_ID",
        "    scopes:",
        '      - "github.com"',
        '      - "api.github.com"',
        '      - "*.githubusercontent.com"',
        "    allow_foreign_credentials: false",
        '    base_url: "https://api.github.com"',
        "    permissions:",
        "      contents: write",
        "      pull_requests: write",
        "    repositories:",
        "      - my-repo",
    ],
    "RepoServerConfig.schedules": [
        "schedules:",
        "  # Prompt mode: run Claude with a fixed prompt on a schedule",
        "  daily-report:",
        '    cron: "0 9 * * 1-5"',
        "    prompt: >",
        "      Summarize recent changes and open issues.",
        "    deliver:",
        "      to: team@example.com",
        "    # subject: Daily Report",
        "    # timezone: America/New_York",
        "    # model: sonnet",
        "",
        "  # Script mode: run a command, then Claude if it produces output",
        "  # nightly-check:",
        '  #   cron: "0 2 * * *"',
        '  #   trigger_command: "./scripts/check-status.sh"',
        "  #   trigger_timeout: 120",
        "  #   deliver:",
        "  #     to: oncall@example.com",
    ],
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
        ("_EXAMPLE_VALUES", _EXAMPLE_VALUES),
        ("_COMPLEX_EXAMPLES", _COMPLEX_EXAMPLES),
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
    cls: type, f: dataclasses.Field[Any]
) -> tuple[str | None, bool]:
    """Return (formatted_value, has_real_default) for a field.

    Looks up _EXAMPLE_VALUES for overrides, then falls back to the
    dataclass default.
    """
    key = f"{cls.__name__}.{f.name}"
    if key in _EXAMPLE_VALUES:
        has_default = (
            f.default is not dataclasses.MISSING
            or f.default_factory is not dataclasses.MISSING
        )
        return _EXAMPLE_VALUES[key], has_default

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
    """Prepend '# ' to each line, with optional prefix indentation."""
    return [f"{prefix}# {line}" if line else f"{prefix}#" for line in lines]


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
    """
    fm = get_field_meta(f)
    if fm is None:
        return []  # pragma: no cover

    key = f"{cls.__name__}.{f.name}"
    out: list[str] = []

    # Complex field with example snippet
    if key in _COMPLEX_EXAMPLES:
        out.append(f"{indent}# {fm.doc}")
        snippet = _COMPLEX_EXAMPLES[key]
        value, has_default = _field_value(cls, f)
        commented = force_comment or (has_default and not plain)
        for line in snippet:
            if commented:
                out.append(f"{indent}# {line}" if line else f"{indent}#")
            else:
                out.append(f"{indent}{line}")
        return out

    # Nested dataclass (e.g. resource_limits → ResourceLimits)
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
            # Complex examples (e.g. authorized_senders)
            if nk in _COMPLEX_EXAMPLES:
                nested_lines.append(f"  # {nfm.doc}")
                snippet = _COMPLEX_EXAMPLES[nk]
                nval, has_default = _field_value(nested_cls, nf)
                commented = force_comment or (has_default and not plain)
                for sline in snippet:
                    if commented:
                        nested_lines.append(f"  # {sline}" if sline else "  #")
                    else:
                        nested_lines.append(f"  {sline}")
                continue
            nval = _EXAMPLE_VALUES.get(nk)
            if nval is None and nf.default not in (
                dataclasses.MISSING,
                None,
            ):
                nval = _format_yaml(nf.default)
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
    value, has_default = _field_value(cls, f)
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
        all_have_defaults = all(_field_value(cls, f)[1] for f in section_fields)
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
    nothing is duplicated here.

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

    out: list[str] = [_HEADER]

    # ── Global settings ───────────────────────────────────────────────
    out.append("")
    out.extend(_render_class(GlobalConfig, YAML_GLOBAL_STRUCTURE))

    # ── Repos ─────────────────────────────────────────────────────────
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
        _render_class(EmailChannelConfig, YAML_EMAIL_STRUCTURE, indent="      ")
    )
    out.append("")

    # Repo-level fields (git, model, effort, etc.)
    out.extend(
        _render_class(RepoServerConfig, YAML_REPO_STRUCTURE, indent="    ")
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

    out: list[str] = [
        "# Airut Server Configuration",
        "#",
        "# For all available options, see the documented example:",
        f"# {_DOCS_BASE}/config/airut.example.yaml",
        "",
    ]

    # Show a couple of useful global defaults (commented)
    out.extend(_render_class(GlobalConfig, YAML_GLOBAL_STRUCTURE))

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
            if nk in _COMPLEX_EXAMPLES:
                for line in _COMPLEX_EXAMPLES[nk]:
                    out.append(f"        {line}")
                continue
            value = _EXAMPLE_VALUES.get(nk)
            if value is None:
                continue
            out.append(f"        {sub_yaml_name}: {value}")

    # repo_url and secrets
    git_url = _EXAMPLE_VALUES["RepoServerConfig.git_repo_url"]
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
