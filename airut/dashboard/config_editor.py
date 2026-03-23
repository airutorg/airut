# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor request handlers.

Schema-driven web UI for editing the server configuration file.
Forms are generated from ``schema_for_ui()`` metadata so new fields
appear automatically when added to config dataclasses.
"""

import logging
import os
import re
import time
from collections.abc import Callable
from typing import Any

from werkzeug.wrappers import Request, Response

from airut.config.schema import FieldSchema, schema_for_ui
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
    YamlConfigSource,
    _set_nested,
)
from airut.dashboard.templating import render_template
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
)
from airut.gateway.slack.config import SlackChannelConfig
from airut.sandbox.types import ResourceLimits
from airut.yaml_env import EnvVar, VarRef


logger = logging.getLogger(__name__)

_VALID_CRED_TYPES = frozenset(
    {"masked_secret", "signing_credential", "github_app"}
)


# ── Value mode detection ─────────────────────────────────────────────


def detect_mode(raw_value: object) -> str:
    """Return the value mode: ``literal``, ``var``, or ``env``."""
    if isinstance(raw_value, VarRef):
        return "var"
    if isinstance(raw_value, EnvVar):
        return "env"
    return "literal"


def detect_mode_value(raw_value: object) -> str:
    """Return the display value for the current mode."""
    if isinstance(raw_value, VarRef):
        return raw_value.var_name
    if isinstance(raw_value, EnvVar):
        return raw_value.var_name
    if raw_value is None:
        return ""
    if isinstance(raw_value, (list, tuple)):
        return "\n".join(str(item) for item in raw_value)
    return str(raw_value)


# ── Raw dict lookup helpers ──────────────────────────────────────────


def lookup_global_raw(
    raw: dict[str, Any],
    field_name: str,
) -> object:
    """Look up a GlobalConfig field value from the raw YAML dict.

    Uses ``YAML_GLOBAL_STRUCTURE`` to navigate nested paths.
    """
    path = YAML_GLOBAL_STRUCTURE.get(field_name)
    if path is not None:
        d = raw
        for key in path:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d

    # Top-level (e.g. container_command)
    return raw.get(field_name)


def lookup_repo_raw(
    raw_repo: dict[str, Any],
    field_name: str,
) -> object:
    """Look up a RepoServerConfig field value from its raw YAML dict."""
    path = YAML_REPO_STRUCTURE.get(field_name)
    if path is not None:
        d = raw_repo
        for key in path:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d
    return raw_repo.get(field_name)


def lookup_email_raw(
    raw_email: dict[str, Any],
    field_name: str,
) -> object:
    """Look up an EmailChannelConfig field from the raw email YAML dict."""
    path = YAML_EMAIL_STRUCTURE.get(field_name)
    if path is not None:
        d = raw_email
        for key in path:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d
    return raw_email.get(field_name)


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


# ── Form parsing ─────────────────────────────────────────────────────


def _coerce_value(
    raw_str: str,
    type_name: str,
) -> tuple[Any, str | None]:
    """Coerce a form string to the appropriate Python type.

    Returns ``(value, error_message)``.
    """
    if "list" in type_name:
        # Textarea: one item per line — check before int/float
        # so that list[int] is not confused with int.
        items = [line.strip() for line in raw_str.splitlines() if line.strip()]
        return items, None
    if "bool" in type_name:
        if raw_str == "true":
            return True, None
        if raw_str == "false":
            return False, None
        return None, None  # unset / default
    if "int" in type_name and "dict" not in type_name:
        if not raw_str:
            return None, None
        try:
            return int(raw_str), None
        except ValueError:
            return None, f"Expected integer, got: {raw_str}"
    if "float" in type_name:
        if not raw_str:
            return None, None
        try:
            return float(raw_str), None
        except ValueError:
            return None, f"Expected number, got: {raw_str}"
    return raw_str, None


def parse_form_fields(
    form: dict[str, str],
    schema: list[FieldSchema],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Parse form submission into raw config values.

    Returns ``(parsed_values, errors)`` where errors maps field names
    to error messages.
    """
    parsed: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for field in schema:
        mode_key = f"field.{field.name}.mode"
        value_key = f"field.{field.name}.value"

        mode = form.get(mode_key, "literal")
        value_str = form.get(value_key, "")

        if mode == "var":
            if value_str:
                parsed[field.name] = VarRef(value_str)
            elif field.required:
                errors[field.name] = "Variable name is required"
        elif mode == "env":
            if value_str:
                parsed[field.name] = EnvVar(value_str)
            elif field.required:
                errors[field.name] = "Environment variable name is required"
        else:
            # literal
            if not value_str and not field.required:
                # Skip unset optional fields
                continue
            if not value_str and field.required:
                errors[field.name] = "This field is required"
                continue

            coerced, err = _coerce_value(value_str, field.type_name)
            if err:
                errors[field.name] = err
            elif coerced is not None:
                parsed[field.name] = coerced

    return parsed, errors


def _remap_prefixed_fields(
    form: dict[str, str],
    prefix: str,
) -> dict[str, str]:
    """Remap form keys that start with ``field.<prefix>`` to ``field.``.

    This allows sub-object fields (like resource_limits) to be parsed
    by ``parse_form_fields`` which expects ``field.<name>.mode/value``.
    """
    result: dict[str, str] = {}
    field_prefix = f"field.{prefix}"
    for key, value in form.items():
        if key.startswith(field_prefix):
            result[f"field.{key[len(field_prefix) :]}"] = value
    return result


# ── Credential parsing ───────────────────────────────────────────────


def _parse_mode_value(form: dict[str, str], prefix: str) -> object:
    """Parse a mode/value pair from form data."""
    mode = form.get(f"{prefix}.mode", "literal")
    value = form.get(f"{prefix}.value", "")
    if mode == "var" and value:
        return VarRef(value)
    if mode == "env" and value:
        return EnvVar(value)
    return value


def parse_key_value_table(
    form: dict[str, str],
    prefix: str,
) -> dict[str, Any]:
    """Parse a dynamic key-value table from form data.

    Expects keys like ``prefix.0.key``, ``prefix.0.value``, etc.
    """
    result: dict[str, Any] = {}
    indices = set()
    pat = re.compile(rf"^{re.escape(prefix)}\.(\d+)\.key$")
    for key in form:
        m = pat.match(key)
        if m:
            indices.add(int(m.group(1)))

    for i in sorted(indices):
        k = form.get(f"{prefix}.{i}.key", "").strip()
        if not k:
            continue
        v = _parse_mode_value(form, f"{prefix}.{i}.value")
        result[k] = v

    return result


def parse_masked_secrets(
    form: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Parse masked secrets from indexed form data."""
    result: dict[str, dict[str, Any]] = {}
    indices = set()
    pat = re.compile(r"^masked_secret\.(\d+)\.key$")
    for key in form:
        m = pat.match(key)
        if m:
            indices.add(int(m.group(1)))

    for i in sorted(indices):
        k = form.get(f"masked_secret.{i}.key", "").strip()
        if not k:
            continue
        value = _parse_mode_value(form, f"masked_secret.{i}.value")
        scopes_str = form.get(f"masked_secret.{i}.scopes", "")
        scopes = [s.strip() for s in scopes_str.splitlines() if s.strip()]
        headers_str = form.get(f"masked_secret.{i}.headers", "")
        headers = [h.strip() for h in headers_str.splitlines() if h.strip()]
        allow_foreign = form.get(f"masked_secret.{i}.allow_foreign") == "true"

        entry: dict[str, Any] = {
            "value": value,
            "scopes": scopes,
            "headers": headers,
        }
        if allow_foreign:
            entry["allow_foreign_credentials"] = True
        result[k] = entry

    return result


def parse_signing_credentials(
    form: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Parse signing credentials from indexed form data."""
    result: dict[str, dict[str, Any]] = {}
    indices = set()
    pat = re.compile(r"^signing_credential\.(\d+)\.key$")
    for key in form:
        m = pat.match(key)
        if m:
            indices.add(int(m.group(1)))

    for i in sorted(indices):
        k = form.get(f"signing_credential.{i}.key", "").strip()
        if not k:
            continue
        entry: dict[str, Any] = {
            "type": "aws-sigv4",
            "access_key_id": {
                "name": form.get(
                    f"signing_credential.{i}.access_key_id.name", ""
                ),
                "value": _parse_mode_value(
                    form, f"signing_credential.{i}.access_key_id.value"
                ),
            },
            "secret_access_key": {
                "name": form.get(
                    f"signing_credential.{i}.secret_access_key.name", ""
                ),
                "value": _parse_mode_value(
                    form, f"signing_credential.{i}.secret_access_key.value"
                ),
            },
            "scopes": [
                s.strip()
                for s in form.get(
                    f"signing_credential.{i}.scopes", ""
                ).splitlines()
                if s.strip()
            ],
        }
        # Optional session_token
        st_name = form.get(f"signing_credential.{i}.session_token.name", "")
        if st_name:
            entry["session_token"] = {
                "name": st_name,
                "value": _parse_mode_value(
                    form, f"signing_credential.{i}.session_token.value"
                ),
            }
        result[k] = entry

    return result


def parse_github_app_credentials(
    form: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Parse GitHub App credentials from indexed form data."""
    result: dict[str, dict[str, Any]] = {}
    indices = set()
    pat = re.compile(r"^github_app\.(\d+)\.key$")
    for key in form:
        m = pat.match(key)
        if m:
            indices.add(int(m.group(1)))

    for i in sorted(indices):
        k = form.get(f"github_app.{i}.key", "").strip()
        if not k:
            continue
        entry: dict[str, Any] = {
            "app_id": _parse_mode_value(form, f"github_app.{i}.app_id"),
            "private_key": _parse_mode_value(
                form, f"github_app.{i}.private_key"
            ),
            "installation_id": _parse_mode_value(
                form, f"github_app.{i}.installation_id"
            ),
            "scopes": [
                s.strip()
                for s in form.get(f"github_app.{i}.scopes", "").splitlines()
                if s.strip()
            ],
        }
        allow_foreign = form.get(f"github_app.{i}.allow_foreign") == "true"
        if allow_foreign:
            entry["allow_foreign_credentials"] = True
        base_url = form.get(f"github_app.{i}.base_url", "").strip()
        if base_url:
            entry["base_url"] = base_url
        perms_str = form.get(f"github_app.{i}.permissions", "").strip()
        if perms_str:
            perms = {}
            for line in perms_str.splitlines():
                line = line.strip()
                if ":" in line:
                    pk, pv = line.split(":", 1)
                    perms[pk.strip()] = pv.strip()
            if perms:
                entry["permissions"] = perms
        repos_str = form.get(f"github_app.{i}.repositories", "").strip()
        if repos_str:
            entry["repositories"] = [
                r.strip() for r in repos_str.splitlines() if r.strip()
            ]
        result[k] = entry

    return result


# ── Raw dict merging ─────────────────────────────────────────────────


def _delete_nested(
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


def merge_global_fields(
    raw: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed global config fields into the raw YAML dict.

    Fields present in ``parsed`` are set; fields in ``schema`` but
    absent from ``parsed`` are removed (user cleared them).
    """
    for field in schema:
        path = YAML_GLOBAL_STRUCTURE.get(field.name)
        if field.name in parsed:
            if path:
                _set_nested(raw, path, parsed[field.name])
            else:
                raw[field.name] = parsed[field.name]
        else:
            # Remove field if user cleared it (optional field)
            if not field.required:
                if path:
                    _delete_nested(raw, path)
                else:
                    raw.pop(field.name, None)


def merge_repo_fields(
    raw_repo: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed repo config fields into the raw repo dict."""
    for field in schema:
        path = YAML_REPO_STRUCTURE.get(field.name)
        if field.name in parsed:
            if path:
                _set_nested(raw_repo, path, parsed[field.name])
            else:
                raw_repo[field.name] = parsed[field.name]
        elif not field.required:
            if path:
                _delete_nested(raw_repo, path)
            else:
                raw_repo.pop(field.name, None)


def merge_email_fields(
    raw_email: dict[str, Any],
    parsed: dict[str, Any],
    schema: list[FieldSchema],
) -> None:
    """Merge parsed email config fields into the raw email dict."""
    for field in schema:
        path = YAML_EMAIL_STRUCTURE.get(field.name)
        if field.name in parsed:
            if path:
                _set_nested(raw_email, path, parsed[field.name])
            else:
                raw_email[field.name] = parsed[field.name]
        elif not field.required:
            if path:
                _delete_nested(raw_email, path)
            else:
                raw_email.pop(field.name, None)


# ── Variable helpers ─────────────────────────────────────────────────


def parse_vars_from_form(
    form: dict[str, str],
) -> dict[str, Any]:
    """Parse variables from form data.

    Variables use a key-value table with mode support (literal or !env).
    """
    result: dict[str, Any] = {}
    indices = set()
    pat = re.compile(r"^var\.(\d+)\.name$")
    for key in form:
        m = pat.match(key)
        if m:
            indices.add(int(m.group(1)))

    for i in sorted(indices):
        name = form.get(f"var.{i}.name", "").strip()
        if not name:
            continue
        mode = form.get(f"var.{i}.mode", "literal")
        value_str = form.get(f"var.{i}.value", "")
        if mode == "env" and value_str:
            result[name] = EnvVar(value_str)
        else:
            result[name] = value_str

    return result


# ── ConfigEditor handler class ───────────────────────────────────────


class ConfigEditor:
    """Config editor request handlers.

    Reads and writes config via ConfigSource.  Forms are rendered from
    schema metadata -- no per-field code needed for new fields.
    """

    def __init__(
        self,
        config_source: YamlConfigSource,
        status_callback: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        self.source = config_source
        self._status_callback = status_callback
        self._global_schema = [
            f
            for f in schema_for_ui(GlobalConfig)
            if f.name != "resource_limits"
        ]
        self._email_schema = schema_for_ui(EmailChannelConfig)
        self._slack_schema = schema_for_ui(SlackChannelConfig)
        self._repo_schema = [
            f
            for f in schema_for_ui(RepoServerConfig)
            if f.name
            not in {
                "repo_id",
                "git_repo_url",
                "channels",
                "secrets",
                "masked_secrets",
                "signing_credentials",
                "github_app_credentials",
                "resource_limits",
            }
        ]
        self._resource_limits_schema = schema_for_ui(ResourceLimits)

    def _load_raw(self) -> dict[str, Any]:
        """Load the raw config dict from the YAML source."""
        return self.source.load()

    def _save(self, raw: dict[str, Any]) -> None:
        """Save raw dict to YAML (triggers inotify reload)."""
        self.source.save(raw)

    def _require_csrf(self, request: Request) -> Response | None:
        """Check for CSRF header on mutating requests.

        Returns an error Response if the header is missing, else None.
        """
        if not request.headers.get("X-Requested-With"):
            return Response(
                render_template(
                    "config/error.html",
                    breadcrumbs=[("Config", "/config")],
                    error="Missing X-Requested-With header",
                ),
                status=403,
                content_type="text/html; charset=utf-8",
            )
        return None

    def _get_vars(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Extract the vars: section from the raw dict."""
        v = raw.get("vars")
        if isinstance(v, dict):
            return v
        return {}

    def _get_repo_ids(self, raw: dict[str, Any]) -> list[str]:
        """Return sorted list of repo IDs from the raw dict."""
        repos = raw.get("repos")
        if isinstance(repos, dict):
            return sorted(repos.keys())
        return []

    def _resolve_env(self, var_name: str) -> str | None:
        """Resolve an environment variable (for display hints)."""
        return os.environ.get(var_name)

    # ── Page handlers ────────────────────────────────────────────────

    def handle_config_index(self, request: Request) -> Response:
        """Redirect /config to /config/global."""
        return Response(
            status=302,
            headers={"Location": "/config/global"},
        )

    def handle_global(self, request: Request) -> Response:
        """Handle GET/POST for global config page."""
        if request.method == "POST":
            return self._handle_global_post(request)
        return self._handle_global_get(request)

    def _handle_global_get(
        self,
        request: Request,
        save_message: str | None = None,
        errors: dict[str, str] | None = None,
    ) -> Response:
        """Render the global settings page."""
        raw = self._load_raw()
        variables = self._get_vars(raw)
        repo_ids = self._get_repo_ids(raw)
        global_groups = group_fields(self._global_schema, YAML_GLOBAL_STRUCTURE)

        # Resource limits raw dict
        raw_resource_limits = raw.get("resource_limits")
        if not isinstance(raw_resource_limits, dict):
            raw_resource_limits = {}

        return Response(
            render_template(
                "config/global.html",
                breadcrumbs=[("Config", "/config/global")],
                global_groups=global_groups,
                global_schema=self._global_schema,
                resource_limits_schema=self._resource_limits_schema,
                raw_resource_limits=raw_resource_limits,
                variables=variables,
                repo_ids=repo_ids,
                raw=raw,
                lookup_global_raw=lookup_global_raw,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
                save_message=save_message,
                errors=errors or {},
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_global_post(self, request: Request) -> Response:
        """Process global config form submission."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)

        # Parse global config fields
        parsed, errors = parse_form_fields(form, self._global_schema)
        if errors:
            return self._handle_global_get(request, errors=errors)

        # Parse resource limits sub-fields
        rl_parsed, rl_errors = parse_form_fields(
            _remap_prefixed_fields(form, "rl_"),
            self._resource_limits_schema,
        )
        if rl_errors:
            prefixed = {f"rl_{k}": v for k, v in rl_errors.items()}
            errors.update(prefixed)
            return self._handle_global_get(request, errors=errors)

        # Parse variables
        new_vars = parse_vars_from_form(form)

        # Load current raw, merge, save
        raw = self._load_raw()
        merge_global_fields(raw, parsed, self._global_schema)

        # Merge resource limits
        if rl_parsed:
            raw["resource_limits"] = rl_parsed
        else:
            raw.pop("resource_limits", None)

        # Update vars
        if new_vars:
            raw["vars"] = new_vars
        else:
            raw.pop("vars", None)

        self._save(raw)

        return self._handle_global_get(
            request,
            save_message="Global configuration saved successfully.",
        )

    def handle_repo(self, request: Request, repo_id: str) -> Response:
        """Handle GET/POST for repo config page."""
        if request.method == "POST":
            return self._handle_repo_post(request, repo_id)
        return self._handle_repo_get(request, repo_id)

    def _handle_repo_get(
        self,
        request: Request,
        repo_id: str,
        save_message: str | None = None,
        errors: dict[str, str] | None = None,
    ) -> Response:
        """Render the repo settings page."""
        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        raw_repo = repos[repo_id]
        repo_ids = self._get_repo_ids(raw)
        variables = self._get_vars(raw)

        # Channel presence
        has_email = "email" in raw_repo
        has_slack = "slack" in raw_repo
        raw_email = raw_repo.get("email", {})
        raw_slack = raw_repo.get("slack", {})

        email_groups = group_email_fields(self._email_schema)

        # Resource limits raw dict
        raw_resource_limits = raw_repo.get("resource_limits")
        if not isinstance(raw_resource_limits, dict):
            raw_resource_limits = {}

        return Response(
            render_template(
                "config/repo.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    (repo_id, ""),
                ],
                repo_id=repo_id,
                repo_ids=repo_ids,
                raw_repo=raw_repo,
                raw_email=raw_email,
                raw_slack=raw_slack,
                has_email=has_email,
                has_slack=has_slack,
                email_groups=email_groups,
                email_schema=self._email_schema,
                slack_schema=self._slack_schema,
                repo_schema=self._repo_schema,
                resource_limits_schema=self._resource_limits_schema,
                raw_resource_limits=raw_resource_limits,
                variables=variables,
                lookup_repo_raw=lookup_repo_raw,
                lookup_email_raw=lookup_email_raw,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
                save_message=save_message,
                errors=errors or {},
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_post(self, request: Request, repo_id: str) -> Response:
        """Process repo config form submission."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)

        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        raw_repo = repos[repo_id]

        # Parse repo-level fields
        parsed, errors = parse_form_fields(form, self._repo_schema)
        if errors:
            return self._handle_repo_get(request, repo_id, errors=errors)

        # Git repo URL — uses mode/value pattern like other fields
        git_parsed = _parse_mode_value(form, "git_repo_url")
        if git_parsed:
            raw_repo["git"] = raw_repo.get("git", {})
            raw_repo["git"]["repo_url"] = git_parsed

        merge_repo_fields(raw_repo, parsed, self._repo_schema)

        # Handle resource limits sub-fields
        rl_parsed, rl_errors = parse_form_fields(
            _remap_prefixed_fields(form, "rl_"),
            self._resource_limits_schema,
        )
        if rl_errors:
            prefixed = {f"rl_{k}": v for k, v in rl_errors.items()}
            errors.update(prefixed)
            return self._handle_repo_get(request, repo_id, errors=errors)
        if rl_parsed:
            raw_repo["resource_limits"] = rl_parsed
        else:
            raw_repo.pop("resource_limits", None)

        # Handle channels
        has_email = form.get("has_email") == "true"
        has_slack = form.get("has_slack") == "true"

        if has_email:
            email_parsed, email_errors = parse_form_fields(
                form, self._email_schema
            )
            if email_errors:
                errors.update(email_errors)
                return self._handle_repo_get(request, repo_id, errors=errors)
            raw_email = raw_repo.get("email", {})
            merge_email_fields(raw_email, email_parsed, self._email_schema)
            raw_repo["email"] = raw_email
        else:
            raw_repo.pop("email", None)

        if has_slack:
            # Parse slack scalar fields
            slack_parsed: dict[str, Any] = {}
            for sf in self._slack_schema:
                if sf.name == "authorized":
                    continue  # handled separately
                mode = form.get(f"field.{sf.name}.mode", "literal")
                val = form.get(f"field.{sf.name}.value", "")
                if mode == "var" and val:
                    slack_parsed[sf.name] = VarRef(val)
                elif mode == "env" and val:
                    slack_parsed[sf.name] = EnvVar(val)
                elif val:
                    slack_parsed[sf.name] = val

            raw_slack = raw_repo.get("slack", {})
            for k, v in slack_parsed.items():
                raw_slack[k] = v

            # Parse Slack authorized rules
            auth_text = form.get("slack_authorized", "").strip()
            if auth_text:
                auth_rules = []
                for line in auth_text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        rk, rv = line.split(":", 1)
                        rk = rk.strip()
                        rv = rv.strip()
                        if rv.lower() in ("true", "false"):
                            auth_rules.append({rk: rv.lower() == "true"})
                        else:
                            auth_rules.append({rk: rv})
                raw_slack["authorized"] = auth_rules
            else:
                raw_slack.pop("authorized", None)

            raw_repo["slack"] = raw_slack
        else:
            raw_repo.pop("slack", None)

        # Handle credential pools
        secrets = parse_key_value_table(form, "secret")
        if secrets:
            raw_repo["secrets"] = secrets
        else:
            raw_repo.pop("secrets", None)

        container_env = parse_key_value_table(form, "container_env")
        if container_env:
            raw_repo["container_env"] = container_env
        else:
            raw_repo.pop("container_env", None)

        masked = parse_masked_secrets(form)
        if masked:
            raw_repo["masked_secrets"] = masked
        else:
            raw_repo.pop("masked_secrets", None)

        signing = parse_signing_credentials(form)
        if signing:
            raw_repo["signing_credentials"] = signing
        else:
            raw_repo.pop("signing_credentials", None)

        github_app = parse_github_app_credentials(form)
        if github_app:
            raw_repo["github_app_credentials"] = github_app
        else:
            raw_repo.pop("github_app_credentials", None)

        self._save(raw)

        return self._handle_repo_get(
            request,
            repo_id,
            save_message="Repository configuration saved successfully.",
        )

    def handle_repo_new(self, request: Request) -> Response:
        """Handle GET/POST for new repo creation."""
        if request.method == "POST":
            return self._handle_repo_new_post(request)
        return self._handle_repo_new_get(request)

    def _handle_repo_new_get(
        self,
        request: Request,
        error: str | None = None,
    ) -> Response:
        """Render the new repo form."""
        raw = self._load_raw()
        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/repo_new.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    ("New Repo", ""),
                ],
                repo_ids=repo_ids,
                error=error,
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_new_post(self, request: Request) -> Response:
        """Create a new repo and redirect."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)
        repo_id = form.get("repo_id", "").strip()
        git_url = form.get("git_repo_url", "").strip()

        if not repo_id:
            return self._handle_repo_new_get(
                request, error="Repository ID is required"
            )

        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", repo_id):
            return self._handle_repo_new_get(
                request,
                error="Invalid repo ID (use letters, numbers, .-_)",
            )

        if not git_url:
            return self._handle_repo_new_get(
                request, error="Git repository URL is required"
            )

        raw = self._load_raw()
        repos = raw.setdefault("repos", {})
        if repo_id in repos:
            return self._handle_repo_new_get(
                request, error=f"Repository '{repo_id}' already exists"
            )

        # Create minimal repo entry
        new_repo: dict[str, Any] = {
            "git": {"repo_url": git_url},
            "model": "opus",
        }

        add_email = form.get("add_email") == "true"
        add_slack = form.get("add_slack") == "true"

        if add_email:
            new_repo["email"] = {
                "imap_server": "",
                "smtp_server": "",
                "username": "",
                "password": "",
                "from": "",
                "authorized_senders": [],
                "trusted_authserv_id": "",
            }

        if add_slack:
            new_repo["slack"] = {
                "bot_token": "",
                "app_token": "",
                "authorized": [{"workspace_members": True}],
            }

        # Ensure at least one channel placeholder
        if not add_email and not add_slack:
            new_repo["email"] = {
                "imap_server": "",
                "smtp_server": "",
                "username": "",
                "password": "",
                "from": "",
                "authorized_senders": [],
                "trusted_authserv_id": "",
            }

        repos[repo_id] = new_repo
        self._save(raw)

        return Response(
            status=302,
            headers={"Location": f"/config/repo/{repo_id}"},
        )

    def handle_repo_delete(self, request: Request, repo_id: str) -> Response:
        """Handle GET/POST for repo deletion."""
        if request.method == "POST":
            return self._handle_repo_delete_post(request, repo_id)
        return self._handle_repo_delete_get(request, repo_id)

    def _handle_repo_delete_get(
        self, request: Request, repo_id: str
    ) -> Response:
        """Render the deletion confirmation page."""
        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/repo_delete.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    (repo_id, f"/config/repo/{repo_id}"),
                    ("Delete", ""),
                ],
                repo_id=repo_id,
                repo_ids=repo_ids,
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_delete_post(
        self, request: Request, repo_id: str
    ) -> Response:
        """Delete a repo and redirect to global."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        del repos[repo_id]
        self._save(raw)

        return Response(
            status=302,
            headers={"Location": "/config/global"},
        )

    # ── Fragment endpoints ───────────────────────────────────────────

    def handle_nav(self, request: Request) -> Response:
        """Return the sidebar navigation fragment."""
        raw = self._load_raw()
        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/components/nav.html",
                repo_ids=repo_ids,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_field_input(self, request: Request) -> Response:
        """Return the input widget fragment for a field mode change."""
        name = request.args.get("name", "")
        type_name = request.args.get("type", "str")
        mode = request.args.get(f"field.{name}.mode", "literal")

        raw = self._load_raw()
        variables = self._get_vars(raw)

        return Response(
            render_template(
                "config/components/field_input.html",
                field_name=name,
                type_name=type_name,
                mode=mode,
                variables=variables,
                resolve_env=self._resolve_env,
                current_value="",
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_vars_add(self, request: Request) -> Response:
        """Return a new variable row fragment."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        # Use a high index to avoid collisions
        idx = int(time.time() * 1000) % 100000

        return Response(
            render_template(
                "config/components/variable_row.html",
                idx=idx,
                var_name="",
                var_value="",
                var_mode="literal",
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_credential_add(self, request: Request, repo_id: str) -> Response:
        """Return a new credential card fragment."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        cred_type = request.args.get("type", "masked_secret")
        if cred_type not in _VALID_CRED_TYPES:
            return Response("Invalid credential type", status=400)

        idx = int(time.time() * 1000) % 100000

        raw = self._load_raw()
        variables = self._get_vars(raw)

        return Response(
            render_template(
                f"config/components/credential_{cred_type}.html",
                idx=idx,
                key="",
                entry={},
                variables=variables,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_reload_status(self, request: Request) -> Response:
        """Return reload status polling fragment.

        Checks whether the config generation has advanced past
        ``expected_gen``.  When it has (or when no status callback is
        available), returns a fragment without the polling trigger so
        the browser stops polling.
        """
        expected_gen = request.args.get("gen", "")

        # Check if reload is complete
        if expected_gen and self._status_callback is not None:
            status = self._status_callback()
            current_gen = status.get("config_generation", 0)
            try:
                if int(str(current_gen)) >= int(expected_gen):
                    expected_gen = ""  # stop polling
            except (ValueError, TypeError):
                expected_gen = ""  # stop polling on bad values

        return Response(
            render_template(
                "config/components/reload_status.html",
                expected_gen=expected_gen,
            ),
            content_type="text/html; charset=utf-8",
        )
