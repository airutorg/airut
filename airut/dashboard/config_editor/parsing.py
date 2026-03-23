# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Form parsing and value coercion for the config editor.

Handles parsing of HTML form submissions into raw config values,
including mode detection (literal/!var/!env), credential parsing,
and variable extraction.
"""

import itertools
import re
from typing import Any

from airut.yaml_env import EnvVar, VarRef


#: Monotonic counter for dynamically added form rows.
_idx_counter = itertools.count(100000)


def next_idx() -> int:
    """Return a unique index for dynamically added form rows."""
    return next(_idx_counter)


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


# ── Form parsing ─────────────────────────────────────────────────────


def coerce_value(
    raw_str: str,
    type_name: str,
) -> tuple[str | int | float | bool | list[str] | None, str | None]:
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
    schema: list[Any],
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

            coerced, err = coerce_value(value_str, field.type_name)
            if err:
                errors[field.name] = err
            elif coerced is not None:
                parsed[field.name] = coerced

    return parsed, errors


def remap_prefixed_fields(
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


def parse_mode_value(form: dict[str, str], prefix: str) -> object:
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
        v = parse_mode_value(form, f"{prefix}.{i}.value")
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
        value = parse_mode_value(form, f"masked_secret.{i}.value")
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
                "value": parse_mode_value(
                    form, f"signing_credential.{i}.access_key_id.value"
                ),
            },
            "secret_access_key": {
                "name": form.get(
                    f"signing_credential.{i}.secret_access_key.name", ""
                ),
                "value": parse_mode_value(
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
                "value": parse_mode_value(
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
            "app_id": parse_mode_value(form, f"github_app.{i}.app_id"),
            "private_key": parse_mode_value(
                form, f"github_app.{i}.private_key"
            ),
            "installation_id": parse_mode_value(
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
