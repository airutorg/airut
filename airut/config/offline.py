# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Offline config checks: validate a config without its secrets.

``airut check --offline`` validates a config where the values its
``!env``/``!file`` references point at are not available, e.g. in a Nix
build sandbox.  ``secret_values()`` supports pointing out secrets that
end up in the (world-readable) Nix store.
"""

from pathlib import Path
from typing import Any

from airut.config.editor import MISSING, get_raw_value
from airut.config.editor_schema import EditorFieldSchema
from airut.config.server_schema import (
    email_schema,
    global_schema,
    repo_schema,
    slack_schema,
)
from airut.config.source import ConfigReadOnlyError, YamlConfigSource
from airut.yaml_env import EnvVar, FileRef, Unresolved, VarRef, YamlValue


class OfflineConfigSource:
    """Read-only YAML config source that leaves references unresolved.

    Every ``!env``/``!file`` reference becomes an ``Unresolved``
    stand-in, so validation never reads referenced variables or files
    and treats their values as present.

    Attributes:
        references: Number of references replaced by the last ``load()``.
    """

    def __init__(self, path: Path) -> None:
        self._source = YamlConfigSource(path)
        self.references = 0

    def load(self) -> dict[str, Any]:
        """Load the raw config dict with ``Unresolved`` stand-ins."""
        raw = self._source.load()
        self.references = 0
        for key in raw:
            raw[key] = self._unresolve(raw[key])
        return raw

    def _unresolve(self, value: YamlValue) -> YamlValue:
        """Replace references in *value* with stand-ins, recursively."""
        if isinstance(value, (EnvVar, FileRef)):
            self.references += 1
            return Unresolved(value)
        if isinstance(value, dict):
            for key in value:
                value[key] = self._unresolve(value[key])
        elif isinstance(value, list):
            for i, item in enumerate(value):
                value[i] = self._unresolve(item)
        return value

    def save(self, data: dict[str, Any]) -> None:
        """Not supported: an offline check never writes."""
        raise ConfigReadOnlyError("Config is read-only: offline check")

    def read_only_reason(self) -> str:
        """Always read-only."""
        return "offline check"


def is_literal(value: object) -> bool:
    """Whether a raw secret value is written literally (and non-empty)."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float)) or (
        isinstance(value, str) and bool(value)
    )


def is_file_in(value: object, directory: Path) -> bool:
    """Whether *value* is a ``!file`` reference to a file in *directory*."""
    if isinstance(value, Unresolved):
        value = value.ref
    if not isinstance(value, FileRef):
        return False
    path = value.expanded_path()
    return path.is_absolute() and path.resolve().is_relative_to(directory)


#: Placeholder repo ID (without dots) for looking up repo fields.
_REPO = "_"


def secret_values(raw: dict[str, Any]) -> list[tuple[str, object]]:
    """The raw values of all secrets in *raw*, with their YAML paths.

    Covers secret fields, entries of secret mappings (``secrets:``), and
    secret fields of collection items (``masked_secrets:`` and the
    like).  For a ``!var`` reference, reports the variable
    (``vars.<name>``) and its value instead.

    Args:
        raw: Raw config dict as loaded (tags still in place).

    Returns:
        ``(path, value)`` pairs in schema order (global, then each
        repo's settings, email and Slack), each path once.
    """
    raw_vars = raw.get("vars")
    variables: dict[str, Any] = raw_vars if isinstance(raw_vars, dict) else {}
    found: dict[str, object] = {}  # ordered, unique paths

    def check(path: str, value: object) -> None:
        if isinstance(value, VarRef):
            path = f"vars.{value.var_name}"
            value = variables.get(value.var_name)
        if value is not None and value is not MISSING:
            found.setdefault(path, value)

    def visit(
        fields: list[EditorFieldSchema],
        node: dict[str, Any],
        prefix: str,
        strip: str = "",
    ) -> None:
        """Check *fields* in *node*; report ``prefix`` + path - ``strip``."""
        for fs in fields:
            if fs.nested_fields:
                visit(fs.nested_fields, node, prefix, strip)
                continue
            value = get_raw_value(node, fs.path)
            path = prefix + fs.path.removeprefix(strip)
            if fs.type_tag == "keyed_collection":
                if isinstance(value, dict) and fs.item_fields:
                    for key, item in value.items():
                        if isinstance(item, dict):
                            visit(fs.item_fields, item, f"{path}.{key}.")
            elif fs.secret and fs.type_tag == "dict_str_str":
                if isinstance(value, dict):
                    for key, entry in value.items():
                        check(f"{path}.{key}", entry)
            elif fs.secret:
                check(path, value)

    visit(global_schema(), raw, "")
    repos = raw.get("repos")
    if isinstance(repos, dict):
        for repo_id, repo in repos.items():
            if not isinstance(repo, dict):
                continue
            # Schema paths are dot-separated, so look the repo up under a
            # placeholder ID: its real ID may contain dots.
            node = {"repos": {_REPO: repo}}
            for schema in (
                repo_schema(_REPO),
                email_schema(_REPO),
                slack_schema(_REPO),
            ):
                visit(schema, node, f"repos.{repo_id}.", f"repos.{_REPO}.")
    return list(found.items())
