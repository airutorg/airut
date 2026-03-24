# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Schema-driven config editor: field introspection and context building.

``EditorFieldSchema`` extends the basic ``FieldSchema`` with recursive
structure for composite types.  ``schema_for_editor()`` walks config
dataclasses to produce the editor schema tree.
``build_editor_context()`` produces the full template context.

Form parsing, raw value helpers, and ``InMemoryConfigSource`` live in
``editor_form.py``.
"""

import dataclasses
import typing
from dataclasses import dataclass
from typing import Any

from airut.config.migration import CURRENT_CONFIG_VERSION
from airut.config.schema import get_field_meta
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
)


# ---------------------------------------------------------------------------
# Tagged union metadata (the only hardcoded schema mapping)
# ---------------------------------------------------------------------------

#: Rule types for tagged union list fields.
#: Key = "ClassName.field_name", value = list of (tag, value_type, label).
TAGGED_UNION_RULES: dict[str, list[tuple[str, str, str]]] = {
    "SlackChannelConfig.authorized": [
        ("workspace_members", "bool", "Allow all workspace members"),
        ("user_group", "str", "User group handle"),
        ("user_id", "str", "Slack user ID"),
    ],
}


# ---------------------------------------------------------------------------
# EditorFieldSchema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EditorFieldSchema:
    """Recursive field description for the config editor.

    Attributes:
        name: Dataclass field name.
        yaml_path: Nested YAML location as a path tuple.
        type_tag: Widget type discriminator.
        python_type: Base Python type as string.
        default: Default value (``MISSING`` sentinel if required).
        required: True if no default value.
        doc: Human-readable description from FieldMeta.
        scope: Scope value string.
        secret: Whether the field holds a secret.
        multiline: Whether to render as textarea.
        nested_fields: Sub-fields for nested dataclasses.
        item_class_name: Class name for keyed collection items.
        item_fields: Sub-fields for keyed collection item types.
        tagged_union_rules: Rule definitions for tagged union lists.
        env_eligible: Whether the field supports ``!env``.
        var_eligible: Whether the field supports ``!var``.
    """

    name: str
    yaml_path: tuple[str, ...]
    type_tag: str
    python_type: str
    default: Any
    required: bool
    doc: str
    scope: str
    secret: bool
    multiline: bool = False
    nested_fields: tuple["EditorFieldSchema", ...] | None = None
    item_class_name: str | None = None
    item_fields: tuple["EditorFieldSchema", ...] | None = None
    tagged_union_rules: tuple[tuple[str, str, str], ...] | None = None
    env_eligible: bool = True
    var_eligible: bool = True


# ---------------------------------------------------------------------------
# Type introspection helpers
# ---------------------------------------------------------------------------


def _get_origin(tp: Any) -> Any:  # noqa: ANN401 — type introspection
    """Get the origin of a generic type (e.g. list for list[str])."""
    return typing.get_origin(tp)


def _get_args(tp: Any) -> tuple[Any, ...]:  # noqa: ANN401 — type introspection
    """Get the type arguments of a generic type."""
    return typing.get_args(tp)


def _is_optional(tp: Any) -> tuple[bool, Any]:  # noqa: ANN401 — type introspection
    """Check if a type is Optional[X] (Union[X, None]).

    Returns (is_optional, inner_type).
    """
    origin = _get_origin(tp)
    if origin is typing.Union or origin is type(int | str):
        args = _get_args(tp)
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1 and type(None) in args:
            return True, non_none[0]
    return False, tp


def _is_dataclass_with_meta(tp: Any) -> bool:  # noqa: ANN401 — type introspection
    """Check if tp is a dataclass with at least one FieldMeta field."""
    if not dataclasses.is_dataclass(tp) or not isinstance(tp, type):
        return False
    return any(get_field_meta(f) is not None for f in dataclasses.fields(tp))


def _classify_type(
    tp: Any,  # noqa: ANN401 — type introspection
    class_name: str,
    field_name: str,
) -> tuple[str, str, Any | None]:
    """Classify a type annotation into a type_tag.

    Returns (type_tag, python_type_str, item_type_or_None).
    """
    # Check tagged union
    key = f"{class_name}.{field_name}"
    if key in TAGGED_UNION_RULES:
        return "tagged_union_list", "tagged_union", None

    # Unwrap Optional
    is_opt, inner = _is_optional(tp)
    if is_opt:
        tp = inner

    origin = _get_origin(tp)
    args = _get_args(tp)

    # Nested dataclass
    if _is_dataclass_with_meta(tp):
        return "nested", tp.__name__, None

    # list[str], tuple[str, ...], frozenset[str]
    if origin in (list, tuple, frozenset) or tp in (list, tuple, frozenset):
        if args:
            item_type = args[0]
            if item_type is str or (
                origin is tuple and len(args) == 2 and args[1] is Ellipsis
            ):
                return "list_str", "list[str]", None
        return "list_str", "list[str]", None

    # dict types
    if origin is dict:
        if len(args) == 2:
            _key_type, val_type = args
            # dict[str, str]
            if val_type is str:
                return "dict_str_str", "dict[str, str]", None
            # dict[str, <dataclass>] — keyed collection
            _, val_inner_unwrapped = _is_optional(val_type)
            if _is_dataclass_with_meta(val_inner_unwrapped):
                return (
                    "keyed_collection",
                    f"dict[str, {val_inner_unwrapped.__name__}]",
                    val_inner_unwrapped,
                )
        return "dict_str_str", "dict[str, str]", None

    # Scalar types
    if tp is bool:
        return "scalar", "bool", None
    if tp is int:
        return "scalar", "int", None
    if tp is float:
        return "scalar", "float", None
    if tp is str:
        return "scalar", "str", None

    # Fallback
    type_name = tp.__name__ if isinstance(tp, type) else str(tp)
    return "scalar", type_name, None


# ---------------------------------------------------------------------------
# schema_for_editor
# ---------------------------------------------------------------------------


def schema_for_editor(
    config_cls: type,
    *,
    yaml_structure: dict[str, tuple[str, ...]] | None = None,
    prefix: tuple[str, ...] = (),
) -> tuple[EditorFieldSchema, ...]:
    """Walk a config dataclass to produce the editor schema tree.

    Only fields annotated with ``FieldMeta`` are included.

    Args:
        config_cls: A dataclass class with ``FieldMeta`` annotations.
        yaml_structure: Optional mapping of field name to YAML path.
        prefix: Path prefix for YAML path construction.

    Returns:
        Tuple of ``EditorFieldSchema`` for each annotated field.
    """
    result: list[EditorFieldSchema] = []
    hints = typing.get_type_hints(config_cls)

    for f in dataclasses.fields(config_cls):
        fm = get_field_meta(f)
        if fm is None:
            continue

        annotation = hints.get(f.name, f.type)
        class_name = config_cls.__name__

        # Determine YAML path
        if yaml_structure and f.name in yaml_structure:
            yaml_path = prefix + yaml_structure[f.name]
        else:
            yaml_path = prefix + (f.name,)

        # Determine default
        has_default = (
            f.default is not dataclasses.MISSING
            or f.default_factory is not dataclasses.MISSING
        )
        if f.default is not dataclasses.MISSING:
            default_value = f.default
        elif f.default_factory is not dataclasses.MISSING:
            default_value = f.default_factory()
        else:
            default_value = dataclasses.MISSING

        type_tag, python_type, item_type = _classify_type(
            annotation, class_name, f.name
        )

        # Determine eligibility for !env and !var
        is_opt, inner_type = _is_optional(annotation)
        env_eligible = python_type not in ("bool",)
        var_eligible = python_type not in ("bool", "int", "float")

        # Determine multiline
        multiline = f.name in ("private_key",)

        # Build nested fields for nested dataclasses
        nested_fields: tuple[EditorFieldSchema, ...] | None = None
        if type_tag == "nested":
            _, unwrapped = _is_optional(annotation)
            nested_fields = schema_for_editor(unwrapped, prefix=yaml_path)

        # Build item fields for keyed collections
        item_class_name: str | None = None
        item_fields_tuple: tuple[EditorFieldSchema, ...] | None = None
        if type_tag == "keyed_collection" and item_type is not None:
            item_class_name = item_type.__name__
            item_fields_tuple = schema_for_editor(item_type)

        # Build tagged union rules
        tagged_rules: tuple[tuple[str, str, str], ...] | None = None
        union_key = f"{class_name}.{f.name}"
        if union_key in TAGGED_UNION_RULES:
            tagged_rules = tuple(
                tuple(r) for r in TAGGED_UNION_RULES[union_key]
            )

        result.append(
            EditorFieldSchema(
                name=f.name,
                yaml_path=yaml_path,
                type_tag=type_tag,
                python_type=python_type,
                default=default_value,
                required=not has_default,
                doc=fm.doc,
                scope=fm.scope.value,
                secret=fm.secret,
                multiline=multiline,
                nested_fields=nested_fields,
                item_class_name=item_class_name,
                item_fields=item_fields_tuple,
                tagged_union_rules=tagged_rules,
                env_eligible=env_eligible,
                var_eligible=var_eligible,
            )
        )

    return tuple(result)


# ---------------------------------------------------------------------------
# build_editor_context
# ---------------------------------------------------------------------------


def build_editor_context(
    snapshot: Any,  # noqa: ANN401 — ServerConfig circular import
    config_generation: int,
    vars_section: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the full template context for the config editor page.

    Args:
        snapshot: ``ConfigSnapshot[ServerConfig]`` from the gateway.
        config_generation: Current config generation counter.
        vars_section: Resolved vars section for !var hint display.

    Returns:
        Dict of template variables for the config page.
    """
    from airut.gateway.config import (
        EmailChannelConfig,
        GlobalConfig,
        RepoServerConfig,
    )
    from airut.gateway.slack.config import SlackChannelConfig

    config = snapshot.value
    raw = snapshot.raw

    # Build global section schema
    global_schema = schema_for_editor(
        GlobalConfig,
        yaml_structure=YAML_GLOBAL_STRUCTURE,
    )

    # Build per-repo sections
    repos_context: list[dict[str, Any]] = []
    raw_repos = raw.get("repos", {}) if raw else {}

    for repo_id, repo_config in config.repos.items():
        raw_repo = (
            raw_repos.get(repo_id, {}) if isinstance(raw_repos, dict) else {}
        )

        repo_schema = schema_for_editor(
            RepoServerConfig,
            yaml_structure=YAML_REPO_STRUCTURE,
            prefix=("repos", repo_id),
        )

        # Channel schemas — always built so the editor can enable them
        has_email = "email" in repo_config.channels
        has_slack = "slack" in repo_config.channels

        email_schema = schema_for_editor(
            EmailChannelConfig,
            yaml_structure=YAML_EMAIL_STRUCTURE,
            prefix=("repos", repo_id, "email"),
        )
        slack_schema = schema_for_editor(
            SlackChannelConfig,
            prefix=("repos", repo_id, "slack"),
        )

        repos_context.append(
            {
                "repo_id": repo_id,
                "config": repo_config,
                "raw": raw_repo,
                "schema": repo_schema,
                "email_schema": email_schema,
                "slack_schema": slack_schema,
                "has_email": has_email,
                "has_slack": has_slack,
            }
        )

    # Extract vars section from raw
    raw_vars = raw.get("vars", {}) if raw else {}

    return {
        "config": config,
        "raw": raw,
        "global_schema": global_schema,
        "repos": repos_context,
        "raw_vars": raw_vars,
        "vars_section": vars_section or {},
        "config_generation": config_generation,
        "config_version": CURRENT_CONFIG_VERSION,
    }
