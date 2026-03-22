# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config variable resolution (vars: / !var)."""

from typing import Any

import pytest

from airut.config.vars import resolve_var_refs, resolve_vars_section
from airut.gateway.config import ConfigError
from airut.yaml_env import EnvVar, VarRef


class TestResolveVarsSection:
    """Tests for resolve_vars_section()."""

    def test_no_vars_section(self) -> None:
        """Returns empty table when vars: is absent."""
        raw: dict[str, Any] = {"repos": {}}
        assert resolve_vars_section(raw) == {}

    def test_empty_vars_section(self) -> None:
        """Returns empty table when vars: is empty."""
        raw: dict[str, Any] = {"vars": {}}
        assert resolve_vars_section(raw) == {}

    def test_literal_values(self) -> None:
        """Literal strings are resolved as-is."""
        raw: dict[str, Any] = {
            "vars": {
                "mail_server": "mail.example.com",
                "port": 993,
            }
        }
        table = resolve_vars_section(raw)
        assert table == {"mail_server": "mail.example.com", "port": "993"}

    def test_env_var_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvVar values in vars: are resolved from the environment."""
        monkeypatch.setenv("TEST_SECRET", "s3cret")
        raw: dict[str, Any] = {"vars": {"api_key": EnvVar("TEST_SECRET")}}
        table = resolve_vars_section(raw)
        assert table == {"api_key": "s3cret"}

    def test_env_var_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unset env var produces None in the vars table."""
        monkeypatch.delenv("UNSET_VAR", raising=False)
        raw: dict[str, Any] = {"vars": {"missing": EnvVar("UNSET_VAR")}}
        table = resolve_vars_section(raw)
        assert table == {"missing": None}

    def test_none_value(self) -> None:
        """None values in vars: produce None in the table."""
        raw: dict[str, Any] = {"vars": {"empty": None}}
        table = resolve_vars_section(raw)
        assert table == {"empty": None}

    def test_var_to_var_raises(self) -> None:
        """VarRef inside vars: raises ConfigError."""
        raw: dict[str, Any] = {"vars": {"x": VarRef("other")}}
        with pytest.raises(ConfigError, match="var-to-var"):
            resolve_vars_section(raw)

    def test_vars_not_mapping_raises(self) -> None:
        """Non-mapping vars: raises ConfigError."""
        raw: dict[str, Any] = {"vars": "not a dict"}
        with pytest.raises(ConfigError, match="YAML mapping"):
            resolve_vars_section(raw)


class TestResolveVarRefs:
    """Tests for resolve_var_refs()."""

    def test_replaces_var_ref(self) -> None:
        """VarRef in the dict is replaced with the resolved value."""
        raw: dict[str, Any] = {
            "vars": {"mail": "mail.example.com"},
            "repos": {"test": {"server": VarRef("mail")}},
        }
        table: dict[str, str | None] = {"mail": "mail.example.com"}
        result = resolve_var_refs(raw, table)

        assert result["repos"]["test"]["server"] == "mail.example.com"
        assert "vars" not in result

    def test_replaces_in_nested_dict(self) -> None:
        """VarRef deep in nested dicts is resolved."""
        raw: dict[str, Any] = {
            "a": {"b": {"c": VarRef("key")}},
        }
        table: dict[str, str | None] = {"key": "value"}
        resolve_var_refs(raw, table)
        assert raw["a"]["b"]["c"] == "value"

    def test_replaces_in_list(self) -> None:
        """VarRef inside a list is resolved."""
        raw: dict[str, Any] = {"items": [VarRef("x"), "literal", VarRef("y")]}
        table: dict[str, str | None] = {"x": "X", "y": "Y"}
        resolve_var_refs(raw, table)
        assert raw["items"] == ["X", "literal", "Y"]

    def test_env_var_left_in_place(self) -> None:
        """EnvVar objects are not touched by resolve_var_refs."""
        env = EnvVar("MY_SECRET")
        raw: dict[str, Any] = {"password": env}
        resolve_var_refs(raw, {})
        assert raw["password"] is env

    def test_undefined_var_raises(self) -> None:
        """Referencing an undefined variable raises ConfigError."""
        raw: dict[str, Any] = {"key": VarRef("undefined")}
        with pytest.raises(ConfigError, match="undefined variable"):
            resolve_var_refs(raw, {})

    def test_removes_vars_key(self) -> None:
        """The vars: key is removed from the result."""
        raw: dict[str, Any] = {"vars": {"x": "1"}, "other": "val"}
        resolve_var_refs(raw, {"x": "1"})
        assert "vars" not in raw
        assert raw["other"] == "val"

    def test_none_value_from_var(self) -> None:
        """Var resolving to None replaces VarRef with None."""
        raw: dict[str, Any] = {"key": VarRef("missing_env")}
        table = {"missing_env": None}
        resolve_var_refs(raw, table)
        assert raw["key"] is None

    def test_no_vars_no_refs(self) -> None:
        """No-op when there are no vars and no refs."""
        raw: dict[str, Any] = {"repos": {"test": {"model": "opus"}}}
        original = {"repos": {"test": {"model": "opus"}}}
        resolve_var_refs(raw, {})
        assert raw == original


class TestEndToEnd:
    """Integration tests: vars + var refs through the full pipeline."""

    def test_shared_value_across_repos(self) -> None:
        """A single var is referenced by multiple repos."""
        raw: dict[str, Any] = {
            "vars": {"mail": "mail.example.com"},
            "repos": {
                "repo-a": {"imap": VarRef("mail")},
                "repo-b": {"imap": VarRef("mail")},
            },
        }
        table = resolve_vars_section(raw)
        resolve_var_refs(raw, table)

        assert raw["repos"]["repo-a"]["imap"] == "mail.example.com"
        assert raw["repos"]["repo-b"]["imap"] == "mail.example.com"

    def test_mixed_env_and_literal_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Vars can mix literals and !env values."""
        monkeypatch.setenv("SECRET_KEY", "abc123")
        raw: dict[str, Any] = {
            "vars": {
                "server": "smtp.example.com",
                "api_key": EnvVar("SECRET_KEY"),
            },
            "repos": {
                "test": {
                    "smtp": VarRef("server"),
                    "key": VarRef("api_key"),
                    "password": EnvVar("EMAIL_PW"),
                },
            },
        }
        table = resolve_vars_section(raw)
        resolve_var_refs(raw, table)

        assert raw["repos"]["test"]["smtp"] == "smtp.example.com"
        assert raw["repos"]["test"]["key"] == "abc123"
        # EnvVar is left for _resolve() to handle
        assert isinstance(raw["repos"]["test"]["password"], EnvVar)


class TestEdgeCases:
    """Edge cases from error handling table in spec."""

    def test_var_ref_as_mapping_key_raises(self) -> None:
        """VarRef used as a dict key raises ConfigError."""
        raw: dict[str, Any] = {VarRef("x"): "value"}  # type: ignore[dict-item]
        with pytest.raises(ConfigError, match="mapping key"):
            resolve_var_refs(raw, {"x": "resolved"})

    def test_non_scalar_var_value_raises_list(self) -> None:
        """List value in vars: raises ConfigError."""
        raw: dict[str, Any] = {"vars": {"urls": ["a", "b"]}}
        with pytest.raises(ConfigError, match="scalars"):
            resolve_vars_section(raw)

    def test_non_scalar_var_value_raises_dict(self) -> None:
        """Dict value in vars: raises ConfigError."""
        raw: dict[str, Any] = {"vars": {"nested": {"a": "b"}}}
        with pytest.raises(ConfigError, match="scalars"):
            resolve_vars_section(raw)

    def test_var_ref_in_list_of_dicts(self) -> None:
        """VarRef inside a list of dicts is resolved."""
        raw: dict[str, Any] = {
            "items": [{"key": VarRef("x")}, {"key": "literal"}]
        }
        table: dict[str, str | None] = {"x": "resolved"}
        resolve_var_refs(raw, table)
        assert raw["items"][0]["key"] == "resolved"
        assert raw["items"][1]["key"] == "literal"
