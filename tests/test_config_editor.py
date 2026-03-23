# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor logic (airut/config/editor.py)."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from airut.config.editor import (
    FieldChange,
    PreviewResult,
    _decode_value,
    _diff_global,
    _diff_repo,
    _encode_value,
    atomic_save,
    backup_config,
    json_to_raw,
    preview_changes,
    raw_to_json,
    validate_raw,
)
from airut.gateway.config import ConfigError, ServerConfig
from airut.yaml_env import EnvVar, VarRef


class TestRawToJson:
    def test_encode_env_var(self) -> None:
        raw = {"key": EnvVar("MY_VAR")}
        result = raw_to_json(raw)
        assert result == {"key": {"__tag__": "env", "name": "MY_VAR"}}

    def test_encode_var_ref(self) -> None:
        raw = {"key": VarRef("my_var")}
        result = raw_to_json(raw)
        assert result == {"key": {"__tag__": "var", "name": "my_var"}}

    def test_encode_nested(self) -> None:
        raw = {
            "top": {
                "inner": EnvVar("INNER_VAR"),
                "list": [VarRef("list_var"), "literal"],
            }
        }
        result = raw_to_json(raw)
        assert result["top"]["inner"] == {
            "__tag__": "env",
            "name": "INNER_VAR",
        }
        assert result["top"]["list"][0] == {
            "__tag__": "var",
            "name": "list_var",
        }
        assert result["top"]["list"][1] == "literal"

    def test_encode_plain_values(self) -> None:
        raw = {"str": "hello", "int": 42, "bool": True, "none": None}
        result = raw_to_json(raw)
        assert result == raw

    def test_encode_tuple(self) -> None:
        raw = {"t": (EnvVar("A"), "b")}
        result = raw_to_json(raw)
        assert result == {"t": [{"__tag__": "env", "name": "A"}, "b"]}


class TestJsonToRaw:
    def test_decode_env_tag(self) -> None:
        data = {"key": {"__tag__": "env", "name": "MY_VAR"}}
        result = json_to_raw(data)
        assert isinstance(result["key"], EnvVar)
        assert result["key"].var_name == "MY_VAR"

    def test_decode_var_tag(self) -> None:
        data = {"key": {"__tag__": "var", "name": "my_var"}}
        result = json_to_raw(data)
        assert isinstance(result["key"], VarRef)
        assert result["key"].var_name == "my_var"

    def test_decode_nested(self) -> None:
        data = {
            "top": {
                "inner": {"__tag__": "env", "name": "INNER"},
                "list": [{"__tag__": "var", "name": "v"}, "lit"],
            }
        }
        result = json_to_raw(data)
        assert isinstance(result["top"]["inner"], EnvVar)
        assert isinstance(result["top"]["list"][0], VarRef)
        assert result["top"]["list"][1] == "lit"

    def test_decode_regular_dict(self) -> None:
        data = {"key": {"not_a_tag": True, "name": "x"}}
        result = json_to_raw(data)
        assert result["key"] == {"not_a_tag": True, "name": "x"}

    def test_decode_tag_with_extra_keys(self) -> None:
        data = {"key": {"__tag__": "env", "name": "X", "extra": "y"}}
        result = json_to_raw(data)
        # Extra keys mean it's not a tag marker
        assert isinstance(result["key"], dict)
        assert "__tag__" in result["key"]

    def test_roundtrip(self) -> None:
        raw: dict[str, Any] = {
            "vars": {
                "server": "mail.example.com",
                "key": EnvVar("API_KEY"),
            },
            "repos": {
                "test": {
                    "email": {
                        "password": VarRef("mail_pw"),
                    }
                }
            },
            "plain": "value",
            "number": 42,
        }
        encoded = raw_to_json(raw)
        decoded = json_to_raw(encoded)

        assert isinstance(decoded["vars"]["key"], EnvVar)
        assert decoded["vars"]["key"].var_name == "API_KEY"
        assert isinstance(decoded["repos"]["test"]["email"]["password"], VarRef)
        assert (
            decoded["repos"]["test"]["email"]["password"].var_name == "mail_pw"
        )
        assert decoded["plain"] == "value"
        assert decoded["number"] == 42


class TestEncodeDecodeValue:
    def test_encode_env_var(self) -> None:
        assert _encode_value(EnvVar("X")) == {"__tag__": "env", "name": "X"}

    def test_encode_var_ref(self) -> None:
        assert _encode_value(VarRef("Y")) == {"__tag__": "var", "name": "Y"}

    def test_encode_list(self) -> None:
        assert _encode_value([EnvVar("A"), 1]) == [
            {"__tag__": "env", "name": "A"},
            1,
        ]

    def test_encode_scalar(self) -> None:
        assert _encode_value("hello") == "hello"
        assert _encode_value(42) == 42
        assert _encode_value(None) is None

    def test_decode_env_tag(self) -> None:
        val = _decode_value({"__tag__": "env", "name": "X"})
        assert isinstance(val, EnvVar)

    def test_decode_var_tag(self) -> None:
        val = _decode_value({"__tag__": "var", "name": "Y"})
        assert isinstance(val, VarRef)

    def test_decode_regular_dict(self) -> None:
        val = _decode_value({"a": 1, "b": 2})
        assert val == {"a": 1, "b": 2}

    def test_decode_list(self) -> None:
        val = _decode_value([{"__tag__": "env", "name": "A"}, "b"])
        assert isinstance(val, list)
        assert isinstance(val[0], EnvVar)
        assert val[1] == "b"

    def test_decode_scalar(self) -> None:
        assert _decode_value("hello") == "hello"
        assert _decode_value(42) == 42
        assert _decode_value(None) is None


def _make_minimal_raw(
    *,
    repo_url: str = "https://github.com/test/repo",
    model: str = "opus",
    max_concurrent: int = 3,
) -> dict[str, Any]:
    """Build a minimal valid raw config dict for testing."""
    return {
        "config_version": 2,
        "execution": {"max_concurrent": max_concurrent},
        "repos": {
            "test-repo": {
                "git": {"repo_url": repo_url},
                "email": {
                    "imap_server": "imap.example.com",
                    "imap_port": 993,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "bot@example.com",
                    "password": "secret",
                    "from": "bot@example.com",
                    "authorized_senders": ["admin@example.com"],
                    "trusted_authserv_id": "example.com",
                },
                "model": model,
            }
        },
    }


class TestValidateRaw:
    def test_valid_config(self) -> None:
        raw = _make_minimal_raw()
        config = validate_raw(raw)
        assert isinstance(config, ServerConfig)
        assert config.global_config.max_concurrent_executions == 3
        assert "test-repo" in config.repos

    def test_invalid_config(self) -> None:
        raw = _make_minimal_raw()
        raw["repos"]["test-repo"]["email"]["imap_port"] = "not-a-number"
        with pytest.raises((ConfigError, ValueError)):
            validate_raw(raw)

    def test_validates_vars(self) -> None:
        raw = _make_minimal_raw()
        raw["vars"] = {"server": "mail.example.com"}
        raw["repos"]["test-repo"]["email"]["imap_server"] = VarRef("server")
        config = validate_raw(raw)
        assert "test-repo" in config.repos

    def test_undefined_var_raises(self) -> None:
        raw = _make_minimal_raw()
        raw["repos"]["test-repo"]["email"]["imap_server"] = VarRef(
            "nonexistent"
        )
        with pytest.raises(ConfigError, match="undefined variable"):
            validate_raw(raw)


class TestPreviewChanges:
    def _make_config(
        self,
        model: str = "opus",
        max_concurrent: int = 3,
    ) -> ServerConfig:
        raw = _make_minimal_raw(model=model, max_concurrent=max_concurrent)
        return validate_raw(raw)

    def test_no_changes(self) -> None:
        config = self._make_config()
        raw = _make_minimal_raw()
        result = preview_changes(config, raw)
        assert result.valid is True
        assert result.diff is not None
        assert not any(result.diff[scope] for scope in result.diff)
        assert result.warnings == []

    def test_server_scope_change(self) -> None:
        current = self._make_config(max_concurrent=3)
        edited = _make_minimal_raw(max_concurrent=5)
        result = preview_changes(current, edited)
        assert result.valid is True
        assert result.diff is not None
        assert len(result.diff["server"]) > 0
        change = result.diff["server"][0]
        assert change.field == "max_concurrent_executions"
        assert change.old == 3
        assert change.new == 5
        assert "server-scope" in result.warnings[0]

    def test_task_scope_change(self) -> None:
        current = self._make_config(model="opus")
        edited = _make_minimal_raw(model="sonnet")
        result = preview_changes(current, edited)
        assert result.valid is True
        assert result.diff is not None
        assert len(result.diff["task"]) > 0
        change = result.diff["task"][0]
        assert change.field == "model"
        assert change.repo == "test-repo"

    def test_invalid_edit(self) -> None:
        current = self._make_config()
        edited = _make_minimal_raw()
        # Remove required field
        del edited["repos"]["test-repo"]["git"]
        result = preview_changes(current, edited)
        assert result.valid is False
        assert result.error is not None
        assert result.diff is None

    def test_repo_added(self) -> None:
        current = self._make_config()
        edited = _make_minimal_raw()
        edited["repos"]["new-repo"] = {
            "git": {"repo_url": "https://github.com/test/new"},
            "email": {
                "imap_server": "imap2.example.com",
                "imap_port": 993,
                "smtp_server": "smtp2.example.com",
                "smtp_port": 587,
                "username": "bot2@example.com",
                "password": "secret2",
                "from": "bot2@example.com",
                "authorized_senders": ["admin@example.com"],
                "trusted_authserv_id": "example.com",
            },
        }
        result = preview_changes(current, edited)
        assert result.valid is True
        assert result.diff is not None
        added = [c for c in result.diff["repo"] if c.repo == "new-repo"]
        assert len(added) > 0

    def test_repo_removed(self) -> None:
        current = self._make_config()
        # Create edited config replacing test-repo with extra-repo
        edited2 = _make_minimal_raw()
        edited2["repos"]["extra-repo"] = edited2["repos"].pop("test-repo")
        edited2["repos"]["extra-repo"]["email"]["imap_server"] = (
            "imap2.example.com"
        )
        edited2["repos"]["extra-repo"]["email"]["username"] = "bot2@example.com"
        result = preview_changes(current, edited2)
        assert result.valid is True
        assert result.diff is not None
        # test-repo was removed, extra-repo was added
        repo_changes = result.diff["repo"]
        removed = [c for c in repo_changes if c.new is None]
        added = [c for c in repo_changes if c.old is None]
        assert len(removed) > 0
        assert len(added) > 0


class TestDiffGlobal:
    def test_detects_change(self) -> None:
        from airut.gateway.config import GlobalConfig

        current = GlobalConfig(max_concurrent_executions=3)
        new = GlobalConfig(max_concurrent_executions=5)
        changes: dict[str, list[FieldChange]] = {
            "server": [],
            "repo": [],
            "task": [],
        }
        _diff_global(current, new, changes)
        assert len(changes["server"]) == 1
        assert changes["server"][0].field == "max_concurrent_executions"

    def test_no_changes(self) -> None:
        from airut.gateway.config import GlobalConfig

        config = GlobalConfig()
        changes: dict[str, list[FieldChange]] = {
            "server": [],
            "repo": [],
            "task": [],
        }
        _diff_global(config, config, changes)
        assert not changes["server"]


class TestDiffRepo:
    def test_detects_change(self) -> None:
        raw = _make_minimal_raw()
        config = validate_raw(raw)
        current_repo = config.repos["test-repo"]

        raw2 = _make_minimal_raw(model="sonnet")
        config2 = validate_raw(raw2)
        new_repo = config2.repos["test-repo"]

        changes: dict[str, list[FieldChange]] = {
            "server": [],
            "repo": [],
            "task": [],
        }
        _diff_repo(current_repo, new_repo, "test-repo", changes)
        assert len(changes["task"]) >= 1
        model_change = [c for c in changes["task"] if c.field == "model"]
        assert len(model_change) == 1
        assert model_change[0].repo == "test-repo"


class TestBackupConfig:
    def test_creates_backup(self, tmp_path: Path) -> None:
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("test: config\n")

        backup_path = backup_config(config_file)
        assert backup_path.exists()
        assert backup_path.read_text() == "test: config\n"
        assert ".bak" in backup_path.suffix

    def test_prunes_old_backups(self, tmp_path: Path) -> None:
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("test: config\n")

        # Create 6 backups
        paths = []
        for i in range(6):
            with patch("airut.config.editor.time") as mock_time:
                mock_time.time.return_value = 1000000.0 + i
                p = backup_config(config_file)
                paths.append(p)

        # Only 5 should remain
        remaining = list(tmp_path.glob("airut.*.bak"))
        assert len(remaining) == 5
        # Oldest should be pruned
        assert not paths[0].exists()

    def test_backup_preserves_content(self, tmp_path: Path) -> None:
        config_file = tmp_path / "airut.yaml"
        content = (
            "complex:\n  nested: value\n  list:\n    - item1\n    - item2\n"
        )
        config_file.write_text(content)
        backup_path = backup_config(config_file)
        assert backup_path.read_text() == content


class TestAtomicSave:
    def test_writes_yaml(self, tmp_path: Path) -> None:
        target = tmp_path / "config.yaml"
        target.write_text("old: content\n")
        raw = {"new": "content", "nested": {"key": "value"}}
        atomic_save(raw, target)
        loaded = yaml.safe_load(target.read_text())
        assert loaded == {"new": "content", "nested": {"key": "value"}}

    def test_preserves_tags(self, tmp_path: Path) -> None:
        from airut.yaml_env import make_env_loader

        target = tmp_path / "config.yaml"
        target.write_text("")
        raw = {"password": EnvVar("SECRET"), "ref": VarRef("my_var")}
        atomic_save(raw, target)
        content = target.read_text()
        assert "!env" in content
        assert "!var" in content

        # Verify round-trip
        loaded = yaml.load(target.read_text(), Loader=make_env_loader())
        assert isinstance(loaded["password"], EnvVar)
        assert isinstance(loaded["ref"], VarRef)

    def test_atomic_no_partial_write(self, tmp_path: Path) -> None:
        target = tmp_path / "config.yaml"
        target.write_text("original: content\n")

        # Simulate a write error by patching yaml.dump to raise
        with (
            patch("airut.config.editor.yaml.dump", side_effect=OSError("fail")),
            pytest.raises(OSError),
        ):
            atomic_save({"key": "value"}, target)

        # Original file should be untouched
        assert target.read_text() == "original: content\n"
        # Temp file should be cleaned up
        assert not (tmp_path / "config.tmp").exists()


class TestPreviewResult:
    def test_valid_result(self) -> None:
        result = PreviewResult(
            valid=True,
            error=None,
            diff={"server": [], "repo": [], "task": []},
            warnings=[],
        )
        assert result.valid is True
        assert result.error is None

    def test_invalid_result(self) -> None:
        result = PreviewResult(
            valid=False,
            error="Some error",
            diff=None,
            warnings=[],
        )
        assert result.valid is False
        assert result.error == "Some error"


class TestFieldChange:
    def test_field_change(self) -> None:
        fc = FieldChange(
            field="model",
            doc="Claude model",
            old="opus",
            new="sonnet",
            repo="test-repo",
        )
        assert fc.field == "model"
        assert fc.repo == "test-repo"

    def test_global_field_change(self) -> None:
        fc = FieldChange(
            field="max_concurrent",
            doc="Max concurrent",
            old=3,
            new=5,
            repo=None,
        )
        assert fc.repo is None
