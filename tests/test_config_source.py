# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config source protocol and YAML implementation."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from airut.config.source import (
    ConfigReadOnlyError,
    YamlConfigSource,
    _set_nested,
    flat_to_nested_email,
    flat_to_nested_global,
    flat_to_nested_repo,
    make_tag_dumper,
)
from airut.yaml_env import EnvVar, VarRef


class TestSetNested:
    def test_single_level(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, ("key",), "value")
        assert d == {"key": "value"}

    def test_two_levels(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, ("a", "b"), 42)
        assert d == {"a": {"b": 42}}

    def test_three_levels(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, ("a", "b", "c"), True)
        assert d == {"a": {"b": {"c": True}}}

    def test_merges_into_existing(self) -> None:
        d: dict[str, Any] = {"a": {"x": 1}}
        _set_nested(d, ("a", "y"), 2)
        assert d == {"a": {"x": 1, "y": 2}}


class TestFlatToNestedGlobal:
    def test_maps_execution_fields(self) -> None:
        flat = {
            "max_concurrent_executions": 5,
            "shutdown_timeout_seconds": 120,
        }
        nested = flat_to_nested_global(flat)
        assert nested == {
            "execution": {
                "max_concurrent": 5,
                "shutdown_timeout": 120,
            }
        }

    def test_maps_dashboard_fields(self) -> None:
        flat = {
            "dashboard_enabled": True,
            "dashboard_host": "0.0.0.0",
            "dashboard_port": 8080,
            "dashboard_base_url": "https://example.com",
        }
        nested = flat_to_nested_global(flat)
        assert nested == {
            "dashboard": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080,
                "base_url": "https://example.com",
            }
        }

    def test_maps_network_fields(self) -> None:
        flat = {"upstream_dns": "8.8.8.8"}
        nested = flat_to_nested_global(flat)
        assert nested == {"network": {"upstream_dns": "8.8.8.8"}}

    def test_unmapped_field_stays_flat(self) -> None:
        flat = {"container_command": "docker"}
        nested = flat_to_nested_global(flat)
        assert nested == {"container_command": "docker"}


class TestFlatToNestedEmail:
    def test_passthrough_no_remapping(self) -> None:
        """YAML_EMAIL_STRUCTURE is empty so all keys pass through unchanged."""
        flat = {
            "imap_poll_interval_seconds": 30,
            "imap_use_idle": False,
        }
        nested = flat_to_nested_email(flat)
        assert nested == flat

    def test_passthrough_preserves_all_keys(self) -> None:
        flat = {
            "account": {"username": "user@example.com"},
            "imap": {"server": "imap.example.com"},
            "custom_field": "custom_value",
        }
        nested = flat_to_nested_email(flat)
        assert nested == flat


class TestFlatToNestedRepo:
    def test_maps_git_url(self) -> None:
        flat = {"git_repo_url": "https://github.com/org/repo.git"}
        nested = flat_to_nested_repo(flat)
        assert nested == {"repo_url": "https://github.com/org/repo.git"}

    def test_maps_network_sandbox(self) -> None:
        flat = {"network_sandbox_enabled": False}
        nested = flat_to_nested_repo(flat)
        assert nested == {"network": {"sandbox_enabled": False}}

    def test_container_path_stays_flat(self) -> None:
        flat = {"container_path": ".devcontainer"}
        nested = flat_to_nested_repo(flat)
        assert nested == {"container_path": ".devcontainer"}

    def test_unmapped_stays_flat(self) -> None:
        flat = {"model": "sonnet"}
        nested = flat_to_nested_repo(flat)
        assert nested == {"model": "sonnet"}


class TestYamlConfigSource:
    def test_load(self, tmp_path: Path) -> None:
        config = {"execution": {"max_concurrent": 5}, "repos": {}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config))

        source = YamlConfigSource(config_file)
        assert source.last_file_sha256 is None

        with patch("airut.config.source.load_dotenv_once"):
            loaded = source.load()

        assert loaded["execution"]["max_concurrent"] == 5
        assert source.last_file_sha256 is not None
        assert len(source.last_file_sha256) == 64  # SHA-256 hex

    def test_load_missing_file(self, tmp_path: Path) -> None:
        source = YamlConfigSource(tmp_path / "missing.yaml")
        with (
            patch("airut.config.source.load_dotenv_once"),
            pytest.raises(FileNotFoundError),
        ):
            source.load()

    def test_load_non_mapping(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("- item1\n- item2\n")

        source = YamlConfigSource(config_file)
        with (
            patch("airut.config.source.load_dotenv_once"),
            pytest.raises(ValueError, match="YAML mapping"),
        ):
            source.load()

    def test_save(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        source = YamlConfigSource(config_file)

        data = {"execution": {"max_concurrent": 10}}
        source.save(data)

        loaded = yaml.safe_load(config_file.read_text())
        assert loaded == data

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        config_file = tmp_path / "sub" / "dir" / "config.yaml"
        source = YamlConfigSource(config_file)

        source.save({"key": "value"})

        assert config_file.exists()
        loaded = yaml.safe_load(config_file.read_text())
        assert loaded == {"key": "value"}

    def test_round_trip(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        original = {
            "execution": {"max_concurrent": 3},
            "dashboard": {"enabled": True, "port": 5200},
        }
        config_file.write_text(yaml.dump(original))

        source = YamlConfigSource(config_file)
        with patch("airut.config.source.load_dotenv_once"):
            loaded = source.load()

        source.save(loaded)

        with patch("airut.config.source.load_dotenv_once"):
            reloaded = source.load()
        assert reloaded == loaded


class TestReadOnly:
    """When the editor must not save to a YAML config file."""

    def test_writable(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("{}\n")
        assert YamlConfigSource(config_file).read_only_reason() is None

    def test_missing_file_in_writable_dir(self, tmp_path: Path) -> None:
        """A config not created yet is writable if its directory is."""
        source = YamlConfigSource(tmp_path / "sub" / "dir" / "config.yaml")
        assert source.read_only_reason() is None

    def test_forced(self, tmp_path: Path) -> None:
        source = YamlConfigSource(tmp_path / "config.yaml", read_only=True)
        assert source.read_only_reason() == (
            "the gateway runs with --read-only-config"
        )

    def test_symlink(self, tmp_path: Path) -> None:
        """A symlinked config (e.g. into the Nix store) is read-only.

        Saving replaces the path with a plain file, which would silently
        detach it from wherever the link points.
        """
        target = tmp_path / "target.yaml"
        target.write_text("{}\n")
        link = tmp_path / "config.yaml"
        link.symlink_to(target)

        reason = YamlConfigSource(link).read_only_reason()

        assert reason == f"{link} is a symlink, managed elsewhere"

    def test_file_not_writable(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("{}\n")
        with patch(
            "airut.config.source.os.access",
            side_effect=lambda path, mode: path != config_file,
        ):
            reason = YamlConfigSource(config_file).read_only_reason()
        assert reason == f"{config_file} is not writable"

    def test_directory_not_writable(self, tmp_path: Path) -> None:
        """Saving writes a temp file next to the config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("{}\n")
        with patch(
            "airut.config.source.os.access",
            side_effect=lambda path, mode: path != tmp_path,
        ):
            reason = YamlConfigSource(config_file).read_only_reason()
        assert reason == f"{tmp_path} is not writable"

    def test_nearest_existing_ancestor_checked(self, tmp_path: Path) -> None:
        checked: list[Path] = []

        def fake_access(path: Path, mode: int) -> bool:
            checked.append(path)
            return False

        source = YamlConfigSource(tmp_path / "a" / "b" / "config.yaml")
        with patch("airut.config.source.os.access", side_effect=fake_access):
            assert source.read_only_reason() == f"{tmp_path} is not writable"
        assert checked == [tmp_path]

    def test_save_refused(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("original: true\n")
        source = YamlConfigSource(config_file, read_only=True)

        with pytest.raises(ConfigReadOnlyError, match="--read-only-config"):
            source.save({"changed": True})

        assert config_file.read_text() == "original: true\n"

    def test_save_keeps_symlink(self, tmp_path: Path) -> None:
        target = tmp_path / "target.yaml"
        target.write_text("original: true\n")
        link = tmp_path / "config.yaml"
        link.symlink_to(target)

        with pytest.raises(ConfigReadOnlyError, match="symlink"):
            YamlConfigSource(link).save({"changed": True})

        assert link.is_symlink()
        assert target.read_text() == "original: true\n"


class TestTagDumper:
    def test_env_var_represented(self) -> None:
        """EnvVar objects are dumped as !env tags."""
        data = {"password": EnvVar("MY_SECRET")}
        output = yaml.dump(data, Dumper=make_tag_dumper())
        assert "!env" in output
        assert "MY_SECRET" in output

    def test_var_ref_represented(self) -> None:
        """VarRef objects are dumped as !var tags."""
        data = {"server": VarRef("mail_server")}
        output = yaml.dump(data, Dumper=make_tag_dumper())
        assert "!var" in output
        assert "mail_server" in output

    def test_round_trip_with_tags(self, tmp_path: Path) -> None:
        """Save and reload preserves !env and !var tags."""
        from airut.yaml_env import make_env_loader

        data: dict[str, Any] = {
            "vars": {"key": EnvVar("API_KEY")},
            "repos": {
                "test": {
                    "server": VarRef("mail"),
                    "password": EnvVar("PW"),
                    "model": "opus",
                },
            },
        }
        config_file = tmp_path / "config.yaml"
        source = YamlConfigSource(config_file)
        source.save(data)

        # Reload with env loader (which understands !env and !var)
        with open(config_file) as f:
            reloaded = yaml.load(f, Loader=make_env_loader())

        assert isinstance(reloaded["vars"]["key"], EnvVar)
        assert reloaded["vars"]["key"].var_name == "API_KEY"
        assert isinstance(reloaded["repos"]["test"]["server"], VarRef)
        assert reloaded["repos"]["test"]["server"].var_name == "mail"
        assert isinstance(reloaded["repos"]["test"]["password"], EnvVar)
        assert reloaded["repos"]["test"]["model"] == "opus"
