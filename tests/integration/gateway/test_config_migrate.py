# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for config schema version check and migration.

Tests the ``airut check`` schema reporting and ``airut migrate`` command
with real YAML files, verifying end-to-end round-trip behavior including
``!env`` tag preservation and version stamping.
"""

from pathlib import Path

import yaml

from airut.config.migration import (
    CURRENT_CONFIG_VERSION,
    get_file_config_version,
)
from airut.config.source import YamlConfigSource
from airut.yaml_env import EnvVar, make_env_loader


# -- Helpers ---------------------------------------------------------


_V3_CONFIG = """\
config_version: 3
repos:
  test:
    email:
      account:
        username: user@test.com
        password: !env EMAIL_PASSWORD
        from: "Test <test@example.com>"
      imap:
        server: imap.test.com
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - auth@test.com
        trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/repo.git
"""

_CURRENT_CONFIG = f"""\
config_version: {CURRENT_CONFIG_VERSION}
repos:
  test:
    email:
      account:
        username: user@test.com
        password: !env EMAIL_PASSWORD
        from: "Test <test@example.com>"
      imap:
        server: imap.test.com
      smtp:
        server: smtp.test.com
      auth:
        authorized_senders:
          - auth@test.com
        trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/repo.git
"""


# -- get_file_config_version ----------------------------------------


class TestGetFileConfigVersionIntegration:
    def test_reads_v3_config(self, tmp_path: Path) -> None:
        """Reads version from a v3 config file with !env tags."""
        config = tmp_path / "airut.yaml"
        config.write_text(_V3_CONFIG)
        assert get_file_config_version(config) == 3

    def test_reads_current_config(self, tmp_path: Path) -> None:
        """Reads version from a current-version config file."""
        config = tmp_path / "airut.yaml"
        config.write_text(_CURRENT_CONFIG)
        assert get_file_config_version(config) == CURRENT_CONFIG_VERSION

    def test_absent_version_defaults_to_1(self, tmp_path: Path) -> None:
        """Config without config_version is treated as v1."""
        config = tmp_path / "airut.yaml"
        config.write_text("repos: {}\n")
        assert get_file_config_version(config) == 1


# -- migrate_config_file ---------------------------------------------


class TestMigrateConfigFileIntegration:
    def test_migrate_v3_to_current(self, tmp_path: Path) -> None:
        """Migrates a v3 config file to current version."""
        from airut.config.migration import migrate_config_file

        config = tmp_path / "airut.yaml"
        config.write_text(_V3_CONFIG)

        old, new = migrate_config_file(config)
        assert old == 3
        assert new == CURRENT_CONFIG_VERSION

        # Re-read and verify version stamp
        assert get_file_config_version(config) == CURRENT_CONFIG_VERSION

    def test_noop_when_already_current(self, tmp_path: Path) -> None:
        """No-op when config is already at current version."""
        from airut.config.migration import migrate_config_file

        config = tmp_path / "airut.yaml"
        config.write_text(_CURRENT_CONFIG)
        original = config.read_text()

        old, new = migrate_config_file(config)
        assert old == CURRENT_CONFIG_VERSION
        assert new == CURRENT_CONFIG_VERSION
        # File unchanged
        assert config.read_text() == original

    def test_preserves_env_tags_round_trip(self, tmp_path: Path) -> None:
        """!env tags survive the migration round-trip."""
        from airut.config.migration import migrate_config_file

        config = tmp_path / "airut.yaml"
        config.write_text(_V3_CONFIG)

        migrate_config_file(config)

        # Re-parse with !env-aware loader
        raw = yaml.load(config.read_bytes(), Loader=make_env_loader())
        email = raw["repos"]["test"]["email"]
        password = email["account"]["password"]
        assert isinstance(password, EnvVar)
        assert password.var_name == "EMAIL_PASSWORD"

    def test_migrated_config_loads_successfully(self, tmp_path: Path) -> None:
        """Migrated config can be loaded via YamlConfigSource."""
        from unittest.mock import patch

        from airut.config.migration import migrate_config_file
        from airut.gateway.config import ServerConfig

        config = tmp_path / "airut.yaml"
        config.write_text(_V3_CONFIG)

        migrate_config_file(config)

        # Load with !env values set
        with patch.dict(
            "os.environ", {"EMAIL_PASSWORD": "test_secret"}, clear=False
        ):
            source = YamlConfigSource(config)
            snapshot = ServerConfig.from_source(source)
            assert "test" in snapshot.value.repos

    def test_idempotent_double_migration(self, tmp_path: Path) -> None:
        """Running migrate twice produces the same result."""
        from airut.config.migration import migrate_config_file

        config = tmp_path / "airut.yaml"
        config.write_text(_V3_CONFIG)

        migrate_config_file(config)
        content_after_first = config.read_text()

        # Second run should be a no-op
        old, new = migrate_config_file(config)
        assert old == CURRENT_CONFIG_VERSION
        assert new == CURRENT_CONFIG_VERSION
        assert config.read_text() == content_after_first


# -- cmd_check schema reporting (end-to-end) -------------------------


class TestCmdCheckSchemaIntegration:
    def _run_check_with_config(
        self, tmp_path: Path, config_text: str
    ) -> tuple[int, str]:
        """Run cmd_check with a real config file and capture output."""
        from unittest.mock import patch

        import airut.cli

        config_path = tmp_path / "airut.yaml"
        config_path.write_text(config_text)
        dotenv_path = tmp_path / ".env"

        with (
            patch("airut.cli.get_config_path", return_value=config_path),
            patch("airut.cli.get_dotenv_path", return_value=dotenv_path),
            patch(
                "airut.cli._check_dependency",
                return_value=(True, "git: 2.43.0 (>= 2.25)"),
            ),
            patch(
                "airut.version.get_git_version_info",
                return_value=type(
                    "FakeVI",
                    (),
                    {
                        "version": "v0.9.0",
                        "sha_short": "abc1234",
                        "sha_full": "abc1234" * 5,
                        "full_status": "",
                    },
                )(),
            ),
            patch("airut.cli._is_service_installed", return_value=False),
            patch("airut.cli._is_service_running", return_value=False),
            patch("airut.cli._fetch_running_version", return_value=None),
            patch("airut.version.check_upstream_version", return_value=None),
            patch("airut.cli._use_color", return_value=False),
            patch(
                "airut.cli._check_cgroups_v2",
                return_value=(True, "cgroups v2: delegated (cpu memory pids)"),
            ),
            patch.dict(
                "os.environ",
                {"EMAIL_PASSWORD": "test_secret"},
                clear=False,
            ),
        ):
            import io
            import sys

            captured = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                result = airut.cli.cmd_check([])
            finally:
                sys.stdout = old_stdout
            return result, captured.getvalue()

    def test_shows_migration_pending_for_v3(self, tmp_path: Path) -> None:
        """cmd_check reports migration pending for v3 config."""
        result, out = self._run_check_with_config(tmp_path, _V3_CONFIG)
        assert result == 0
        assert "migration pending" in out
        assert "v3" in out
        assert f"v{CURRENT_CONFIG_VERSION}" in out
        assert "airut migrate" in out

    def test_shows_up_to_date_for_current(self, tmp_path: Path) -> None:
        """cmd_check reports up to date for current-version config."""
        result, out = self._run_check_with_config(tmp_path, _CURRENT_CONFIG)
        assert result == 0
        assert "up to date" in out
        assert f"v{CURRENT_CONFIG_VERSION}" in out


# -- cmd_migrate (end-to-end) ----------------------------------------


class TestCmdMigrateIntegration:
    def test_migrate_v3_config(self, tmp_path: Path) -> None:
        """Migrates v3 config and reports success."""
        from unittest.mock import patch

        from airut.cli import cmd_migrate

        config_path = tmp_path / "airut.yaml"
        config_path.write_text(_V3_CONFIG)

        import io
        import sys

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            with (
                patch("airut.cli.get_config_path", return_value=config_path),
                patch("airut.cli._use_color", return_value=False),
            ):
                result = cmd_migrate([])
        finally:
            sys.stdout = old_stdout

        out = captured.getvalue()
        assert result == 0
        assert "Migrated" in out
        assert "v3" in out
        assert f"v{CURRENT_CONFIG_VERSION}" in out
        assert get_file_config_version(config_path) == CURRENT_CONFIG_VERSION

    def test_migrate_then_check_shows_up_to_date(self, tmp_path: Path) -> None:
        """After migration, check reports schema up to date."""
        from unittest.mock import patch

        from airut.cli import cmd_migrate

        config_path = tmp_path / "airut.yaml"
        config_path.write_text(_V3_CONFIG)

        with (
            patch("airut.cli.get_config_path", return_value=config_path),
            patch("airut.cli._use_color", return_value=False),
        ):
            cmd_migrate([])

        # Now check should show up to date
        assert get_file_config_version(config_path) == CURRENT_CONFIG_VERSION
