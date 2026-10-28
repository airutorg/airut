# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for offline config checks (``airut check --offline``)."""

from pathlib import Path
from typing import Any

import pytest

from airut.config.offline import (
    OfflineConfigSource,
    is_file_in,
    is_literal,
    secret_values,
)
from airut.config.source import ConfigReadOnlyError
from airut.config.vars import resolve_vars_section
from airut.gateway.config import ConfigError, ServerConfig, _resolve
from airut.yaml_env import EnvVar, FileRef, Unresolved, VarRef


_REFERENCING_CONFIG = """\
vars:
  imap_port: !env IMAP_PORT_UNSET
  shared_key: !file /nonexistent/shared-key
dashboard:
  port: !env DASHBOARD_PORT_UNSET
repos:
  test:
    repo_url: !env REPO_URL_UNSET
    email:
      account:
        username: user@example.com
        password: !file $CREDENTIALS_DIRECTORY/email-password
        from: "Bot <bot@example.com>"
      imap:
        server: imap.example.com
        port: !var imap_port
      smtp:
        server: {"!env": SMTP_SERVER_UNSET}
      auth:
        authorized_senders:
          - !env ADMIN_SENDER_UNSET
        trusted_authserv_id: mx.example.com
    secrets:
      ANTHROPIC_API_KEY: !var shared_key
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN_UNSET
        scopes: ["api.github.com"]
        headers: ["Authorization"]
"""


class TestUnresolved:
    def test_str(self) -> None:
        assert str(Unresolved(EnvVar("A"))) == "<!env A>"
        assert str(Unresolved(FileRef("/b"))) == "<!file /b>"
        assert repr(Unresolved(EnvVar("A"))) == "Unresolved(EnvVar('A'))"

    def test_strings_get_stand_in_text(self) -> None:
        """Assumed set: e.g. a password other settings make required."""
        env = Unresolved(EnvVar("X"))
        assert _resolve(env, str) == "<!env X>"
        assert _resolve(env, str, required="x") == "<!env X>"
        assert _resolve(env, Path) == Path("<!env X>")
        assert _resolve(env, str, default="opus") == "opus"

    def test_other_optional_types_take_default(self) -> None:
        """A number cannot be guessed: the field's default applies."""
        value = Unresolved(EnvVar("PORT"))
        assert _resolve(value, int) is None
        assert _resolve(value, int, default=993) == 993
        assert _resolve(value, bool) is None

    def test_other_required_types_get_minimal_value(self) -> None:
        env = Unresolved(EnvVar("X"))
        assert _resolve(env, int, required="x") == 1
        assert _resolve(env, float, required="x") == 1.0
        assert _resolve(env, bool, required="x") is False

    def test_vars_keep_stand_ins(self) -> None:
        """A field reading a variable sees the stand-in, not its text."""
        stand_in = Unresolved(EnvVar("X"))
        table = resolve_vars_section({"vars": {"v": stand_in, "w": "lit"}})
        assert table == {"v": stand_in, "w": "lit"}


class TestOfflineConfigSource:
    def test_references_replaced_without_reading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SET_VAR", "real-value")
        secret = tmp_path / "secret"
        secret.write_text("real-file")
        config_file = tmp_path / "airut.yaml"
        config_file.write_text(
            f"a: !env SET_VAR\n"
            f"b: [!file {secret}, plain]\n"
            f"c:\n  d: {{'!env': OTHER}}\n"
            f"e: !var name\n"
        )
        source = OfflineConfigSource(config_file)

        raw = source.load()

        assert source.references == 3
        assert str(raw["a"]) == "<!env SET_VAR>"
        assert [str(v) for v in raw["b"]] == [f"<!file {secret}>", "plain"]
        assert str(raw["c"]["d"]) == "<!env OTHER>"
        assert raw["e"] == VarRef("name")

    def test_read_only(self, tmp_path: Path) -> None:
        source = OfflineConfigSource(tmp_path / "airut.yaml")
        assert source.read_only_reason() == "offline check"
        with pytest.raises(ConfigReadOnlyError):
            source.save({})

    def test_validates_without_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every reference unavailable, as in a Nix build sandbox."""
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        config_file = tmp_path / "airut.yaml"
        config_file.write_text(_REFERENCING_CONFIG)

        config = ServerConfig.from_source(
            OfflineConfigSource(config_file)
        ).value

        assert list(config.repos) == ["test"]
        # Optional references take their defaults.
        assert config.global_config.dashboard_port == 5200

    def test_online_load_of_same_config_fails(self, tmp_path: Path) -> None:
        """The offline check is what makes this config checkable."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text(_REFERENCING_CONFIG)
        with pytest.raises(ConfigError, match="environment variable"):
            ServerConfig.from_yaml(config_file)

    def test_structural_errors_still_found(self, tmp_path: Path) -> None:
        config_file = tmp_path / "airut.yaml"
        config_file.write_text(
            _REFERENCING_CONFIG.replace(
                "        server: imap.example.com\n", ""
            )
        )
        with pytest.raises(ConfigError, match="imap.server"):
            ServerConfig.from_source(OfflineConfigSource(config_file))


def _repo(**sections: dict[str, Any]) -> dict[str, Any]:
    return {"repos": {"r": sections}}


def _paths(raw: dict[str, Any]) -> list[str]:
    """Paths of the literal secrets in *raw*."""
    return [path for path, value in secret_values(raw) if is_literal(value)]


class TestSecretValues:
    def test_scalar_secrets(self) -> None:
        raw = _repo(
            email={
                "account": {"password": "hunter2", "username": "u"},
                "microsoft_oauth2": {"client_secret": "oauth-secret"},
            },
            slack={"bot_token": "xoxb-1", "app_token": EnvVar("APP")},
        )
        assert _paths(raw) == [
            "repos.r.email.account.password",
            "repos.r.email.microsoft_oauth2.client_secret",
            "repos.r.slack.bot_token",
        ]
        assert ("repos.r.slack.app_token", EnvVar("APP")) in secret_values(raw)

    def test_secret_mappings_and_collections(self) -> None:
        raw = _repo(
            secrets={"A": "literal", "B": FileRef("/run/b"), "C": ""},
            masked_secrets={
                "GH": {"value": "ghp_x", "scopes": ["api.github.com"]}
            },
            signing_credentials={
                "AWS": {
                    "type": "aws-sigv4",
                    "access_key_id": {"name": "AWS_KEY", "value": "AKIA"},
                    "secret_access_key": {
                        "name": "AWS_SECRET",
                        "value": EnvVar("S"),
                    },
                }
            },
            github_app_credentials={
                "GH_APP": {"app_id": "1", "private_key": "-----BEGIN"}
            },
        )
        assert _paths(raw) == [
            "repos.r.secrets.A",
            "repos.r.masked_secrets.GH.value",
            "repos.r.signing_credentials.AWS.access_key_id.value",
            "repos.r.github_app_credentials.GH_APP.private_key",
        ]

    def test_dotted_repo_id(self) -> None:
        """Repo IDs may contain dots; their secrets are still found."""
        raw = {"repos": {"a.b": {"secrets": {"K": "sk-literal"}}}}
        assert _paths(raw) == ["repos.a.b.secrets.K"]

    def test_numeric_literals(self) -> None:
        """YAML reads unquoted digits as numbers; still literal secrets."""
        raw = _repo(secrets={"PIN": 1234, "RATE": 1.5})
        assert _paths(raw) == ["repos.r.secrets.PIN", "repos.r.secrets.RATE"]

    def test_var_reference_reports_variable_once(self) -> None:
        raw = _repo(
            secrets={
                "A": VarRef("key"),
                "B": VarRef("key"),
                "C": VarRef("env_key"),
            }
        )
        raw["vars"] = {"key": "sk-literal", "env_key": EnvVar("K")}
        assert secret_values(raw) == [
            ("vars.key", "sk-literal"),
            ("vars.env_key", EnvVar("K")),
        ]

    def test_no_secrets(self) -> None:
        assert secret_values({"dashboard": {"port": 1}}) == []
        assert secret_values({"repos": "not-a-mapping"}) == []
        assert secret_values({"repos": {"r": "not-a-mapping"}}) == []


class TestPredicates:
    def test_is_literal(self) -> None:
        assert is_literal("x")
        assert is_literal(0)
        assert is_literal(1.5)
        assert not is_literal("")
        assert not is_literal(None)
        assert not is_literal(True)
        assert not is_literal(EnvVar("X"))

    def test_is_file_in(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = tmp_path / "store"
        monkeypatch.setenv("SECRETS", str(store))
        assert is_file_in(FileRef(f"{store}/abc-secret"), store)
        assert is_file_in(FileRef("$SECRETS/abc-secret"), store)
        assert is_file_in(Unresolved(FileRef(f"{store}/x")), store)
        assert not is_file_in(FileRef("/run/agenix/secret"), store)
        assert not is_file_in(FileRef("relative/secret"), store)
        assert not is_file_in(EnvVar("X"), store)
