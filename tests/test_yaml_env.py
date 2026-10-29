# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for YAML ``!env`` tag resolution."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
import yaml.constructor

from airut.yaml_env import (
    EnvVar,
    FileRef,
    FileRefError,
    VarRef,
    env_constructor,
    make_env_loader,
    raw_resolve,
    var_constructor,
)


class TestEnvVar:
    """Tests for EnvVar placeholder class."""

    def test_construction(self) -> None:
        """EnvVar stores the variable name."""
        ev = EnvVar("MY_VAR")
        assert ev.var_name == "MY_VAR"

    def test_different_names(self) -> None:
        """EnvVar works with various variable names."""
        for name in ("HOME", "PATH", "A_B_C_123", ""):
            ev = EnvVar(name)
            assert ev.var_name == name

    def test_repr(self) -> None:
        """EnvVar has a readable repr."""
        ev = EnvVar("MY_VAR")
        assert repr(ev) == "EnvVar('MY_VAR')"

    def test_equality_same_name(self) -> None:
        """Two EnvVar with same var_name are equal."""
        assert EnvVar("X") == EnvVar("X")

    def test_equality_different_name(self) -> None:
        """Two EnvVar with different var_name are not equal."""
        assert EnvVar("X") != EnvVar("Y")

    def test_equality_not_other_type(self) -> None:
        """EnvVar is not equal to a plain string."""
        assert EnvVar("X") != "X"

    def test_hash_same_name(self) -> None:
        """Two EnvVar with same var_name have the same hash."""
        assert hash(EnvVar("X")) == hash(EnvVar("X"))

    def test_usable_in_set(self) -> None:
        """EnvVar can be used in sets and as dict keys."""
        s = {EnvVar("A"), EnvVar("A"), EnvVar("B")}
        assert len(s) == 2

    def test_dict_equality_with_envvar_values(self) -> None:
        """Dicts containing EnvVar values compare equal when content matches."""
        d1 = {"password": EnvVar("SECRET"), "port": 993}
        d2 = {"password": EnvVar("SECRET"), "port": 993}
        assert d1 == d2


class TestVarRef:
    """Tests for VarRef placeholder class."""

    def test_construction(self) -> None:
        """VarRef stores the variable name."""
        vr = VarRef("my_var")
        assert vr.var_name == "my_var"

    def test_different_names(self) -> None:
        """VarRef works with various names."""
        for name in ("mail_server", "api_key", "x"):
            vr = VarRef(name)
            assert vr.var_name == name

    def test_repr(self) -> None:
        """VarRef has a readable repr."""
        vr = VarRef("my_var")
        assert repr(vr) == "VarRef('my_var')"

    def test_equality_same_name(self) -> None:
        """Two VarRef with same var_name are equal."""
        assert VarRef("x") == VarRef("x")

    def test_equality_different_name(self) -> None:
        """Two VarRef with different var_name are not equal."""
        assert VarRef("x") != VarRef("y")

    def test_equality_not_other_type(self) -> None:
        """VarRef is not equal to a plain string."""
        assert VarRef("x") != "x"

    def test_hash_same_name(self) -> None:
        """Two VarRef with same var_name have the same hash."""
        assert hash(VarRef("x")) == hash(VarRef("x"))


class TestVarConstructor:
    """Tests for var_constructor()."""

    def test_returns_varref(self) -> None:
        """var_constructor returns a VarRef from a YAML scalar node."""
        loader = yaml.SafeLoader("!var my_var")
        node = yaml.ScalarNode(tag="!var", value="my_var")
        result = var_constructor(loader, node)
        assert isinstance(result, VarRef)
        assert result.var_name == "my_var"


class TestEnvConstructor:
    """Tests for env_constructor()."""

    def test_returns_envvar(self) -> None:
        """env_constructor returns an EnvVar from a YAML scalar node."""
        loader = yaml.SafeLoader("!env MY_SECRET")
        node = yaml.ScalarNode(tag="!env", value="MY_SECRET")
        result = env_constructor(loader, node)
        assert isinstance(result, EnvVar)
        assert result.var_name == "MY_SECRET"

    def test_non_string_value_stringified(self) -> None:
        """env_constructor stringifies the node value."""
        node = yaml.ScalarNode(tag="!env", value="123")
        loader = yaml.SafeLoader("")
        result = env_constructor(loader, node)
        assert isinstance(result, EnvVar)
        assert result.var_name == "123"


class TestMakeEnvLoader:
    """Tests for make_env_loader()."""

    def test_returns_loader_subclass(self) -> None:
        """make_env_loader returns a SafeLoader subclass."""
        loader_cls = make_env_loader()
        assert issubclass(loader_cls, yaml.SafeLoader)
        assert loader_cls is not yaml.SafeLoader

    def test_handles_env_tag(self) -> None:
        """Loader parses ``!env VAR_NAME`` into EnvVar."""
        loader_cls = make_env_loader()
        result = yaml.load("key: !env MY_VAR", Loader=loader_cls)
        assert isinstance(result["key"], EnvVar)
        assert result["key"].var_name == "MY_VAR"

    def test_regular_values_unaffected(self) -> None:
        """Loader handles plain scalars normally."""
        loader_cls = make_env_loader()
        result = yaml.load("key: hello", Loader=loader_cls)
        assert result["key"] == "hello"

    def test_multiple_env_tags(self) -> None:
        """Loader handles multiple ``!env`` tags in one doc."""
        loader_cls = make_env_loader()
        doc = "a: !env VAR_A\nb: !env VAR_B\nc: plain"
        result = yaml.load(doc, Loader=loader_cls)
        assert isinstance(result["a"], EnvVar)
        assert result["a"].var_name == "VAR_A"
        assert isinstance(result["b"], EnvVar)
        assert result["b"].var_name == "VAR_B"
        assert result["c"] == "plain"

    def test_handles_var_tag(self) -> None:
        """Loader parses ``!var VAR_NAME`` into VarRef."""
        loader_cls = make_env_loader()
        result = yaml.load("key: !var my_var", Loader=loader_cls)
        assert isinstance(result["key"], VarRef)
        assert result["key"].var_name == "my_var"

    def test_mixed_env_and_var_tags(self) -> None:
        """Loader handles both ``!env`` and ``!var`` in one doc."""
        loader_cls = make_env_loader()
        doc = "a: !env VAR_A\nb: !var my_var\nc: plain"
        result = yaml.load(doc, Loader=loader_cls)
        assert isinstance(result["a"], EnvVar)
        assert isinstance(result["b"], VarRef)
        assert result["c"] == "plain"

    def test_does_not_pollute_base_loader(self) -> None:
        """Creating an env loader does not modify SafeLoader."""
        make_env_loader()
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.load(
                "key: !env MY_VAR",
                Loader=yaml.SafeLoader,
            )


class TestRawResolve:
    """Tests for raw_resolve()."""

    def test_envvar_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns the env var value when it is set."""
        monkeypatch.setenv("TEST_YAML_ENV_VAR", "secret_value")
        result = raw_resolve(EnvVar("TEST_YAML_ENV_VAR"))
        assert result == "secret_value"

    def test_envvar_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns None when the env var is not set."""
        monkeypatch.delenv("TEST_YAML_ENV_MISSING", raising=False)
        result = raw_resolve(EnvVar("TEST_YAML_ENV_MISSING"))
        assert result is None

    def test_envvar_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns empty str when env var is set to empty."""
        monkeypatch.setenv("TEST_YAML_ENV_EMPTY", "")
        result = raw_resolve(EnvVar("TEST_YAML_ENV_EMPTY"))
        assert result == ""

    def test_none_input(self) -> None:
        """Returns None when the input is None."""
        result = raw_resolve(None)
        assert result is None

    def test_literal_string(self) -> None:
        """Returns the string as-is for a literal string."""
        result = raw_resolve("hello")
        assert result == "hello"

    def test_integer(self) -> None:
        """Returns str(int) for an integer value."""
        result = raw_resolve(42)
        assert result == "42"

    def test_float(self) -> None:
        """Returns str(float) for a float value."""
        result = raw_resolve(3.14)
        assert result == "3.14"

    def test_boolean(self) -> None:
        """Returns str(bool) for a boolean value."""
        result = raw_resolve(True)
        assert result == "True"


class TestRoundTrip:
    """End-to-end: load YAML with !env tags and resolve."""

    def test_load_and_resolve(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Load a YAML doc with !env tags and resolve all."""
        monkeypatch.setenv("RT_DB_HOST", "localhost")
        monkeypatch.setenv("RT_DB_PORT", "5432")
        monkeypatch.delenv("RT_MISSING", raising=False)

        doc = """\
database:
  host: !env RT_DB_HOST
  port: !env RT_DB_PORT
  name: mydb
  password: !env RT_MISSING
"""
        loader_cls = make_env_loader()
        config = yaml.load(doc, Loader=loader_cls)

        assert raw_resolve(config["database"]["host"]) == "localhost"
        assert raw_resolve(config["database"]["port"]) == "5432"
        assert raw_resolve(config["database"]["name"]) == "mydb"
        assert raw_resolve(config["database"]["password"]) is None

    def test_nested_env_tags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env tags work in nested YAML structures."""
        monkeypatch.setenv("NESTED_VAL", "found")

        doc = """\
level1:
  level2:
    key: !env NESTED_VAL
"""
        loader_cls = make_env_loader()
        config = yaml.load(doc, Loader=loader_cls)

        result = raw_resolve(config["level1"]["level2"]["key"])
        assert result == "found"


class TestFileRef:
    """Tests for the FileRef placeholder (``!file``)."""

    def test_equality_and_hash(self) -> None:
        assert FileRef("/a") == FileRef("/a")
        assert FileRef("/a") != FileRef("/b")
        assert FileRef("/a") != EnvVar("/a")
        assert len({FileRef("/a"), FileRef("/a")}) == 1
        assert repr(FileRef("/a")) == "FileRef('/a')"

    def test_read_strips_trailing_newlines(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret"
        secret.write_text("s3cret value\n")
        assert FileRef(str(secret)).read() == "s3cret value"
        secret.write_text("windows\r\n\r\n")
        assert FileRef(str(secret)).read() == "windows"

    def test_read_keeps_inner_and_leading_whitespace(
        self, tmp_path: Path
    ) -> None:
        secret = tmp_path / "secret"
        secret.write_text("  line one\nline two")
        assert FileRef(str(secret)).read() == "  line one\nline two"

    def test_missing_file_is_unset(self, tmp_path: Path) -> None:
        """Like an unset env var: callers apply defaults or report it."""
        assert FileRef(str(tmp_path / "missing")).read() is None

    def test_expands_environment_variables(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Systemd LoadCredential= files live in $CREDENTIALS_DIRECTORY."""
        (tmp_path / "slack-token").write_text("xoxb-1\n")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
        ref = FileRef("$CREDENTIALS_DIRECTORY/slack-token")
        assert ref.read() == "xoxb-1"

    def test_expands_user(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / "token").write_text("t\n")
        assert FileRef("~/token").read() == "t"

    def test_relative_path_rejected(self) -> None:
        with pytest.raises(FileRefError, match="got secrets/token"):
            FileRef("secrets/token").read()

    def test_unset_variable_rejected_as_relative(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unset variable stays unexpanded, so the path is relative."""
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        with pytest.raises(FileRefError, match="must be absolute"):
            FileRef("$CREDENTIALS_DIRECTORY/token").read()

    def test_empty_path_is_unset(self) -> None:
        """Like ``!env ''``: e.g. the editor's File tab before a path."""
        assert FileRef("").read() is None

    def test_not_a_regular_file_rejected(self, tmp_path: Path) -> None:
        """A path that exists but is not a file is an error, not unset.

        A FIFO or device could otherwise block the config load.
        """
        with pytest.raises(FileRefError, match=r"^!file \S+: not a regular"):
            FileRef(str(tmp_path)).read()  # a directory
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(FileRefError, match="not a regular file"):
            FileRef(str(fifo)).read()

    def test_unreadable_file_rejected(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret"
        secret.write_text("x")
        with (
            patch.object(Path, "read_text", side_effect=PermissionError("no")),
            pytest.raises(FileRefError, match="cannot read: no"),
        ):
            FileRef(str(secret)).read()

    def test_inaccessible_parent_rejected(self, tmp_path: Path) -> None:
        """A directory the service cannot enter is an error, not unset."""
        with (
            patch.object(Path, "stat", side_effect=PermissionError("denied")),
            pytest.raises(FileRefError, match="cannot read: denied"),
        ):
            FileRef(str(tmp_path / "token")).read()

    def test_parent_not_a_directory_is_unset(self, tmp_path: Path) -> None:
        (tmp_path / "file").write_text("x")
        assert FileRef(str(tmp_path / "file" / "token")).read() is None

    def test_nul_byte_rejected(self) -> None:
        with pytest.raises(FileRefError, match="cannot read"):
            FileRef("/run/secrets/a\x00b").read()

    def test_vanishing_file_is_unset(self, tmp_path: Path) -> None:
        """A file removed between the checks and the read is unset."""
        secret = tmp_path / "secret"
        secret.write_text("x")
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            assert FileRef(str(secret)).read() is None

    def test_reads_utf8_regardless_of_locale(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret"
        secret.write_bytes("pässword".encode())
        assert FileRef(str(secret)).read() == "pässword"

    def test_non_utf8_rejected(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret"
        secret.write_bytes(b"\xff\xfe")
        with pytest.raises(FileRefError, match="cannot read"):
            FileRef(str(secret)).read()

    def test_raw_resolve(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret"
        secret.write_text("value\n")
        assert raw_resolve(FileRef(str(secret))) == "value"
        assert raw_resolve(FileRef(str(tmp_path / "missing"))) is None

    def test_env_loader_has_no_file_tag(self) -> None:
        """The shared loader does not read host files.

        The sandbox CLI uses it for repository-provided config.
        """
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.load("k: !file /etc/passwd\n", Loader=make_env_loader())
