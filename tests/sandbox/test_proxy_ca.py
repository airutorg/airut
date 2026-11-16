# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/_proxy_ca.py -- mitmproxy CA generation."""

from __future__ import annotations

import fcntl
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import IO
from unittest.mock import patch

import pytest

from airut.sandbox._proxy_ca import (
    CA_CERT_FILENAME,
    CA_FILENAMES,
    CA_GENERATION_TIMEOUT,
    CaCertError,
    ensure_ca_cert,
)


IMAGE_TAG = "airut-proxy:test123"
CONTAINER_NAME = "airut-ca-init"


class FakeRuntime:
    """Fake container runtime standing in for ``subprocess.run``.

    ``run`` writes CA files into the host directory mounted into the
    container, as mitmproxy would, then exits with *returncode* or,
    with *hang*, times out.  ``rm`` succeeds.

    Attributes:
        calls: Every command run, with its keyword arguments.
    """

    def __init__(
        self,
        *,
        write: Sequence[str] = CA_FILENAMES,
        returncode: int = 0,
        stderr: str = "",
        hang: bool = False,
    ) -> None:
        self._write = write
        self._returncode = returncode
        self._stderr = stderr
        self._hang = hang
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(
        self, cmd: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((cmd, kwargs))
        if cmd[1] == "run":
            mount = cmd[cmd.index("-v") + 1]
            host_dir = Path(mount.split(":")[0])
            for name in self._write:
                (host_dir / name).write_text(f"new {name}")
            if self._hang:
                raise subprocess.TimeoutExpired(cmd, CA_GENERATION_TIMEOUT)
        return subprocess.CompletedProcess(
            cmd, self._returncode if cmd[1] == "run" else 0, "", self._stderr
        )

    def commands(self, verb: str) -> list[list[str]]:
        """Commands run with *verb* (``"run"`` or ``"rm"``), in order."""
        return [cmd for cmd, _ in self.calls if cmd[1] == verb]


def _ensure(confdir: Path, runtime: FakeRuntime) -> Path:
    """Call ensure_ca_cert() with *runtime* faking the container runtime."""
    with patch("airut.sandbox._proxy_ca.subprocess.run", runtime):
        return ensure_ca_cert(
            confdir,
            container_command="podman",
            image_tag=IMAGE_TAG,
            container_name=CONTAINER_NAME,
        )


def _write_ca(confdir: Path, content: str = "old") -> None:
    """Write a complete CA into *confdir*."""
    confdir.mkdir(parents=True, exist_ok=True)
    for name in CA_FILENAMES:
        (confdir / name).write_text(f"{content} {name}")


def _ca_files(confdir: Path) -> dict[str, str]:
    """CA files present in *confdir*, with their contents."""
    return {
        name: (confdir / name).read_text()
        for name in CA_FILENAMES
        if (confdir / name).exists()
    }


def _leftovers(confdir: Path) -> list[str]:
    """Entries in *confdir* other than CA files and the lock file."""
    return sorted(
        p.name
        for p in confdir.iterdir()
        if p.name not in CA_FILENAMES and p.name != ".airut-ca.lock"
    )


class TestReuse:
    """An existing complete CA is reused."""

    def test_complete_ca_is_reused(self, tmp_path: Path) -> None:
        """No container runs and the CA is left untouched."""
        _write_ca(tmp_path)
        runtime = FakeRuntime()

        result = _ensure(tmp_path, runtime)

        assert result == tmp_path / CA_CERT_FILENAME
        assert runtime.calls == []
        assert _ca_files(tmp_path) == {
            name: f"old {name}" for name in CA_FILENAMES
        }

    def test_ca_generated_while_waiting_for_lock_is_reused(
        self, tmp_path: Path
    ) -> None:
        """A CA another process finished while we waited is reused."""
        runtime = FakeRuntime()
        real_flock = fcntl.flock

        def flock(file: IO[str], operation: int) -> None:
            # The lock holder finishes generating before releasing it.
            if operation == fcntl.LOCK_EX:
                _write_ca(tmp_path, "concurrent")
            real_flock(file, operation)

        with patch("airut.sandbox._proxy_ca.fcntl.flock", flock):
            result = _ensure(tmp_path, runtime)

        assert result == tmp_path / CA_CERT_FILENAME
        assert runtime.calls == []
        assert _ca_files(tmp_path)[CA_CERT_FILENAME] == (
            f"concurrent {CA_CERT_FILENAME}"
        )


class TestGenerate:
    """A missing or incomplete CA is generated."""

    def test_generates_missing_ca(self, tmp_path: Path) -> None:
        """Every CA file is written, and nothing else is left behind."""
        confdir = tmp_path / "confdir"
        runtime = FakeRuntime()

        result = _ensure(confdir, runtime)

        assert result == confdir / CA_CERT_FILENAME
        assert _ca_files(confdir) == {
            name: f"new {name}" for name in CA_FILENAMES
        }
        assert _leftovers(confdir) == []

    def test_runs_mitmproxy_cert_store_to_completion(
        self, tmp_path: Path
    ) -> None:
        """The container runs CertStore.from_store() and must exit."""
        runtime = FakeRuntime()

        _ensure(tmp_path, runtime)

        [(cmd, kwargs)] = [c for c in runtime.calls if c[0][1] == "run"]
        assert cmd[:2] == ["podman", "run"]
        assert "--rm" in cmd
        assert cmd[cmd.index("--name") + 1] == CONTAINER_NAME
        assert cmd[cmd.index("--network") + 1] == "none"
        assert cmd[cmd.index("--entrypoint") + 1] == "python3"
        image_index = cmd.index(IMAGE_TAG)
        assert cmd[image_index + 1] == "-c"
        script = cmd[image_index + 2]
        assert "CertStore.from_store(" in script
        assert "CONF_BASENAME, KEY_SIZE" in script
        assert "os.fsync(" in script
        # The script's directory argument is the mounted staging dir.
        mount = cmd[cmd.index("-v") + 1]
        host_dir, container_dir, mode = mount.split(":")
        assert cmd[image_index + 3] == container_dir
        assert mode == "rw"
        assert Path(host_dir).parent == tmp_path
        assert kwargs["timeout"] == CA_GENERATION_TIMEOUT == 60.0

    def test_removes_stale_container_before_run(self, tmp_path: Path) -> None:
        """A container left by an interrupted generation is removed."""
        runtime = FakeRuntime()

        _ensure(tmp_path, runtime)

        verbs = [cmd[1] for cmd, _ in runtime.calls]
        assert verbs == ["rm", "run"]
        assert runtime.commands("rm") == [
            ["podman", "rm", "-f", CONTAINER_NAME]
        ]

    def test_replaces_partial_ca(self, tmp_path: Path) -> None:
        """A CA missing files is replaced by a new one, not mixed."""
        (tmp_path / CA_CERT_FILENAME).write_text("old cert")
        (tmp_path / "mitmproxy-ca.pem").write_text("old key")
        runtime = FakeRuntime()

        _ensure(tmp_path, runtime)

        assert _ca_files(tmp_path) == {
            name: f"new {name}" for name in CA_FILENAMES
        }

    def test_empty_file_makes_ca_incomplete(self, tmp_path: Path) -> None:
        """A CA with an empty file is regenerated."""
        _write_ca(tmp_path)
        (tmp_path / CA_CERT_FILENAME).write_text("")
        runtime = FakeRuntime()

        _ensure(tmp_path, runtime)

        assert _ca_files(tmp_path) == {
            name: f"new {name}" for name in CA_FILENAMES
        }

    def test_removes_stale_staging_dirs(self, tmp_path: Path) -> None:
        """Staging dirs left by an interrupted generation are removed."""
        stale = tmp_path / ".airut-ca-staging-old"
        stale.mkdir()
        (stale / CA_CERT_FILENAME).write_text("partial")

        _ensure(tmp_path, FakeRuntime())

        assert _leftovers(tmp_path) == []

    def test_installs_files_host_cannot_open(self, tmp_path: Path) -> None:
        """Root-owned 0600 files from a rootful runtime are installed.

        The host user cannot open such files, so the host must neither
        read nor fsync them: the container flushes them instead.
        """
        real_open = os.open
        staging_opens: list[str] = []

        def os_open(
            path: str | Path, flags: int, *args: int, **kwargs: int
        ) -> int:
            if Path(path).parent.name.startswith(".airut-ca-staging-"):
                staging_opens.append(str(path))
                raise PermissionError(13, "Permission denied", str(path))
            return real_open(path, flags, *args, **kwargs)

        with patch("airut.sandbox._proxy_ca.os.open", os_open):
            _ensure(tmp_path, FakeRuntime())

        assert staging_opens == []
        assert _ca_files(tmp_path) == {
            name: f"new {name}" for name in CA_FILENAMES
        }

    def test_preserves_file_modes(self, tmp_path: Path) -> None:
        """The private key keeps the restrictive mode mitmproxy gave it."""

        class PrivateKeyRuntime(FakeRuntime):
            def __call__(
                self, cmd: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                result = super().__call__(cmd, **kwargs)
                if cmd[1] == "run":
                    host_dir = Path(cmd[cmd.index("-v") + 1].split(":")[0])
                    (host_dir / "mitmproxy-ca.pem").chmod(0o600)
                return result

        _ensure(tmp_path, PrivateKeyRuntime())

        assert (tmp_path / "mitmproxy-ca.pem").stat().st_mode & 0o777 == 0o600


class TestGenerationFailure:
    """A failed generation leaves no partial CA behind."""

    def test_nonzero_exit_raises(self, tmp_path: Path) -> None:
        """A failing container raises with its exit status and stderr."""
        runtime = FakeRuntime(
            write=["mitmproxy-ca.pem"],
            returncode=1,
            stderr="Traceback ...\nModuleNotFoundError: mitmproxy\n",
        )

        with pytest.raises(
            CaCertError,
            match=r"exit status 1: Traceback .*\nModuleNotFoundError",
        ):
            _ensure(tmp_path, runtime)

        assert _ca_files(tmp_path) == {}
        assert _leftovers(tmp_path) == []

    def test_timeout_raises_and_removes_container(self, tmp_path: Path) -> None:
        """A container that does not exit in time is removed."""
        runtime = FakeRuntime(
            write=["mitmproxy-ca.pem", CA_CERT_FILENAME], hang=True
        )

        with pytest.raises(
            CaCertError,
            match=r"CA certificate generation did not finish within 60s",
        ):
            _ensure(tmp_path, runtime)

        verbs = [cmd[1] for cmd, _ in runtime.calls]
        assert verbs == ["rm", "run", "rm"]
        assert runtime.commands("rm")[-1] == [
            "podman",
            "rm",
            "-f",
            CONTAINER_NAME,
        ]
        assert _ca_files(tmp_path) == {}
        assert _leftovers(tmp_path) == []

    def test_missing_output_raises(self, tmp_path: Path) -> None:
        """A container that exits 0 without every file is a failure."""
        runtime = FakeRuntime(write=["mitmproxy-ca.pem", CA_CERT_FILENAME])

        with pytest.raises(
            CaCertError,
            match=(
                r"did not write mitmproxy-ca\.p12, mitmproxy-ca-cert\.cer, "
                r"mitmproxy-ca-cert\.p12, mitmproxy-dhparam\.pem$"
            ),
        ):
            _ensure(tmp_path, runtime)

        assert _ca_files(tmp_path) == {}
        assert _leftovers(tmp_path) == []

    def test_failure_leaves_partial_ca_untrusted(self, tmp_path: Path) -> None:
        """After a failure, a partial CA is still regenerated next start."""
        (tmp_path / CA_CERT_FILENAME).write_text("old cert")

        with pytest.raises(CaCertError):
            _ensure(tmp_path, FakeRuntime(returncode=1))
        runtime = FakeRuntime()
        _ensure(tmp_path, runtime)

        assert runtime.commands("run") != []
        assert _ca_files(tmp_path) == {
            name: f"new {name}" for name in CA_FILENAMES
        }
