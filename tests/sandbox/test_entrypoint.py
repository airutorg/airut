# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_entrypoint.py -- container entrypoint generation."""

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from airut.sandbox._entrypoint import (
    AGENT_ENTRYPOINT_SCRIPT,
    PASSTHROUGH_ENTRYPOINT_SCRIPT,
    SYSTEM_CA_BUNDLE,
    get_entrypoint_content,
)
from airut.sandbox._network import CA_CONTAINER_PATH
from airut.sandbox.claude_binary import CLAUDE_BINARY_CONTAINER_PATH


class TestGetEntrypointContent:
    """Tests for get_entrypoint_content function."""

    def test_agent_matches_script_constant(self) -> None:
        """Default variant is the agent entrypoint, UTF-8 encoded."""
        content = get_entrypoint_content()
        assert content == AGENT_ENTRYPOINT_SCRIPT.encode("utf-8")

    def test_passthrough_matches_script_constant(self) -> None:
        """passthrough=True returns the passthrough entrypoint."""
        content = get_entrypoint_content(passthrough=True)
        assert content == PASSTHROUGH_ENTRYPOINT_SCRIPT.encode("utf-8")

    def test_variants_differ(self) -> None:
        """Variants differ, so they get different overlay image tags."""
        assert get_entrypoint_content() != get_entrypoint_content(
            passthrough=True
        )

    @pytest.mark.parametrize("passthrough", [False, True])
    def test_strict_bash_script(self, passthrough: bool) -> None:
        """Both variants are bash scripts with strict error handling."""
        content = get_entrypoint_content(passthrough=passthrough)
        assert content.startswith(b"#!/usr/bin/env bash\nset -euo pipefail\n")


# -- Behaviour tests: run the generated script in bash ----------------------

_BASH = shutil.which("bash")

# Tools the entrypoint needs from PATH, plus ``cat`` for test commands.
# ``update-ca-certificates`` is deliberately absent unless a test adds it.
_TOOLS = ("cat", "mkdir", "mv")

_SCRIPTS = {
    "agent": AGENT_ENTRYPOINT_SCRIPT,
    "passthrough": PASSTHROUGH_ENTRYPOINT_SCRIPT,
}


class _Container:
    """Fake container root for running an entrypoint on the host.

    Rewrites the container paths in the script to locations under
    *root*.  The agent variant's Claude binary is replaced by a stub
    that runs its arguments, so both variants can run the same test
    command.
    """

    def __init__(self, root: Path) -> None:
        assert _BASH is not None, "bash not found on host"
        self.root = root
        self.ca = root / "ca.crt"
        self.bundle = root / "etc" / "ssl" / "certs" / "ca-certificates.crt"
        self.bin = root / "bin"
        self.bin.mkdir()
        for tool in _TOOLS:
            path = shutil.which(tool)
            assert path is not None, f"{tool} not found on host"
            (self.bin / tool).symlink_to(path)
        claude = root / "claude"
        claude.write_text(f'#!{_BASH}\nexec "$@"\n')
        claude.chmod(0o755)

    def add_tool(self, name: str, body: str) -> None:
        """Add an executable shell script to the container PATH."""
        tool = self.bin / name
        tool.write_text(f"#!{_BASH}\n{body}\n")
        tool.chmod(0o755)

    def run(
        self,
        variant: str,
        *command: str,
        env: dict[str, str] | None = None,
        stdin: str = "",
    ) -> subprocess.CompletedProcess[str]:
        """Run the entrypoint *variant* with *command* as arguments."""
        assert _BASH is not None
        script = (
            _SCRIPTS[variant]
            .replace(CA_CONTAINER_PATH, str(self.ca))
            .replace(SYSTEM_CA_BUNDLE, str(self.bundle))
            .replace(CLAUDE_BINARY_CONTAINER_PATH, str(self.root / "claude"))
        )
        script_path = self.root / "entrypoint.sh"
        script_path.write_text(script)
        return subprocess.run(
            [_BASH, str(script_path), *command],
            env={"PATH": str(self.bin), **(env or {})},
            input=stdin,
            capture_output=True,
            text=True,
            timeout=30,
        )


@pytest.fixture
def container(tmp_path: Path) -> _Container:
    """Fake container root under a temporary directory."""
    return _Container(tmp_path)


@pytest.mark.parametrize("variant", ["agent", "passthrough"])
class TestCaTrust:
    """CA trust setup, run in bash against a fake container root."""

    def test_no_proxy_ca_skips_setup(
        self, container: _Container, variant: str
    ) -> None:
        """Without a mounted proxy CA, CA setup does nothing."""
        container.bundle.parent.mkdir(parents=True)
        container.bundle.write_text("SYSTEM\n")
        marker = container.root / "updated"
        container.add_tool(
            "update-ca-certificates", f"touch {shlex.quote(str(marker))}"
        )

        result = container.run(variant, "cat", str(container.bundle))

        assert result.returncode == 0
        assert result.stdout == "SYSTEM\n"
        assert result.stderr == ""
        assert not marker.exists()

    def test_runs_update_ca_certificates_when_available(
        self, container: _Container, variant: str
    ) -> None:
        """Debian-style images use update-ca-certificates."""
        container.ca.write_text("PROXY\n")
        marker = container.root / "updated"
        container.add_tool(
            "update-ca-certificates", f"echo ran > {shlex.quote(str(marker))}"
        )

        result = container.run(variant, "cat", str(marker))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "ran\n"
        assert not container.bundle.exists()

    def test_appends_ca_to_bundle_without_update_tool(
        self, container: _Container, variant: str
    ) -> None:
        """Without update-ca-certificates, the CA is appended directly."""
        container.ca.write_text("PROXY\n")
        container.bundle.parent.mkdir(parents=True)
        container.bundle.write_text("SYSTEM\n")

        result = container.run(variant, "cat", str(container.bundle))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "SYSTEM\n\nPROXY\n"

    def test_replaces_symlinked_bundle(
        self, container: _Container, variant: str
    ) -> None:
        """A bundle symlink is replaced, not written through.

        Nix images link the bundle into /nix/store; writing through the
        link would modify the store path.
        """
        container.ca.write_text("PROXY\n")
        store_bundle = container.root / "store" / "ca-bundle.crt"
        store_bundle.parent.mkdir()
        store_bundle.write_text("STORE\n")
        container.bundle.parent.mkdir(parents=True)
        container.bundle.symlink_to(store_bundle)

        result = container.run(variant, "cat", str(container.bundle))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "STORE\n\nPROXY\n"
        assert not container.bundle.is_symlink()
        assert store_bundle.read_text() == "STORE\n"

    def test_creates_bundle_when_missing(
        self, container: _Container, variant: str
    ) -> None:
        """Images without any system bundle get one with the proxy CA."""
        container.ca.write_text("PROXY\n")

        result = container.run(variant, "cat", str(container.bundle))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "\nPROXY\n"

    def test_bundle_failure_is_not_fatal(
        self, container: _Container, variant: str
    ) -> None:
        """A bundle that cannot be written does not stop the command."""
        container.ca.write_text("PROXY\n")
        # A file where the bundle directory should be makes mkdir fail.
        (container.root / "etc").write_text("not a directory")

        result = container.run(variant, "cat", str(container.ca))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "PROXY\n"

    def test_update_tool_failure_is_not_fatal(
        self, container: _Container, variant: str
    ) -> None:
        """A failing update-ca-certificates does not stop the command."""
        container.ca.write_text("PROXY\n")
        container.add_tool(
            "update-ca-certificates", "echo out; echo err >&2; exit 1"
        )

        result = container.run(variant, "cat", str(container.ca))

        assert result.returncode == 0
        assert result.stdout == "PROXY\n"
        assert result.stderr == ""

    def test_setup_does_not_consume_stdin(
        self, container: _Container, variant: str
    ) -> None:
        """Setup steps cannot read the command's stdin (the prompt)."""
        container.ca.write_text("PROXY\n")
        container.add_tool("update-ca-certificates", "cat >/dev/null")

        result = container.run(variant, "cat", stdin="prompt\n")

        assert result.returncode == 0
        assert result.stdout == "prompt\n"

    def test_setup_silent_by_default(
        self, container: _Container, variant: str
    ) -> None:
        """Setup output never reaches the command's stdout or stderr."""
        container.ca.write_text("PROXY\n")
        container.add_tool("update-ca-certificates", "echo out; echo err >&2")

        result = container.run(variant, "cat", str(container.ca))

        assert result.stdout == "PROXY\n"
        assert result.stderr == ""

    def test_verbose_logs_setup_to_stderr(
        self, container: _Container, variant: str
    ) -> None:
        """AIRUT_VERBOSE=1 shows setup output on stderr only."""
        container.ca.write_text("PROXY\n")

        result = container.run(
            variant,
            "cat",
            str(container.ca),
            env={"AIRUT_VERBOSE": "1"},
        )

        assert result.stdout == "PROXY\n"
        assert f"Added proxy CA to {container.bundle}" in result.stderr


class TestExec:
    """Final exec step, run in bash against a fake container root."""

    def test_agent_runs_claude_with_arguments(
        self, container: _Container
    ) -> None:
        """The agent entrypoint passes all arguments to Claude."""
        claude = container.root / "claude"
        claude.write_text(f'#!{_BASH}\necho "claude: $*"\n')

        result = container.run("agent", "--model", "opus")

        assert result.returncode == 0
        assert result.stdout == "claude: --model opus\n"

    def test_passthrough_runs_command(self, container: _Container) -> None:
        """The passthrough entrypoint runs its arguments as a command."""
        container.ca.write_text("PROXY\n")

        result = container.run("passthrough", "cat", str(container.ca))

        assert result.returncode == 0
        assert result.stdout == "PROXY\n"

    def test_is_sandbox_exported(self, container: _Container) -> None:
        """IS_SANDBOX=1 reaches the command's environment."""
        container.add_tool("show-env", 'echo "IS_SANDBOX=$IS_SANDBOX"')

        result = container.run("passthrough", "show-env")

        assert result.stdout == "IS_SANDBOX=1\n"
