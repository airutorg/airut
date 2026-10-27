# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/_entrypoint.py -- container entrypoint generation."""

import shlex

import pytest

from airut.sandbox._entrypoint import (
    AGENT_ENTRYPOINT_SCRIPT,
    PASSTHROUGH_ENTRYPOINT_SCRIPT,
    get_entrypoint_content,
)
from tests.sandbox.entrypoint_harness import (
    BASH,
    FakeContainer,
    write_binary_without_loader,
)


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


@pytest.mark.parametrize("variant", ["agent", "passthrough"])
class TestCaTrust:
    """CA trust setup, run in bash against a fake container root."""

    def test_no_proxy_ca_skips_setup(
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
    ) -> None:
        """Images without any system bundle get one with the proxy CA."""
        container.ca.write_text("PROXY\n")

        result = container.run(variant, "cat", str(container.bundle))

        assert result.returncode == 0
        assert result.stderr == ""
        assert result.stdout == "\nPROXY\n"

    def test_bundle_failure_is_not_fatal(
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer, variant: str
    ) -> None:
        """Setup steps cannot read the command's stdin (the prompt)."""
        container.ca.write_text("PROXY\n")
        container.add_tool("update-ca-certificates", "cat >/dev/null")

        result = container.run(variant, "cat", stdin="prompt\n")

        assert result.returncode == 0
        assert result.stdout == "prompt\n"

    def test_setup_silent_by_default(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Setup output never reaches the command's stdout or stderr."""
        container.ca.write_text("PROXY\n")
        container.add_tool("update-ca-certificates", "echo out; echo err >&2")

        result = container.run(variant, "cat", str(container.ca))

        assert result.stdout == "PROXY\n"
        assert result.stderr == ""

    def test_verbose_logs_setup_to_stderr(
        self, container: FakeContainer, variant: str
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
        self, container: FakeContainer
    ) -> None:
        """The agent entrypoint passes all arguments to Claude."""
        claude = container.root / "claude"
        claude.write_text(f'#!{BASH}\necho "claude: $*"\n')

        result = container.run("agent", "--model", "opus")

        assert result.returncode == 0
        assert result.stdout == "claude: --model opus\n"

    def test_agent_explains_missing_loader(
        self, container: FakeContainer
    ) -> None:
        """A binary whose loader is missing gets an explanation."""
        claude = container.root / "claude"
        write_binary_without_loader(claude)

        result = container.run("agent", "--model", "opus")

        assert result.returncode == 127
        assert f"airut: cannot execute {claude} (status 127)" in result.stderr
        assert "lacks the dynamic loader" in result.stderr
        assert "/lib64/ld-linux-x86-64.so.2" in result.stderr
        assert result.stdout == ""

    def test_agent_missing_binary_has_no_loader_hint(
        self, container: FakeContainer
    ) -> None:
        """A missing binary is reported without the loader hint."""
        claude = container.root / "claude"
        claude.unlink()

        result = container.run("agent")

        assert result.returncode == 127
        assert f"airut: cannot execute {claude} (status 127)" in result.stderr
        assert "dynamic loader" not in result.stderr

    def test_agent_non_executable_binary(
        self, container: FakeContainer
    ) -> None:
        """A binary without execute permission reports status 126."""
        claude = container.root / "claude"
        claude.chmod(0o644)

        result = container.run("agent")

        assert result.returncode == 126
        assert f"airut: cannot execute {claude} (status 126)" in result.stderr
        assert "dynamic loader" not in result.stderr

    def test_passthrough_runs_command(self, container: FakeContainer) -> None:
        """The passthrough entrypoint runs its arguments as a command."""
        container.ca.write_text("PROXY\n")

        result = container.run("passthrough", "cat", str(container.ca))

        assert result.returncode == 0
        assert result.stdout == "PROXY\n"

    def test_is_sandbox_exported(self, container: FakeContainer) -> None:
        """IS_SANDBOX=1 reaches the command's environment."""
        container.add_tool("show-env", 'echo "IS_SANDBOX=$IS_SANDBOX"')

        result = container.run("passthrough", "show-env")

        assert result.stdout == "IS_SANDBOX=1\n"
