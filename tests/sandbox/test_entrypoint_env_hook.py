# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the container entrypoint's environment hook."""

import shlex

import pytest

from airut.sandbox._entrypoint import FORCED_CLAUDE_ENV
from airut.sandbox._network import CA_ENV_VARS
from tests.sandbox.entrypoint_harness import FakeContainer


@pytest.mark.parametrize("variant", ["agent", "passthrough"])
class TestEnvHook:
    """Environment hook, run in bash against a fake container root."""

    def test_exports_reach_command(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Exported values reach the command intact, quoting and all."""
        value = "a b\"c$d`e\\f'g\nsecond line"
        container.write_hook(
            f"export FOO={shlex.quote(value)}\nexport PATH=/x:$PATH"
        )

        result = container.run(variant, "show", "FOO", "PATH")

        assert result.returncode == 0
        assert result.stdout == f"FOO={value}\nPATH=/x:{container.bin}\n"
        assert result.stderr == ""

    def test_unexported_variables_not_imported(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Only exported variables reach the command."""
        container.write_hook("FOO=local")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=<unset>\n"

    def test_output_goes_to_stderr(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Hook output never reaches the command's stdout."""
        container.write_hook("echo hello from hook")

        result = container.run(variant, "cat", stdin="prompt\n")

        assert result.stdout == "prompt\n"
        assert result.stderr == "hello from hook\n"

    def test_cannot_consume_stdin(
        self, container: FakeContainer, variant: str
    ) -> None:
        """The hook cannot read the command's stdin (the prompt)."""
        container.write_hook('read -r line; export GOT="${line:-none}"')

        result = container.run(variant, "show", "GOT", stdin="prompt\n")

        assert result.stdout == "GOT=none\n"

    def test_exit_trap_not_run_after_normal_return(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook's EXIT trap does not run when the hook returns.

        devShell hooks that start a service often stop it in an EXIT
        trap; the service must keep running for the command.
        """
        container.write_hook("export FOO=1; trap 'echo stopping' EXIT")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=1\n"
        assert result.stderr == ""

    def test_exit_trap_isolated_on_early_exit(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook's own EXIT trap cannot touch the command's I/O.

        The hook's trap replaces the snapshot trap, so its exports are
        lost, with a warning.
        """
        container.write_hook(
            "export FOO=1; trap 'echo stopping; read -r line' EXIT; exit 3"
        )

        result = container.run(variant, "cat", stdin="prompt\n")
        shown = container.run(variant, "show", "FOO")

        assert result.returncode == 0
        assert result.stdout == "prompt\n"
        assert result.stderr.startswith("stopping\n")
        assert "could not capture the environment" in shown.stderr
        assert shown.stdout == "FOO=<unset>\n"

    def test_xtrace_does_not_leak_environment(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook with set -x does not trace other variables' values."""
        container.write_hook("set -x; export FOO=1")

        result = container.run(
            variant, "show", "FOO", env={"SECRET_TOKEN": "ghp_hunter2"}
        )

        assert result.stdout == "FOO=1\n"
        assert "ghp_hunter2" not in result.stderr

    def test_works_without_compgen(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Bash built without readline (no compgen) still imports."""
        container.write_hook("enable -n compgen 2>/dev/null; export FOO=1")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=1\n"
        assert result.stderr == ""

    def test_truncated_snapshot_is_not_imported(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A snapshot cut short (e.g. disk full) only warns."""
        container.write_hook(
            "export AAA=$(printf 'x\\tx%.0s' {1..2000}); export FOO=1\n"
            "ulimit -f 1"
        )

        result = container.run(variant, "show", "FOO")

        assert result.returncode == 0
        assert result.stdout == "FOO=<unset>\n"
        assert "could not capture the environment" in result.stderr

    def test_exported_arrays_skipped(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Arrays are not imported (bash never exports them)."""
        container.write_hook("declare -ax ARR=(a b); export FOO=1")

        result = container.run(variant, "show", "ARR", "FOO")

        assert result.stdout == "ARR=<unset>\nFOO=1\n"

    def test_receives_no_arguments(
        self, container: FakeContainer, variant: str
    ) -> None:
        """The command's arguments are not the hook's positional params.

        Activation scripts (e.g. conda's) interpret their arguments.
        """
        container.write_hook('export ARGS="$#:$*"')

        result = container.run(variant, "show", "ARGS")

        assert result.stdout == "ARGS=0:\n"

    @pytest.mark.parametrize(
        ("body", "status"),
        [
            ("export FOO=1; exit 3", 3),
            ("set -u; export FOO=1; echo $UNDEFINED_VARIABLE", 1),
            ("set -e; export FOO=1; false; export FOO=2", 1),
            ("export FOO=1; false", 1),
        ],
        ids=["exit", "set-u", "set-e", "failing-last-command"],
    )
    def test_failure_warns_and_continues(
        self, container: FakeContainer, variant: str, body: str, status: int
    ) -> None:
        """A failing hook only warns; exports made so far still apply."""
        container.write_hook(body)

        result = container.run(variant, "show", "FOO")

        assert result.returncode == 0
        assert result.stdout == "FOO=1\n"
        assert (
            f"airut: warning: {container.hook} exited with status {status}"
            in result.stderr
        )

    def test_exec_in_hook_warns_and_continues(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook that replaces its shell cannot hijack the entrypoint."""
        container.write_hook("export FOO=1; exec cat")

        result = container.run(variant, "show", "FOO")

        assert result.returncode == 0
        assert result.stdout == "FOO=<unset>\n"
        assert "could not capture the environment" in result.stderr

    def test_replaced_path_does_not_break_startup(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Setup after the import uses no external commands.

        The hook's PATH need not contain anything the entrypoint uses.
        """
        container.write_hook(f"export PATH={shlex.quote(str(container.tools))}")
        container.add_tool("hello", "echo hello", directory=container.tools)

        result = container.run(variant, "hello")

        assert result.returncode == 0
        assert result.stdout == "hello\n"
        assert result.stderr == ""
        assert list(container.tmp.iterdir()) == []

    def test_cd_does_not_change_working_directory(
        self, container: FakeContainer, variant: str
    ) -> None:
        """The command runs, and sees PWD, in the original directory."""
        container.write_hook("cd /")

        result = container.run(variant, "printenv", "PWD")
        oldpwd = container.run(variant, "printenv", "OLDPWD")

        assert result.stdout == f"{container.workdir}\n"
        assert oldpwd.stdout == ""

    def test_cannot_override_sandbox_settings(
        self, container: FakeContainer, variant: str
    ) -> None:
        """IS_SANDBOX and the proxy CA variables are re-applied.

        A Nix devShell that includes cacert resets NIX_SSL_CERT_FILE,
        which would break TLS through the proxy.  Even readonly
        declarations cannot pin the hook's values.
        """
        container.ca.write_text("PROXY\n")
        container.write_hook(
            "declare -rx IS_SANDBOX=0\n"
            + "".join(
                f"declare -rx {var}=/nix/store/cacert\n" for var in CA_ENV_VARS
            )
        )

        result = container.run(variant, "show", "IS_SANDBOX", *CA_ENV_VARS)

        assert result.returncode == 0
        assert result.stdout == "IS_SANDBOX=1\n" + "".join(
            f"{var}={container.ca}\n" for var in CA_ENV_VARS
        )
        assert result.stderr == ""

    def test_entrypoint_variables_not_leaked(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook with set -a does not export the entrypoint's variables."""
        container.write_hook("set -a; FOO=1")

        result = container.run(variant, "printenv")

        assert "FOO=1\n" in result.stdout
        assert "airut_" not in result.stdout

    def test_debug_trap_cannot_corrupt_snapshot(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A hook's inherited DEBUG trap does not write into the snapshot."""
        container.write_hook("set -T; trap 'echo dbg' DEBUG; export FOO=1")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=1\n"
        assert "warning" not in result.stderr

    def test_namerefs_skipped(
        self, container: FakeContainer, variant: str
    ) -> None:
        """A nameref is not imported as a copy of its target."""
        container.write_hook("export FOO=1; declare -n REF=FOO")

        result = container.run(variant, "show", "REF", "FOO")

        assert result.stdout == "REF=<unset>\nFOO=1\n"

    def test_ca_variables_kept_without_proxy(
        self, container: FakeContainer, variant: str
    ) -> None:
        """Without the network sandbox, the hook's CA settings stand."""
        container.write_hook("export NIX_SSL_CERT_FILE=/nix/store/cacert")

        result = container.run(variant, "show", "NIX_SSL_CERT_FILE")

        assert result.stdout == "NIX_SSL_CERT_FILE=/nix/store/cacert\n"

    def test_exporting_shell_readonly_variable_is_quiet(
        self, container: FakeContainer, variant: str
    ) -> None:
        """``export UID`` (a docker compose idiom) causes no noise."""
        container.write_hook("export UID; export FOO=1")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=1\n"
        assert result.stderr == ""

    def test_runs_after_ca_trust(
        self, container: FakeContainer, variant: str
    ) -> None:
        """The hook sees the proxy CA already trusted (it may fetch)."""
        container.ca.write_text("PROXY\n")
        bundle = shlex.quote(str(container.bundle))
        container.write_hook(f'export SEEN="$(cat {bundle})"')

        result = container.run(variant, "show", "SEEN")

        assert result.stdout == "SEEN=\nPROXY\n"

    def test_leaves_no_temporary_files(
        self, container: FakeContainer, variant: str
    ) -> None:
        """The environment snapshot is removed after import."""
        container.write_hook("export FOO=1")

        result = container.run(variant, "show", "FOO")

        assert result.stdout == "FOO=1\n"
        assert list(container.tmp.iterdir()) == []

    @pytest.mark.parametrize("tmpdir", ["missing", "relative"])
    def test_unusable_tmpdir_falls_back_to_tmp(
        self, container: FakeContainer, variant: str, tmpdir: str
    ) -> None:
        """A missing or relative TMPDIR does not lose the environment."""
        container.write_hook("cd /; export FOO=1")
        value = str(container.root / "missing") if tmpdir == "missing" else "."

        result = container.run(variant, "show", "FOO", env={"TMPDIR": value})

        assert result.stdout == "FOO=1\n"
        assert result.stderr == ""


class TestEnvHookAgentOnly:
    """Agent-specific re-applied settings."""

    def test_cannot_override_forced_claude_settings(
        self, container: FakeContainer
    ) -> None:
        """Settings Airut forces for Claude win over the hook."""
        container.write_hook(
            "".join(f"export {name}=hook\n" for name in FORCED_CLAUDE_ENV)
        )

        result = container.run("agent", "show", *FORCED_CLAUDE_ENV)

        assert result.stdout == "".join(
            f"{name}={value}\n" for name, value in FORCED_CLAUDE_ENV.items()
        )
