# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for the repo image build context.

The container directory is read from the git mirror's default branch.
Symlinks in it (e.g. to a flake at the repository root) and
subdirectories must reach the image build context with the content of
their targets; symlinks leaving the repository must fail the task with
an explanatory error.
"""

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from email.message import Message
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


_MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Built"),
    generate_result_event(session_id, "Done"),
]
"""


def _commit(repo: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)


def _repo_build_contexts() -> list[dict[str, dict[str, object]]]:
    """Return the recorded build contexts of repo images."""
    builds = Path(os.environ["MOCK_PODMAN_STATE_DIR"]) / "builds"
    return [
        json.loads(record.read_text())
        for record in sorted(builds.glob("*-repo_*.json"))
    ]


def _run_one_message(
    integration_env: IntegrationEnvironment,
    create_email,
    predicate: Callable[[Message], bool],
) -> Message | None:
    integration_env.email_server.inject_message(
        create_email(subject="Build context", body=_MOCK_CODE)
    )
    service = integration_env.create_service()
    thread = threading.Thread(target=service.start, daemon=True)
    thread.start()
    try:
        return integration_env.email_server.wait_for_sent(
            predicate, timeout=30.0
        )
    finally:
        service.stop()
        thread.join(timeout=10.0)


class TestBuildContext:
    """Repo image build context from the git mirror."""

    def test_symlinks_and_subdirectories_reach_build(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Linked flake files and directories are built with their targets."""
        repo = integration_env.master_repo
        container = repo / ".airut" / "container"
        (repo / "flake.nix").write_text("{ outputs = _: { }; }\n")
        (repo / "flake.lock").write_text('{"version": 7}\n')
        (repo / "nix").mkdir()
        (repo / "nix" / "shell.nix").write_text("{ pkgs }: pkgs.mkShell { }\n")
        (container / "flake.nix").symlink_to("../../flake.nix")
        (container / "flake.lock").symlink_to("../../flake.lock")
        (container / "nix").symlink_to("../../nix")
        script = container / "bin" / "setup.sh"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        _commit(repo, "Build the image from the flake")

        response = _run_one_message(
            integration_env,
            create_email,
            lambda m: "Built" in get_message_text(m),
        )

        assert response is not None
        contexts = _repo_build_contexts()
        assert contexts, "repo image was not built"
        context = contexts[-1]
        assert context["flake.nix"]["content"] == "{ outputs = _: { }; }\n"
        assert context["flake.lock"]["content"] == '{"version": 7}\n'
        assert context["nix/shell.nix"]["content"] == (
            "{ pkgs }: pkgs.mkShell { }\n"
        )
        assert context["bin/setup.sh"]["executable"] is True
        assert context["flake.nix"]["executable"] is False

    def test_symlink_outside_repository_fails_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """A symlink leaving the repository is reported, not followed."""
        repo = integration_env.master_repo
        link = repo / ".airut" / "container" / "secret"
        link.symlink_to("../../../outside")
        _commit(repo, "Add escaping symlink")

        response = _run_one_message(
            integration_env,
            create_email,
            lambda m: "outside the repository" in get_message_text(m),
        )

        assert response is not None, "expected a build context error reply"
        assert _repo_build_contexts() == []
