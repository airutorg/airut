# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for partial boot success scenarios.

Tests the boot sequence behavior (gateway.py:_boot) when some repo
listeners fail to start while others succeed. This is distinct from
repo init failures (tested in test_repo_init_failures.py) — here the
repos initialize successfully but the listener start_listener() call
fails.

Scenarios:
1. One repo listener fails to start → service continues with remaining
2. Boot state correctly reflects partial success
3. Working repos continue to process messages
"""

import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import BootPhase, RepoStatus

from .conftest import MOCK_CONTAINER_COMMAND, get_message_text
from .environment import IntegrationEnvironment


def _poll_boot_phase(
    service,
    target_phase: BootPhase,
    timeout: float = 10.0,
    interval: float = 0.05,
) -> bool:
    """Poll until boot phase reaches or passes the target."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        phase = service._boot_store.get().value.phase
        if phase == target_phase:
            return True
        time.sleep(interval)
    return False


class TestPartialBootListenerFailure:
    """Test service boot when a repo listener fails to start."""

    def test_one_listener_fails_service_continues(
        self,
        tmp_path: Path,
        create_email,
    ) -> None:
        """Service boots successfully when one of two listeners fails.

        Scenario:
        1. Two repos configured (repo-a, repo-b)
        2. repo-a's listener start raises an exception
        3. repo-b's listener starts successfully
        4. Service reaches READY state
        5. repo-a is marked FAILED, repo-b is marked LIVE
        6. Messages to repo-b are processed normally

        Validates:
        - Partial boot failure doesn't crash the service
        - Boot phase reaches READY
        - Repo states accurately reflect success/failure
        - Working repos continue to accept messages
        """
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["repo-a", "repo-b"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            service = env.create_service()

            # Patch repo-a's listener to fail on start
            repo_a_handler = service.repo_handlers["repo-a"]

            def failing_start():
                raise ConnectionError(
                    "Simulated listener startup failure: "
                    "IMAP connection timed out"
                )

            repo_a_handler.start_listener = failing_start

            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            # Wait for boot to reach READY (polls every 50ms)
            booted = _poll_boot_phase(service, BootPhase.READY)
            assert booted, "Service did not reach READY boot phase"

            try:
                # Verify boot phase reached READY (not FAILED)
                boot_state = service._boot_store.get().value
                assert boot_state.phase == BootPhase.READY, (
                    f"Expected READY boot phase, got {boot_state.phase}"
                )

                # Verify repo states
                repo_states = {
                    r.repo_id: r for r in service._repos_store.get().value
                }
                assert len(repo_states) == 2

                # repo-a should be FAILED with error details
                assert repo_states["repo-a"].status == RepoStatus.FAILED
                assert repo_states["repo-a"].error_message is not None
                assert "listener" in (
                    repo_states["repo-a"].error_message.lower()
                ) or "connection" in (
                    repo_states["repo-a"].error_message.lower()
                )
                assert repo_states["repo-a"].error_type == "ConnectionError"

                # repo-b should be LIVE
                assert repo_states["repo-b"].status == RepoStatus.LIVE

                # Verify working repo still processes messages
                mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Partial boot response"),
    generate_result_event(session_id, "Done"),
]
"""
                msg = create_email(
                    subject="Partial boot test",
                    body=mock_code,
                    recipient="repo-b@test.local",
                )
                env.email_server.inject_message_to("repo-b", msg)

                response = env.email_server.wait_for_sent(
                    lambda m: "partial boot" in get_message_text(m).lower(),
                    timeout=15.0,
                )
                assert response is not None, (
                    "Working repo should still process messages after "
                    "partial boot failure"
                )

            finally:
                service.stop()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_all_listeners_fail_service_raises(
        self,
        tmp_path: Path,
    ) -> None:
        """Service raises RuntimeError when all listeners fail.

        Validates that when ALL repos fail to start their listeners,
        the boot sequence raises RuntimeError (consistent with the
        "all repos failed" check in _boot).
        """
        import pytest

        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["repo-x", "repo-y"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            service = env.create_service()

            # Patch both listeners to fail
            for repo_id in ["repo-x", "repo-y"]:
                handler = service.repo_handlers[repo_id]

                def make_failing():
                    def failing_start():
                        raise ConnectionError(
                            f"Simulated failure for {repo_id}"
                        )

                    return failing_start

                handler.start_listener = make_failing()

            with pytest.raises(RuntimeError, match="All 2 repo"):
                service.start()
        finally:
            env.cleanup()
