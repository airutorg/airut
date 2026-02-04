# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for multi-repo support.

Tests that multiple repositories with independent IMAP listeners correctly:
1. Route messages to the correct repo handler
2. Share the global executor pool
3. Maintain isolated storage per repo
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import MOCK_CONTAINER_COMMAND, get_message_text
from .environment import IntegrationEnvironment


# Timeout for waiting on responses from mock_claude.  Kept short since
# mock_claude replies instantly; the only real latency is IMAP polling
# (1 s interval) + git clone + container startup simulation.
_TIMEOUT = 15.0


def _start_service(env: IntegrationEnvironment):
    """Create and start a service in a daemon thread.

    Returns:
        Tuple of (service, thread).
    """
    service = env.create_service()
    thread = threading.Thread(target=service.start, daemon=True)
    thread.start()
    return service, thread


def _stop_service(service, thread) -> None:
    """Stop a running service and join the thread."""
    service.running = False
    for handler in service.repo_handlers.values():
        handler.listener.interrupt()
    thread.join(timeout=10.0)


class TestMultiRepoRouting:
    """Test message routing across multiple repos."""

    def test_messages_route_to_correct_repo(
        self,
        tmp_path: Path,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Messages route to correct repo based on IMAP inbox.

        Verifies that messages injected into different inboxes are handled
        by the correct repo handler, producing responses from the right
        email address and storing sessions in the right storage directory.
        """
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["alpha", "beta"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Alpha response"),
    generate_result_event(session_id, "Done"),
]
"""
            msg_alpha = create_email(
                subject="Alpha task",
                body=mock_code,
                recipient="alpha@test.local",
            )
            env.email_server.inject_message_to("alpha", msg_alpha)

            service, thread = _start_service(env)

            try:
                response = env.email_server.wait_for_sent(
                    lambda m: "alpha response" in get_message_text(m).lower(),
                    timeout=_TIMEOUT,
                )
                assert response is not None, "No response for alpha task"

                # Response should come from alpha's email address
                assert "alpha@test.local" in response["From"]

                # Verify storage isolation
                conv_id = extract_conversation_id(response["Subject"])
                assert conv_id is not None
                alpha_session = env.storage_dir / "alpha" / "sessions" / conv_id
                assert alpha_session.exists(), (
                    f"Session not in alpha storage: {alpha_session}"
                )

                beta_sessions = env.storage_dir / "beta" / "sessions"
                if beta_sessions.exists():
                    assert not list(beta_sessions.iterdir()), (
                        "Beta storage should be empty"
                    )

            finally:
                _stop_service(service, thread)
        finally:
            env.cleanup()

    def test_both_repos_process_concurrently(
        self,
        tmp_path: Path,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Both repos process messages concurrently.

        Verifies that messages sent to both repos are processed, both
        listeners are active, and the shared executor pool handles work
        from multiple repos.
        """
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["repo-a", "repo-b"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            mock_code_a = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Response from A"),
    generate_result_event(session_id, "Done"),
]
"""
            mock_code_b = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Response from B"),
    generate_result_event(session_id, "Done"),
]
"""
            msg_a = create_email(
                subject="Task for repo A",
                body=mock_code_a,
                recipient="repo-a@test.local",
                message_id="<msg-a@test.local>",
            )
            msg_b = create_email(
                subject="Task for repo B",
                body=mock_code_b,
                recipient="repo-b@test.local",
                message_id="<msg-b@test.local>",
            )

            env.email_server.inject_message_to("repo-a", msg_a)
            env.email_server.inject_message_to("repo-b", msg_b)

            service, thread = _start_service(env)

            try:
                # Wait for each response using wait_for_sent with
                # predicates.  The two calls are sequential but each
                # blocks only until its predicate matches, so total
                # wall-time is bounded by the slower repo.
                resp_a = env.email_server.wait_for_sent(
                    lambda m: "response from a" in get_message_text(m).lower(),
                    timeout=_TIMEOUT,
                )
                resp_b = env.email_server.wait_for_sent(
                    lambda m: "response from b" in get_message_text(m).lower(),
                    timeout=_TIMEOUT,
                )

                assert resp_a is not None, (
                    "Did not receive response from repo-a"
                )
                assert resp_b is not None, (
                    "Did not receive response from repo-b"
                )

                # Verify sessions in correct storage dirs
                a_sessions = env.storage_dir / "repo-a" / "sessions"
                b_sessions = env.storage_dir / "repo-b" / "sessions"
                assert a_sessions.exists() and list(a_sessions.iterdir()), (
                    "repo-a should have sessions"
                )
                assert b_sessions.exists() and list(b_sessions.iterdir()), (
                    "repo-b should have sessions"
                )

            finally:
                _stop_service(service, thread)
        finally:
            env.cleanup()

    def test_dashboard_tracks_repo_id(
        self,
        tmp_path: Path,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Tasks are tagged with the correct repo_id in the tracker."""
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["main-repo", "side-repo"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Tracked response"),
    generate_result_event(session_id, "Done"),
]
"""
            msg = create_email(
                subject="Track this task",
                body=mock_code,
                recipient="main-repo@test.local",
            )
            env.email_server.inject_message_to("main-repo", msg)

            service, thread = _start_service(env)

            try:
                response = env.email_server.wait_for_sent(
                    lambda m: "tracked response" in get_message_text(m).lower(),
                    timeout=_TIMEOUT,
                )
                assert response is not None

                conv_id = extract_conversation_id(response["Subject"])
                assert conv_id is not None

                # By the time we have the result email, the task should
                # already be completed in the tracker (send happens
                # before task completion callback).  Use wait_for_sent's
                # guarantee that the response was already sent as a
                # synchronization point instead of polling.
                task = service.tracker.get_task(conv_id)
                assert task is not None, f"Task {conv_id} not found in tracker"
                assert task.repo_id == "main-repo"

            finally:
                _stop_service(service, thread)
        finally:
            env.cleanup()
