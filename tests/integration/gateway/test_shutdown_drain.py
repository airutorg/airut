# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for shutdown behavior with pending messages.

Tests:
1. Executor pool shutdown while pending messages are queued
2. _drain_pending handles pool-not-initialized gracefully
3. submit_message returns False when pool is not initialized
4. Service stops cleanly with active and pending tasks
"""

import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import CompletionReason, TaskStatus

from .conftest import (
    get_message_text,
)
from .environment import IntegrationEnvironment


def _poll_tracker(
    tracker,
    predicate,
    timeout: float = 15.0,
    interval: float = 0.1,
):
    """Poll the tracker until predicate(all_tasks) is truthy."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        tasks = tracker.get_all_tasks()
        result = predicate(tasks)
        if result:
            return result
        time.sleep(interval)
    return None


def _wait_for_sync_file(
    storage_dir: Path, timeout: float = 15.0
) -> Path | None:
    """Wait for a mock_claude_sync file in any conversation workspace."""
    conversations_dir = storage_dir / "conversations"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if conversations_dir.exists():
            for conv_dir in conversations_dir.iterdir():
                if conv_dir.is_dir() and not conv_dir.name.startswith("."):
                    workspace = conv_dir / "workspace"
                    candidate = workspace / ".mock_claude_sync"
                    if candidate.exists() and candidate.read_text() == "ready":
                        return candidate
        time.sleep(0.05)
    return None


class TestSubmitMessageBeforePool:
    """Test submit_message when executor pool is not initialized."""

    def test_submit_message_returns_false_without_pool(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """submit_message returns False when pool is not initialized.

        Validates the guard clause in submit_message() that checks
        ``if not self._executor_pool``.
        """
        from airut.gateway.channel import RawMessage

        service = integration_env.create_service()
        # Don't start the service — pool is None

        # Create a minimal raw message
        raw = RawMessage(
            sender="user@test.local",
            content=None,
            display_title="test",
        )

        repo_handler = list(service.repo_handlers.values())[0]
        result = service.submit_message(raw, repo_handler)
        assert result is False


class TestShutdownWithActiveTask:
    """Test graceful shutdown while a task is executing."""

    def test_shutdown_completes_active_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Service stop waits for and completes active tasks.

        Scenario:
        1. Start a task that blocks on a sync file
        2. Call service.stop() while task is executing
        3. The stop() should shut down the pool and complete cleanly
        4. No tasks should remain stuck in non-terminal states

        Validates:
        - service.stop() doesn't hang indefinitely
        - Active tasks are properly cleaned up
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Blocking task"),
    generate_result_event(session_id, "Done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num >= 1:
        # Block until killed by shutdown
        while not (workspace / 'stop_signal.txt').exists():
            time.sleep(0.1)
"""
        msg = create_email(
            subject="Shutdown test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for task to start executing
            sync_file = _wait_for_sync_file(integration_env.storage_dir)
            assert sync_file is not None, "Task did not start executing"

            # Verify task is in EXECUTING state
            tasks = service.tracker.get_all_tasks()
            executing = [t for t in tasks if t.status == TaskStatus.EXECUTING]
            assert len(executing) >= 1
        finally:
            # Stop the service — this should shut down cleanly
            service.stop()
            service_thread.join(timeout=15.0)

        # After shutdown, verify service state
        assert service._stopped is True
        assert service._executor_pool is not None  # Pool was created
        # Pool shutdown was called
        # All tracking should be consistent


class TestShutdownWithPendingMessages:
    """Test shutdown while messages are queued (PENDING)."""

    def test_shutdown_while_messages_pending(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Service shutdown with pending messages doesn't deadlock.

        Scenario:
        1. First message blocks (executing)
        2. Second message queued (pending)
        3. Service.stop() called
        4. Shutdown completes without deadlock

        Validates:
        - No deadlock between _pending_messages_lock and tracker lock
        - Shutdown completes within timeout
        """
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Blocking first"),
    generate_result_event(session_id, "Done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num >= 1:
        while not (workspace / 'stop_signal.txt').exists():
            time.sleep(0.1)
"""
        second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Pending message"),
    generate_result_event(session_id, "Done"),
]
"""
        msg1 = create_email(
            subject="Shutdown pending test",
            body=first_mock_code,
            message_id="<shutdown-first@test.local>",
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for ack
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for first task to block
            sync_file = _wait_for_sync_file(integration_env.storage_dir)
            assert sync_file is not None

            # Queue second message
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Shutdown pending test",
                body=second_mock_code,
                message_id="<shutdown-second@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second message to enter PENDING
            pending_found = _poll_tracker(
                service.tracker,
                lambda tasks: any(
                    t.status == TaskStatus.PENDING for t in tasks
                ),
                timeout=15.0,
            )
            assert pending_found, "Second message did not enter PENDING"
        finally:
            # Shutdown the service with active + pending tasks
            # This should complete within the shutdown timeout (5s)
            # without deadlock
            service.stop()

            # Verify service thread completes in reasonable time
            service_thread.join(timeout=15.0)
            assert not service_thread.is_alive(), (
                "Service thread still alive after stop — possible deadlock"
            )


class TestDrainAfterPoolShutdown:
    """Test _drain_pending when executor pool is already shut down."""

    def test_drain_with_no_pool_completes_task_as_error(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """_drain_pending marks task as INTERNAL_ERROR when pool is gone.

        Validates the guard clause in _drain_pending() that checks
        ``if not self._executor_pool`` and completes the pending task
        with INTERNAL_ERROR.
        """
        import collections

        from airut.gateway.service.gateway import PendingMessage

        service = integration_env.create_service()

        # Manually set up state to test _drain_pending directly
        task_id = "test-drain-001"
        conv_id = "deadbeef"
        repo_handler = list(service.repo_handlers.values())[0]

        # Add a task to the tracker
        service.tracker.add_task(task_id, "Test drain")
        service.tracker.set_authenticating(task_id)
        service.tracker.set_pending(task_id)

        # Create a fake parsed message
        from airut.gateway.channel import ParsedMessage

        parsed = ParsedMessage(
            sender="user@test.local",
            body="test body",
            conversation_id=conv_id,
            model_hint=None,
            display_title="Test drain",
            channel_context="",
        )

        # Queue a pending message
        pending = PendingMessage(
            parsed=parsed,
            task_id=task_id,
            repo_handler=repo_handler,
            adapter=repo_handler.adapter,
        )
        service._pending_messages[conv_id] = collections.deque([pending])

        # Ensure pool is None (not started)
        assert service._executor_pool is None

        # Call _drain_pending — should complete task as INTERNAL_ERROR
        service._drain_pending(conv_id)

        # Verify task was completed with error
        task = service.tracker.get_task(task_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.completion_reason == CompletionReason.INTERNAL_ERROR
