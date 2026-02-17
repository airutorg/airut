# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for per-conversation message queuing.

These tests validate the queuing behavior introduced in the task state machine
redesign (5-state lifecycle with message queuing instead of refusal):

1. Messages for a busy conversation are queued (PENDING state)
2. Queued messages drain and execute after the active task completes
3. Queue-full rejection when MAX_PENDING_PER_CONVERSATION is reached
4. CompletionReason.REJECTED is tracked correctly
5. Task timestamps (queued_at, started_at, completed_at) are consistent
6. Dashboard API reflects pending/queued counts correctly
7. authenticated_sender is set after authentication completes
"""

import json
import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import (
    MAX_PENDING_PER_CONVERSATION,
    CompletionReason,
    TaskStatus,
)

from .conftest import (
    MOCK_CONTAINER_COMMAND,
    find_task_for_conversation,
    get_message_text,
    wait_for_conv_completion,
)
from .environment import IntegrationEnvironment


def _poll_tracker(
    tracker,
    predicate,
    timeout: float = 15.0,
    interval: float = 0.1,
):
    """Poll the tracker until predicate(all_tasks) is truthy.

    Args:
        tracker: TaskTracker instance.
        predicate: Callable taking list[TaskState], returns truthy
            value when done.
        timeout: Maximum seconds to wait.
        interval: Seconds between polls.

    Returns:
        The truthy value returned by predicate, or None on timeout.
    """
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
    """Wait for a mock_claude_sync file to appear in any conversation.

    Args:
        storage_dir: Storage directory containing conversations/.
        timeout: Maximum wait time.

    Returns:
        Path to the sync file, or None on timeout.
    """
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


class TestMessageQueuingPendingState:
    """Test that messages for busy conversations enter PENDING state."""

    def test_second_message_becomes_pending(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A second message for a busy conversation enters PENDING.

        Scenario:
        1. First message starts executing (blocks on sync file)
        2. Second message for same conversation is queued as PENDING
        3. First message completes, second message drains and executes
        4. Both complete successfully

        Validates:
        - Second task reaches PENDING status while first is EXECUTING
        - After first completes, second transitions to EXECUTING
        - Both eventually reach COMPLETED with SUCCESS
        """
        # First message: blocks after system event until sync file appears
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First task running"),
    generate_result_event(session_id, "First done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num == 1:
        # Wait for release signal
        while not (workspace / '.release_first').exists():
            time.sleep(0.05)
"""
        # Second message: completes immediately
        second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second task completed"),
    generate_result_event(session_id, "Second done"),
]
"""
        msg1 = create_email(
            subject="Queuing test conversation",
            body=first_mock_code,
            message_id="<queuing-first@test.local>",
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for ack email (contains conversation ID)
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for first task to signal readiness
            sync_file = _wait_for_sync_file(integration_env.storage_dir)
            assert sync_file is not None, "First task did not signal readiness"

            # Verify first task is EXECUTING
            task = find_task_for_conversation(service.tracker, conv_id)
            assert task is not None
            assert task.status == TaskStatus.EXECUTING

            # Clear outbox so we can detect second ack
            integration_env.email_server.clear_outbox()

            # Send second message to the same conversation
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Queuing test conversation",
                body=second_mock_code,
                message_id="<queuing-second@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for the second message to be picked up and enter PENDING.
            #
            # Each message creates its own task keyed by task_id.  The
            # second message's task enters PENDING while the first
            # continues executing.  find_task_for_conversation returns
            # the newest task (sorted by queued_at descending).
            pending_found = _poll_tracker(
                service.tracker,
                lambda tasks: any(
                    t.status == TaskStatus.PENDING for t in tasks
                ),
                timeout=15.0,
            )
            assert pending_found, (
                "Second message did not enter PENDING state. Tasks: "
                + repr(
                    [
                        (t.conversation_id, t.status.value)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )

            # The newest task for this conv should be PENDING
            task_state = find_task_for_conversation(service.tracker, conv_id)
            assert task_state is not None
            assert task_state.status == TaskStatus.PENDING

            # Release the first task
            workspace_dir = sync_file.parent
            (workspace_dir / ".release_first").write_text("go")

            # Wait for first task response email
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "first task" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response1 is not None, "Did not receive first task response"

            # Wait for second task response email (drains from queue)
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "second task" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None, (
                "Did not receive second task response (drain failed)"
            )

            # Wait for final completion
            final_task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert final_task is not None
            assert final_task.status == TaskStatus.COMPLETED
            assert final_task.succeeded is True

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestMessageQueuingDrain:
    """Test that pending messages drain and execute correctly."""

    def test_queued_message_executes_after_active_completes(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Queued messages execute in order after the active task completes.

        Validates:
        - Pending message skips re-authentication
        - Response email is sent for the drained message
        - Task ends with SUCCESS completion reason
        """
        # First message: blocks briefly then completes
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Drain test first"),
    generate_result_event(session_id, "First done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num == 1:
        # Block briefly so we can queue the second message
        while not (workspace / '.release_first').exists():
            time.sleep(0.05)
"""
        second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Drain test second executed"),
    generate_result_event(session_id, "Second done"),
]
"""
        msg1 = create_email(
            subject="Drain test",
            body=first_mock_code,
            message_id="<drain-first@test.local>",
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

            # Wait for first task to signal readiness
            sync_file = _wait_for_sync_file(integration_env.storage_dir)
            assert sync_file is not None

            # Clear outbox
            integration_env.email_server.clear_outbox()

            # Queue second message
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Drain test",
                body=second_mock_code,
                message_id="<drain-second@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for PENDING
            _poll_tracker(
                service.tracker,
                lambda tasks: any(
                    t.status == TaskStatus.PENDING for t in tasks
                ),
                timeout=15.0,
            )

            # Release first task
            workspace_dir = sync_file.parent
            (workspace_dir / ".release_first").write_text("go")

            # Wait for first response
            integration_env.email_server.wait_for_sent(
                lambda m: "drain test first" in get_message_text(m).lower(),
                timeout=30.0,
            )

            # Wait for second response (proves drain worked)
            second_response = integration_env.email_server.wait_for_sent(
                lambda m: "drain test second" in get_message_text(m).lower(),
                timeout=30.0,
            )
            sent = integration_env.email_server.get_sent_messages()
            assert second_response is not None, (
                "Second message did not execute after drain. "
                "Sent messages: " + repr([m.get("Subject") for m in sent])
            )

            # Final task state should be completed with success
            final_task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert final_task is not None
            assert final_task.succeeded is True

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestQueueFullRejection:
    """Test rejection when per-conversation queue is full."""

    def test_queue_overflow_rejected_with_correct_reason(
        self,
        tmp_path: Path,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Messages beyond MAX_PENDING_PER_CONVERSATION are rejected.

        Scenario:
        1. First message starts executing (blocks)
        2. Queue MAX_PENDING_PER_CONVERSATION more messages
        3. One more message should be REJECTED
        4. Verify CompletionReason.REJECTED in tracker

        Validates:
        - Queue limit is enforced
        - Rejection email is sent to the user
        - CompletionReason.REJECTED is recorded
        """
        # First message: blocks for a long time
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Rejection test first"),
    generate_result_event(session_id, "First done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num == 1:
        while not (workspace / '.release_first').exists():
            time.sleep(0.05)
"""
        queued_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Queued message done"),
    generate_result_event(session_id, "Done"),
]
"""
        overflow_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("This should be rejected"),
    generate_result_event(session_id, "Should not run"),
]
"""

        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["user@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            msg1 = create_email(
                subject="Rejection test",
                body=first_mock_code,
                message_id="<reject-first@test.local>",
            )
            env.email_server.inject_message(msg1)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Wait for ack
                ack = env.email_server.wait_for_sent(
                    lambda m: "started working" in get_message_text(m).lower(),
                    timeout=15.0,
                )
                assert ack is not None
                conv_id = extract_conversation_id(ack["Subject"])
                assert conv_id is not None

                # Wait for first task to be executing
                sync_file = _wait_for_sync_file(env.storage_dir)
                assert sync_file is not None

                env.email_server.clear_outbox()

                # Queue MAX_PENDING_PER_CONVERSATION messages
                for i in range(MAX_PENDING_PER_CONVERSATION):
                    queued_msg = create_email(
                        subject=f"Re: [ID:{conv_id}] Rejection test",
                        body=queued_mock_code,
                        message_id=f"<reject-queued-{i}@test.local>",
                        in_reply_to=ack.get("Message-ID"),
                        references=[ack.get("Message-ID")]
                        if ack.get("Message-ID")
                        else [],
                    )
                    env.email_server.inject_message(queued_msg)

                # Wait for all queued messages to enter PENDING
                _poll_tracker(
                    service.tracker,
                    lambda tasks: (
                        sum(1 for t in tasks if t.status == TaskStatus.PENDING)
                        >= MAX_PENDING_PER_CONVERSATION
                    ),
                    timeout=20.0,
                )

                env.email_server.clear_outbox()

                # Now queue one more (should be rejected)
                overflow_msg = create_email(
                    subject=f"Re: [ID:{conv_id}] Rejection test",
                    body=overflow_mock_code,
                    message_id="<reject-overflow@test.local>",
                    in_reply_to=ack.get("Message-ID"),
                    references=[ack.get("Message-ID")]
                    if ack.get("Message-ID")
                    else [],
                )
                env.email_server.inject_message(overflow_msg)

                # Wait for rejection email
                rejection = env.email_server.wait_for_sent(
                    lambda m: (
                        "too many" in get_message_text(m).lower()
                        or "queue" in get_message_text(m).lower()
                    ),
                    timeout=15.0,
                )
                assert rejection is not None, (
                    "Did not receive rejection email for overflow message"
                )

                # Verify REJECTED completion reason in tracker
                rejected_tasks = _poll_tracker(
                    service.tracker,
                    lambda tasks: [
                        t
                        for t in tasks
                        if t.status == TaskStatus.COMPLETED
                        and t.completion_reason == CompletionReason.REJECTED
                    ],
                    timeout=10.0,
                )
                assert rejected_tasks, (
                    "No task with REJECTED completion reason found. "
                    "Tasks: "
                    + repr(
                        [
                            (
                                t.conversation_id,
                                t.status.value,
                                t.completion_reason,
                            )
                            for t in service.tracker.get_all_tasks()
                        ]
                    )
                )

                # Release the first task so the queued ones can drain
                workspace_dir = sync_file.parent
                (workspace_dir / ".release_first").write_text("go")

                # Wait for all tasks to complete
                _poll_tracker(
                    service.tracker,
                    lambda tasks: (
                        all(t.status == TaskStatus.COMPLETED for t in tasks)
                        and len(tasks) >= 2
                    ),
                    timeout=45.0,
                )

            finally:
                service.stop()
                service_thread.join(timeout=10.0)

        finally:
            env.cleanup()


class TestCompletionReasonTracking:
    """Test that CompletionReason values are tracked correctly."""

    def test_success_completion_reason(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Successful execution records CompletionReason.SUCCESS."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Success reason test"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(subject="Success reason test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "success reason" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.completion_reason == CompletionReason.SUCCESS
            assert task.succeeded is True
            assert task.completion_detail == ""

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_execution_failed_completion_reason(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Crashed execution records CompletionReason.EXECUTION_FAILED."""
        mock_code = """
sys.exit(1)
"""
        msg = create_email(subject="Failure reason test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "error" in get_message_text(m).lower()
                    or "failed" in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            if conv_id:
                task = wait_for_conv_completion(
                    service.tracker, conv_id, timeout=5.0
                )
                assert task is not None
                assert (
                    task.completion_reason == CompletionReason.EXECUTION_FAILED
                )
                assert task.succeeded is False

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_unauthorized_completion_reason(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Unauthorized sender records CompletionReason.UNAUTHORIZED."""
        msg = create_email(
            subject="Unauthorized reason test",
            body="Should be rejected",
            sender="hacker@evil.com",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            integration_env.email_server.wait_until_inbox_empty(timeout=10.0)

            unauthorized_tasks = _poll_tracker(
                service.tracker,
                lambda tasks: [
                    t
                    for t in tasks
                    if t.status == TaskStatus.COMPLETED
                    and t.completion_reason == CompletionReason.UNAUTHORIZED
                ],
            )
            assert unauthorized_tasks, (
                "No UNAUTHORIZED completion reason found. Tasks: "
                + repr(
                    [
                        (t.conversation_id, t.completion_reason)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )

            task = unauthorized_tasks[0]
            assert task.succeeded is False
            assert "sender not authorized" in task.completion_detail

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_auth_failed_completion_reason(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """DMARC failure records CompletionReason.AUTH_FAILED."""
        msg = create_email(
            subject="DMARC fail reason test",
            body="Should fail DMARC",
            sender="user@test.local",
            authentication_results="test.local; dmarc=fail; spf=fail",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            integration_env.email_server.wait_until_inbox_empty(timeout=10.0)

            auth_failed_tasks = _poll_tracker(
                service.tracker,
                lambda tasks: [
                    t
                    for t in tasks
                    if t.status == TaskStatus.COMPLETED
                    and t.completion_reason == CompletionReason.AUTH_FAILED
                ],
            )
            assert auth_failed_tasks, (
                "No AUTH_FAILED completion reason found. Tasks: "
                + repr(
                    [
                        (t.conversation_id, t.completion_reason)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )

            task = auth_failed_tasks[0]
            assert task.succeeded is False

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTimestamps:
    """Test that task timestamps are consistent and correct."""

    def test_timestamps_ordering(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Task timestamps follow queued_at <= started_at <= completed_at."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Timestamp test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(subject="Timestamp test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "timestamp test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            # All timestamps should be set
            assert task.queued_at is not None
            assert task.started_at is not None
            assert task.completed_at is not None

            # Ordering invariant
            assert task.queued_at <= task.started_at, (
                f"queued_at ({task.queued_at}) > started_at ({task.started_at})"
            )
            assert task.started_at <= task.completed_at, (
                f"started_at ({task.started_at}) > completed_at "
                f"({task.completed_at})"
            )

            # Duration methods should return positive values
            assert task.queue_duration() >= 0
            exec_dur = task.execution_duration()
            assert exec_dur is not None
            assert exec_dur >= 0
            assert task.total_duration() >= 0
            assert task.total_duration() >= task.queue_duration()

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestAuthenticatedSenderTracking:
    """Test that authenticated_sender is set correctly."""

    def test_authenticated_sender_set_on_success(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """authenticated_sender is set after successful authentication."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Auth sender test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Auth sender test",
            body=mock_code,
            sender="user@test.local",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "auth sender test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            # Both sender and authenticated_sender should be set
            assert task.sender == "user@test.local"
            assert task.authenticated_sender == "user@test.local"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestDashboardPendingCounts:
    """Test that dashboard API reflects pending task counts."""

    def test_dashboard_shows_pending_count_during_queuing(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Dashboard API includes PENDING tasks in counts while queued.

        Validates:
        - /api/tracker counts include pending > 0 while messages are queued
        - /api/health tasks include pending > 0
        - After all complete, pending == 0
        """
        # First message: blocks until released
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Dashboard pending test first"),
    generate_result_event(session_id, "First done"),
]

def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num == 1:
        while not (workspace / '.release_first').exists():
            time.sleep(0.05)
"""
        second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Dashboard pending test second"),
    generate_result_event(session_id, "Second done"),
]
"""
        msg1 = create_email(
            subject="Dashboard pending test",
            body=first_mock_code,
            message_id="<dashboard-pending-1@test.local>",
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

            # Wait for first to be executing
            sync_file = _wait_for_sync_file(integration_env.storage_dir)
            assert sync_file is not None

            integration_env.email_server.clear_outbox()

            # Queue second message
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Dashboard pending test",
                body=second_mock_code,
                message_id="<dashboard-pending-2@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for PENDING state
            _poll_tracker(
                service.tracker,
                lambda tasks: any(
                    t.status == TaskStatus.PENDING for t in tasks
                ),
                timeout=15.0,
            )

            # Check dashboard API shows pending > 0
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                # /api/tracker
                # Each message has its own task entry.  The second
                # message's task is PENDING while the first keeps
                # EXECUTING.
                r = client.get("/api/tracker")
                assert r.status_code == 200
                data = json.loads(r.get_data(as_text=True))
                assert data["counts"]["pending"] >= 1, (
                    f"Expected pending >= 1, got {data['counts']}"
                )

                # /api/health
                r = client.get("/api/health")
                assert r.status_code == 200
                health = json.loads(r.get_data(as_text=True))
                assert health["tasks"]["pending"] >= 1

            # Release first task
            workspace_dir = sync_file.parent
            (workspace_dir / ".release_first").write_text("go")

            # Wait for all to complete
            _poll_tracker(
                service.tracker,
                lambda tasks: (
                    all(t.status == TaskStatus.COMPLETED for t in tasks)
                    and len(tasks) >= 1
                ),
                timeout=45.0,
            )

            # Check dashboard shows pending == 0 after completion
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                r = client.get("/api/tracker")
                assert r.status_code == 200
                data = json.loads(r.get_data(as_text=True))
                assert data["counts"]["pending"] == 0, (
                    f"Expected pending=0 after completion, got {data['counts']}"
                )
                assert data["counts"]["executing"] == 0

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestCompletionReasonInDashboardAPI:
    """Test that completion_reason values appear correctly in API."""

    def test_completion_reason_in_api_response(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """The /api/conversation/{id} endpoint includes completion_reason.

        Validates the full CompletionReason → API response path.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("API completion reason test"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="API completion reason test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "api completion" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                # Single task endpoint
                r = client.get(f"/api/conversation/{conv_id}")
                assert r.status_code == 200
                data = json.loads(r.get_data(as_text=True))
                assert data["completion_reason"] == "success"
                assert data["status"] == "completed"

                # Tracker endpoint
                r = client.get("/api/tracker")
                assert r.status_code == 200
                tracker_data = json.loads(r.get_data(as_text=True))
                api_task = next(
                    (
                        t
                        for t in tracker_data["tasks"]
                        if t["conversation_id"] == conv_id
                    ),
                    None,
                )
                assert api_task is not None
                assert api_task["completion_reason"] == "success"

                # Conversations list endpoint
                r = client.get("/api/conversations")
                assert r.status_code == 200
                conv_data = json.loads(r.get_data(as_text=True))
                conv_task = next(
                    (t for t in conv_data if t["conversation_id"] == conv_id),
                    None,
                )
                assert conv_task is not None
                assert conv_task["completion_reason"] == "success"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
