# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for TodoWrite lifecycle through the gateway.

These tests validate that todo progress data from Claude's TodoWrite tool
is correctly tracked through task completion and conversation resume:

1. Todos are captured during execution via streaming events
2. Todos are cleared when a task completes (success or failure)
3. Todos are not carried over when a conversation is resumed
4. Dashboard API does not expose stale todos for completed tasks
"""

import json
import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import TaskStatus

from .conftest import get_message_text
from .environment import IntegrationEnvironment


def _poll_tracker(
    tracker,
    predicate,
    timeout: float = 10.0,
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


class TestTodoLifecycleSuccess:
    """Test that todos are cleared when a task completes successfully."""

    def test_todos_cleared_on_successful_completion(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Todos emitted during execution must be cleared on success.

        Validates:
        - TodoWrite events are captured during execution
        - After successful completion, task.todos is None
        - Dashboard API does not include todos for the completed task
        """
        mock_code = """
todo1 = {"content": "Step 1", "status": "completed"}
todo2 = {"content": "Step 2", "status": "in_progress"}
todo3 = {"content": "Step 3", "status": "pending"}
events = [
    generate_system_event(session_id),
    generate_tool_use_event("TodoWrite", {
        "todos": [todo1, todo2, todo3],
    }),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Step 1", "status": "completed"},
            {"content": "Step 2", "status": "completed"},
            {"content": "Step 3", "status": "completed"},
        ],
    }),
    generate_assistant_event("All steps done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Todo lifecycle success test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "all steps done" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = service.tracker.wait_for_completion(conv_id, timeout=5.0)
            assert task is not None, f"Task {conv_id} not completed"
            assert task.status == TaskStatus.COMPLETED
            assert task.success is True

            # CRITICAL: Todos must be cleared after completion
            assert task.todos is None, (
                f"Todos should be None after successful completion, "
                f"got {task.todos!r}"
            )

            # Verify via dashboard API as well
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                r = client.get(f"/api/conversation/{conv_id}")
                assert r.status_code == 200
                data = json.loads(r.get_data(as_text=True))
                assert "todos" not in data, (
                    f"API should not include todos for completed task, "
                    f"got {data.get('todos')!r}"
                )

        finally:
            service.running = False
            service.repo_handlers["test"].adapter.listener.interrupt()
            service_thread.join(timeout=10.0)


class TestTodoLifecycleFailure:
    """Test that todos are cleared when a task fails."""

    def test_todos_cleared_on_execution_failure(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Todos emitted during execution must be cleared on failure.

        Validates:
        - TodoWrite events captured before a crash
        - After failed completion, task.todos is None
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Analyze", "status": "in_progress"},
            {"content": "Fix bug", "status": "pending"},
        ],
    }),
]
# Simulate crash - no result event
sys.exit(1)
"""
        msg = create_email(
            subject="Todo lifecycle failure test",
            body=mock_code,
        )
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
            assert response is not None, "Did not receive error response"

            conv_id = extract_conversation_id(response["Subject"])
            if conv_id:
                task = service.tracker.wait_for_completion(conv_id, timeout=5.0)
                assert task is not None
                assert task.status == TaskStatus.COMPLETED
                assert task.success is False

                # CRITICAL: Todos must be cleared even on failure
                assert task.todos is None, (
                    f"Todos should be None after failed completion, "
                    f"got {task.todos!r}"
                )

        finally:
            service.running = False
            service.repo_handlers["test"].adapter.listener.interrupt()
            service_thread.join(timeout=10.0)


class TestTodoLifecycleResume:
    """Test that stale todos don't carry over on conversation resume."""

    def test_stale_todos_not_visible_on_resume(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Stale todos from a previous execution must not persist on resume.

        Validates:
        - First message emits todos and completes
        - Todos are cleared after first completion
        - Second message (resume) starts with no stale todos
        - New todos from second execution replace old ones
        """
        # First message with todos
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Step A", "status": "completed"},
            {"content": "Step B", "status": "completed"},
        ],
    }),
    generate_assistant_event("First message with todos done"),
    generate_result_event(session_id, "First done"),
]
"""
        msg1 = create_email(
            subject="Todo resume test",
            body=first_mock_code,
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first ack
            ack1 = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack1 is not None
            conv_id = extract_conversation_id(ack1["Subject"])
            assert conv_id is not None

            # Wait for first completion
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "first message with todos" in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response1 is not None

            task_after_first = service.tracker.wait_for_completion(
                conv_id, timeout=5.0
            )
            assert task_after_first is not None
            assert task_after_first.success is True

            # CRITICAL: Todos must be cleared after first completion
            assert task_after_first.todos is None, (
                f"Todos should be None after first completion, "
                f"got {task_after_first.todos!r}"
            )

            # Clear outbox for second message
            integration_env.email_server.clear_outbox()

            # Second message (resume) — no TodoWrite events
            second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second message no todos done"),
    generate_result_event(session_id, "Second done"),
]
"""
            original_msg_id = ack1.get("Message-ID")
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Todo resume test",
                body=second_mock_code,
                in_reply_to=original_msg_id,
                references=[original_msg_id] if original_msg_id else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "second message no todos" in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response2 is not None

            task_after_resume = service.tracker.wait_for_completion(
                conv_id, timeout=5.0
            )
            assert task_after_resume is not None
            assert task_after_resume.success is True
            assert task_after_resume.message_count == 2

            # CRITICAL: No stale todos from previous execution
            assert task_after_resume.todos is None, (
                f"Todos should be None after resume with no TodoWrite, "
                f"got {task_after_resume.todos!r}"
            )

            # Verify via API
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)
                r = client.get(f"/api/conversation/{conv_id}")
                assert r.status_code == 200
                data = json.loads(r.get_data(as_text=True))
                assert "todos" not in data, (
                    f"API should not include stale todos after resume, "
                    f"got {data.get('todos')!r}"
                )

        finally:
            service.running = False
            service.repo_handlers["test"].adapter.listener.interrupt()
            service_thread.join(timeout=10.0)
