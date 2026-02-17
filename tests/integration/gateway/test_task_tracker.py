# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for task tracker state through the gateway lifecycle.

These tests validate that the task tracker correctly reflects task state
throughout all major gateway scenarios:

1. New conversation: queued → executing → completed (success)
2. Conversation resume: existing completed task transitions back through
   executing → completed
3. Unauthorized sender: task appears with "(not authorized)" and completes
   as failed
4. Execution error: task tracks failure correctly
5. Concurrent messages: multiple tasks tracked independently
6. Dashboard /api/tracker endpoint returns correct state
7. Model tracking: model is recorded in tracker
8. Task display_title and sender are updated after authentication
"""

import json
import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import TaskStatus

from .conftest import (
    get_message_text,
    wait_for_conv_completion,
)
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


class TestTaskTrackerNewConversation:
    """Test task tracker state during new conversation lifecycle."""

    def test_task_lifecycle_new_conversation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Tracker transitions: queued → executing → completed.

        Validates:
        - Task is created with correct display_title and sender
        - Task transitions to completed with succeeded=True
        - Conversation ID in tracker matches email subject ID
        - Message count is 1 for new conversation
        - Model is recorded in tracker
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Tracker test completed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Track this task",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response email (task completed)
            response = integration_env.email_server.wait_for_sent(
                lambda m: "tracker test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            # Extract conversation ID
            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            # Wait for task completion in tracker
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None, f"Task {conv_id} not completed in tracker"

            # Validate final task state
            assert task.status == TaskStatus.COMPLETED
            assert task.succeeded is True
            assert task.conversation_id == conv_id
            assert "Track this task" in task.display_title
            assert task.sender == "user@test.local"
            assert task.model is not None  # Model should be set
            assert task.started_at is not None
            assert task.completed_at is not None
            assert task.completed_at >= task.started_at
            assert task.queued_at <= task.started_at

            # Validate counts
            counts = service.tracker.get_counts()
            assert counts["completed"] >= 1
            assert counts["executing"] == 0
            assert counts["queued"] == 0

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_task_display_title_updated_from_authenticating(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Task display_title updates from '(authenticating)' to real title.

        This was a regression in the protocol-agnostic decoupling where tasks
        would remain stuck with '(authenticating)' as the display_title forever.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Subject test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Verify display_title update",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for completion
            response = integration_env.email_server.wait_for_sent(
                lambda m: "subject test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            # CRITICAL: display_title must NOT be "(authenticating)"
            assert task.display_title != "(authenticating)", (
                "Task display_title was never updated from placeholder"
            )
            assert "Verify display_title update" in task.display_title

            # Sender must be set
            assert task.sender == "user@test.local"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerConversationResume:
    """Test task tracker state during conversation resume."""

    def test_task_tracker_resume_creates_separate_tasks(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that resuming a conversation creates separate tasks.

        Each message creates its own task keyed by task_id. After both
        complete, there should be two tasks sharing the same
        conversation_id.
        """
        # First message
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First message processed"),
    generate_result_event(session_id, "First done"),
]
"""
        msg1 = create_email(subject="Resume test", body=first_mock_code)
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first response
            ack1 = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack1 is not None
            conv_id = extract_conversation_id(ack1["Subject"])
            assert conv_id is not None

            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "first message" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response1 is not None

            # Verify first task completion
            task_after_first = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task_after_first is not None
            assert task_after_first.succeeded is True

            # Clear outbox for second message
            integration_env.email_server.clear_outbox()

            # Second message to same conversation
            second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second message processed"),
    generate_result_event(session_id, "Second done"),
]
"""
            original_msg_id = ack1.get("Message-ID")
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Resume test",
                body=second_mock_code,
                in_reply_to=original_msg_id,
                references=[original_msg_id] if original_msg_id else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "second message" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None

            # Verify all tasks for this conversation completed
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                conv_tasks = service.tracker.get_tasks_for_conversation(conv_id)
                if len(conv_tasks) >= 2 and all(
                    t.status == TaskStatus.COMPLETED for t in conv_tasks
                ):
                    break
                time.sleep(0.1)

            conv_tasks = service.tracker.get_tasks_for_conversation(conv_id)

            # There should be 2 tasks (one per message) for this conv
            assert len(conv_tasks) >= 2, (
                f"Expected 2 tasks for {conv_id}, found {len(conv_tasks)}."
            )

            # All should be completed and successful
            for t in conv_tasks:
                assert t.succeeded is True
                assert t.conversation_id == conv_id

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerUnauthorized:
    """Test task tracker state for unauthorized senders."""

    def test_unauthorized_sender_tracked_as_not_authorized(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that unauthorized sender creates a failed task with sender info.

        This was a regression where unauthorized senders were invisible in
        the dashboard because the task stayed with '(authenticating)' as
        display_title and no sender.
        """
        msg = create_email(
            subject="Unauthorized request",
            body="This should be rejected",
            sender="hacker@evil.com",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for message to be processed
            processed = integration_env.email_server.wait_until_inbox_empty(
                timeout=10.0
            )
            assert processed, "Service did not process message in time"

            # Poll tracker for completed auth rejection task
            auth_tasks = _poll_tracker(
                service.tracker,
                lambda tasks: [
                    t
                    for t in tasks
                    if t.status == TaskStatus.COMPLETED
                    and (
                        t.display_title == "(not authorized)"
                        or t.sender == "hacker@evil.com"
                    )
                ],
            )
            assert auth_tasks, "No auth rejection task found. Tasks: " + repr(
                [
                    (t.conversation_id, t.display_title, t.sender)
                    for t in service.tracker.get_all_tasks()
                ]
            )

            task = auth_tasks[0]

            # CRITICAL: Task should be completed (not stuck executing)
            assert task.status == TaskStatus.COMPLETED, (
                f"Auth failure task stuck in {task.status.value}"
            )
            assert task.succeeded is False

            # CRITICAL: Sender should be visible for security auditing
            assert task.sender == "hacker@evil.com", (
                f"Sender not recorded: {task.sender!r}"
            )

            # display_title should indicate rejection
            assert task.display_title == "(not authorized)"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_dmarc_failure_tracked(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that DMARC failure is tracked in task tracker."""
        msg = create_email(
            subject="DMARC fail",
            body="Should fail DMARC",
            sender="user@test.local",
            authentication_results="test.local; dmarc=fail; spf=fail",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            processed = integration_env.email_server.wait_until_inbox_empty(
                timeout=10.0
            )
            assert processed

            # Poll for completed auth rejection task
            auth_tasks = _poll_tracker(
                service.tracker,
                lambda tasks: [
                    t
                    for t in tasks
                    if t.status == TaskStatus.COMPLETED
                    and t.display_title == "(not authorized)"
                ],
            )
            assert auth_tasks, "No DMARC rejection task found. Tasks: " + repr(
                [
                    (t.conversation_id, t.display_title, t.sender)
                    for t in service.tracker.get_all_tasks()
                ]
            )

            task = auth_tasks[0]
            assert task.succeeded is False

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerErrors:
    """Test task tracker state for execution errors."""

    def test_crash_tracked_as_failure(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that execution crash is tracked as a failed task."""
        mock_code = """
sys.exit(1)
"""
        msg = create_email(subject="Crash test task", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "failed" in get_message_text(m).lower()
                    or "error" in get_message_text(m).lower()
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
                assert task.status == TaskStatus.COMPLETED
                assert task.succeeded is False
                assert task.display_title == "Crash test task"
                assert task.sender == "user@test.local"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_empty_body_tracked(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that an empty body message is tracked and completed."""
        msg = create_email(subject="Empty body test", body="   ")
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for error response about empty message
            response = integration_env.email_server.wait_for_sent(
                lambda m: "empty" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert response is not None

            # Poll for at least one completed task
            completed = _poll_tracker(
                service.tracker,
                lambda tasks: [
                    t for t in tasks if t.status == TaskStatus.COMPLETED
                ],
            )
            assert completed, "No completed tasks after empty body. " + repr(
                [
                    (t.conversation_id, t.status.value)
                    for t in service.tracker.get_all_tasks()
                ]
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerConcurrent:
    """Test task tracker with concurrent messages."""

    def test_multiple_messages_tracked_independently(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that multiple concurrent messages get independent tasks."""
        mock_code_1 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First concurrent task done"),
    generate_result_event(session_id, "Done 1"),
]
"""
        mock_code_2 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second concurrent task done"),
    generate_result_event(session_id, "Done 2"),
]
"""
        msg1 = create_email(
            subject="Concurrent task 1",
            body=mock_code_1,
            message_id="<concurrent-1@test.local>",
        )
        msg2 = create_email(
            subject="Concurrent task 2",
            body=mock_code_2,
            message_id="<concurrent-2@test.local>",
        )

        integration_env.email_server.inject_message(msg1)
        integration_env.email_server.inject_message(msg2)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for both responses
            seen_first = False
            seen_second = False
            deadline = time.monotonic() + 45.0

            while time.monotonic() < deadline and not (
                seen_first and seen_second
            ):
                for m in integration_env.email_server.get_sent_messages():
                    text = get_message_text(m).lower()
                    if "first concurrent" in text:
                        seen_first = True
                    if "second concurrent" in text:
                        seen_second = True
                time.sleep(0.5)

            assert seen_first, "First concurrent task not completed"
            assert seen_second, "Second concurrent task not completed"

            # Poll for at least 2 completed tasks
            completed_tasks = _poll_tracker(
                service.tracker,
                lambda tasks: (
                    [t for t in tasks if t.status == TaskStatus.COMPLETED]
                    if sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
                    >= 2
                    else None
                ),
            )
            assert completed_tasks, (
                "Expected at least 2 completed tasks. "
                + repr(
                    [
                        (t.conversation_id, t.display_title)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )

            # Verify they have different conversation IDs
            conv_ids = {t.conversation_id for t in completed_tasks}
            assert len(conv_ids) >= 2, (
                "Concurrent tasks should have different conversation IDs"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerDashboardAPI:
    """Test task tracker via dashboard API endpoints."""

    def test_tracker_api_returns_correct_state(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Verify /api/tracker returns correct state after completion."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("API test completed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(subject="API tracker test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response
            response = integration_env.email_server.wait_for_sent(
                lambda m: "api test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            # Wait for completion
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            # Query dashboard API if dashboard is running
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                # Test /api/tracker endpoint
                api_response = client.get("/api/tracker")
                assert api_response.status_code == 200
                data = json.loads(api_response.get_data(as_text=True))

                # Validate structure
                assert "version" in data
                assert "counts" in data
                assert "tasks" in data
                assert isinstance(data["version"], int)

                # Find our task
                api_task = next(
                    (
                        t
                        for t in data["tasks"]
                        if t["conversation_id"] == conv_id
                    ),
                    None,
                )
                assert api_task is not None, (
                    f"Task {conv_id} not found in /api/tracker response"
                )

                # Validate task data
                assert api_task["status"] == "completed"
                assert api_task["completion_reason"] == "success"
                assert api_task["sender"] == "user@test.local"
                assert api_task["display_title"] == "API tracker test"
                assert "task_id" in api_task
                assert api_task["model"] is not None
                assert api_task["repo_id"] == "test"

                # Validate counts match
                assert data["counts"]["completed"] >= 1
                assert data["counts"]["executing"] == 0
                assert data["counts"]["queued"] == 0

                # Test /api/conversations endpoint matches
                conv_response = client.get("/api/conversations")
                assert conv_response.status_code == 200
                conv_data = json.loads(conv_response.get_data(as_text=True))
                conv_task = next(
                    (t for t in conv_data if t["conversation_id"] == conv_id),
                    None,
                )
                assert conv_task is not None
                assert conv_task["status"] == "completed"

                # Test /api/health endpoint
                health_response = client.get("/api/health")
                assert health_response.status_code == 200
                health_data = json.loads(health_response.get_data(as_text=True))
                assert health_data["status"] == "ok"
                assert health_data["tasks"]["completed"] >= 1

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_tracker_api_etag_changes_on_mutation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that /api/tracker ETag changes when state is mutated."""
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            if service.dashboard is not None:
                from werkzeug.test import Client

                client = Client(service.dashboard._wsgi_app)

                # Dashboard WSGI app is available immediately (no
                # need to wait for the HTTP server thread — we use
                # the werkzeug test client which calls the app
                # directly).

                # Get initial ETag
                r1 = client.get("/api/tracker")
                assert r1.status_code == 200
                etag1 = r1.headers.get("ETag")
                assert etag1 is not None

                # Send a message to mutate state
                mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("ETag test done"),
    generate_result_event(session_id, "Done"),
]
"""
                msg = create_email(subject="ETag test", body=mock_code)
                integration_env.email_server.inject_message(msg)

                # Wait for completion
                integration_env.email_server.wait_for_sent(
                    lambda m: "etag test" in get_message_text(m).lower(),
                    timeout=30.0,
                )

                # Poll until ETag changes (tracker updated)
                deadline = time.monotonic() + 10.0
                etag2 = etag1
                while etag2 == etag1 and time.monotonic() < deadline:
                    time.sleep(0.1)
                    r2 = client.get("/api/tracker")
                    etag2 = r2.headers.get("ETag")
                assert etag1 != etag2, "ETag should change after state mutation"

                # Old ETag should still return 200 (not 304)
                r3 = client.get(
                    "/api/tracker",
                    headers={"If-None-Match": etag1},
                )
                assert r3.status_code == 200

                # New ETag should return 304
                r4 = client.get(
                    "/api/tracker",
                    headers={"If-None-Match": etag2},
                )
                assert r4.status_code == 304

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerModelTracking:
    """Test that model selection is correctly tracked."""

    def test_model_tracked_for_new_conversation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that the default model is recorded in tracker."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Model test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(subject="Model tracking test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "model test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None

            # Default model from test repo config is "sonnet"
            assert task.model == "sonnet", (
                f"Expected model='sonnet', got '{task.model}'"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerRepoId:
    """Test that repo_id is correctly tracked."""

    def test_repo_id_tracked(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that repo_id is set on tasks."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Repo test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(subject="Repo ID test", body=mock_code)
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "repo test" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.repo_id == "test", (
                f"Expected repo_id='test', got '{task.repo_id}'"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestTaskTrackerNoStuckTasks:
    """Test that tasks never get stuck in intermediate states."""

    def test_no_tasks_stuck_in_queued_or_executing(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that after processing, no tasks remain queued or executing.

        Sends multiple messages (including one that will fail) and verifies
        that all end up in COMPLETED state — none stuck in QUEUED or
        EXECUTING.
        """
        # Good message
        good_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Good task done"),
    generate_result_event(session_id, "Done"),
]
"""
        # Bad message (unauthorized)
        msg1 = create_email(subject="Good task", body=good_code)
        msg2 = create_email(
            subject="Bad sender task",
            body="Reject me",
            sender="badguy@evil.com",
        )

        integration_env.email_server.inject_message(msg1)
        integration_env.email_server.inject_message(msg2)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for good response
            integration_env.email_server.wait_for_sent(
                lambda m: "good task" in get_message_text(m).lower(),
                timeout=30.0,
            )

            # Wait for inbox to be processed
            integration_env.email_server.wait_until_inbox_empty(timeout=10.0)

            # Poll until no tasks are in non-terminal states
            _poll_tracker(
                service.tracker,
                lambda tasks: (
                    len(tasks) >= 2
                    and all(t.status == TaskStatus.COMPLETED for t in tasks)
                ),
            )

            all_tasks = service.tracker.get_all_tasks()
            stuck_tasks = [
                t
                for t in all_tasks
                if t.status in (TaskStatus.QUEUED, TaskStatus.EXECUTING)
            ]
            assert len(stuck_tasks) == 0, (
                "Tasks stuck in non-terminal state: "
                + repr(
                    [
                        (t.conversation_id, t.display_title, t.status.value)
                        for t in stuck_tasks
                    ]
                )
            )

            # All tasks should be completed
            for t in all_tasks:
                assert t.status == TaskStatus.COMPLETED, (
                    f"Task {t.conversation_id} ({t.display_title}) "
                    f"not completed: {t.status.value}"
                )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
