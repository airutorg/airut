# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for streaming progress updates and stop functionality.

Tests:
1. Session file is updated progressively as events arrive
2. Tasks can be stopped while in progress
3. Stopped tasks clean up properly
"""

import sys
import threading
import time
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from lib.sandbox import SessionStore

from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestStreamingProgressUpdates:
    """Test progressive session file updates during execution."""

    def test_session_file_updates_during_execution(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that session file is updated as events arrive."""
        # Create email with mock code that generates multiple events
        mock_code = """
# Build events list
events = [
    generate_system_event(session_id),
    generate_assistant_event("Listing files..."),
    generate_result_event(session_id, "Files listed"),
]
"""
        msg = create_email(
            subject="Test streaming updates",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        # Start service in background thread
        service = integration_env.create_service()

        def run_service():
            try:
                service.start()
            except Exception:
                pass  # Expected when we stop the service

        service_thread = threading.Thread(target=run_service, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment email
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Extract conversation ID from acknowledgment
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None
            assert len(conv_id) == 8

            # Get session directory
            session_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            session_store = SessionStore(session_dir)

            # Poll for session file updates during execution
            # The mock Claude will generate multiple events
            updates_seen = 0
            max_wait = 10.0
            start_time = time.time()

            while time.time() - start_time < max_wait:
                session_data = session_store.load()
                if session_data and session_data.replies:
                    # Check if we have events
                    latest_reply = session_data.replies[-1]
                    if latest_reply.events:
                        event_count = len(latest_reply.events)
                        if event_count > updates_seen:
                            updates_seen = event_count
                            # If we see multiple events, streaming is working
                            if updates_seen >= 2:
                                break
                time.sleep(0.1)

            # Verify we saw progressive updates (at least 2 events)
            assert updates_seen >= 2, (
                f"Expected at least 2 events, got {updates_seen}. "
                "Session file may not be updating progressively."
            )

            # Wait for final response email
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack and "listing" in get_message_text(m).lower(),
                timeout=20.0,
            )
            assert response is not None, "Did not receive response email"

            # Verify final session file has all events
            final_session = session_store.load()
            assert final_session is not None
            assert len(final_session.replies) > 0

            # CRITICAL: Should only have ONE reply, not multiple
            # Bug: streaming was creating a new reply on each event
            assert len(final_session.replies) == 1, (
                f"Expected exactly 1 reply, but found "
                f"{len(final_session.replies)}. "
                "Streaming updates should modify the same reply, "
                "not create new ones."
            )

            final_reply = final_session.replies[-1]
            # Mock Claude generates: system, assistant, result (min 3)
            assert len(final_reply.events) >= 3, (
                f"Expected at least 3 events in final session, "
                f"got {len(final_reply.events)}"
            )

        finally:
            # Stop the service
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)


class TestStopFunctionality:
    """Test task stop functionality."""

    def test_stop_running_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test stopping a task while it's running."""
        # Mock code that signals readiness and blocks
        mock_code = """
# Build events list
events = [
    generate_system_event(session_id),
    generate_assistant_event("Working..."),
    generate_result_event(session_id, "Work complete"),
]

# Define synchronization function
def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num >= 1:
        # Block to keep process alive (will be interrupted by SIGTERM)
        while not (workspace / 'stop_signal.txt').exists():
            time.sleep(0.1)
"""

        # Create email with mock code
        msg = create_email(
            subject="Test stop functionality",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        # Start service
        service = integration_env.create_service()

        def run_service():
            try:
                service.start()
            except Exception:
                pass

        service_thread = threading.Thread(target=run_service, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Extract conversation ID
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for sync file to appear in conversation directory
            # The sync file is created as workspace/.mock_claude_sync
            # where workspace is the conversation directory
            max_wait = 10.0
            start_time = time.time()
            sync_file = None

            while time.time() - start_time < max_wait:
                # Find sync file in any conversation directory
                conversations_dir = (
                    integration_env.storage_dir / "conversations"
                )
                for conv_dir in conversations_dir.iterdir():
                    # Skip hidden directories
                    if conv_dir.is_dir() and not conv_dir.name.startswith("."):
                        # Sync file is in workspace subdirectory
                        workspace = conv_dir / "workspace"
                        candidate = workspace / ".mock_claude_sync"
                        if candidate.exists():
                            content = candidate.read_text()
                            if content == "ready":
                                sync_file = candidate
                                break
                if sync_file:
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Task did not signal readiness via sync file")

            # Verify task is actually in progress
            task = service.tracker.get_task(conv_id)
            assert task is not None
            assert task.status.value == "in_progress"

            # Stop the task
            stop_success = service._stop_execution(conv_id)
            assert stop_success, "Failed to stop task"

            # Task should eventually be marked as completed
            # (process_message unregisters the task in its finally block)
            task = service.tracker.wait_for_completion(conv_id, timeout=5.0)
            if not task or task.status.value != "completed":
                pytest.fail("Task did not complete after stop")

            # After completion, task should be unregistered
            assert conv_id not in service._active_tasks, (
                "Task still tracked after completion"
            )

        finally:
            # Stop the service gracefully
            try:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=3.0)
            except Exception:
                pass  # Best effort cleanup

    def test_stop_nonexistent_task(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Test stopping a task that doesn't exist."""
        # Start service
        service = integration_env.create_service()

        # Try to stop a nonexistent task
        result = service._stop_execution("nonexistent-id")
        assert result is False, "Should return False for nonexistent task"

    def test_dashboard_stop_endpoint(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test the dashboard stop API endpoint."""
        # Mock code that signals readiness and blocks
        mock_code = """
# Build events list
events = [
    generate_system_event(session_id),
    generate_assistant_event("Dashboard test..."),
    generate_result_event(session_id, "Dashboard complete"),
]

# Define synchronization function
def sync_between_events(event_num):
    if event_num == 0:
        (workspace / '.mock_claude_sync').write_text('ready')
    elif event_num >= 1:
        while not (workspace / 'stop_signal.txt').exists():
            time.sleep(0.1)
"""

        # Create email with mock code
        msg = create_email(
            subject="Test dashboard stop",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        # Start service with dashboard enabled
        service = integration_env.create_service()

        def run_service():
            try:
                service.start()
            except Exception:
                pass

        service_thread = threading.Thread(target=run_service, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Extract conversation ID
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for sync file to appear in conversation directory
            max_wait = 10.0
            start_time = time.time()
            sync_file = None

            while time.time() - start_time < max_wait:
                # Find sync file in any conversation directory
                conversations_dir = (
                    integration_env.storage_dir / "conversations"
                )
                for conv_dir in conversations_dir.iterdir():
                    # Skip hidden directories
                    if conv_dir.is_dir() and not conv_dir.name.startswith("."):
                        # Sync file is in workspace subdirectory
                        workspace = conv_dir / "workspace"
                        candidate = workspace / ".mock_claude_sync"
                        if candidate.exists():
                            content = candidate.read_text()
                            if content == "ready":
                                sync_file = candidate
                                break
                if sync_file:
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Task did not signal readiness via sync file")

            # Verify task is in progress
            task = service.tracker.get_task(conv_id)
            assert task is not None
            assert task.status.value == "in_progress"

            # Use dashboard's stop callback
            assert service.dashboard is not None, "Dashboard not started"
            assert service.dashboard.stop_callback is not None

            # Call the stop callback (simulating what the API endpoint does)
            stop_result = service.dashboard.stop_callback(conv_id)
            assert stop_result is True, "Dashboard stop callback failed"

            # Verify task eventually completes
            task = service.tracker.wait_for_completion(conv_id, timeout=5.0)
            if not task or task.status.value != "completed":
                pytest.fail("Task did not complete after dashboard stop")

        finally:
            # Stop the service gracefully
            try:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=3.0)
            except Exception:
                pass  # Best effort cleanup
