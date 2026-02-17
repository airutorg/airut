# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for git mirror update behavior.

Tests that the git mirror cache is properly updated when:
1. Service starts
2. New conversations are created
3. Multiple conversations are created over time

These tests ensure that conversations created after repository updates
get the latest code, not stale code from an outdated mirror.
"""

import subprocess
import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


def _poll_for_mirror(
    storage_dir: Path, *, timeout: float = 10.0, interval: float = 0.1
) -> Path:
    """Poll until git mirror directory is initialized with a HEAD file."""
    mirror_path = storage_dir / "git-mirror"
    head_file = mirror_path / "HEAD"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if head_file.exists():
            return mirror_path
        time.sleep(interval)
    raise TimeoutError(
        f"Git mirror not initialized within {timeout}s at {mirror_path}"
    )


class TestGitMirrorUpdates:
    """Test git mirror update behavior."""

    def test_mirror_updated_on_service_start(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Test that git mirror is updated when service starts."""
        # Create mirror directory path
        mirror_path = integration_env.storage_dir / "git-mirror"

        # Start service (should initialize and update mirror)
        service = integration_env.create_service()

        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Poll until mirror is initialized
            _poll_for_mirror(integration_env.storage_dir)

            # Verify mirror exists
            assert mirror_path.exists(), "Mirror was not created"
            assert (mirror_path / "refs").exists(), "Mirror is not a git repo"

            # Verify mirror has been fetched recently
            # (git mirror should have HEAD file with recent mtime)
            head_file = mirror_path / "HEAD"
            assert head_file.exists(), "Mirror HEAD file not found"

            # Check that HEAD was modified recently (within last 5 seconds)
            mtime = head_file.stat().st_mtime
            age = time.time() - mtime
            assert age < 5.0, (
                f"Mirror HEAD file is too old ({age:.1f}s), "
                "suggesting mirror was not updated"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_new_conversation_gets_latest_code(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that new conversations get latest code from mirror."""
        # Add a marker file to master repo
        marker_file = integration_env.master_repo / "marker1.txt"
        marker_file.write_text("First version")

        subprocess.run(
            ["git", "add", "marker1.txt"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Add marker file"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )

        # Start service (should update mirror)
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Created"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Create first conversation",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "Created" in get_message_text(m)
                    and "received" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response is not None

            # Get conversation ID
            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            # Verify conversation has the marker file
            conv_workspace = (
                integration_env.storage_dir
                / "conversations"
                / conv_id
                / "workspace"
            )
            conv_marker = conv_workspace / "marker1.txt"
            assert conv_marker.exists(), (
                "Conversation should have marker file from master repo"
            )
            assert conv_marker.read_text() == "First version"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_subsequent_conversation_sees_updated_code(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that conversations created after repo updates get new code.

        This is the critical test that validates the bug fix:
        - Service starts and creates mirror
        - First conversation is created
        - Master repo is updated (simulating git push to main)
        - Second conversation is created WITHOUT restarting service
        - Second conversation should see the updated code
        """
        # Initial commit: marker file version 1
        marker_file = integration_env.master_repo / "marker2.txt"
        marker_file.write_text("Version 1")

        subprocess.run(
            ["git", "add", "marker2.txt"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Add marker v1"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )

        # Start service
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Create first conversation
            mock_code1 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First conversation"),
    generate_result_event(session_id, "Done"),
]
"""
            msg1 = create_email(
                subject="First conversation",
                body=mock_code1,
            )
            integration_env.email_server.inject_message(msg1)

            # Wait for first response
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "First conversation" in get_message_text(m)
                    and "received" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response1 is not None

            conv_id1 = extract_conversation_id(response1["Subject"])
            assert conv_id1 is not None

            # Verify first conversation has version 1
            conv1_workspace = (
                integration_env.storage_dir
                / "conversations"
                / conv_id1
                / "workspace"
            )
            conv1_marker = conv1_workspace / "marker2.txt"
            assert conv1_marker.exists()
            assert conv1_marker.read_text() == "Version 1"

            # Update master repo (simulating git push)
            marker_file.write_text("Version 2 - UPDATED")
            subprocess.run(
                ["git", "add", "marker2.txt"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "Update marker to v2"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )

            # Create second conversation WITHOUT restarting service
            mock_code2 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second conversation"),
    generate_result_event(session_id, "Done"),
]
"""
            msg2 = create_email(
                subject="Second conversation",
                body=mock_code2,
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "Second conversation" in get_message_text(m)
                    and "received" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response2 is not None

            conv_id2 = extract_conversation_id(response2["Subject"])
            assert conv_id2 is not None
            assert conv_id2 != conv_id1, "Should be different conversations"

            # Verify second conversation has version 2
            # THIS IS THE KEY ASSERTION that will fail before the fix
            conv2_workspace = (
                integration_env.storage_dir
                / "conversations"
                / conv_id2
                / "workspace"
            )
            conv2_marker = conv2_workspace / "marker2.txt"
            assert conv2_marker.exists(), (
                "Second conversation should have marker file"
            )

            # This assertion will FAIL if mirror is not updated
            # because conv2 will clone from stale mirror with v1
            actual_content = conv2_marker.read_text()
            assert actual_content == "Version 2 - UPDATED", (
                f"Second conversation should see updated code. "
                f"Got '{actual_content}', expected 'Version 2 - UPDATED'. "
                f"This indicates git mirror was not updated "
                f"between conversations."
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_mirror_reflects_master_branch_updates(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Test that mirror update actually fetches latest refs from origin."""
        # Create initial commit
        test_file = integration_env.master_repo / "test_update.txt"
        test_file.write_text("Initial")

        subprocess.run(
            ["git", "add", "test_update.txt"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Initial version"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )

        # Get initial commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
            text=True,
        )
        initial_sha = result.stdout.strip()

        # Start service (creates and updates mirror)
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Poll until mirror is initialized
            mirror_path = _poll_for_mirror(integration_env.storage_dir)
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=mirror_path,
                check=True,
                capture_output=True,
                text=True,
            )
            mirror_sha = result.stdout.strip()
            assert mirror_sha == initial_sha, (
                "Mirror should have initial commit"
            )

            # Update master repo
            test_file.write_text("Updated")
            subprocess.run(
                ["git", "add", "test_update.txt"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "Update version"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )

            # Get new commit SHA
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
                text=True,
            )
            new_sha = result.stdout.strip()
            assert new_sha != initial_sha, "Should have new commit"

            # Manually trigger mirror update (simulating what should happen
            # before each conversation creation)
            service.repo_handlers[
                "test"
            ].conversation_manager.mirror.update_mirror()

            # Verify mirror now has new commit
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=mirror_path,
                check=True,
                capture_output=True,
                text=True,
            )
            mirror_sha_after = result.stdout.strip()
            assert mirror_sha_after == new_sha, (
                f"Mirror should have updated to new commit. "
                f"Expected {new_sha}, got {mirror_sha_after}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_mirror_updated_between_conversations(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that git mirror itself is updated between conversations.

        This test specifically checks that the git mirror (not just the
        conversation workspaces) reflects changes made to master repo
        between conversation creations, WITHOUT restarting the service.

        THIS TEST SHOULD FAIL before the fix is implemented.
        """
        # Create initial commit
        test_file = integration_env.master_repo / "mirror_test.txt"
        test_file.write_text("Initial")

        subprocess.run(
            ["git", "add", "mirror_test.txt"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Initial version"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
        )

        # Get initial commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=integration_env.master_repo,
            check=True,
            capture_output=True,
            text=True,
        )
        initial_sha = result.stdout.strip()

        # Start service
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Poll until mirror is initialized
            mirror_path = _poll_for_mirror(integration_env.storage_dir)
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=mirror_path,
                check=True,
                capture_output=True,
                text=True,
            )
            mirror_sha_before = result.stdout.strip()
            assert mirror_sha_before == initial_sha

            # Create first conversation
            mock_code1 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First"),
    generate_result_event(session_id, "Done"),
]
"""
            msg1 = create_email(
                subject="First conversation",
                body=mock_code1,
            )
            integration_env.email_server.inject_message(msg1)

            # Wait for first response
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "First" in get_message_text(m)
                    and "received" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response1 is not None

            # Update master repo (simulating git push after first conversation)
            test_file.write_text("Updated")
            subprocess.run(
                ["git", "add", "mirror_test.txt"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "Update version"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
            )

            # Get new commit SHA
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=integration_env.master_repo,
                check=True,
                capture_output=True,
                text=True,
            )
            new_sha = result.stdout.strip()
            assert new_sha != initial_sha

            # Create second conversation
            mock_code2 = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second"),
    generate_result_event(session_id, "Done"),
]
"""
            msg2 = create_email(
                subject="Second conversation",
                body=mock_code2,
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "Second" in get_message_text(m)
                    and "received" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response2 is not None

            # THE KEY ASSERTION: Check if mirror was updated
            # This will FAIL if mirror.update_mirror() is not called
            # before creating the second conversation
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=mirror_path,
                check=True,
                capture_output=True,
                text=True,
            )
            mirror_sha_after = result.stdout.strip()

            assert mirror_sha_after == new_sha, (
                f"Git mirror should be updated between conversations. "
                f"Expected mirror to have {new_sha}, "
                f"but got {mirror_sha_after}. "
                f"This indicates the mirror is only updated at "
                f"service startup, not before each new conversation."
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
