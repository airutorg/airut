# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for integration tests.

These fixtures provide the test infrastructure needed to run end-to-end
tests of the email gateway service with minimal mocking.
"""

import os
import sys
from collections.abc import Callable, Generator
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import patch


if TYPE_CHECKING:
    from airut.dashboard.tracker import TaskState

import pytest


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from .environment import IntegrationEnvironment


@pytest.fixture(autouse=True)
def _mock_proxy_infra(tmp_path: Path):
    """Mock proxy infrastructure for integration tests.

    Creates fake mitmproxy config directory and CA cert so that
    proxy and network modules work without real infrastructure.

    Also patches XDG state directory so that ``get_storage_dir()``
    returns paths under ``tmp_path`` for test isolation.
    """
    confdir = tmp_path / "mitmproxy-confdir"
    confdir.mkdir(exist_ok=True)
    (confdir / "mitmproxy-ca-cert.pem").write_text("FAKE CA CERT")
    state_dir = tmp_path / "mock_podman_state"
    state_dir.mkdir(exist_ok=True)
    # Redirect XDG state to tmp_path so get_storage_dir("repo_id")
    # returns tmp_path/storage/repo_id instead of ~/.local/state/airut/repo_id
    storage_root = tmp_path / "storage"
    storage_root.mkdir(exist_ok=True)
    with (
        patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", confdir),
        patch("airut.sandbox._network.MITMPROXY_CONFDIR", confdir),
        patch.dict(os.environ, {"MOCK_PODMAN_STATE_DIR": str(state_dir)}),
        patch(
            "airut.gateway.config.user_state_path",
            return_value=storage_root,
        ),
    ):
        yield


# Configure mock_podman for all integration tests
_project_root = Path(__file__).parent.parent.parent.parent
_mock_podman_script = Path(__file__).parent / "mock_podman_wrapper.sh"
MOCK_CONTAINER_COMMAND = str(_mock_podman_script)
# Ensure PYTHONPATH includes project root for module imports
_original_pythonpath = os.environ.get("PYTHONPATH", "")
os.environ["PYTHONPATH"] = (
    f"{_project_root}:{_original_pythonpath}"
    if _original_pythonpath
    else str(_project_root)
)


# Enable socket access for all integration tests
# This overrides the --disable-socket from pyproject.toml
def pytest_collection_modifyitems(items):
    """Add enable_socket marker to all integration tests."""
    for item in items:
        # Only apply to tests in this directory
        if "tests/integration" in str(item.fspath):
            item.add_marker(pytest.mark.enable_socket)


@pytest.fixture
def integration_env(tmp_path: Path) -> Generator[IntegrationEnvironment]:
    """Create a complete integration test environment.

    Provides:
    - Git repository for conversations
    - Test email server (SMTP/IMAP)
    - ServerConfig configured for testing

    container_command is set to use mock_podman, which simulates podman
    and runs mock_claude for responses.

    Yields:
        IntegrationEnvironment with all components started.
    """
    # Create and start environment
    env = IntegrationEnvironment.create(
        tmp_path,
        authorized_senders=["user@test.local"],
        container_command=MOCK_CONTAINER_COMMAND,
    )

    try:
        yield env
    finally:
        # Clean up
        env.cleanup()


@pytest.fixture
def create_email() -> Callable[..., MIMEMultipart | MIMEText]:
    """Factory fixture for creating test email messages.

    Returns a function that creates email messages with the specified
    parameters. Messages include the necessary headers for processing
    by the email gateway.

    Example:
        def test_something(create_email):
            msg = create_email(
                subject="Help with task",
                body="Please do something",
                sender="user@test.local",
            )
    """

    def _create(
        subject: str,
        body: str,
        sender: str = "user@test.local",
        recipient: str = "claude@test.local",
        message_id: str | None = None,
        in_reply_to: str | None = None,
        references: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        authentication_results: str = "test.local; dmarc=pass; spf=pass",
    ) -> MIMEMultipart | MIMEText:
        """Create a test email message.

        Args:
            subject: Email subject line.
            body: Plain text body.
            sender: From address.
            recipient: To address.
            message_id: Message-ID header (auto-generated if not provided).
            in_reply_to: In-Reply-To header for threading.
            references: References header values for threading.
            attachments: List of (filename, content, mimetype) tuples.
            authentication_results: Authentication-Results header value.

        Returns:
            Email message ready for injection into test server.
        """
        import time

        if attachments:
            msg: MIMEMultipart | MIMEText = MIMEMultipart("mixed")
            msg.attach(MIMEText(body, "plain"))

            for filename, content, mimetype in attachments:
                maintype, subtype = mimetype.split("/", 1)
                part = MIMEBase(maintype, subtype)
                part.set_payload(content)
                part.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=filename,
                )
                msg.attach(part)
        else:
            msg = MIMEText(body, "plain")

        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["Message-ID"] = (
            message_id or f"<test-{int(time.time() * 1000)}@test.local>"
        )
        if authentication_results:
            msg["Authentication-Results"] = authentication_results

        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to

        if references:
            msg["References"] = " ".join(references)

        return msg

    return _create


@pytest.fixture
def wait_for_response(
    integration_env: IntegrationEnvironment,
) -> Callable[..., Any]:
    """Fixture that provides a helper to wait for email responses.

    Returns a function that waits for a response email matching
    the given criteria.

    Example:
        def test_something(integration_env, wait_for_response):
            # Send email and wait for response
            response = wait_for_response(
                lambda m: "started working" in get_message_text(m).lower()
            )
    """

    def _wait(
        predicate: Callable[[Any], bool] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Wait for a response email.

        Args:
            predicate: Function to match messages.
            timeout: Maximum time to wait.

        Returns:
            The matching message.

        Raises:
            TimeoutError: If no matching message arrives within timeout.
        """
        msg = integration_env.email_server.wait_for_sent(predicate, timeout)
        if msg is None:
            raise TimeoutError(f"No matching email received within {timeout}s")
        return msg

    return _wait


@pytest.fixture
def extract_conversation_id() -> Callable[[str], str | None]:
    """Fixture that provides a helper to extract conversation ID from subject.

    Returns a function that extracts the [ID:xxxxxxxx] pattern from
    email subjects.
    """
    import re

    def _extract(subject: str) -> str | None:
        """Extract conversation ID from subject line.

        Args:
            subject: Email subject line.

        Returns:
            The 8-character hex conversation ID, or None if not found.
        """
        match = re.search(r"\[ID:([a-f0-9]{8})\]", subject, re.IGNORECASE)
        return match.group(1) if match else None

    return _extract


def find_task_for_conversation(tracker, conv_id: str):
    """Find the most recent task for a conversation.

    Uses ``get_tasks_for_conversation`` to look up tasks by
    ``conversation_id`` since the tracker is keyed by ``task_id``
    (which tests cannot predict).

    Args:
        tracker: TaskTracker instance.
        conv_id: Conversation ID to look up.

    Returns:
        The most recent TaskState for the conversation, or None.
    """
    tasks = tracker.get_tasks_for_conversation(conv_id)
    return tasks[0] if tasks else None


def wait_for_conv_completion(
    tracker,
    conv_id: str,
    timeout: float = 10.0,
) -> "TaskState | None":
    """Wait for the most recent task in a conversation to complete.

    Polls ``get_tasks_for_conversation`` until the newest task reaches
    COMPLETED status, using the tracker's version clock for efficient
    wakeups.

    Args:
        tracker: TaskTracker instance.
        conv_id: Conversation ID to wait for.
        timeout: Maximum seconds to wait.

    Returns:
        The completed TaskState, or None on timeout.
    """
    import time

    deadline = time.monotonic() + timeout
    while True:
        tasks = tracker.get_tasks_for_conversation(conv_id)
        if tasks and tasks[0].status.value == "completed":
            return tasks[0]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # Return whatever we have
            return tasks[0] if tasks else None
        time.sleep(min(0.1, remaining))


def get_message_text(msg: MIMEMultipart | MIMEText | Any) -> str:
    """Extract text content from an email message.

    Handles both simple text messages and multipart messages.
    """
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    parts.append(payload.decode("utf-8", errors="replace"))
        return "\n".join(parts)
    else:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")
        return str(payload) if payload else ""
