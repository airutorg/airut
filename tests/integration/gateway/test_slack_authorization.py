# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack authorization.

Tests that authorization rules are enforced through the full
gateway pipeline: unauthorized users are rejected, bots are
rejected, and only valid workspace members can interact.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import MOCK_CONTAINER_COMMAND, wait_for_task
from .environment import IntegrationEnvironment


MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Should not reach here"),
    generate_result_event(session_id, "Unreachable"),
]
"""


def _is_unauthorized_task(task, sender: str) -> bool:
    """Check if a task was completed as unauthorized for *sender*."""
    from airut.dashboard.tracker import CompletionReason, TaskStatus

    return (
        task.status == TaskStatus.COMPLETED
        and task.completion_reason
        in (
            CompletionReason.UNAUTHORIZED,
            CompletionReason.AUTH_FAILED,
        )
        and task.sender == sender
    )


class TestSlackAuthorization:
    """Test Slack authorization enforcement."""

    def test_unregistered_user_rejected(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Message from unregistered user (users.info fails) is rejected."""
        assert slack_env.slack_server is not None
        # Do NOT register U_UNKNOWN — users.info will raise SlackApiError

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_UNKNOWN",
                text=MOCK_CODE,
                thread_ts="1700000000.000020",
            )

            task = wait_for_task(
                service.tracker,
                lambda t: _is_unauthorized_task(t, "U_UNKNOWN"),
                timeout=10.0,
            )
            assert task is not None, (
                "Unregistered user should be rejected by tracker"
            )

            # Verify no execution happened
            posted = slack_env.slack_server.get_posted_texts()
            for text in posted:
                assert "should not reach" not in text.lower(), (
                    f"Unauthorized user's code was executed: {text}"
                )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_bot_user_rejected(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Message from a bot user is rejected."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user(
            "U_BOT_USER", display_name="Bot", is_bot=True
        )

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_BOT_USER",
                text=MOCK_CODE,
                thread_ts="1700000000.000021",
            )

            task = wait_for_task(
                service.tracker,
                lambda t: _is_unauthorized_task(t, "U_BOT_USER"),
                timeout=10.0,
            )
            assert task is not None, "Bot user should be rejected by tracker"

            posted = slack_env.slack_server.get_posted_texts()
            for text in posted:
                assert "should not reach" not in text.lower(), (
                    f"Bot user's code was executed: {text}"
                )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_deactivated_user_rejected(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Message from a deactivated user is rejected."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user(
            "U_DEACTIVATED", display_name="Gone", deleted=True
        )

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_DEACTIVATED",
                text=MOCK_CODE,
                thread_ts="1700000000.000022",
            )

            task = wait_for_task(
                service.tracker,
                lambda t: _is_unauthorized_task(t, "U_DEACTIVATED"),
                timeout=10.0,
            )
            assert task is not None, (
                "Deactivated user should be rejected by tracker"
            )

            posted = slack_env.slack_server.get_posted_texts()
            for text in posted:
                assert "should not reach" not in text.lower(), (
                    f"Deactivated user's code was executed: {text}"
                )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_user_id_rule_allows_specific_user(
        self,
        tmp_path: Path,
    ) -> None:
        """user_id authorization rule allows only the specified user."""
        from unittest.mock import patch

        env = IntegrationEnvironment.create_slack(
            tmp_path,
            authorized_rules=({"user_id": "U_SPECIFIC"},),
            container_command=MOCK_CONTAINER_COMMAND,
        )

        assert env.slack_server is not None
        env.slack_server.register_user(
            "U_SPECIFIC", display_name="Specific User"
        )

        try:
            with patch(
                "airut.gateway.service.repo_handler.create_adapters",
                new=_create_slack_adapter_factory_for(env),
            ):
                service = env.create_service()
                service_thread = threading.Thread(
                    target=service.start, daemon=True
                )
                service_thread.start()
                env.slack_server.wait_for_ready()

                try:
                    mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Authorized reply"),
    generate_result_event(session_id, "Done"),
]
"""
                    env.slack_server.inject_user_message(
                        user_id="U_SPECIFIC",
                        text=mock_code,
                        thread_ts="1700000000.000023",
                    )

                    reply = env.slack_server.wait_for_sent(
                        predicate=lambda m: (
                            m.method == "chat_postMessage"
                            and (
                                "authorized reply"
                                in m.kwargs.get("text", "").lower()
                                or any(
                                    "authorized reply"
                                    in b.get("text", "").lower()
                                    for b in m.kwargs.get("blocks", [])
                                    if isinstance(b, dict)
                                )
                            )
                        ),
                        timeout=30.0,
                    )
                    assert reply is not None, "Authorized user should get reply"

                finally:
                    service.stop()
                    service_thread.join(timeout=10.0)
        finally:
            env.cleanup()


def _create_slack_adapter_factory_for(env: IntegrationEnvironment):
    """Import and call conftest helper for standalone test."""
    from .conftest import _create_slack_adapter_factory

    return _create_slack_adapter_factory(env)
