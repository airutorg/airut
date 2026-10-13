# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for the Slack ``sticky_threads`` setting.

With ``sticky_threads: false`` the bot only receives channel messages that
``@``-mention it, so a later mention in an engaged thread replays the
messages posted since the previous mention.  The replay is observed via a
file attached to one of those messages: it reaches the inbox only when the
catch-up ran.
"""

import sys
import threading
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import (
    MOCK_CONTAINER_COMMAND,
    _create_slack_adapter_factory,
    slack_download_patch,
)
from .environment import IntegrationEnvironment


THREAD_ROOT = "1700000000.000100"
SECOND_TS = "1700000000.000300"

FIRST_MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First task done"),
    generate_result_event(session_id, "First complete"),
]
"""

SECOND_MOCK_CODE = """
f = inbox / 'notes.txt'
msg = f"Got notes: {f.read_text()}" if f.exists() else "No notes found"

events = [
    generate_system_event(session_id),
    generate_assistant_event(msg),
    generate_result_event(session_id, "Notes check done"),
]
"""


def _run_two_mentions(env: IntegrationEnvironment) -> str:
    """Mention the bot twice in one thread; return the second reply text.

    Between the two mentions another user posts ``notes.txt`` without
    mentioning the bot.
    """
    server = env.slack_server
    assert server is not None
    server.register_user("U_ALICE", display_name="Alice")
    server.register_user("U_BOB", display_name="Bob")

    with patch(
        "airut.gateway.service.repo_handler.create_adapters",
        new=_create_slack_adapter_factory(env),
    ):
        service = env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        server.wait_for_ready()

        try:
            server.inject_channel_message(
                user_id="U_ALICE",
                text=f"<@U_BOT>\n{FIRST_MOCK_CODE}",
                ts=THREAD_ROOT,
            )
            first = server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and m.contains("first task done")
                ),
                timeout=30.0,
            )
            assert first is not None, "First mention got no reply"

            server.thread_history = [
                {
                    "ts": THREAD_ROOT,
                    "user": "U_ALICE",
                    "text": f"<@U_BOT>\n{FIRST_MOCK_CODE}",
                },
                {
                    "ts": "1700000000.000200",
                    "user": "U_BOB",
                    "subtype": "file_share",
                    "text": "my notes",
                    "files": [
                        {
                            "name": "notes.txt",
                            "url_private_download": (
                                "https://files.slack.com/notes.txt"
                            ),
                        }
                    ],
                },
                {
                    "ts": SECOND_TS,
                    "user": "U_ALICE",
                    "text": f"<@U_BOT>\n{SECOND_MOCK_CODE}",
                },
            ]

            with slack_download_patch(
                {"https://files.slack.com/notes.txt": b"NOTES-BODY"}
            ):
                server.inject_channel_message(
                    user_id="U_ALICE",
                    text=f"<@U_BOT>\n{SECOND_MOCK_CODE}",
                    ts=SECOND_TS,
                    thread_ts=THREAD_ROOT,
                )
                second = server.wait_for_sent(
                    predicate=lambda m: (
                        m.method == "chat_postMessage" and m.contains("notes")
                    ),
                    timeout=30.0,
                )
            assert second is not None, server.get_posted_texts()
            return second.text()
        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestSlackStickyThreads:
    def test_non_sticky_mention_replays_missed_messages(
        self, tmp_path: Path
    ) -> None:
        """A file posted between mentions is delivered with the next one."""
        env = IntegrationEnvironment.create_slack(
            tmp_path,
            container_command=MOCK_CONTAINER_COMMAND,
            sticky_threads=False,
        )
        try:
            reply = _run_two_mentions(env)
        finally:
            env.cleanup()

        assert "Got notes: NOTES-BODY" in reply

    def test_sticky_follow_up_does_not_replay(self, tmp_path: Path) -> None:
        """Default sticky threads already delivered every message: no replay."""
        env = IntegrationEnvironment.create_slack(
            tmp_path,
            container_command=MOCK_CONTAINER_COMMAND,
        )
        try:
            reply = _run_two_mentions(env)
        finally:
            env.cleanup()

        assert "No notes found" in reply
