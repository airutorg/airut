# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack thread mapping garbage collection.

Tests that stale thread-to-conversation mappings are pruned when
``cleanup_conversations`` is called with the active set.
"""

import json
import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.gateway.config import get_storage_dir

from .environment import IntegrationEnvironment


MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("GC test reply"),
    generate_result_event(session_id, "Done"),
]
"""


class TestSlackThreadGC:
    """Test thread mapping garbage collection."""

    def test_stale_thread_mapping_pruned(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Thread mappings for deleted conversations are removed."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=MOCK_CODE,
                thread_ts="1700000000.000070",
            )

            # Wait for reply
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "gc test" in m.kwargs.get("text", "").lower()
                        or any(
                            "gc test" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Read the thread store file
            state_dir = get_storage_dir("test")
            thread_store_path = state_dir / "slack_threads.json"
            assert thread_store_path.exists(), "Thread store file not created"

            with thread_store_path.open() as f:
                mappings = json.load(f)
            assert len(mappings) >= 1, "Expected at least one thread mapping"

            # Call cleanup with an empty active set (simulates all
            # conversations being deleted)
            repo_handler = service.repo_handlers["test"]
            slack_adapter = repo_handler.adapters["slack"]
            slack_adapter.cleanup_conversations(active_conversation_ids=set())

            # Verify the thread store is now empty
            with thread_store_path.open() as f:
                mappings_after = json.load(f)
            assert len(mappings_after) == 0, (
                f"Expected 0 mappings after GC, got {len(mappings_after)}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_active_thread_mapping_preserved(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Thread mappings for active conversations are kept."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_BOB",
                text=MOCK_CODE,
                thread_ts="1700000000.000071",
            )

            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "gc test" in m.kwargs.get("text", "").lower()
                        or any(
                            "gc test" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Read thread store
            state_dir = get_storage_dir("test")
            thread_store_path = state_dir / "slack_threads.json"

            with thread_store_path.open() as f:
                mappings = json.load(f)
            conv_id = list(mappings.values())[0]

            # Call cleanup with the active conversation
            repo_handler = service.repo_handlers["test"]
            slack_adapter = repo_handler.adapters["slack"]
            slack_adapter.cleanup_conversations(
                active_conversation_ids={conv_id}
            )

            # Verify the mapping is preserved
            with thread_store_path.open() as f:
                mappings_after = json.load(f)
            assert len(mappings_after) == 1, (
                f"Expected 1 mapping preserved, got {len(mappings_after)}"
            )
            assert list(mappings_after.values())[0] == conv_id

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
