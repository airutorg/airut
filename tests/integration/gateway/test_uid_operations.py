# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration test for IMAP UID-based operations.

Verifies that the email listener correctly processes multiple messages
fetched in a single poll cycle.  When IMAP sequence numbers are used
instead of UIDs, deleting messages mid-loop shifts the sequence numbers
of subsequent messages, causing wrong deletions and "Invalid messageset"
errors.

This test injects three messages simultaneously and asserts that all
three are processed exactly once with the inbox fully drained afterward.
"""

import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestUIDOperations:
    """Test IMAP UID operations for multi-message processing."""

    def test_multiple_messages_all_processed_and_deleted(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Three messages injected at once are each processed once.

        This is a regression test for sequence-number invalidation:
        when sequence numbers are used, deleting message 1 shifts
        the remaining IDs, causing message 2's delete to target
        message 3 instead, leaving message 2 undeleted.  With UIDs
        this does not happen.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed"),
    generate_result_event(session_id, "Done"),
]
"""
        # Inject three messages before starting the service so they
        # are all returned by a single SEARCH UNSEEN call.
        subjects = [
            "UID test message A",
            "UID test message B",
            "UID test message C",
        ]
        for subj in subjects:
            msg = create_email(
                subject=subj,
                body=mock_code,
                message_id=f"<uid-test-{subj[-1].lower()}@test.local>",
            )
            integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait until the inbox is fully drained (all messages
            # fetched AND deleted).  With sequence-number-based
            # operations, at least one message would remain
            # undeleted after the first poll cycle.
            drained = integration_env.email_server.wait_until_inbox_empty(
                timeout=15.0
            )
            assert drained, (
                "Inbox not empty after processing — messages were "
                "not correctly deleted (sequence number invalidation?)"
            )

            # Collect ack messages and extract conversation IDs.
            # Each conversation produces an ack ("started working")
            # followed by a completion response.
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                sent = integration_env.email_server.get_sent_messages()
                acks = [
                    m
                    for m in sent
                    if "started working" in get_message_text(m).lower()
                ]
                completions = [
                    m
                    for m in sent
                    if "completed" in get_message_text(m).lower()
                ]
                if len(acks) >= 3 and len(completions) >= 3:
                    break
                time.sleep(0.2)

            sent = integration_env.email_server.get_sent_messages()
            acks = [
                m
                for m in sent
                if "started working" in get_message_text(m).lower()
            ]
            completions = [
                m for m in sent if "completed" in get_message_text(m).lower()
            ]

            assert len(acks) == 3, f"Expected 3 ack messages, got {len(acks)}"
            assert len(completions) == 3, (
                f"Expected 3 completion responses, got {len(completions)}"
                " — a message was likely processed more than once"
                " due to failed deletion"
            )

            # Extract conversation IDs from acks and verify each
            # conversation received exactly one completion.
            ack_conv_ids = set()
            for ack in acks:
                conv_id = extract_conversation_id(ack["Subject"])
                assert conv_id is not None, (
                    f"No conversation ID in ack subject: {ack['Subject']}"
                )
                ack_conv_ids.add(conv_id)
            assert len(ack_conv_ids) == 3, (
                f"Expected 3 distinct conversations, "
                f"got {len(ack_conv_ids)}: {ack_conv_ids}"
            )

            completion_conv_ids = set()
            for comp in completions:
                conv_id = extract_conversation_id(comp["Subject"])
                assert conv_id is not None, (
                    f"No conversation ID in completion subject: "
                    f"{comp['Subject']}"
                )
                completion_conv_ids.add(conv_id)

            assert completion_conv_ids == ack_conv_ids, (
                f"Completion conversation IDs {completion_conv_ids} "
                f"do not match ack IDs {ack_conv_ids}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
