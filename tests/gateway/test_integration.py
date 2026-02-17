# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for email gateway service.

Tests the full end-to-end flow with all components:
- Email received → parsed → authorized → conversation managed →
  Claude executed → reply sent
"""

import concurrent.futures
import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.claude_output import StreamEvent, parse_stream_events
from airut.gateway import (
    ConversationManager,
    EmailListener,
    EmailResponder,
    RawMessage,
    SenderAuthenticator,
    SenderAuthorizer,
    SMTPSendError,
)
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)
from airut.gateway.email.parsing import (
    extract_attachments,
    extract_body,
    extract_conversation_id,
)
from airut.gateway.service.usage_stats import extract_usage_stats


class TestEndToEndFlow:
    """Test complete message processing flow."""

    def test_new_conversation_flow(
        self,
        email_config: RepoServerConfig,
        master_repo: Path,
        sample_email_message,
    ):
        """Test processing new conversation from start to finish."""
        # Initialize components
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )
        authenticator = SenderAuthenticator(
            email_config.channel.trusted_authserv_id
        )
        authorizer = SenderAuthorizer(email_config.channel.authorized_senders)
        responder = EmailResponder(email_config.channel)

        # Extract underlying email from RawMessage
        email_msg = sample_email_message.content
        email_msg.replace_header("Subject", "Please help with task")
        email_msg.replace_header(
            "From", email_config.channel.authorized_senders[0]
        )

        # Validate authentication and authorization
        sender = authenticator.authenticate(email_msg)
        assert sender is not None
        assert authorizer.is_authorized(sender) is True

        # Extract conversation ID (should be None for new)
        conv_id = extract_conversation_id(email_msg.get("Subject"))
        assert conv_id is None

        # Create new conversation
        conv_id, repo_path = conversation_manager.initialize_new()
        assert len(conv_id) == 8
        assert repo_path.exists()
        assert (repo_path / ".git").exists()

        # Create inbox and extract attachments
        inbox_path = repo_path / "inbox"
        inbox_path.mkdir(exist_ok=True)
        filenames = extract_attachments(email_msg, inbox_path)

        # Extract body (HTML quotes stripped in extract_body)
        clean_body = extract_body(email_msg)

        # Build prompt
        if filenames:
            prompt = f"Files: {', '.join(filenames)}. {clean_body}"
        else:
            prompt = clean_body

        # Verify we can use the prompt (mock the execution part)
        assert len(prompt) > 0

        # Mock responder send
        with patch.object(responder, "send_reply") as mock_send:
            responder.send_reply(
                to=email_msg.get("From"),
                subject=f"Re: [ID:{conv_id}] {email_msg.get('Subject')}",
                body="Done!",
                in_reply_to=email_msg.get("Message-ID"),
                references=[email_msg.get("Message-ID")],
            )
            mock_send.assert_called_once()

    def test_resume_conversation_flow(
        self,
        email_config: RepoServerConfig,
        master_repo: Path,
        sample_email_message,
    ):
        """Test resuming existing conversation."""
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )

        # Create initial conversation
        conv_id, repo_path = conversation_manager.initialize_new()

        # Simulate follow-up message
        email_msg = sample_email_message.content
        email_msg.replace_header(
            "Subject", f"Re: [ID:{conv_id}] Follow-up question"
        )

        # Extract conversation ID
        extracted_id = extract_conversation_id(email_msg.get("Subject"))
        assert extracted_id == conv_id

        # Resume conversation
        resumed_path = conversation_manager.resume_existing(conv_id)
        assert resumed_path == repo_path
        assert resumed_path.exists()

    def test_unauthorized_sender_rejected(
        self, email_config: RepoServerConfig, sample_email_message
    ):
        """Test that unauthorized senders are rejected."""
        authenticator = SenderAuthenticator(
            email_config.channel.trusted_authserv_id
        )
        authorizer = SenderAuthorizer(email_config.channel.authorized_senders)

        # Modify message to have unauthorized sender
        email_msg = sample_email_message.content
        email_msg.replace_header("From", "hacker@evil.com")

        # Should authenticate (DMARC passes) but not authorize
        sender = authenticator.authenticate(email_msg)
        assert sender is not None
        assert authorizer.is_authorized(sender) is False

    def test_conversation_garbage_collection(
        self, email_config: RepoServerConfig, master_repo: Path
    ):
        """Test garbage collection of old conversations."""
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )

        # Create conversation
        conv_id, repo_path = conversation_manager.initialize_new()

        # Verify exists
        assert conversation_manager.exists(conv_id)

        # Delete (simulate GC)
        result = conversation_manager.delete(conv_id)
        assert result is True
        assert not conversation_manager.exists(conv_id)
        assert not repo_path.exists()

    def test_full_pipeline_with_attachments(
        self, email_config: RepoServerConfig, master_repo: Path
    ):
        """Test full pipeline with email attachments."""
        from email import encoders
        from email.mime.base import MIMEBase
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        # Create email with attachment
        msg = MIMEMultipart()
        msg["From"] = email_config.channel.authorized_senders[0]
        msg["To"] = "claude@example.com"
        msg["Subject"] = "Please process this file"
        msg["Message-ID"] = "<attach123@example.com>"
        msg["Authentication-Results"] = "mx.example.com; dmarc=pass; spf=pass"

        # Add body
        body = MIMEText("Please review the attached document.", "plain")
        msg.attach(body)

        # Add attachment
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(b"test content")
        encoders.encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename="test.txt",
        )
        msg.attach(attachment)

        # Initialize components
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )
        authenticator = SenderAuthenticator(
            email_config.channel.trusted_authserv_id
        )
        authorizer = SenderAuthorizer(email_config.channel.authorized_senders)

        # Validate authentication and authorization
        sender = authenticator.authenticate(msg)
        assert sender is not None
        assert authorizer.is_authorized(sender) is True

        # Create conversation
        conv_id, repo_path = conversation_manager.initialize_new()

        # Create inbox and extract attachments
        inbox_path = repo_path / "inbox"
        inbox_path.mkdir(exist_ok=True)
        filenames = extract_attachments(msg, inbox_path)

        # Verify attachment was saved
        assert len(filenames) == 1
        assert filenames[0] == "test.txt"
        assert (inbox_path / "test.txt").exists()
        assert (inbox_path / "test.txt").read_bytes() == b"test content"


class TestErrorRecovery:
    """Test error handling and recovery."""

    def test_git_clone_failure_handling(self, email_config: RepoServerConfig):
        """Test handling of git clone failures."""
        # Use empty repo URL
        with pytest.raises(ValueError, match="Repository URL cannot be empty"):
            ConversationManager(
                repo_url="",
                storage_dir=email_config.storage_dir,
            )

    def test_smtp_send_retry(self, email_config: RepoServerConfig):
        """Test SMTP send retry on failure."""
        from smtplib import SMTPException

        responder = EmailResponder(email_config.channel)

        # Mock SMTP to fail
        with patch(
            "airut.gateway.email.responder.smtplib.SMTP"
        ) as mock_smtp_class:
            # Create mock that raises exception in send_message
            mock_smtp = MagicMock()
            mock_smtp.__enter__.return_value.send_message.side_effect = (
                SMTPException("Connection refused")
            )
            mock_smtp_class.return_value = mock_smtp

            # Should raise SMTPSendError
            with pytest.raises(SMTPSendError):
                responder.send_reply(
                    to="user@example.com",
                    subject="Test",
                    body="Test body",
                )

        # Now test successful send
        with patch(
            "airut.gateway.email.responder.smtplib.SMTP"
        ) as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp.__enter__.return_value.send_message.return_value = {}
            mock_smtp_class.return_value = mock_smtp

            # Should succeed
            responder.send_reply(
                to="user@example.com",
                subject="Test",
                body="Test body",
            )

    def test_plain_text_body_passed_through(
        self, email_config: RepoServerConfig, sample_email_message
    ):
        """Test that plain text body passes through without stripping."""
        from email.parser import BytesParser

        # Create message with quoted text (no HTML part)
        sample_bytes = b"""From: user@example.com
To: claude@example.com
Subject: Re: Previous discussion
Message-ID: <empty123@example.com>

> On Jan 12, 2026, Claude wrote:
> Previous message content
"""
        message = BytesParser().parsebytes(sample_bytes)

        # Plain text body passes through as-is (LLM handles context)
        body = extract_body(message)
        assert "> On Jan 12, 2026, Claude wrote:" in body

    def test_conversation_age_calculation(
        self, email_config: RepoServerConfig, master_repo: Path
    ):
        """Test conversation age calculation for garbage collection."""
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )

        # Create conversation
        conv_id, repo_path = conversation_manager.initialize_new()

        # Get modification time
        mtime = repo_path.stat().st_mtime
        age_days = (time.time() - mtime) / (24 * 60 * 60)

        # Should be very young (< 1 day)
        assert age_days < 1.0

        # Simulate old conversation by setting mtime to 31 days ago
        old_time = time.time() - (31 * 24 * 60 * 60)
        import os

        os.utime(repo_path, (old_time, old_time))

        # Recalculate age
        mtime = repo_path.stat().st_mtime
        age_days = (time.time() - mtime) / (24 * 60 * 60)

        # Should be old enough for GC (> 30 days)
        assert age_days > 30.0


class TestComponentIntegration:
    """Test integration between different components."""

    def test_config_to_components(
        self,
        email_config: RepoServerConfig,
        master_repo: Path,
    ):
        """Test that config properly initializes all components."""
        # Create all components from config
        listener = EmailListener(email_config.channel)
        responder = EmailResponder(email_config.channel)
        authenticator = SenderAuthenticator(
            email_config.channel.trusted_authserv_id
        )
        authorizer = SenderAuthorizer(email_config.channel.authorized_senders)
        conversation_manager = ConversationManager(
            repo_url=email_config.git_repo_url,
            storage_dir=email_config.storage_dir,
        )

        # Verify components initialized
        assert listener.config == email_config.channel
        assert responder.config == email_config.channel
        assert authenticator.trusted_authserv_id == "mx.example.com"
        # Verify authorizer patterns match config
        assert authorizer.is_authorized("authorized@example.com") is True
        assert conversation_manager.repo_url == email_config.git_repo_url

    def test_conversation_id_roundtrip(
        self, email_config: RepoServerConfig, master_repo: Path
    ):
        """Test conversation ID extraction and embedding in subject."""
        conversation_manager = ConversationManager(
            repo_url=str(master_repo),
            storage_dir=email_config.storage_dir,
        )

        # Create conversation
        conv_id, repo_path = conversation_manager.initialize_new()

        # Build subject with conversation ID
        original_subject = "Help with task"
        reply_subject = f"Re: [ID:{conv_id}] {original_subject}"

        # Extract conversation ID from reply subject
        extracted_id = extract_conversation_id(reply_subject)

        # Should match
        assert extracted_id == conv_id

        # Verify conversation exists (extracted_id can't be None here)
        assert extracted_id is not None
        assert conversation_manager.exists(extracted_id)

    def test_message_threading_headers(self, email_config: RepoServerConfig):
        """Test email threading headers construction."""
        from email.parser import BytesParser

        # Create original message
        sample_bytes = b"""From: user@example.com
To: claude@example.com
Subject: Original request
Message-ID: <msg1@example.com>

Please help.
"""
        _original = BytesParser().parsebytes(sample_bytes)

        # Simulate follow-up with references
        followup_bytes = b"""From: user@example.com
To: claude@example.com
Subject: Re: [ID:abc12345] Original request
Message-ID: <msg2@example.com>
In-Reply-To: <msg1@example.com>
References: <msg1@example.com>

Follow-up question.
"""
        followup = BytesParser().parsebytes(followup_bytes)

        # Extract references from follow-up
        followup_refs = followup.get("References", "").split()

        # Should contain original message ID
        assert "<msg1@example.com>" in followup_refs

        # Extract In-Reply-To
        in_reply_to = followup.get("In-Reply-To")
        assert in_reply_to == "<msg1@example.com>"

    def test_channel_listener_health_status(
        self,
        email_config: RepoServerConfig,
    ) -> None:
        """Listener reports STARTING then CONNECTED after start()."""
        from airut.gateway.channel import ChannelHealth
        from airut.gateway.email.channel_listener import EmailChannelListener

        mock_el = MagicMock()
        cl = EmailChannelListener(
            email_config.channel, email_listener=mock_el, repo_id="test-repo"
        )

        # Before start, status is STARTING
        assert cl.status.health == ChannelHealth.STARTING

        # After start, status is CONNECTED
        with patch.object(cl, "_listener_loop"):
            cl.start(submit=MagicMock(return_value=True))

        assert cl.status.health == ChannelHealth.CONNECTED

        cl.stop()

    def test_submit_callback_chain(
        self,
        email_config: RepoServerConfig,
    ) -> None:
        """Full callback chain: listener → RepoHandler → GatewayService.

        Verifies the wiring from EmailChannelListener's submit callback
        through RepoHandler._submit_message to GatewayService.submit_message.
        Uses the real adapter and listener created by from_config, with
        only the low-level EmailListener mocked for IMAP control.
        """
        from email.parser import BytesParser

        from airut.gateway.email.adapter import EmailChannelAdapter
        from airut.gateway.email.channel_listener import (
            EmailChannelListener,
        )
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # The real adapter has a real EmailChannelListener.
        # Replace its low-level EmailListener with a mock.
        adapter = handler.adapter
        assert isinstance(adapter, EmailChannelAdapter)
        real_listener = adapter.listener
        assert isinstance(real_listener, EmailChannelListener)
        mock_el = MagicMock()
        real_listener._email_listener = mock_el

        # Track calls to service.submit_message
        received: list[RawMessage] = []

        def tracking_submit(
            raw_message: RawMessage, repo_handler: object
        ) -> bool:
            received.append(raw_message)
            return False  # Don't actually process

        mock_submit = MagicMock(side_effect=tracking_submit)

        # Build a test email
        raw_bytes = (
            b"From: user@example.com\r\n"
            b"Subject: Chain test\r\n"
            b"Message-ID: <chain@example.com>\r\n"
            b"\r\nHello"
        )
        msg = BytesParser().parsebytes(raw_bytes)

        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            real_listener._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        with (
            patch("time.sleep"),
            patch.object(
                handler.conversation_manager.mirror,
                "update_mirror",
            ),
            patch.object(
                service,
                "submit_message",
                mock_submit,
            ),
        ):
            handler.start_listener()
            assert real_listener._thread is not None
            real_listener._thread.join(timeout=5)

        # Verify the full chain was invoked
        assert len(received) == 1
        assert received[0].sender == "user@example.com"
        assert received[0].subject == "Chain test"
        assert received[0].content is msg

        # service.submit_message was called with (raw_message, handler)
        mock_submit.assert_called_once()
        assert mock_submit.call_args[0][1] is handler

        real_listener.stop()


class TestParallelExecution:
    """Tests for parallel execution functionality."""

    def test_service_initializes_parallel_state(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test service initializes parallel execution state."""
        # Import here to avoid circular imports
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)

        # Verify parallel state initialized
        assert service._executor_pool is None  # Not initialized until start()
        assert service._pending_futures == set()
        assert service._conversation_locks == {}

    def test_get_conversation_lock_creates_lock(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test _get_conversation_lock creates and returns locks."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)

        # Get lock for new conversation
        lock1 = service._get_conversation_lock("conv123")
        assert isinstance(lock1, threading.Lock)
        assert "conv123" in service._conversation_locks

        # Get same lock again
        lock2 = service._get_conversation_lock("conv123")
        assert lock1 is lock2

        # Get different lock for different conversation
        lock3 = service._get_conversation_lock("conv456")
        assert lock3 is not lock1
        assert "conv456" in service._conversation_locks

    def test_on_future_complete_removes_future(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test _on_future_complete removes future from tracking."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)

        future = concurrent.futures.Future()
        service._pending_futures = {future}

        # Complete the future
        future.set_result(None)

        # Call callback
        service._on_future_complete(future)

        # Future should be removed
        assert future not in service._pending_futures

    def test_on_future_complete_handles_cancelled(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test _on_future_complete handles cancelled futures."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)

        future = concurrent.futures.Future()
        service._pending_futures = {future}

        # Cancel the future
        future.cancel()

        # Call callback - should not raise
        service._on_future_complete(future)

        # Future should be removed
        assert future not in service._pending_futures

    def test_on_future_complete_logs_exception(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test _on_future_complete logs exceptions from futures."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)

        future = concurrent.futures.Future()
        service._pending_futures = {future}

        # Set an exception
        future.set_exception(RuntimeError("Test error"))

        # Call callback - should not raise
        service._on_future_complete(future)

        # Future should be removed
        assert future not in service._pending_futures

    def test_submit_message_without_pool(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test submit_message returns early if pool not initialized."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]
        assert service._executor_pool is None

        result = service.submit_message(sample_email_message, handler)
        assert result is False

    def test_stop_waits_for_pending_futures(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test stop() waits for pending futures."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        service._executor_pool = ThreadPoolExecutor(max_workers=1)

        # Create a future that completes quickly
        completed = []

        def quick_task():
            time.sleep(0.1)
            completed.append(True)

        future = service._executor_pool.submit(quick_task)
        service._pending_futures = {future}

        # Stop should wait for future
        service.stop()

        # Task should have completed
        assert completed == [True]

    def test_stop_cancels_slow_futures(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test stop() cancels futures that exceed timeout."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.service import GatewayService

        # Create config with very short timeout
        global_config = GlobalConfig(
            shutdown_timeout_seconds=1
        )  # Very short timeout
        config = ServerConfig(
            global_config=global_config,
            repos={"test": email_config},
        )

        service = GatewayService(config)
        service._executor_pool = ThreadPoolExecutor(max_workers=1)

        # Create a slow task
        def slow_task():
            time.sleep(10)  # Will exceed timeout

        future = service._executor_pool.submit(slow_task)
        service._pending_futures = {future}

        # Stop should timeout and cancel
        start = time.time()
        service.stop()
        elapsed = time.time() - start

        # Should have waited about 1 second (the timeout)
        assert elapsed < 3  # Should not wait for full 10 seconds

    def test_process_message_worker_no_lock_for_new_conversation(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test _process_message_worker doesn't lock new conversations."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Do something",
            conversation_id=None,
            model_hint=None,
            subject="New request without ID",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        # Mock process_message to track calls
        with patch(
            "airut.gateway.service.gateway.process_message",
            return_value=(True, None),
        ) as mock_process:
            service._process_message_worker(
                sample_email_message, "test-task-id", handler
            )
            mock_process.assert_called_once()
            call_args = mock_process.call_args
            assert call_args[0][0] is service
            assert call_args[0][1] is parsed
            assert call_args[0][2] == "test-task-id"
            assert call_args[0][3] is handler

        # No conversation locks should have been created
        assert len(service._conversation_locks) == 0

    def test_process_message_worker_locks_existing_conversation(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
        master_repo,
    ) -> None:
        """Test _process_message_worker locks existing conversations."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # Create an existing conversation
        conv_id, _ = handler.conversation_manager.initialize_new()

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
            subject=f"Re: [ID:{conv_id}] Follow-up",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        with patch(
            "airut.gateway.service.gateway.process_message",
            return_value=(True, conv_id),
        ) as mock_process:
            service._process_message_worker(
                sample_email_message, "test-task-id", handler
            )
            mock_process.assert_called_once()

        # Conversation lock should have been created
        assert conv_id in service._conversation_locks


class TestAcknowledgmentReply:
    """Tests for acknowledgment reply functionality.

    Tests the EmailChannelAdapter.send_acknowledgment method which replaced
    the standalone replies.py functions.
    """

    def test_send_acknowledgment_new_conversation(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment reply includes conversation ID for new conv."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="New request",
            conversation_id=None,
            model_hint=None,
            original_message_id="<new123@example.com>",
            decoded_subject="New request",
        )

        conv_id = "abc12345"
        adapter.send_acknowledgment(parsed, conv_id, "sonnet", None)

        responder.send_reply.assert_called_once()
        call_kwargs = responder.send_reply.call_args[1]
        assert call_kwargs["to"] == email_config.channel.authorized_senders[0]
        assert f"[ID:{conv_id}]" in call_kwargs["subject"]
        assert "Re:" in call_kwargs["subject"]
        assert "started working" in call_kwargs["body"]
        assert "reply shortly" in call_kwargs["body"]
        assert call_kwargs["in_reply_to"] == "<new123@example.com>"

    def test_send_acknowledgment_existing_conversation(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment reply preserves existing conversation ID."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        conv_id = "xyz98765"
        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
            original_message_id="<followup456@example.com>",
            decoded_subject=f"Re: [ID:{conv_id}] Original request",
        )

        adapter.send_acknowledgment(parsed, conv_id, "sonnet", None)

        call_kwargs = responder.send_reply.call_args[1]
        subject = call_kwargs["subject"]
        assert subject.count(f"[ID:{conv_id}]") == 1

    def test_send_acknowledgment_smtp_failure_non_fatal(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment SMTP failure doesn't raise exception."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        responder.send_reply.side_effect = SMTPSendError("Send failed")
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Request",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Test",
        )

        # Should not raise - acknowledgment failure is non-fatal
        adapter.send_acknowledgment(parsed, "conv123", "sonnet", None)

    def test_send_acknowledgment_preserves_threading_headers(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test acknowledgment reply has correct threading headers."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender="authorized@example.com",
            body="Please help.",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@example.com>",
            original_references=[
                "<prev1@example.com>",
                "<prev2@example.com>",
            ],
            decoded_subject="Original request",
        )

        conv_id = "thread123"
        adapter.send_acknowledgment(parsed, conv_id, "sonnet", None)

        call_kwargs = responder.send_reply.call_args[1]
        assert call_kwargs["in_reply_to"] == "<msg1@example.com>"
        refs = call_kwargs["references"]
        assert "<prev1@example.com>" in refs
        assert "<prev2@example.com>" in refs
        assert "<msg1@example.com>" in refs

    def test_acknowledgment_sent_before_execution(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
        master_repo: Path,
    ) -> None:
        """Test acknowledgment is sent before Claude execution starts."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        call_order: list[str] = []

        def track_ack(*args, **kwargs):
            call_order.append("acknowledgment")

        def track_execute(prompt, **kwargs):
            call_order.append("execute")
            from airut.claude_output.types import Usage
            from airut.sandbox import ExecutionResult, Outcome

            return ExecutionResult(
                outcome=Outcome.SUCCESS,
                session_id="test-session",
                response_text="Done",
                events=[],
                duration_ms=100,
                total_cost_usd=0.01,
                num_turns=1,
                usage=Usage(),
                stdout="",
                stderr="",
                exit_code=0,
            )

        # Create mock task
        mock_task = MagicMock()
        mock_task.execute.side_effect = track_execute
        mock_task.event_log = MagicMock()
        service.sandbox.ensure_image.return_value = "airut:test"  # type: ignore[invalid-assignment]  # mock
        service.sandbox.create_task.return_value = mock_task  # type: ignore[invalid-assignment]  # mock

        # Create mock adapter
        adapter = MagicMock()
        adapter.send_acknowledgment.side_effect = track_ack
        adapter.save_attachments.return_value = []

        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="New request",
            conversation_id=None,
            model_hint=None,
        )

        from airut.gateway.service.message_processing import (
            process_message,
        )

        process_message(service, parsed, "test-task-id", handler, adapter)

        # Verify acknowledgment comes before execution
        assert "acknowledgment" in call_order
        assert "execute" in call_order
        ack_idx = call_order.index("acknowledgment")
        exec_idx = call_order.index("execute")
        assert ack_idx < exec_idx, (
            "Acknowledgment should be sent before execution"
        )

    def test_task_id_updated_before_acknowledgment_sent(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
        master_repo: Path,
    ) -> None:
        """Test task ID is updated in tracker before acknowledgment is sent.

        This ensures the dashboard link in the acknowledgment email works
        immediately, even for new conversations where a temporary "new-..."
        ID is initially assigned.
        """
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        temp_task_id = "new-12345678"
        service.tracker.add_task(temp_task_id, "New request")

        task_id_at_ack_time: str | None = None

        def track_task_id_at_ack(parsed, conv_id, model, dashboard_url):
            nonlocal task_id_at_ack_time
            task = service.tracker.get_task(conv_id)
            if task is not None:
                task_id_at_ack_time = conv_id

        # Create mock task
        from airut.claude_output.types import Usage
        from airut.sandbox import ExecutionResult, Outcome

        mock_task = MagicMock()
        mock_task.execute.return_value = ExecutionResult(
            outcome=Outcome.SUCCESS,
            session_id="test-session",
            response_text="Done",
            events=[],
            duration_ms=100,
            total_cost_usd=0.01,
            num_turns=1,
            usage=Usage(),
            stdout="",
            stderr="",
            exit_code=0,
        )
        mock_task.event_log = MagicMock()
        service.sandbox.ensure_image.return_value = "airut:test"  # type: ignore[invalid-assignment]  # mock
        service.sandbox.create_task.return_value = mock_task  # type: ignore[invalid-assignment]  # mock

        # Create mock adapter
        adapter = MagicMock()
        adapter.send_acknowledgment.side_effect = track_task_id_at_ack
        adapter.save_attachments.return_value = []

        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="New request without ID",
            conversation_id=None,
            model_hint=None,
        )

        from airut.gateway.service.message_processing import (
            process_message,
        )

        process_message(service, parsed, temp_task_id, handler, adapter)

        # Task should be accessible by real conv_id at ack time
        assert task_id_at_ack_time is not None, (
            "Task should be findable by conversation ID when ack is sent"
        )

    def test_send_acknowledgment_includes_dashboard_link(
        self, master_repo: Path, tmp_path: Path, sample_email_message
    ) -> None:
        """Test acknowledgment includes dashboard link when configured."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=EmailChannelConfig(
                imap_server="imap.example.com",
                imap_port=993,
                smtp_server="smtp.example.com",
                smtp_port=587,
                username="test@example.com",
                password="test_password",
                from_address="Test Service <test@example.com>",
                authorized_senders=["authorized@example.com"],
                trusted_authserv_id="mx.example.com",
            ),
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender="authorized@example.com",
            body="New request",
            conversation_id=None,
            model_hint=None,
            original_message_id="<test123@example.com>",
            decoded_subject="New request",
        )

        conv_id = "abc12345"
        dashboard_url = "https://dashboard.example.com"
        adapter.send_acknowledgment(parsed, conv_id, "sonnet", dashboard_url)

        call_kwargs = responder.send_reply.call_args[1]
        body = call_kwargs["body"]
        html_body = call_kwargs["html_body"]
        expected_url = "https://dashboard.example.com/conversation/abc12345"
        assert expected_url in body
        assert "started working" in body
        assert f'<a href="{expected_url}">{expected_url}</a>' in html_body

    def test_send_acknowledgment_no_dashboard_link_when_not_configured(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment omits dashboard link when not configured."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="New request",
            conversation_id=None,
            model_hint=None,
            decoded_subject="New request",
        )

        adapter.send_acknowledgment(parsed, "abc12345", "sonnet", None)

        call_kwargs = responder.send_reply.call_args[1]
        body = call_kwargs["body"]
        assert "Task URL:" not in body

    def test_acknowledgment_skipped_for_followup_messages(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
        master_repo: Path,
    ) -> None:
        """Test acknowledgment is NOT sent for follow-up messages."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # Create an existing conversation first
        conv_id, _ = handler.conversation_manager.initialize_new()

        # Create mock task
        from airut.claude_output.types import Usage
        from airut.gateway.service.message_processing import (
            process_message,
        )
        from airut.sandbox import ExecutionResult, Outcome

        mock_task = MagicMock()
        mock_task.execute.return_value = ExecutionResult(
            outcome=Outcome.SUCCESS,
            session_id="test-session",
            response_text="Done",
            events=[],
            duration_ms=100,
            total_cost_usd=0.01,
            num_turns=1,
            usage=Usage(),
            stdout="",
            stderr="",
            exit_code=0,
        )
        mock_task.event_log = MagicMock()
        service.sandbox.ensure_image.return_value = "airut:test"  # type: ignore[invalid-assignment]  # mock
        service.sandbox.create_task.return_value = mock_task  # type: ignore[invalid-assignment]  # mock

        # Create mock adapter
        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
        )

        process_message(service, parsed, "test-task-id", handler, adapter)

        # Acknowledgment should NOT be called for follow-up msgs
        adapter.send_acknowledgment.assert_not_called()


class TestExtractUsageStats:
    """Tests for extract_usage_stats function."""

    @staticmethod
    def _make_assistant_event(*tool_uses: tuple[str, str]) -> dict:
        """Create an assistant event dict with tool use blocks.

        Args:
            tool_uses: Pairs of (tool_name, tool_id).
        """
        content = [
            {"type": "tool_use", "name": name, "id": tid}
            for name, tid in tool_uses
        ]
        return {
            "type": "assistant",
            "message": {"content": content},
        }

    @staticmethod
    def _make_result_event(total_cost_usd: float = 0.0) -> dict:
        """Create a result event dict with cost."""
        return {
            "type": "result",
            "subtype": "success",
            "session_id": "sess-test",
            "duration_ms": 1000,
            "total_cost_usd": total_cost_usd,
            "num_turns": 1,
            "is_error": False,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
            "result": "Done.",
        }

    @staticmethod
    def _parse_events(*dicts: dict) -> list[StreamEvent]:
        """Convert dicts to typed StreamEvent list via parse_stream_events."""
        stdout = "\n".join(json.dumps(d) for d in dicts)
        return parse_stream_events(stdout)

    def test_extract_usage_stats_empty_events(self) -> None:
        """Test extraction with empty event list."""
        stats = extract_usage_stats([])
        assert stats.total_cost_usd is None
        assert stats.web_search_requests == 0
        assert stats.web_fetch_requests == 0

    def test_extract_usage_stats_with_cost(self) -> None:
        """Test extraction with total_cost_usd from result event."""
        events = self._parse_events(self._make_result_event(0.0123))
        stats = extract_usage_stats(events)
        assert stats.total_cost_usd == 0.0123

    def test_extract_usage_stats_with_web_search(self) -> None:
        """Test extraction with web search tool uses from streaming events."""
        events = self._parse_events(
            self._make_assistant_event(
                ("WebSearch", "1"),
                ("WebSearch", "2"),
            ),
        )
        stats = extract_usage_stats(events)
        assert stats.web_search_requests == 2

    def test_extract_usage_stats_with_web_fetch(self) -> None:
        """Test extraction with web fetch tool uses from streaming events."""
        events = self._parse_events(
            self._make_assistant_event(("WebFetch", "1")),
            self._make_assistant_event(
                ("WebFetch", "2"),
                ("WebFetch", "3"),
            ),
        )
        stats = extract_usage_stats(events)
        assert stats.web_fetch_requests == 3

    def test_extract_usage_stats_full_output(self) -> None:
        """Test extraction with all stats present from streaming events."""
        events = self._parse_events(
            self._make_assistant_event(
                ("WebSearch", "1"),
                ("WebFetch", "2"),
            ),
            self._make_assistant_event(("WebSearch", "3")),
            self._make_result_event(0.05),
        )
        stats = extract_usage_stats(events)
        assert stats.total_cost_usd == 0.05
        assert stats.web_search_requests == 2
        assert stats.web_fetch_requests == 1

    def test_extract_usage_stats_subscription_flag(self) -> None:
        """Test is_subscription flag is passed through."""
        events = self._parse_events(self._make_result_event(0.05))
        stats = extract_usage_stats(events, is_subscription=True)
        assert stats.is_subscription is True
        assert stats.total_cost_usd == 0.05


class TestTaskIdTracking:
    """Tests for task ID tracking and updates."""

    def test_process_message_worker_updates_task_id_for_new_conversation(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
        master_repo: Path,
    ) -> None:
        """Test task ID is updated when new conversation created."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Do something",
            conversation_id=None,
            model_hint=None,
            subject="New request without ID",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        # Use a temporary task ID
        temp_task_id = "new-12345678"
        new_conv_id = "abc12345"
        service.tracker.add_task(temp_task_id, "New request without ID")

        # Mock process_message to simulate what it does: update task ID
        # then return. Real process_message updates tracker before ack.
        def mock_process_message(svc, p, task_id, handler, adapter):
            service.tracker.update_task_id(task_id, new_conv_id)
            return (True, new_conv_id)

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=mock_process_message,
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # Task should have been updated with new ID
        assert service.tracker.get_task(temp_task_id) is None
        task = service.tracker.get_task(new_conv_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is True

    def test_process_message_worker_keeps_task_id_when_no_conv_id(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test task ID unchanged when conv_id is None (e.g., auth failure)."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Do something",
            conversation_id=None,
            model_hint=None,
            subject="New request",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-87654321"
        service.tracker.add_task(temp_task_id, "New request")

        # Mock process_message to return failure with no conv_id
        with patch(
            "airut.gateway.service.gateway.process_message",
            return_value=(False, None),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # Task should remain with temp ID
        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is False


class TestDuplicateMessageRejection:
    """Tests for rejecting duplicate messages for active conversations."""

    def test_rejects_duplicate_for_active_task(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test duplicate message is rejected when task is active."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "abc12345"

        # Add an active task for this conversation
        service.tracker.add_task(conv_id, "First request")
        service.tracker.start_task(conv_id)

        # Worker receives raw msg; adapter returns parsed with same conv_id
        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
        )

        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        task_id = "new-dup"
        service.tracker.add_task(task_id, "(authenticating)")
        service._process_message_worker(sample_email_message, task_id, handler)

        # Should send rejection reply via adapter
        mock_adapter.send_rejection.assert_called_once()
        call_args = mock_adapter.send_rejection.call_args
        assert call_args[0][0] == parsed
        assert call_args[0][1] == conv_id
        assert "still being processed" in call_args[0][2]

        # Task should be marked as failed
        task = service.tracker.get_task(task_id)
        assert task is not None
        assert task.success is False

    def test_accepts_message_for_completed_task(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test message accepted when previous task is completed."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "xyz98765"

        # Add and complete a task
        service.tracker.add_task(conv_id, "First request")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        # Worker receives raw msg; adapter returns parsed with same conv_id
        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
        )

        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        task_id = "new-followup"
        service.tracker.add_task(task_id, "(authenticating)")

        # Mock process_message to prevent actual execution
        with patch(
            "airut.gateway.service.gateway.process_message",
            return_value=(True, conv_id),
        ):
            service._process_message_worker(
                sample_email_message, task_id, handler
            )

        # Should NOT reject — no active task for this conv_id
        mock_adapter.send_rejection.assert_not_called()

        # Task should be completed successfully
        task = service.tracker.get_task(conv_id)
        assert task is not None
        assert task.success is True

    def test_accepts_new_conversation(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test new conversation message is always accepted."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # Worker receives a raw message; adapter returns parsed with no conv_id
        parsed = ParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Brand new request",
            conversation_id=None,
            model_hint=None,
        )

        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        task_id = "new-fresh"
        service.tracker.add_task(task_id, "(authenticating)")

        # Mock process_message to simulate what it does: update task ID
        def mock_process(svc, parsed_msg, tid, handler, adapter):
            service.tracker.update_task_id(tid, "newconv1")
            return (True, "newconv1")

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=mock_process,
        ):
            service._process_message_worker(
                sample_email_message, task_id, handler
            )

        # Should NOT reject — new conversation has no conv_id
        mock_adapter.send_rejection.assert_not_called()

        # Task should be completed successfully with the new conv_id
        task = service.tracker.get_task("newconv1")
        assert task is not None
        assert task.success is True


class TestRejectionReply:
    """Tests for adapter.send_rejection method."""

    def test_send_rejection_includes_conv_id(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test rejection reply includes conversation ID in subject."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Original request",
            conversation_id=None,
            model_hint=None,
            original_message_id="<reject123@example.com>",
            decoded_subject="Original request",
        )

        conv_id = "def45678"
        reason = "Task already in progress"

        adapter.send_rejection(parsed, conv_id, reason, None)

        responder.send_reply.assert_called_once()
        call_kwargs = responder.send_reply.call_args[1]
        assert f"[ID:{conv_id}]" in call_kwargs["subject"]
        assert "could not be processed" in call_kwargs["body"]
        assert reason in call_kwargs["body"]
        assert conv_id in call_kwargs["body"]

    def test_send_rejection_includes_dashboard_link(
        self, master_repo: Path, tmp_path: Path, sample_email_message
    ) -> None:
        """Test rejection reply includes dashboard link when configured."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        email_channel_config = EmailChannelConfig(
            imap_server="imap.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="test@example.com",
            password="test_password",
            from_address="Test Service <test@example.com>",
            authorized_senders=["authorized@example.com"],
            trusted_authserv_id="mx.example.com",
        )
        adapter = EmailChannelAdapter(
            config=email_channel_config,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender="authorized@example.com",
            body="Request",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Request",
        )

        conv_id = "link1234"
        dashboard_url = "https://dashboard.example.com"
        adapter.send_rejection(parsed, conv_id, "Test reason", dashboard_url)

        call_kwargs = responder.send_reply.call_args[1]
        expected_url = f"https://dashboard.example.com/conversation/{conv_id}"
        assert expected_url in call_kwargs["body"]
        assert conv_id in call_kwargs["body"]
        expected_link = f'<a href="{expected_url}">{conv_id}</a>'
        assert expected_link in call_kwargs["html_body"]

    def test_send_rejection_smtp_failure_non_fatal(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test rejection SMTP failure doesn't raise exception."""
        from unittest.mock import MagicMock

        from airut.gateway.email.adapter import (
            EmailChannelAdapter,
            EmailParsedMessage,
        )

        responder = MagicMock()
        responder.send_reply.side_effect = SMTPSendError("Send failed")
        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=responder,
            repo_id="test",
        )

        parsed = EmailParsedMessage(
            sender=email_config.channel.authorized_senders[0],
            body="Request",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Test",
        )

        # Should not raise
        adapter.send_rejection(parsed, "conv123", "Test reason", None)


class TestConversationResumeTaskTracking:
    """Tests for task tracker state during conversation resume.

    Regression: d0bfb11 moved authentication to worker thread and uses
    temporary ``new-XXXX`` task IDs. For resumed conversations,
    ``process_message`` does NOT call ``update_task_id`` (only new
    conversations do). This left the temp task stuck in IN_PROGRESS
    while ``complete_task`` updated the old completed task.
    """

    def test_resume_updates_task_id_from_temp_to_real(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Task ID updates from new-XX to conv_id when resuming conversation."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "aabb1122"

        # Simulate a previously completed conversation
        service.tracker.add_task(conv_id, "Original request")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)
        task = service.tracker.get_task(conv_id)
        assert task is not None
        assert task.status.value == "completed"

        # New message arrives for the same conversation
        parsed = ParsedMessage(
            sender="user@example.com",
            body="Follow-up message",
            conversation_id=conv_id,
            model_hint=None,
            subject="Re: [ID:aabb1122] Follow-up",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-deadbeef"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        # Mock process_message — it returns conv_id but does NOT call
        # update_task_id (because this is an existing conversation).
        # Also patch exists() to simulate the conversation existing.
        with (
            patch(
                "airut.gateway.service.gateway.process_message",
                return_value=(True, conv_id),
            ),
            patch.object(
                handler.conversation_manager, "exists", return_value=True
            ),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # The temporary task should be gone
        assert service.tracker.get_task(temp_task_id) is None

        # The real conv_id task should be completed and successful
        task = service.tracker.get_task(conv_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is True

    def test_resume_task_shows_in_progress_during_execution(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """While executing a resumed conversation, dashboard shows IN_PROGRESS.

        The user should see the task as in_progress under the real conv_id
        during execution, not as completed (stale) or under a temp ID.
        """
        from airut.dashboard.tracker import TaskStatus
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "ccdd4455"

        # Previously completed
        service.tracker.add_task(conv_id, "First request")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        # New message for same conversation
        parsed = ParsedMessage(
            sender="user@example.com",
            body="Another message",
            conversation_id=conv_id,
            model_hint=None,
            subject="Re: [ID:ccdd4455] Another message",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-baadf00d"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        # Capture task state during process_message execution
        task_state_during_execution = {}

        def mock_process(svc, p, task_id, rh, adapter):
            # During execution, check the tracker state
            conv_task = service.tracker.get_task(conv_id)
            temp_task = service.tracker.get_task(temp_task_id)
            task_state_during_execution["conv_task_status"] = (
                conv_task.status if conv_task else None
            )
            task_state_during_execution["temp_task_exists"] = (
                temp_task is not None
            )
            return (True, conv_id)

        with (
            patch(
                "airut.gateway.service.gateway.process_message",
                side_effect=mock_process,
            ),
            patch.object(
                handler.conversation_manager, "exists", return_value=True
            ),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # During execution, conv_id task should have been IN_PROGRESS
        assert (
            task_state_during_execution["conv_task_status"]
            == TaskStatus.IN_PROGRESS
        )
        # The temp task should have been merged (not exist separately)
        assert task_state_during_execution["temp_task_exists"] is False

    def test_resume_failure_marks_conv_id_task_failed(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """When resumed conversation fails, the conv_id task shows failed."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "eeff6677"

        service.tracker.add_task(conv_id, "Original")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Resume me",
            conversation_id=conv_id,
            model_hint=None,
            subject="Re: [ID:eeff6677] Resume",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-cafebabe"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        with (
            patch(
                "airut.gateway.service.gateway.process_message",
                return_value=(False, conv_id),
            ),
            patch.object(
                handler.conversation_manager, "exists", return_value=True
            ),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # Temp task should be gone
        assert service.tracker.get_task(temp_task_id) is None

        # Conv task should show failure
        task = service.tracker.get_task(conv_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is False

    def test_resume_exception_marks_conv_id_task_failed(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Task is completed even when process_message raises on resume."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "11223344"

        service.tracker.add_task(conv_id, "Original")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Resume me",
            conversation_id=conv_id,
            model_hint=None,
            subject="Re: [ID:11223344] Resume",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-d00dd00d"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        with (
            patch(
                "airut.gateway.service.gateway.process_message",
                side_effect=RuntimeError("sandbox crash"),
            ),
            patch.object(
                handler.conversation_manager, "exists", return_value=True
            ),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        # Temp task should be gone
        assert service.tracker.get_task(temp_task_id) is None

        # Conv task should be completed (failed), not stuck in_progress
        task = service.tracker.get_task(conv_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is False

    def test_resume_updates_subject_and_sender(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Resumed conversation updates subject from (authenticating)."""
        from airut.gateway.channel import ParsedMessage
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "55667788"

        service.tracker.add_task(conv_id, "Original subject")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        parsed = ParsedMessage(
            sender="alice@example.com",
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
            subject="Re: [ID:55667788] Original subject",
        )
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.return_value = parsed
        handler.adapter = mock_adapter

        temp_task_id = "new-abcdef01"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        with (
            patch(
                "airut.gateway.service.gateway.process_message",
                return_value=(True, conv_id),
            ),
            patch.object(
                handler.conversation_manager, "exists", return_value=True
            ),
        ):
            service._process_message_worker(
                sample_email_message, temp_task_id, handler
            )

        task = service.tracker.get_task(conv_id)
        assert task is not None
        # Subject should be the real subject, not "(authenticating)"
        assert task.subject == "Re: [ID:55667788] Original subject"
        assert task.sender == "alice@example.com"


class TestUnauthorizedSenderTracking:
    """Tests for task tracker visibility when sender is not authorized.

    Regression: when authenticate_and_parse returns None (unauthorized),
    the task subject stayed as ``(authenticating)`` and the sender was
    never recorded. This made it impossible to see who sent the rejected
    message in the dashboard.
    """

    def test_unauthorized_shows_not_authorized_subject(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Unauthorized message updates subject to '(not authorized)'."""
        from airut.gateway.channel import AuthenticationError
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # Adapter raises AuthenticationError (auth failed)
        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.side_effect = AuthenticationError(
            sender="bad@example.com",
            reason="sender not authorized",
        )
        handler.adapter = mock_adapter

        temp_task_id = "new-unauth01"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        service._process_message_worker(
            sample_email_message, temp_task_id, handler
        )

        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is False
        # Subject should NOT remain "(authenticating)"
        assert task.subject != "(authenticating)"
        assert "(not authorized)" in task.subject
        assert task.sender == "bad@example.com"

    def test_unauthorized_records_sender_from_raw_email(
        self,
        email_config: RepoServerConfig,
    ) -> None:
        """Unauthorized email records the sender address for visibility."""
        from email.parser import BytesParser

        from airut.gateway.email.adapter import EmailChannelAdapter
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        # Build a raw email with a specific From address
        raw_bytes = (
            b"From: hacker@malicious.com\r\n"
            b"To: claude@example.com\r\n"
            b"Subject: Please do something\r\n"
            b"Message-ID: <unauth@example.com>\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass\r\n"
            b"\r\n"
            b"I want access.\r\n"
        )
        email_msg = BytesParser().parsebytes(raw_bytes)

        # Auth passes DMARC but fails authorization
        mock_authenticator = MagicMock()
        mock_authenticator.authenticate.return_value = "hacker@malicious.com"
        mock_authorizer = MagicMock()
        mock_authorizer.is_authorized.return_value = False

        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=mock_authenticator,
            authorizer=mock_authorizer,
            responder=MagicMock(),
            repo_id="test",
        )
        handler.adapter = adapter  # test mock

        temp_task_id = "new-unauth02"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        raw_message = RawMessage(
            sender="hacker@malicious.com",
            content=email_msg,
            subject="Please do something",
        )
        service._process_message_worker(raw_message, temp_task_id, handler)

        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.success is False
        # Sender should be recorded even though auth failed
        assert "hacker@malicious.com" in task.sender

    def test_unauthenticated_dmarc_records_sender(
        self,
        email_config: RepoServerConfig,
    ) -> None:
        """Failed DMARC authentication still records sender for visibility."""
        from email.parser import BytesParser

        from airut.gateway.email.adapter import EmailChannelAdapter
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        raw_bytes = (
            b"From: spoofed@evil.com\r\n"
            b"To: claude@example.com\r\n"
            b"Subject: Spoofed message\r\n"
            b"Message-ID: <spoof@evil.com>\r\n"
            b"Authentication-Results: mx.example.com; dmarc=fail\r\n"
            b"\r\n"
            b"Spoofed content.\r\n"
        )
        email_msg = BytesParser().parsebytes(raw_bytes)

        # DMARC fails
        mock_authenticator = MagicMock()
        mock_authenticator.authenticate.return_value = None

        adapter = EmailChannelAdapter(
            config=email_config.channel,
            authenticator=mock_authenticator,
            authorizer=MagicMock(),
            responder=MagicMock(),
            repo_id="test",
        )
        handler.adapter = adapter  # test mock

        temp_task_id = "new-unauth03"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        raw_message = RawMessage(
            sender="spoofed@evil.com",
            content=email_msg,
            subject="Spoofed message",
        )
        service._process_message_worker(raw_message, temp_task_id, handler)

        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.success is False
        assert "(not authorized)" in task.subject
        assert "spoofed@evil.com" in task.sender

    def test_generic_exception_completes_task(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Non-auth exception completes task but doesn't change subject.

        A generic RuntimeError (e.g. IMAP disconnect) is different from
        an AuthenticationError: we don't know the sender identity, so
        the subject stays as-is and the task is marked failed.
        """
        from airut.gateway.service import GatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = GatewayService(config)
        handler = service.repo_handlers["test"]

        mock_adapter = MagicMock()
        mock_adapter.authenticate_and_parse.side_effect = RuntimeError(
            "IMAP disconnect"
        )
        handler.adapter = mock_adapter

        temp_task_id = "new-crash04"
        service.tracker.add_task(temp_task_id, "(authenticating)")

        service._process_message_worker(
            sample_email_message, temp_task_id, handler
        )

        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.success is False
        # Subject stays as-is — we don't know who sent it
        assert task.subject == "(authenticating)"
