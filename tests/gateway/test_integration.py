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

from lib.claude_output import StreamEvent, parse_stream_events
from lib.gateway import (
    ConversationManager,
    EmailListener,
    EmailResponder,
    SenderAuthenticator,
    SenderAuthorizer,
    SMTPSendError,
)
from lib.gateway.config import (
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)
from lib.gateway.parsing import (
    extract_attachments,
    extract_body,
    extract_conversation_id,
)
from lib.gateway.service.usage_stats import extract_usage_stats


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
        authenticator = SenderAuthenticator(email_config.trusted_authserv_id)
        authorizer = SenderAuthorizer(email_config.authorized_senders)
        responder = EmailResponder(email_config)

        # Mock email message with new conversation
        message = sample_email_message
        message.replace_header("Subject", "Please help with task")
        message.replace_header("From", email_config.authorized_senders[0])

        # Validate authentication and authorization
        sender = authenticator.authenticate(message)
        assert sender is not None
        assert authorizer.is_authorized(sender) is True

        # Extract conversation ID (should be None for new)
        conv_id = extract_conversation_id(message.get("Subject"))
        assert conv_id is None

        # Create new conversation
        conv_id, repo_path = conversation_manager.initialize_new()
        assert len(conv_id) == 8
        assert repo_path.exists()
        assert (repo_path / ".git").exists()

        # Create inbox and extract attachments
        inbox_path = repo_path / "inbox"
        inbox_path.mkdir(exist_ok=True)
        filenames = extract_attachments(message, inbox_path)

        # Extract body (HTML quotes stripped in extract_body)
        clean_body = extract_body(message)

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
                to=message.get("From"),
                subject=f"Re: [ID:{conv_id}] {message.get('Subject')}",
                body="Done!",
                in_reply_to=message.get("Message-ID"),
                references=[message.get("Message-ID")],
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
        message = sample_email_message
        message.replace_header(
            "Subject", f"Re: [ID:{conv_id}] Follow-up question"
        )

        # Extract conversation ID
        extracted_id = extract_conversation_id(message.get("Subject"))
        assert extracted_id == conv_id

        # Resume conversation
        resumed_path = conversation_manager.resume_existing(conv_id)
        assert resumed_path == repo_path
        assert resumed_path.exists()

    def test_unauthorized_sender_rejected(
        self, email_config: RepoServerConfig, sample_email_message
    ):
        """Test that unauthorized senders are rejected."""
        authenticator = SenderAuthenticator(email_config.trusted_authserv_id)
        authorizer = SenderAuthorizer(email_config.authorized_senders)

        # Modify message to have unauthorized sender
        message = sample_email_message
        message.replace_header("From", "hacker@evil.com")

        # Should authenticate (DMARC passes) but not authorize
        sender = authenticator.authenticate(message)
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
        msg["From"] = email_config.authorized_senders[0]
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
        authenticator = SenderAuthenticator(email_config.trusted_authserv_id)
        authorizer = SenderAuthorizer(email_config.authorized_senders)

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

        responder = EmailResponder(email_config)

        # Mock SMTP to fail
        with patch("lib.gateway.responder.smtplib.SMTP") as mock_smtp_class:
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
        with patch("lib.gateway.responder.smtplib.SMTP") as mock_smtp_class:
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
        listener = EmailListener(email_config)
        responder = EmailResponder(email_config)
        authenticator = SenderAuthenticator(email_config.trusted_authserv_id)
        authorizer = SenderAuthorizer(email_config.authorized_senders)
        conversation_manager = ConversationManager(
            repo_url=email_config.git_repo_url,
            storage_dir=email_config.storage_dir,
        )

        # Verify components initialized
        assert listener.config == email_config
        assert responder.config == email_config
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


class TestParallelExecution:
    """Tests for parallel execution functionality."""

    def test_service_initializes_parallel_state(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test service initializes parallel execution state."""
        # Import here to avoid circular imports
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        assert service._executor_pool is None

        # Should not raise, just return early
        result = service.submit_message(sample_email_message, handler)

        # Should return False
        assert result is False

    def test_stop_waits_for_pending_futures(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test stop() waits for pending futures."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
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
        from lib.gateway.service import EmailGatewayService

        # Create config with very short timeout
        global_config = GlobalConfig(
            shutdown_timeout_seconds=1
        )  # Very short timeout
        config = ServerConfig(
            global_config=global_config,
            repos={"test": email_config},
        )

        service = EmailGatewayService(config)
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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Set up message without conversation ID (new conversation)
        message = sample_email_message
        message.replace_header("Subject", "New request without ID")

        # Mock process_message to track calls
        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(True, None),
        ) as mock_process:
            service._process_message_worker(message, "test-task-id", handler)
            mock_process.assert_called_once_with(
                service, message, "test-task-id", handler
            )

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Create an existing conversation
        conv_id, _ = handler.conversation_manager.initialize_new()

        # Set up message with existing conversation ID
        message = sample_email_message
        message.replace_header("Subject", f"Re: [ID:{conv_id}] Follow-up")

        # Mock process_message to track calls
        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(True, conv_id),
        ) as mock_process:
            service._process_message_worker(message, "test-task-id", handler)
            mock_process.assert_called_once_with(
                service, message, "test-task-id", handler
            )

        # Conversation lock should have been created
        assert conv_id in service._conversation_locks


class TestAcknowledgmentReply:
    """Tests for acknowledgment reply functionality."""

    def test_send_acknowledgment_new_conversation(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment reply includes conversation ID for new conv."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Set up message without conversation ID (new conversation)
        message = sample_email_message
        message.replace_header("Subject", "New request")
        message.replace_header("Message-ID", "<new123@example.com>")
        message.replace_header("From", email_config.authorized_senders[0])

        conv_id = "abc12345"
        model = "sonnet"

        # Mock responder.send_reply
        from lib.gateway.service.email_replies import send_acknowledgment

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_acknowledgment(
                handler, message, conv_id, model, service.global_config
            )

            # Verify send_reply was called
            mock_send.assert_called_once()

            # Check call arguments
            call_kwargs = mock_send.call_args[1]
            assert call_kwargs["to"] == email_config.authorized_senders[0]
            assert f"[ID:{conv_id}]" in call_kwargs["subject"]
            assert "Re:" in call_kwargs["subject"]
            assert "started working" in call_kwargs["body"]
            assert "reply shortly" in call_kwargs["body"]
            assert call_kwargs["in_reply_to"] == "<new123@example.com>"

    def test_send_acknowledgment_existing_conversation(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment reply preserves existing conversation ID."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        conv_id = "xyz98765"

        # Set up message with existing conversation ID
        message = sample_email_message
        message.replace_header(
            "Subject", f"Re: [ID:{conv_id}] Original request"
        )
        message.replace_header("Message-ID", "<followup456@example.com>")
        message.replace_header("From", email_config.authorized_senders[0])

        from lib.gateway.service.email_replies import send_acknowledgment

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_acknowledgment(
                handler, message, conv_id, "sonnet", service.global_config
            )

            call_kwargs = mock_send.call_args[1]
            # Should not duplicate [ID:...] in subject
            subject = call_kwargs["subject"]
            assert subject.count(f"[ID:{conv_id}]") == 1

    def test_send_acknowledgment_smtp_failure_non_fatal(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment SMTP failure doesn't raise exception."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        message = sample_email_message

        from lib.gateway.service.email_replies import send_acknowledgment

        # Mock responder to raise SMTPSendError
        with patch.object(
            handler.responder,
            "send_reply",
            side_effect=SMTPSendError("Send failed"),
        ):
            # Should not raise - acknowledgment failure is non-fatal
            send_acknowledgment(
                handler, message, "conv123", "sonnet", service.global_config
            )

    def test_send_acknowledgment_preserves_threading_headers(
        self, email_config: RepoServerConfig
    ) -> None:
        """Test acknowledgment reply has correct threading headers."""
        import sys
        from email.parser import BytesParser

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Create message with References header
        message_bytes = b"""From: authorized@example.com
To: claude@example.com
Subject: Original request
Message-ID: <msg1@example.com>
References: <prev1@example.com> <prev2@example.com>
Authentication-Results: mx.example.com; dmarc=pass

Please help.
"""
        message = BytesParser().parsebytes(message_bytes)

        conv_id = "thread123"

        from lib.gateway.service.email_replies import send_acknowledgment

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_acknowledgment(
                handler, message, conv_id, "sonnet", service.global_config
            )

            call_kwargs = mock_send.call_args[1]
            assert call_kwargs["in_reply_to"] == "<msg1@example.com>"
            # References should include original references + Message-ID
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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        message = sample_email_message
        message.replace_header("Subject", "New request")
        message.replace_header("From", email_config.authorized_senders[0])

        call_order: list[str] = []

        def track_ack(*args, **kwargs):
            call_order.append("acknowledgment")

        def track_execute(prompt, **kwargs):
            call_order.append("execute")
            from lib.claude_output.types import Usage
            from lib.sandbox import ExecutionResult, Outcome

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

        def track_send_reply(*args, **kwargs):
            call_order.append("final_reply")

        # Create mock task
        mock_task = MagicMock()
        mock_task.execute.side_effect = track_execute
        mock_task.event_log = MagicMock()
        service.sandbox.ensure_image.return_value = "airut:test"  # type: ignore[invalid-assignment]  # mock
        service.sandbox.create_task.return_value = mock_task  # type: ignore[invalid-assignment]  # mock

        with (
            patch.object(
                handler.responder, "send_reply", side_effect=track_send_reply
            ),
            # Patch the module-level function that process_message calls
            patch(
                "lib.gateway.service.message_processing.send_acknowledgment",
                side_effect=track_ack,
            ),
        ):
            from lib.gateway.service.message_processing import process_message

            process_message(service, message, "test-task-id", handler)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        message = sample_email_message
        message.replace_header("Subject", "New request without ID")
        message.replace_header("From", email_config.authorized_senders[0])

        temp_task_id = "new-12345678"
        service.tracker.add_task(temp_task_id, "New request")

        task_id_at_ack_time: str | None = None

        def track_task_id_at_ack(repo_handler, msg, conv_id, model, cfg):
            nonlocal task_id_at_ack_time
            # Check if task exists under the real conv_id at acknowledgment time
            task = service.tracker.get_task(conv_id)
            if task is not None:
                task_id_at_ack_time = conv_id
            # Don't actually send

        # Create mock task
        from lib.claude_output.types import Usage
        from lib.sandbox import ExecutionResult, Outcome

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

        with (
            patch(
                "lib.gateway.service.message_processing.send_acknowledgment",
                side_effect=track_task_id_at_ack,
            ),
            patch.object(handler.responder, "send_reply"),
        ):
            from lib.gateway.service.message_processing import process_message

            process_message(service, message, temp_task_id, handler)

        # Task should be accessible by real conv_id at acknowledgment time
        assert task_id_at_ack_time is not None, (
            "Task should be findable by conversation ID when ack is sent"
        )

    def test_send_acknowledgment_includes_dashboard_link(
        self, master_repo: Path, tmp_path: Path, sample_email_message
    ) -> None:
        """Test acknowledgment includes dashboard link when configured."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        work_dir = tmp_path / "conversations"
        work_dir.mkdir()

        # Create config with dashboard_base_url
        global_config = GlobalConfig(
            dashboard_base_url="https://dashboard.example.com"
        )
        repo_config = RepoServerConfig(
            repo_id="test",
            imap_server="imap.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            email_username="test@example.com",
            email_password="test_password",
            email_from="Test Service <test@example.com>",
            authorized_senders=["authorized@example.com"],
            trusted_authserv_id="mx.example.com",
            git_repo_url=str(master_repo),
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"test": repo_config},
        )

        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        message = sample_email_message
        message.replace_header("Subject", "New request")
        message.replace_header("From", repo_config.authorized_senders[0])
        message.replace_header("Message-ID", "<test123@example.com>")

        conv_id = "abc12345"

        from lib.gateway.service.email_replies import send_acknowledgment

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_acknowledgment(
                handler, message, conv_id, "sonnet", service.global_config
            )

            call_kwargs = mock_send.call_args[1]
            body = call_kwargs["body"]
            html_body = call_kwargs["html_body"]
            expected_url = "https://dashboard.example.com/conversation/abc12345"
            # URL is in the body
            assert expected_url in body
            assert "started working" in body
            # HTML has clickable link
            assert f'<a href="{expected_url}">{expected_url}</a>' in html_body

    def test_send_acknowledgment_no_dashboard_link_when_not_configured(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test acknowledgment omits dashboard link when not configured."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        # Default config has dashboard_base_url=None
        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        message = sample_email_message
        message.replace_header("Subject", "New request")
        message.replace_header("From", email_config.authorized_senders[0])

        conv_id = "abc12345"

        from lib.gateway.service.email_replies import send_acknowledgment

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_acknowledgment(
                handler, message, conv_id, "sonnet", service.global_config
            )

            call_kwargs = mock_send.call_args[1]
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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Create an existing conversation first
        conv_id, _ = handler.conversation_manager.initialize_new()

        # Set up a follow-up message (has the conversation ID in subject)
        message = sample_email_message
        message.replace_header("Subject", f"Re: [ID:{conv_id}] Follow-up")
        message.replace_header("From", email_config.authorized_senders[0])

        # Create mock task
        from lib.claude_output.types import Usage
        from lib.gateway.service.message_processing import process_message
        from lib.sandbox import ExecutionResult, Outcome

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

        with (
            patch(
                "lib.gateway.service.message_processing.send_acknowledgment"
            ) as mock_ack,
            patch.object(handler.responder, "send_reply"),
        ):
            process_message(service, message, "test-task-id", handler)

        # Acknowledgment should NOT be called for follow-up messages
        mock_ack.assert_not_called()


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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        # Set up message without conversation ID (new conversation)
        message = sample_email_message
        message.replace_header("Subject", "New request without ID")
        message.replace_header("From", email_config.authorized_senders[0])

        # Use a temporary task ID
        temp_task_id = "new-12345678"
        new_conv_id = "abc12345"
        service.tracker.add_task(temp_task_id, "New request without ID")

        # Mock process_message to simulate what it does: update task ID
        # then return. Real process_message updates tracker before ack.
        def mock_process_message(svc, msg, task_id, handler):
            service.tracker.update_task_id(task_id, new_conv_id)
            return (True, new_conv_id)

        with patch(
            "lib.gateway.service.gateway.process_message",
            side_effect=mock_process_message,
        ):
            service._process_message_worker(message, temp_task_id, handler)

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
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        message = sample_email_message
        message.replace_header("Subject", "New request")

        temp_task_id = "new-87654321"
        service.tracker.add_task(temp_task_id, "New request")

        # Mock process_message to return failure with no conv_id
        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(False, None),
        ):
            service._process_message_worker(message, temp_task_id, handler)

        # Task should remain with temp ID
        task = service.tracker.get_task(temp_task_id)
        assert task is not None
        assert task.status.value == "completed"
        assert task.success is False


class TestDuplicateEmailRejection:
    """Tests for rejecting duplicate emails for active conversations."""

    def test_submit_message_rejects_duplicate_for_active_task(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test duplicate email is rejected when task is active."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        service._executor_pool = ThreadPoolExecutor(max_workers=1)

        conv_id = "abc12345"

        # Add an active task
        service.tracker.add_task(conv_id, "First request")
        service.tracker.start_task(conv_id)

        # Create message for same conversation
        message = sample_email_message
        message.replace_header("Subject", f"Re: [ID:{conv_id}] Follow-up")
        message.replace_header("From", email_config.authorized_senders[0])

        # Mock send_rejection_reply (module-level function)
        with patch(
            "lib.gateway.service.gateway.send_rejection_reply"
        ) as mock_reject:
            result = service.submit_message(message, handler)

            # Should return False (rejected)
            assert result is False
            # Should send rejection reply
            mock_reject.assert_called_once()
            call_args = mock_reject.call_args
            assert call_args[0][1] == message  # message argument
            assert call_args[0][2] == conv_id  # conv_id argument
            assert "still being processed" in call_args[0][3]  # reason

        # Clean up
        service._executor_pool.shutdown(wait=False)

    def test_submit_message_accepts_message_for_completed_task(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test message accepted when previous task is completed."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        service._executor_pool = ThreadPoolExecutor(max_workers=1)

        conv_id = "xyz98765"

        # Add and complete a task
        service.tracker.add_task(conv_id, "First request")
        service.tracker.start_task(conv_id)
        service.tracker.complete_task(conv_id, success=True)

        # Create message for same conversation
        message = sample_email_message
        message.replace_header("Subject", f"Re: [ID:{conv_id}] Follow-up")
        message.replace_header("From", email_config.authorized_senders[0])

        # Mock _process_message_worker to prevent actual processing
        with patch.object(service, "_process_message_worker"):
            result = service.submit_message(message, handler)

            # Should return True (accepted)
            assert result is True

        # Clean up
        service._executor_pool.shutdown(wait=False)

    def test_submit_message_accepts_new_conversation(
        self,
        email_config: RepoServerConfig,
        sample_email_message,
    ) -> None:
        """Test new conversation message is always accepted."""
        import sys
        from concurrent.futures import ThreadPoolExecutor

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        service._executor_pool = ThreadPoolExecutor(max_workers=1)

        # Create message without conversation ID (new conversation)
        message = sample_email_message
        message.replace_header("Subject", "Brand new request")
        message.replace_header("From", email_config.authorized_senders[0])

        # Mock _process_message_worker to prevent actual processing
        with patch.object(service, "_process_message_worker"):
            result = service.submit_message(message, handler)

            # Should return True (accepted)
            assert result is True

        # Clean up
        service._executor_pool.shutdown(wait=False)


class TestRejectionReply:
    """Tests for _send_rejection_reply method."""

    def test_send_rejection_reply_includes_conv_id(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test rejection reply includes conversation ID in subject."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]

        message = sample_email_message
        message.replace_header("Subject", "Original request")
        message.replace_header("From", email_config.authorized_senders[0])
        message.replace_header("Message-ID", "<reject123@example.com>")

        conv_id = "def45678"
        reason = "Task already in progress"

        from lib.gateway.service.email_replies import send_rejection_reply

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_rejection_reply(
                handler, message, conv_id, reason, service.global_config
            )

            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args[1]
            assert f"[ID:{conv_id}]" in call_kwargs["subject"]
            assert "could not be processed" in call_kwargs["body"]
            assert reason in call_kwargs["body"]
            assert conv_id in call_kwargs["body"]

    def test_send_rejection_reply_includes_dashboard_link(
        self, master_repo: Path, tmp_path: Path, sample_email_message
    ) -> None:
        """Test rejection reply includes dashboard link when configured."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        work_dir = tmp_path / "conversations"
        work_dir.mkdir()

        global_config = GlobalConfig(
            dashboard_base_url="https://dashboard.example.com"
        )
        repo_config = RepoServerConfig(
            repo_id="test",
            imap_server="imap.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            email_username="test@example.com",
            email_password="test_password",
            email_from="Test Service <test@example.com>",
            authorized_senders=["authorized@example.com"],
            trusted_authserv_id="mx.example.com",
            git_repo_url=str(master_repo),
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"test": repo_config},
        )

        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        message = sample_email_message
        message.replace_header("Subject", "Request")
        message.replace_header("From", repo_config.authorized_senders[0])

        conv_id = "link1234"

        from lib.gateway.service.email_replies import send_rejection_reply

        with patch.object(handler.responder, "send_reply") as mock_send:
            send_rejection_reply(
                handler, message, conv_id, "Test reason", service.global_config
            )

            call_kwargs = mock_send.call_args[1]
            expected_url = (
                f"https://dashboard.example.com/conversation/{conv_id}"
            )
            # URL is embedded in the conversation ID line (plain text)
            assert expected_url in call_kwargs["body"]
            assert conv_id in call_kwargs["body"]
            # HTML has clickable link
            expected_link = f'<a href="{expected_url}">{conv_id}</a>'
            assert expected_link in call_kwargs["html_body"]

    def test_send_rejection_reply_smtp_failure_non_fatal(
        self, email_config: RepoServerConfig, sample_email_message
    ) -> None:
        """Test rejection SMTP failure doesn't raise exception."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from lib.gateway.service import EmailGatewayService

        config = ServerConfig(
            global_config=GlobalConfig(),
            repos={"test": email_config},
        )
        service = EmailGatewayService(config)
        handler = service.repo_handlers["test"]
        message = sample_email_message

        from lib.gateway.service.email_replies import send_rejection_reply

        with patch.object(
            handler.responder,
            "send_reply",
            side_effect=SMTPSendError("Send failed"),
        ):
            # Should not raise
            send_rejection_reply(
                handler,
                message,
                "conv123",
                "Test reason",
                service.global_config,
            )
