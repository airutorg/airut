# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/logging.py."""

import logging

from airut.logging import SecretFilter, configure_logging, get_logger


class TestSecretFilter:
    """Tests for SecretFilter class."""

    def setup_method(self) -> None:
        """Clear secrets before each test."""
        SecretFilter.clear_secrets()

    def teardown_method(self) -> None:
        """Clear secrets after each test."""
        SecretFilter.clear_secrets()

    def test_filter_returns_true(self) -> None:
        """Filter should always return True (never suppress records)."""
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        assert filter_.filter(record) is True

    def test_no_secrets_no_redaction(self) -> None:
        """Without registered secrets, messages pass through unchanged."""
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message with api-key-123",
            args=(),
            exc_info=None,
        )
        filter_.filter(record)
        assert record.msg == "test message with api-key-123"

    def test_redacts_registered_secret(self) -> None:
        """Registered secrets should be redacted from messages."""
        SecretFilter.register_secret("api-key-123")
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Using key: api-key-123",
            args=(),
            exc_info=None,
        )
        filter_.filter(record)
        assert record.msg == "Using key: [REDACTED]"

    def test_redacts_multiple_secrets(self) -> None:
        """Multiple registered secrets should all be redacted."""
        SecretFilter.register_secret("secret1")
        SecretFilter.register_secret("secret2")
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Keys: secret1 and secret2",
            args=(),
            exc_info=None,
        )
        filter_.filter(record)
        assert record.msg == "Keys: [REDACTED] and [REDACTED]"

    def test_redacts_in_args(self) -> None:
        """Secrets in log args should also be redacted."""
        SecretFilter.register_secret("password123")
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login with %s",
            args=("password123",),
            exc_info=None,
        )
        filter_.filter(record)
        assert record.args == ("[REDACTED]",)

    def test_ignores_empty_secret(self) -> None:
        """Empty strings should not be registered as secrets."""
        SecretFilter.register_secret("")
        assert len(SecretFilter._secrets) == 0

    def test_clear_secrets(self) -> None:
        """clear_secrets should remove all registered secrets."""
        SecretFilter.register_secret("secret1")
        SecretFilter.register_secret("secret2")
        SecretFilter.clear_secrets()
        assert len(SecretFilter._secrets) == 0
        assert SecretFilter._pattern is None

    def test_rebuild_pattern_with_empty_secrets(self) -> None:
        """_rebuild_pattern sets pattern to None when secrets empty."""
        # Ensure secrets are empty
        SecretFilter.clear_secrets()
        # Call _rebuild_pattern directly with empty secrets
        SecretFilter._rebuild_pattern()
        assert SecretFilter._pattern is None

    def test_redacts_special_regex_chars(self) -> None:
        """Secrets with regex special characters should be escaped properly."""
        SecretFilter.register_secret("pass[word].*")
        filter_ = SecretFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Secret: pass[word].*",
            args=(),
            exc_info=None,
        )
        filter_.filter(record)
        assert record.msg == "Secret: [REDACTED]"


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def teardown_method(self) -> None:
        """Reset logging after each test."""
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(logging.WARNING)
        SecretFilter.clear_secrets()

    def test_sets_log_level(self) -> None:
        """configure_logging should set the root logger level."""
        configure_logging(level=logging.DEBUG)
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_adds_handler(self) -> None:
        """configure_logging should add a stream handler."""
        configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0], logging.StreamHandler)

    def test_custom_format(self) -> None:
        """configure_logging should accept custom format string."""
        configure_logging(format_string="%(message)s")
        root = logging.getLogger()
        formatter = root.handlers[0].formatter
        assert formatter is not None
        assert formatter._fmt == "%(message)s"

    def test_adds_secret_filter_by_default(self) -> None:
        """Secret filter should be added by default."""
        configure_logging()
        root = logging.getLogger()
        filters = root.handlers[0].filters
        assert any(isinstance(f, SecretFilter) for f in filters)

    def test_can_disable_secret_filter(self) -> None:
        """Secret filter can be disabled."""
        configure_logging(add_secret_filter=False)
        root = logging.getLogger()
        filters = root.handlers[0].filters
        assert not any(isinstance(f, SecretFilter) for f in filters)

    def test_removes_existing_handlers(self) -> None:
        """Calling configure_logging twice should not duplicate handlers."""
        configure_logging()
        configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_logger(self) -> None:
        """get_logger should return a Logger instance."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_same_name_returns_same_logger(self) -> None:
        """Same name should return the same logger instance."""
        logger1 = get_logger("test.same")
        logger2 = get_logger("test.same")
        assert logger1 is logger2
