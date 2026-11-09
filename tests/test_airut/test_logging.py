# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/logging.py."""

import io
import logging

from airut.logging import SecretFilter, configure_logging, get_logger


def _emit(
    level: int,
    msg: str,
    *args: object,
    exc_info: bool = False,
    stack_info: bool = False,
) -> str:
    """Log through a handler with a SecretFilter and return its output.

    The logger stands outside the logging hierarchy, so no other
    handler (such as pytest's capture handlers) sees the record.
    """
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretFilter())
    logger = logging.Logger("test_secret_filter")
    logger.addHandler(handler)
    logger.log(level, msg, *args, exc_info=exc_info, stack_info=stack_info)
    return stream.getvalue()


class TestSecretFilter:
    """Tests for SecretFilter class."""

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
        assert record.getMessage() == "Login with [REDACTED]"

    def test_redacts_in_non_string_args(self) -> None:
        """Secrets inside exceptions and other objects are redacted."""
        SecretFilter.register_secret("password123")
        output = _emit(
            logging.ERROR,
            "Login failed: %s (%r)",
            ValueError("bad password123"),
            {"password": "password123"},
        )
        assert "password123" not in output
        assert output == (
            "Login failed: bad [REDACTED] ({'password': '[REDACTED]'})\n"
        )

    def test_redacts_in_traceback(self) -> None:
        """Secrets in a logged exception's traceback are redacted."""
        SecretFilter.register_secret("password123")
        try:
            raise RuntimeError("cannot log in with password123")
        except RuntimeError:
            output = _emit(logging.ERROR, "Login failed", exc_info=True)
        assert "password123" not in output
        assert "RuntimeError: cannot log in with [REDACTED]" in output
        assert "Traceback (most recent call last)" in output

    def test_redacts_in_stack_info(self) -> None:
        """Secrets in stack info are redacted."""
        SecretFilter.register_secret("test_redacts_in_stack_info")
        output = _emit(logging.INFO, "Here", stack_info=True)
        assert "test_redacts_in_stack_info" not in output
        assert "Stack (most recent call last)" in output

    def test_rendered_message_keeps_percent_signs(self) -> None:
        """A rendered message with % characters is output as-is."""
        SecretFilter.register_secret("password123")
        output = _emit(logging.INFO, "Progress %s: %d%%", "password123", 50)
        assert output == "Progress [REDACTED]: 50%\n"

    def test_malformed_args_are_redacted(self) -> None:
        """Arguments that do not fit the format are still redacted."""
        SecretFilter.register_secret("password123")
        output = _emit(logging.INFO, "Value %d", "password123")
        assert output == (
            "Value %d ('[REDACTED]',) <log format error: TypeError>\n"
        )

    def test_missing_mapping_key_does_not_raise(self) -> None:
        """A mapping without the format's key is logged, not raised."""
        SecretFilter.register_secret("password123")
        output = _emit(logging.INFO, "%(a)s", {"b": "password123"})
        assert output == (
            "%(a)s {'b': '[REDACTED]'} <log format error: KeyError>\n"
        )

    def test_argument_failing_str_does_not_raise(self) -> None:
        """An argument whose str() raises is logged, not raised."""

        class Unprintable:
            def __str__(self) -> str:
                raise RuntimeError("no")

            def __repr__(self) -> str:
                return "<Unprintable password123>"

        SecretFilter.register_secret("password123")
        output = _emit(logging.INFO, "Value %s", Unprintable())
        assert output == (
            "Value %s (<Unprintable [REDACTED]>,) "
            "<log format error: RuntimeError>\n"
        )

    def test_unrepresentable_argument_does_not_raise(self) -> None:
        """When even repr() fails, a placeholder is logged."""

        class Opaque:
            def __str__(self) -> str:
                raise RuntimeError("no")

            def __repr__(self) -> str:
                raise RuntimeError("no")

        SecretFilter.register_secret("password123")
        output = _emit(logging.INFO, "Value %s", Opaque())
        assert output == "<log format error: RuntimeError>\n"

    def test_redacts_repr_escaped_secret(self) -> None:
        """A secret is redacted where repr() escapes it."""
        secret = "line1\nback\\slash 'q' \"dq\""
        SecretFilter.register_secret(secret)
        output = _emit(
            logging.INFO, "%s | %r | %s", secret, secret, {"key": secret}
        )
        assert output == ("[REDACTED] | '[REDACTED]' | {'key': '[REDACTED]'}\n")

    def test_redacts_longer_overlapping_secret_whole(self) -> None:
        """A secret that contains another is redacted in full."""
        SecretFilter.register_secret("abc")
        SecretFilter.register_secret("abcdef")
        output = _emit(logging.INFO, "Key: abcdef")
        assert output == "Key: [REDACTED]\n"

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

    def test_sets_log_level(self) -> None:
        """configure_logging sets the level of Airut's loggers."""
        configure_logging(level=logging.WARNING)
        assert logging.getLogger().level == logging.WARNING
        assert logging.getLogger("airut").level == logging.WARNING

    def test_debug_level_applies_to_airut_only(self) -> None:
        """DEBUG enables Airut's debug logs but not third-party ones.

        Third-party debug output can hold message content: the Slack
        SDK logs every event and request body at DEBUG.
        """
        configure_logging(level=logging.DEBUG)
        assert logging.getLogger("airut.gateway.service").isEnabledFor(
            logging.DEBUG
        )
        assert not logging.getLogger("slack_sdk.web").isEnabledFor(
            logging.DEBUG
        )
        assert logging.getLogger("slack_sdk.web").isEnabledFor(logging.INFO)

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
