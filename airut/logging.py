# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Centralized logging configuration with secret redaction.

This module provides logging utilities for Airut,
including automatic redaction of sensitive information like account
numbers, API keys, and credentials.

Usage:
    # In entry points (scripts, CLI tools)
    from airut.logging import configure_logging
    configure_logging(level=logging.INFO)

    # In library modules
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Processing file: %s", filename)
"""

import logging
import re
import threading
from typing import ClassVar


_REDACTED = "[REDACTED]"
"""Text that replaces a registered secret in log output."""

# Parent of every Airut module's logger (``logging.getLogger(__name__)``).
_PACKAGE_LOGGER = "airut"

# Renders exception tracebacks for redaction the way the handlers'
# formatters would.
_EXCEPTION_FORMATTER = logging.Formatter()


def _describe_unrenderable(record: logging.LogRecord, error: Exception) -> str:
    """Stand in for a message whose arguments cannot be rendered.

    Logging would report such a record with its raw arguments, which
    could hold a secret; this text is redacted and output instead.

    Args:
        record: The log record whose message failed to render.
        error: The error rendering raised.

    Returns:
        The format string and arguments, or a placeholder when even
        those cannot be turned into text.
    """
    marker = f"<log format error: {type(error).__name__}>"
    try:
        return f"{record.msg} {record.args!r} {marker}"
    except Exception:
        return marker


class SecretFilter(logging.Filter):
    """Logging filter that redacts registered secrets from log output.

    Secrets can be registered at runtime using register_secret().  The
    filter renders the complete record -- the message with its
    arguments of any type, exception traceback, and stack trace --
    and replaces every registered secret in it with '[REDACTED]', so a
    secret inside an exception or another non-string argument is
    caught too.  Each secret is also matched as ``repr()`` escapes it,
    as it appears inside a container or an exception message.

    Example:
        filter = SecretFilter()
        filter.register_secret("my-api-key-12345")
        handler.addFilter(filter)
        logger.info("Using key: my-api-key-12345")
        # Output: "Using key: [REDACTED]"
    """

    _secrets: ClassVar[set[str]] = set()
    _pattern: ClassVar[re.Pattern[str] | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact registered secrets from everything the record renders.

        Replaces the message and arguments with the redacted rendered
        message, and the exception and stack text with redacted copies,
        which formatters then output as they are.

        Args:
            record: The log record to filter.

        Returns:
            Always True (record is never suppressed, only modified).
        """
        pattern = self._pattern
        if pattern is None:
            return True
        try:
            message = record.getMessage()
        except Exception as e:
            # Filters run outside the handler's error handling: raising
            # here would raise in the code that logged.
            message = _describe_unrenderable(record, e)
        record.msg = pattern.sub(_REDACTED, message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = _EXCEPTION_FORMATTER.formatException(
                record.exc_info
            )
        if record.exc_text:
            record.exc_text = pattern.sub(_REDACTED, record.exc_text)
        if record.stack_info:
            record.stack_info = pattern.sub(_REDACTED, record.stack_info)
        return True

    @classmethod
    def register_secret(cls, secret: str) -> None:
        """Register a secret to be redacted from all log output.

        Args:
            secret: The secret string to redact. Empty strings are ignored.
        """
        if secret:
            with cls._lock:
                cls._secrets.add(secret)
                cls._rebuild_pattern()

    @classmethod
    def clear_secrets(cls) -> None:
        """Clear all registered secrets. Primarily for testing."""
        with cls._lock:
            cls._secrets.clear()
            cls._pattern = None

    @classmethod
    def _rebuild_pattern(cls) -> None:
        """Rebuild the compiled regex pattern from registered secrets.

        Each secret is matched as is and as ``repr()`` escapes it.
        Longer forms come first so that a secret containing another is
        redacted whole rather than around the shorter one.
        """
        if cls._secrets:
            forms = cls._secrets | {repr(s)[1:-1] for s in cls._secrets}
            ordered = sorted(forms, key=len, reverse=True)
            cls._pattern = re.compile("|".join(map(re.escape, ordered)))
        else:
            cls._pattern = None


def configure_logging(
    level: int = logging.INFO,
    format_string: str | None = None,
    add_secret_filter: bool = True,
) -> None:
    """Configure logging for the application.

    Sets up the root logger with a standard format and optional
    secret redaction filter.

    *level* applies to Airut's own loggers.  Third-party libraries log
    at INFO and above even when *level* is DEBUG: their debug output
    can hold message content (the Slack SDK logs every event and
    request body).

    Args:
        level: The logging level (e.g., logging.INFO, logging.DEBUG).
        format_string: Custom format string. If None, uses default format.
        add_secret_filter: Whether to add the SecretFilter to redact secrets.
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(format_string))

    if add_secret_filter:
        handler.addFilter(SecretFilter())

    root_logger = logging.getLogger()
    root_logger.setLevel(max(level, logging.INFO))
    logging.getLogger(_PACKAGE_LOGGER).setLevel(level)

    # Remove existing handlers to avoid duplicates
    for existing_handler in root_logger.handlers[:]:
        root_logger.removeHandler(existing_handler)

    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a module.

    Convenience wrapper around logging.getLogger().

    Args:
        name: The logger name, typically __name__.

    Returns:
        A configured logger instance.
    """
    return logging.getLogger(name)
