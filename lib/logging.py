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
    from lib.logging import configure_logging
    configure_logging(level=logging.INFO)

    # In library modules
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Processing file: %s", filename)
"""

import logging
import re
from typing import ClassVar


class SecretFilter(logging.Filter):
    """Logging filter that redacts registered secrets from log output.

    Secrets can be registered at runtime using register_secret().
    Any registered secret appearing in a log message will be replaced
    with '[REDACTED]'.

    Example:
        filter = SecretFilter()
        filter.register_secret("my-api-key-12345")
        logger.addFilter(filter)
        logger.info("Using key: my-api-key-12345")
        # Output: "Using key: [REDACTED]"
    """

    _secrets: ClassVar[set[str]] = set()
    _pattern: ClassVar[re.Pattern[str] | None] = None

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log record by redacting any registered secrets.

        Args:
            record: The log record to filter.

        Returns:
            Always True (record is never suppressed, only modified).
        """
        if self._pattern is not None:
            record.msg = self._pattern.sub("[REDACTED]", str(record.msg))
            if record.args:
                record.args = tuple(
                    self._pattern.sub("[REDACTED]", str(arg))
                    if isinstance(arg, str)
                    else arg
                    for arg in record.args
                )
        return True

    @classmethod
    def register_secret(cls, secret: str) -> None:
        """Register a secret to be redacted from all log output.

        Args:
            secret: The secret string to redact. Empty strings are ignored.
        """
        if secret:
            cls._secrets.add(secret)
            cls._rebuild_pattern()

    @classmethod
    def clear_secrets(cls) -> None:
        """Clear all registered secrets. Primarily for testing."""
        cls._secrets.clear()
        cls._pattern = None

    @classmethod
    def _rebuild_pattern(cls) -> None:
        """Rebuild the compiled regex pattern from registered secrets."""
        if cls._secrets:
            escaped = [re.escape(s) for s in cls._secrets]
            cls._pattern = re.compile("|".join(escaped))
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
    root_logger.setLevel(level)

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
