# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures used across multiple test packages."""

from __future__ import annotations

import asyncio
import json
import subprocess
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


def make_sample_raw() -> dict[str, Any]:
    """Create a sample raw config dict for testing.

    Used by config editor tests (both unit and dashboard integration).
    """
    return {
        "config_version": 2,
        "execution": {
            "max_concurrent": 3,
            "shutdown_timeout": 60,
            "conversation_max_age_days": 7,
            "image_prune": True,
        },
        "dashboard": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 5200,
        },
        "repos": {
            "test-repo": {
                "git": {
                    "repo_url": "https://github.com/test/repo.git",
                },
                "email": {
                    "account": {
                        "username": "user@example.com",
                        "password": "secret",
                        "from": "bot@example.com",
                    },
                    "imap": {
                        "server": "imap.example.com",
                        "port": 993,
                    },
                    "smtp": {
                        "server": "smtp.example.com",
                        "port": 587,
                    },
                    "auth": {
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "example.com",
                    },
                },
            },
        },
    }


@pytest.fixture(autouse=True)
def _close_leaked_event_loops() -> Iterator[None]:
    """Close event loops leaked by pytest-asyncio internals.

    pytest-asyncio's ``_temporary_event_loop_policy`` calls
    ``asyncio.get_event_loop()`` which on Python 3.13+ auto-creates
    an event loop that is never closed.  When GC collects the leaked
    loop during a random later test, its ``__del__`` emits a
    ``ResourceWarning`` (unclosed event loop + self-pipe sockets) that
    pytest's ``unraisableexception`` plugin converts to a test failure.

    Closing the stale loop explicitly after each test prevents the
    warning entirely — a closed loop's ``__del__`` is silent regardless
    of when GC runs.

    Note: we intentionally do NOT call ``gc.collect()`` here.  Forcing a
    full GC sweep after every test adds ~45 s to the unit-test suite
    (3 400 tests × ~13 ms/collection under xdist with real object
    graphs).  Since the loop is already closed, deterministic GC timing
    is unnecessary.
    """
    yield
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
    if loop is not None and not loop.is_closed():
        loop.close()


@pytest.fixture
def master_repo(tmp_path: Path) -> Path:
    """Create a minimal git repository to use as master.

    Returns:
        Path to the git repository root.
    """
    repo_path = tmp_path / "master_repo"
    repo_path.mkdir()

    subprocess.run(
        ["git", "init"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    books_dir = repo_path / "books"
    books_dir.mkdir()
    (books_dir / "main.beancount").write_text("2020-01-01 open Assets:Test\n")

    lib_dir = repo_path / "lib"
    lib_dir.mkdir()
    (lib_dir / "__init__.py").write_text("")

    (repo_path / "README.md").write_text("# Test Repo\n")

    airut_dir = repo_path / ".airut"
    airut_dir.mkdir()
    (airut_dir / "network-allowlist.yaml").write_text(
        "domains: []\nurl_prefixes: []\n"
    )
    container_dir = airut_dir / "container"
    container_dir.mkdir()
    (container_dir / "Dockerfile").write_text(
        "FROM python:3.13-slim\nRUN pip install claude-code\n"
    )

    subprocess.run(
        ["git", "add", "."],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def storage_dir(tmp_path: Path) -> Path:
    """Create a temporary storage directory."""
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture
def docker_dir(tmp_path: Path) -> Path:
    """Create a mock docker directory with entrypoint."""
    docker = tmp_path / "docker"
    docker.mkdir()

    entrypoint = docker / "airut-entrypoint.sh"
    entrypoint.write_text('#!/usr/bin/env bash\nexec claude "$@"\n')

    return docker


@pytest.fixture
def mock_mirror(tmp_path: Path) -> MagicMock:
    """Create a mock GitMirrorCache that returns a test Dockerfile."""
    mock = MagicMock()
    mock.list_directory.return_value = ["Dockerfile"]
    mock.read_file.return_value = (
        b"FROM python:3.13-slim\nRUN pip install claude-code\n"
    )
    return mock


@pytest.fixture
def sample_streaming_output() -> str:
    """Sample streaming JSON output from Claude."""
    events = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "test-session-123",
            "tools": ["Bash", "Read", "Write"],
            "model": "claude-opus-4-5-20251101",
        },
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "I've completed the task."}
                ]
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "session_id": "test-session-123",
            "duration_ms": 1500,
            "total_cost_usd": 0.025,
            "num_turns": 1,
            "is_error": False,
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "result": "I've completed the task.",
        },
    ]
    return "\n".join(json.dumps(e) for e in events)


@pytest.fixture
def sample_email_bytes() -> bytes:
    """Sample email message as bytes."""
    return b"""From: user@example.com
To: claude@example.com
Subject: [ID:abc12345] Test request
Message-ID: <test123@example.com>
References: <prev@example.com>
Authentication-Results: mx.example.com; dmarc=pass; spf=pass

Please fix the linting errors.

> On Jan 12, 2026, Claude wrote:
> > Can you review this code?
"""


@pytest.fixture
def sample_email_message():
    """Sample email wrapped as RawMessage.

    Tests that need to manipulate email headers can access the
    underlying email via ``.content``.
    """
    from email.parser import BytesParser

    from airut.gateway.channel import RawMessage

    sample_bytes = b"""From: user@example.com
To: claude@example.com
Subject: [ID:abc12345] Test request
Message-ID: <test123@example.com>
References: <prev@example.com>
Authentication-Results: mx.example.com; dmarc=pass; spf=pass

Please fix the linting errors.

> On Jan 12, 2026, Claude wrote:
> > Can you review this code?
"""
    email_msg = BytesParser().parsebytes(sample_bytes)
    return RawMessage(
        sender="user@example.com",
        content=email_msg,
        display_title="[ID:abc12345] Test request",
    )
