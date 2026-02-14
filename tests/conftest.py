# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures used across multiple test packages."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest


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
    (airut_dir / "airut.yaml").write_text(
        "git:\n"
        "  user: Test User\n"
        "  email: test@example.com\n"
        "default_model: sonnet\n"
        "timeout: 300\n"
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
    """Parsed sample email message."""
    from email.parser import BytesParser

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
    return BytesParser().parsebytes(sample_bytes)
