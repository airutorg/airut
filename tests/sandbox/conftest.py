# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for sandbox tests."""

import json
import subprocess

import pytest

from lib.claude_output import StreamEvent, parse_stream_events


def create_mock_popen(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    raise_timeout: bool = False,
):
    """Create a mock Popen object for Task tests.

    Returns a MagicMock that behaves like subprocess.Popen:
    - stdout is an iterator yielding lines with newlines
    - stderr.readlines() returns a list of lines
    - stdin has a write() and close() method
    - wait() can raise TimeoutExpired if raise_timeout is True
    """
    from unittest.mock import MagicMock

    mock = MagicMock()
    mock.returncode = returncode

    # stdout should be an iterator that yields lines WITH newlines
    if stdout:
        lines = stdout.split("\n")
        mock.stdout = iter(line + "\n" for line in lines if line.strip())
    else:
        mock.stdout = iter([])

    mock.stderr = MagicMock()
    if stderr:
        stderr_lines = stderr.split("\n")
        mock.stderr.readlines.return_value = [
            line + "\n" for line in stderr_lines if line.strip()
        ]
    else:
        mock.stderr.readlines.return_value = []

    mock.stdin = MagicMock()

    if raise_timeout:
        mock.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=["podman"], timeout=1),
            None,
        ]
    else:
        mock.wait.return_value = None

    mock.kill.return_value = None
    return mock


def parse_events(*raw_events: dict) -> list[StreamEvent]:
    """Parse raw event dicts into typed StreamEvents."""
    stdout = "\n".join(json.dumps(e) for e in raw_events)
    return parse_stream_events(stdout)


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
