# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for sandbox tests."""

import json

import pytest

from airut.claude_output import StreamEvent, parse_stream_events
from airut.sandbox._run_container import _RawResult


def create_mock_run_container(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
    duration_ms: int = 100,
):
    """Create an async mock of ``run_container`` for task tests.

    Returns an async function that simulates run_container by invoking
    callbacks line-by-line and returning a ``_RawResult``.

    Args:
        returncode: Simulated exit code.
        stdout: Simulated stdout content.
        stderr: Simulated stderr content.
        timed_out: Whether to simulate a timeout.
        duration_ms: Simulated duration in milliseconds.
    """

    async def fake_run_container(**kwargs):
        on_stdout = kwargs.get("on_stdout_line")
        on_stderr = kwargs.get("on_stderr_line")

        if on_stdout and stdout:
            for line in stdout.splitlines(keepends=True):
                on_stdout(line)

        if on_stderr and stderr:
            for line in stderr.splitlines(keepends=True):
                on_stderr(line)

        return _RawResult(
            exit_code=returncode,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )

    return fake_run_container


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
