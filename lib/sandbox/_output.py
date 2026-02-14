# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Output parsing integration for the sandbox.

Bridges between the sandbox execution and the claude_output library
for streaming JSON event parsing and result classification.
"""

from __future__ import annotations

from lib.claude_output import (
    extract_error_summary as _extract_error_summary,
)
from lib.claude_output import (
    extract_response_text,
    extract_result_summary,
    extract_session_id,
    parse_stream_events,
)
from lib.claude_output.types import Usage
from lib.sandbox.types import ExecutionResult, Outcome


def classify_outcome(
    stdout: str,
    stderr: str,
    exit_code: int,
    timed_out: bool,
) -> Outcome:
    """Classify the execution outcome from raw container output.

    Args:
        stdout: Raw stdout from the container.
        stderr: Raw stderr from the container.
        exit_code: Container process exit code.
        timed_out: Whether the container was killed by timeout.

    Returns:
        Appropriate Outcome variant.
    """
    if timed_out:
        return Outcome.TIMEOUT

    if exit_code == 0:
        return Outcome.SUCCESS

    # Check for prompt-too-long error
    if "Prompt is too long" in stdout:
        return Outcome.PROMPT_TOO_LONG

    # Check for session corruption (API 4xx errors)
    combined = f"{stdout}\n{stderr}"
    if "API Error: 4" in combined:
        return Outcome.SESSION_CORRUPTED

    return Outcome.CONTAINER_FAILED


def build_execution_result(
    stdout: str,
    stderr: str,
    exit_code: int,
    timed_out: bool,
    duration_ms: int,
) -> ExecutionResult:
    """Build an ExecutionResult from raw container output.

    Parses streaming events, extracts metadata from the result event,
    and classifies the outcome.

    Args:
        stdout: Raw stdout from the container.
        stderr: Raw stderr from the container.
        exit_code: Container process exit code.
        timed_out: Whether the container was killed by timeout.
        duration_ms: Execution duration in milliseconds.

    Returns:
        Complete ExecutionResult.
    """
    outcome = classify_outcome(stdout, stderr, exit_code, timed_out)

    # Parse events from stdout
    events = parse_stream_events(stdout) if stdout.strip() else []

    # Extract metadata from events
    summary = extract_result_summary(events)
    session_id = ""
    response_text = ""
    total_cost_usd = 0.0
    num_turns = 0
    usage = Usage()

    if summary is not None:
        session_id = summary.session_id
        total_cost_usd = summary.total_cost_usd
        num_turns = summary.num_turns
        usage = summary.usage
        duration_ms = summary.duration_ms or duration_ms

    if not session_id:
        session_id = extract_session_id(events) or ""

    if outcome == Outcome.SUCCESS:
        response_text = extract_response_text(events)

    return ExecutionResult(
        outcome=outcome,
        session_id=session_id,
        response_text=response_text,
        events=events,
        duration_ms=duration_ms,
        total_cost_usd=total_cost_usd,
        num_turns=num_turns,
        usage=usage,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
    )


def extract_error_summary(stdout: str, max_lines: int = 10) -> str | None:
    """Extract a human-readable error summary from streaming JSON.

    Args:
        stdout: Raw stdout containing streaming JSON.
        max_lines: Maximum number of lines to include in the summary.

    Returns:
        Formatted error summary string, or None if no useful info.
    """
    if not stdout or not stdout.strip():
        return None

    events = parse_stream_events(stdout)
    return _extract_error_summary(events, max_lines=max_lines)
