#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Mock Claude Code CLI for integration tests.

This module simulates Claude Code's behavior for integration testing.
It reads Python code from stdin, executes it, and outputs streaming JSON
to stdout, matching Claude's --output-format stream-json format.

The code should define an events list and optionally per-event synchronization:

Example prompt code:
    # Build events list
    events = [
        generate_system_event(session_id),
        generate_assistant_event("Hello!"),
        generate_result_event(session_id, "Hello!"),
    ]

    # Optional: define sync_between_events function for synchronization
    def sync_between_events(event_num):
        if event_num == 0:
            (workspace / "ready.txt").write_text("ready")
        elif event_num >= 1:
            # Block to keep process alive
            while not (workspace / "stop.txt").exists():
                time.sleep(0.1)

Available in code context:
- workspace: Path to workspace directory
- inbox: Path to inbox directory (for email attachments)
- outbox: Path to outbox directory (for files to send back)

- session_id: Current session ID
- Helper functions: generate_system_event, generate_assistant_event,
  generate_result_event, generate_tool_use_event
- Standard library: Path, time, json, sys, os

Environment Variables:
    MOCK_CLAUDE_WORKSPACE: Path to conversation workspace (set by executor)
    MOCK_CLAUDE_INBOX: Path to inbox directory (set by executor)
    MOCK_CLAUDE_OUTBOX: Path to outbox directory (set by executor)

    MOCK_CLAUDE_SESSION_ID: Session ID for resumption (set by executor)
"""

import json
import os
import pathlib
import sys
import time
from pathlib import Path
from typing import Any


def generate_system_event(session_id: str) -> dict[str, Any]:
    """Generate system/init event."""
    return {
        "type": "system",
        "subtype": "init",
        "session_id": session_id,
        "tools": ["Bash", "Read", "Write", "Edit", "Glob", "Grep"],
        "model": "mock-claude-integration-test",
    }


def generate_assistant_event(text: str) -> dict[str, Any]:
    """Generate assistant message event."""
    return {
        "type": "assistant",
        "message": {
            "content": [{"type": "text", "text": text}],
        },
    }


def generate_tool_use_event(
    tool_name: str, tool_input: dict[str, Any]
) -> dict[str, Any]:
    """Generate assistant event with tool use."""
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": f"tool_{int(time.time() * 1000)}",
                    "name": tool_name,
                    "input": tool_input,
                }
            ],
        },
    }


def generate_result_event(
    session_id: str,
    result_text: str,
    is_error: bool = False,
    duration_ms: int = 100,
) -> dict[str, Any]:
    """Generate result event."""
    return {
        "type": "result",
        "subtype": "error" if is_error else "success",
        "session_id": session_id,
        "duration_ms": duration_ms,
        "total_cost_usd": 0.001,
        "num_turns": 1,
        "is_error": is_error,
        "usage": {"input_tokens": 50, "output_tokens": 25},
        "result": result_text,
    }


def main() -> int:
    """Main entry point for mock Claude CLI.

    Reads Python code from stdin and executes it. The code should create
    an 'events' list. Optionally, it can define 'sync_between_events(event_num)'
    for per-event synchronization logic.
    """
    # Read code from stdin and strip whitespace
    code = sys.stdin.read().strip()

    # If code contains "events = [", extract just the Python code part
    # (email service may prepend email context and attachment info)
    if "events = [" in code and not code.startswith("events"):
        # Look for the first line of actual Python code
        # Email context is plain English text, so we look for Python syntax
        lines = code.split("\n")
        first_code_line = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip empty lines and plain English context
            if not stripped:
                continue
            # Look for Python syntax markers
            if (
                stripped.startswith("import ")
                or stripped.startswith("from ")
                or stripped.startswith("#")
                or stripped.startswith("(")
                or "=" in stripped
                or stripped.startswith("events = [")
            ):
                first_code_line = i
                break

        # Extract from first Python line onwards
        code = "\n".join(lines[first_code_line:])

    # Get configuration from environment
    workspace_str = os.environ.get("MOCK_CLAUDE_WORKSPACE", ".")
    workspace = Path(workspace_str)
    inbox = Path(os.environ.get("MOCK_CLAUDE_INBOX", str(workspace / "inbox")))
    outbox = Path(
        os.environ.get("MOCK_CLAUDE_OUTBOX", str(workspace / "outbox"))
    )
    session_id = (
        os.environ.get("MOCK_CLAUDE_SESSION_ID") or f"mock-{int(time.time())}"
    )

    # Prepare execution context
    context: dict[str, Any] = {
        "workspace": workspace,
        "inbox": inbox,
        "outbox": outbox,
        "session_id": session_id,
        "generate_system_event": generate_system_event,
        "generate_assistant_event": generate_assistant_event,
        "generate_tool_use_event": generate_tool_use_event,
        "generate_result_event": generate_result_event,
        "Path": Path,
        "pathlib": pathlib,
        "time": time,
        "json": json,
        "sys": sys,
        "os": os,
    }

    # Execute the code to generate events and optionally sync function
    try:
        exec(code, context)
    except Exception as e:
        # Return error event
        print(
            json.dumps(
                {
                    "type": "result",
                    "subtype": "error",
                    "is_error": True,
                    "result": f"Mock execution error: {e}",
                }
            )
        )
        return 1

    # Get events list from context
    events = context.get("events")
    if not events or not isinstance(events, list):
        print(
            json.dumps(
                {
                    "type": "result",
                    "subtype": "error",
                    "is_error": True,
                    "result": "Code must create 'events' list",
                }
            )
        )
        return 1

    # Check if sync function is defined
    sync_fn = context.get("sync_between_events")

    # Output events as streaming JSON
    for i, event in enumerate(events):
        # Call sync function if defined
        if callable(sync_fn):
            try:
                sync_fn(i)
            except Exception as e:
                # Log error but continue
                print(
                    json.dumps(
                        {
                            "type": "system",
                            "subtype": "error",
                            "content": f"Sync error at event {i}: {e}",
                        }
                    ),
                    file=sys.stderr,
                )

        # Output the event
        print(json.dumps(event))
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
