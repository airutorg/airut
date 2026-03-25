# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Rich mock data for dashboard screenshot generation.

Creates a DashboardServer populated with realistic task, repo, and
conversation data covering all visual states the dashboard supports.
"""

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from airut.claude_output.types import StreamEvent, Usage
from airut.conversation import (
    ConversationMetadata,
    ConversationStore,
    ReplySummary,
)
from airut.dashboard.formatters import VersionInfo
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import (
    BootPhase,
    BootState,
    ChannelInfo,
    CompletionReason,
    RepoState,
    RepoStatus,
    TaskTracker,
    TodoItem,
    TodoStatus,
)
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.sandbox import EventLog


# Fixed timestamps so screenshots are deterministic
_BASE_TIME = datetime(2026, 3, 25, 14, 0, 0, tzinfo=UTC).timestamp()


def _ts(minutes_offset: float) -> float:
    """Compute a timestamp relative to the base time."""
    return _BASE_TIME + minutes_offset * 60


# ── Task definitions ─────────────────────────────────────────────────

# Task IDs are 12-char hex strings (uuid.uuid4().hex[:12] in production).
# Conversation IDs are 8-char hex strings.
# Each tuple: (task_id, conv_id, title, repo_id, sender, auth_sender)
_TASKS = [
    (
        "a3f8c1d02e47",
        "",
        "Update CI configuration for Python 3.14",
        "backend",
        "dev@acme.com",
        "",
    ),
    (
        "b7e2a9f13c85",
        "a1b2c3d4",
        "Fix authentication race condition in session handler",
        "backend",
        "alice@acme.com",
        "alice@acme.com",
    ),
    (
        "c4d6b8e21f09",
        "e5f6a7b8",
        "Add rate limiting middleware to API gateway",
        "frontend",
        "bob@acme.com",
        "bob@acme.com",
    ),
    (
        "d1a5c7f30e42",
        "c9d0e1f2",
        "Refactor database connection pooling",
        "backend",
        "alice@acme.com",
        "alice@acme.com",
    ),
    (
        "e8b3d6a49c17",
        "f3a4b5c6",
        "Add OpenTelemetry tracing to payment service",
        "frontend",
        "carol@acme.com",
        "carol@acme.com",
    ),
    (
        "f2c9e4b58a03",
        "d7e8f9a0",
        "Migrate legacy OAuth1 endpoints",
        "backend",
        "dave@acme.com",
        "dave@acme.com",
    ),
    (
        "0a7d3e6f1b28",
        "b1c2d3e4",
        "Generate API documentation from OpenAPI spec",
        "frontend",
        "eve@acme.com",
        "eve@acme.com",
    ),
    (
        "1b4e8c2d9f56",
        "",
        "Delete production database",
        "backend",
        "mallory@external.com",
        "",
    ),
]


def _populate_tracker(tracker: TaskTracker) -> None:
    """Add tasks in various lifecycle states to the tracker."""
    # Queued task
    tid, cid, title, repo, sender, auth = _TASKS[0]
    tracker.add_task(tid, title, repo_id=repo, sender=sender)

    # Executing task 1 (with todos)
    tid, cid, title, repo, sender, auth = _TASKS[1]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="opus")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    # Override started_at for deterministic duration display
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-8)
    task.queued_at = _ts(-9)
    task.authenticated_sender = auth
    task.reply_index = 0
    tracker.update_todos(
        tid,
        [
            TodoItem(
                "Analyze the codebase for race conditions",
                TodoStatus.COMPLETED,
                "Analyzing codebase for race conditions",
            ),
            TodoItem(
                "Write failing test for session handler bug",
                TodoStatus.COMPLETED,
                "Writing failing test",
            ),
            TodoItem(
                "Fix the race condition with proper locking",
                TodoStatus.IN_PROGRESS,
                "Fixing race condition with proper locking",
            ),
            TodoItem(
                "Run test suite and verify fix",
                TodoStatus.PENDING,
                "Running test suite",
            ),
            TodoItem(
                "Create pull request",
                TodoStatus.PENDING,
                "Creating pull request",
            ),
        ],
    )

    # Executing task 2 (no todos yet, early in execution)
    tid, cid, title, repo, sender, auth = _TASKS[2]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="sonnet")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-1)
    task.queued_at = _ts(-2)
    task.authenticated_sender = auth
    task.reply_index = 0

    # Completed success 1
    tid, cid, title, repo, sender, auth = _TASKS[3]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="opus")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-35)
    task.queued_at = _ts(-36)
    task.authenticated_sender = auth
    task.reply_index = 0
    tracker.complete_task(tid, CompletionReason.SUCCESS)
    task.completed_at = _ts(-25)

    # Completed success 2
    tid, cid, title, repo, sender, auth = _TASKS[4]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="sonnet")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-50)
    task.queued_at = _ts(-51)
    task.authenticated_sender = auth
    task.reply_index = 0
    tracker.complete_task(tid, CompletionReason.SUCCESS)
    task.completed_at = _ts(-42)

    # Completed failure
    tid, cid, title, repo, sender, auth = _TASKS[5]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="opus")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-20)
    task.queued_at = _ts(-21)
    task.authenticated_sender = auth
    task.reply_index = 0
    tracker.complete_task(
        tid, CompletionReason.EXECUTION_FAILED, "Container exited with code 1"
    )
    task.completed_at = _ts(-15)

    # Completed timeout
    tid, cid, title, repo, sender, auth = _TASKS[6]
    tracker.add_task(tid, title, repo_id=repo, sender=sender, model="sonnet")
    tracker.set_conversation_id(tid, cid)
    tracker.set_authenticating(tid)
    tracker.set_executing(tid)
    task = tracker.get_task(tid)
    assert task is not None
    task.started_at = _ts(-65)
    task.queued_at = _ts(-66)
    task.authenticated_sender = auth
    task.reply_index = 0
    tracker.complete_task(tid, CompletionReason.TIMEOUT, "Timeout after 3600s")
    task.completed_at = _ts(-5)

    # Completed unauthorized
    tid, cid, title, repo, sender, auth = _TASKS[7]
    tracker.add_task(tid, title, repo_id=repo, sender=sender)
    tracker.set_authenticating(tid)
    tracker.complete_task(
        tid, CompletionReason.UNAUTHORIZED, "Sender not in allowlist"
    )
    task = tracker.get_task(tid)
    assert task is not None
    task.completed_at = _ts(-60)


# ── Conversation data on disk ────────────────────────────────────────


def _write_conversation_data(work_dir: Path) -> None:
    """Write conversation.json and events.jsonl for conversations."""
    # Executing task 1 conversation (a1b2c3d4)
    _write_executing_conversation(work_dir)

    # Executing task 2 conversation (e5f6a7b8)
    _write_early_conversation(work_dir)

    # Completed success conversation (c9d0e1f2)
    _write_completed_conversation(work_dir)


def _write_executing_conversation(work_dir: Path) -> None:
    """Write data for the main executing task with rich event log."""
    conv_id = "a1b2c3d4"
    conv_dir = work_dir / conv_id
    conv_dir.mkdir(exist_ok=True)

    store = ConversationStore(conv_dir)
    store.save(
        _make_metadata(
            conv_id,
            model="opus",
            pending_request_text=(
                "Fix the authentication race condition in the session"
                " handler. The bug causes intermittent 401 errors under"
                " high concurrency."
            ),
        )
    )

    event_log = EventLog(conv_dir)
    _write_rich_event_log(event_log)

    # Write network log
    _write_network_log(conv_dir)


def _write_early_conversation(work_dir: Path) -> None:
    """Write data for a task early in execution (minimal events)."""
    conv_id = "e5f6a7b8"
    conv_dir = work_dir / conv_id
    conv_dir.mkdir(exist_ok=True)

    store = ConversationStore(conv_dir)
    store.save(
        _make_metadata(
            conv_id,
            model="sonnet",
            pending_request_text=(
                "Add rate limiting middleware to the API gateway."
                " Use a token bucket algorithm with configurable"
                " per-endpoint limits."
            ),
        )
    )

    event_log = EventLog(conv_dir)
    events: list[dict[str, object]] = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "sess_e5f6",
        },
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "I'll add rate limiting middleware"
                            " to the API gateway. Let me start"
                            " by examining the current"
                            " middleware stack."
                        ),
                    }
                ]
            },
        },
    ]
    for raw in events:
        event_log.append_event(_make_stream_event(raw))


def _write_completed_conversation(work_dir: Path) -> None:
    """Write data for a completed conversation with reply history."""
    conv_id = "c9d0e1f2"
    conv_dir = work_dir / conv_id
    conv_dir.mkdir(exist_ok=True)

    store = ConversationStore(conv_dir)
    store.add_reply(
        conv_id,
        ReplySummary(
            session_id="sess_c9d0",
            timestamp=datetime(2026, 3, 25, 13, 25, 0, tzinfo=UTC).isoformat(),
            duration_ms=480_000,
            total_cost_usd=0.1847,
            num_turns=12,
            is_error=False,
            usage=Usage(
                input_tokens=45_000,
                output_tokens=12_000,
                cache_creation_input_tokens=8_000,
                cache_read_input_tokens=32_000,
            ),
            request_text=(
                "Refactor the database connection pooling to use"
                " async context managers and add health checks."
            ),
            response_text=(
                "I've refactored the database connection pooling. Here's"
                " what changed:\n\n"
                "1. Replaced manual connection management with async"
                " context managers\n"
                "2. Added periodic health checks that ping the database"
                " every 30s\n"
                "3. Implemented automatic reconnection with exponential"
                " backoff\n"
                "4. Added connection pool metrics (active, idle, total)\n\n"
                "PR #247 has been created with all changes."
            ),
        ),
    )

    # Write events for this completed conversation
    event_log = EventLog(conv_dir)
    events: list[dict[str, object]] = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "sess_c9d0",
        },
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "I'll refactor the database"
                            " connection pooling. Let me"
                            " examine the current"
                            " implementation."
                        ),
                    },
                    {
                        "type": "tool_use",
                        "id": "tu_read_c1",
                        "name": "Read",
                        "input": {
                            "file_path": ("/workspace/src/db/pool.py"),
                        },
                    },
                ]
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_read_c1",
                        "content": ("class ConnectionPool:\n    ..."),
                    }
                ]
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "session_id": "sess_c9d0",
            "duration_ms": 480_000,
            "total_cost_usd": 0.1847,
            "num_turns": 12,
            "is_error": False,
            "usage": {
                "input_tokens": 45_000,
                "output_tokens": 12_000,
            },
        },
    ]
    for raw in events:
        event_log.append_event(_make_stream_event(raw))


def _make_metadata(
    conv_id: str,
    *,
    model: str = "opus",
    pending_request_text: str | None = None,
) -> ConversationMetadata:
    """Build a ConversationMetadata with defaults."""
    return ConversationMetadata(
        conversation_id=conv_id,
        model=model,
        pending_request_text=pending_request_text,
    )


def _make_stream_event(raw: dict[str, object]) -> StreamEvent:
    """Create a StreamEvent from a raw dict."""
    from airut.claude_output import parse_event_dict

    event = parse_event_dict(raw)
    assert event is not None, f"Failed to parse event: {raw}"
    return event


def _write_rich_event_log(event_log: EventLog) -> None:
    """Write a rich event log with various event types.

    Uses the Claude streaming JSON format: assistant events wrap content
    in ``{"message": {"content": [...]}}``, tool results are ``"type":
    "user"`` events with ``tool_result`` content blocks.
    """
    events: list[dict[str, object]] = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "sess_a1b2",
            "tools": ["Bash", "Read", "Edit", "Grep", "Glob"],
        },
        # Assistant: text + Grep tool call
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "I'll investigate the authentication"
                            " race condition. Let me start by"
                            " examining the session handler code."
                        ),
                    },
                    {
                        "type": "tool_use",
                        "id": "tu_grep_1",
                        "name": "Grep",
                        "input": {
                            "pattern": "class SessionHandler",
                            "path": "/workspace/src/",
                        },
                    },
                ]
            },
        },
        # Tool result for Grep
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_grep_1",
                        "content": (
                            "src/auth/session.py:42: class SessionHandler:"
                        ),
                    }
                ]
            },
        },
        # Assistant: Read tool call
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tu_read_1",
                        "name": "Read",
                        "input": {
                            "file_path": ("/workspace/src/auth/session.py"),
                        },
                    }
                ]
            },
        },
        # Tool result for Read
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_read_1",
                        "content": (
                            "class SessionHandler:\n"
                            "    def __init__(self):\n"
                            "        self._sessions = {}\n"
                            "        self._lock = Lock()\n"
                        ),
                    }
                ]
            },
        },
        # Assistant: analysis text + Task (subagent) launch
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "I see the issue: `validate_session`"
                            " reads without the lock while"
                            " `create_session` writes under it."
                            " TOCTOU race.\n\n"
                            "Let me write a failing test first."
                        ),
                    },
                    {
                        "type": "tool_use",
                        "id": "tu_task_1",
                        "name": "Task",
                        "input": {
                            "description": "Find session tests",
                            "subagent_type": "Explore",
                            "prompt": (
                                "Search for existing session handler tests"
                            ),
                        },
                    },
                ]
            },
        },
        # Subagent event (parent_tool_use_id links back)
        {
            "type": "assistant",
            "parent_tool_use_id": "tu_task_1",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Found tests/auth/test_session.py"
                            " with 12 existing tests."
                        ),
                    },
                ]
            },
        },
        # Tool result for Task
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_task_1",
                        "content": (
                            "Found tests/auth/test_session.py with 12 tests"
                        ),
                    }
                ]
            },
        },
        # Assistant: Edit tool call
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tu_edit_1",
                        "name": "Edit",
                        "input": {
                            "file_path": (
                                "/workspace/tests/auth/test_session.py"
                            ),
                            "old_string": ("def test_validate_session():"),
                            "new_string": (
                                "def test_concurrent_session_validation():"
                            ),
                        },
                    }
                ]
            },
        },
        # Tool result for Edit
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_edit_1",
                        "content": "File edited successfully",
                    }
                ]
            },
        },
        # Assistant: Bash tool call
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tu_bash_1",
                        "name": "Bash",
                        "input": {
                            "command": (
                                "uv run pytest tests/auth/test_session.py -x"
                            ),
                            "description": "Run session tests",
                        },
                    }
                ]
            },
        },
        # Tool result for Bash
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_bash_1",
                        "content": (
                            "FAILED test_session.py"
                            "::test_concurrent_session"
                            "_validation\n"
                            "1 failed, 11 passed in 2.34s"
                        ),
                    }
                ]
            },
        },
        # Assistant: conclusion text
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "The test reproduces the race"
                            " condition. Now let me fix the"
                            " session handler by adding proper"
                            " locking."
                        ),
                    }
                ]
            },
        },
    ]
    for raw in events:
        event_log.append_event(_make_stream_event(raw))


def _write_network_log(conv_dir: Path) -> None:
    """Write a realistic network log matching the proxy's actual format.

    The proxy emits lines in the format:
        DNS A <host> -> <ip>
        DNS AAAA <host> -> NOTIMP
        allowed <METHOD> <url> -> <status> [masked: N]
        ALLOWED <METHOD> <url> [github-app: refreshed|cached]
        BLOCKED <METHOD> <url> -> <status>
    """
    # fmt: off
    lines = [
        "DNS A api.anthropic.com -> 10.199.10.100",
        "DNS AAAA api.anthropic.com -> NOTIMP",
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "allowed POST https://api.anthropic.com/api/event_logging/batch -> 200",
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "DNS A github.com -> 10.199.10.100",
        "DNS AAAA github.com -> NOTIMP",
        "allowed GET https://github.com/acme/backend.git/info/refs?service=git-upload-pack -> 200",  # noqa: E501
        "allowed POST https://github.com/acme/backend.git/git-upload-pack -> 200",  # noqa: E501
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "allowed POST https://api.anthropic.com/api/event_logging/batch -> 200",
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "DNS A api.github.com -> 10.199.10.100",
        "DNS AAAA api.github.com -> NOTIMP",
        "allowed GET https://api.github.com/repos/acme/backend/contents/src/auth/session.py -> 200",  # noqa: E501
        "allowed GET https://api.github.com/repos/acme/backend/pulls -> 200",
        "BLOCKED GET https://evil.example.com/exfiltrate -> 403",
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "allowed GET https://api.github.com/repos/acme/backend/git/refs -> 200",
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "allowed GET https://api.github.com/repos/acme/backend/contents/session_v2.py -> 404",  # noqa: E501
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "BLOCKED POST https://webhook.site/callback -> 403",
        "allowed POST https://api.anthropic.com/api/event_logging/batch -> 200",
        "DNS A github.com -> 10.199.10.100",
        "DNS AAAA github.com -> NOTIMP",
        "allowed GET https://github.com/acme/backend.git/info/refs?service=git-receive-pack -> 401",  # noqa: E501
        "ALLOWED GET https://github.com/acme/backend.git/info/refs?service=git-receive-pack [github-app: refreshed]",  # noqa: E501
        "allowed GET https://github.com/acme/backend.git/info/refs?service=git-receive-pack -> 200 [masked: 1]",  # noqa: E501
        "ALLOWED POST https://github.com/acme/backend.git/git-receive-pack [github-app: cached]",  # noqa: E501
        "allowed POST https://github.com/acme/backend.git/git-receive-pack -> 200 [masked: 1]",  # noqa: E501
        "allowed POST https://api.anthropic.com/v1/messages?beta=true -> 200 [masked: 1]",  # noqa: E501
        "DNS A pypi.org -> 10.199.10.100",
        "DNS AAAA pypi.org -> NOTIMP",
        "allowed GET https://pypi.org/simple/pytest/ -> 200",
    ]
    # fmt: on
    log_path = conv_dir / "network-sandbox.log"
    log_path.write_text("\n".join(lines) + "\n")


# ── Repository states ────────────────────────────────────────────────


def _make_repo_states() -> tuple[RepoState, ...]:
    """Create repo states covering live and failed cases."""
    return (
        RepoState(
            repo_id="backend",
            status=RepoStatus.LIVE,
            git_repo_url="https://github.com/acme/backend.git",
            channels=(
                ChannelInfo("email", "imap.acme.com", "airut@acme.com"),
                ChannelInfo("slack", "Slack (Socket Mode)"),
            ),
            storage_dir="/var/lib/airut/backend",
            initialized_at=_ts(-120),
        ),
        RepoState(
            repo_id="frontend",
            status=RepoStatus.LIVE,
            git_repo_url="https://github.com/acme/frontend.git",
            channels=(
                ChannelInfo("email", "imap.acme.com", "airut+fe@acme.com"),
            ),
            storage_dir="/var/lib/airut/frontend",
            initialized_at=_ts(-120),
        ),
        RepoState(
            repo_id="legacy-api",
            status=RepoStatus.FAILED,
            error_message=(
                "Failed to clone repository: authentication failed"
                " (deploy key rejected)"
            ),
            error_type="GitCloneError",
            git_repo_url="https://github.com/acme/legacy-api.git",
            storage_dir="/var/lib/airut/legacy-api",
            initialized_at=_ts(-119),
        ),
    )


# ── Boot state ───────────────────────────────────────────────────────


def _make_boot_state() -> BootState:
    """Create a READY boot state."""
    return BootState(
        phase=BootPhase.READY,
        message="All repositories initialized",
        started_at=_ts(-120),
        completed_at=_ts(-119),
    )


# ── Version info from git ────────────────────────────────────────────


def _get_version_info() -> VersionInfo:
    """Resolve version info from the latest git tag.

    Uses ``git describe --tags --long`` to get the latest tagged version,
    ensuring screenshots always show the current release version.
    Falls back to a placeholder if git is unavailable.
    """
    try:
        describe = subprocess.run(
            ["git", "describe", "--tags", "--long"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        # Format: v0.18.0-59-gbe7b9b8
        # Extract: version=v0.18.0, sha=be7b9b8
        parts = describe.rsplit("-", 2)
        if len(parts) == 3:
            version = parts[0]
            sha_short = parts[2].lstrip("g")
        else:
            version = describe
            sha_short = ""

        sha_full = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        return VersionInfo(
            version=version,
            git_sha=sha_short,
            git_sha_full=sha_full,
            full_status=describe,
            started_at=_ts(-120),
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return VersionInfo(
            version="v0.0.0",
            git_sha="0000000",
            git_sha_full="0" * 40,
            full_status="v0.0.0-0-g0000000",
            started_at=_ts(-120),
        )


# ── Public API ───────────────────────────────────────────────────────


class MockDashboard:
    """Running dashboard server with mock data.

    Attributes:
        server: The DashboardServer instance.
        port: The port the server is listening on.
        work_dir: Temporary directory containing conversation data.
        ids: Dict mapping symbolic names to IDs for URL templating.
    """

    def __init__(
        self,
        server: DashboardServer,
        port: int,
        work_dir: Path,
        ids: dict[str, str],
    ) -> None:
        self.server = server
        self.port = port
        self.work_dir = work_dir
        self.ids = ids

    def shutdown(self) -> None:
        """Stop the dashboard server."""
        self.server.stop()


def create_mock_dashboard(work_dir: Path, port: int = 0) -> MockDashboard:
    """Create and start a dashboard server with rich mock data.

    Args:
        work_dir: Directory for conversation data files.
        port: Port to bind to (0 = OS-assigned).

    Returns:
        MockDashboard with running server and URL template IDs.
    """
    clock = VersionClock()
    tracker = TaskTracker(clock=clock)

    boot_store: VersionedStore[BootState] = VersionedStore(
        _make_boot_state(), clock
    )
    repos_store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
        _make_repo_states(), clock
    )

    _populate_tracker(tracker)
    _write_conversation_data(work_dir)

    version_info = _get_version_info()

    server = DashboardServer(
        tracker=tracker,
        host="127.0.0.1",
        port=port,
        version_info=version_info,
        work_dirs=lambda: [work_dir],
        boot_store=boot_store,
        repos_store=repos_store,
        clock=clock,
    )
    server.start()

    actual_port = server._server.server_port  # type: ignore[union-attr]

    ids = {
        "executing_task": "b7e2a9f13c85",
        "executing_conv": "a1b2c3d4",
        "completed_task": "d1a5c7f30e42",
        "completed_conv": "c9d0e1f2",
        "live_repo": "backend",
        "failed_repo": "legacy-api",
    }

    return MockDashboard(server, actual_port, work_dir, ids)
