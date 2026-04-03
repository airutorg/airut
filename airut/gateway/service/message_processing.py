# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Message processing logic for the gateway service.

This module handles:
- Processing parsed messages from any channel adapter
- Managing conversation state and session resumption
- Executing Claude Code in containers via the sandbox
- Handling prompt-too-long recovery

The sandbox execution core is in ``run_in_sandbox()`` — a reusable
function that handles image building, mount assembly, task execution,
and result recording.  ``process_message()`` wraps it with
channel-specific orchestration (conversation init, acknowledgments,
attachments, plan streaming, delivery).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from typing import TYPE_CHECKING

from airut.allowlist import parse_allowlist_yaml
from airut.claude_output.types import StreamEvent, ToolUseBlock
from airut.conversation import (
    ConversationLayout,
    ConversationStore,
    ReplySummary,
    create_conversation_layout,
    prepare_conversation,
)
from airut.dashboard.tracker import (
    CompletionReason,
    TaskTracker,
    TodoItem,
    TodoStatus,
)
from airut.gateway.channel import (
    ChannelAdapter,
    ChannelSendError,
    ParsedMessage,
    PlanStreamer,
)
from airut.gateway.config import ReplacementMap
from airut.gateway.conversation import GitCloneError
from airut.gateway.service.usage_stats import UsageStats
from airut.sandbox import (
    NETWORK_LOG_FILENAME,
    ClaudeBinaryError,
    ContainerEnv,
    Mount,
    NetworkSandboxConfig,
    Outcome,
)
from airut.sandbox.types import ExecutionResult


if TYPE_CHECKING:
    from airut.gateway.service.gateway import GatewayService
    from airut.gateway.service.repo_handler import RepoHandler
    from airut.git_mirror import GitMirrorCache
    from airut.sandbox.secrets import SecretReplacements

logger = logging.getLogger(__name__)


_DEFAULT_CONTAINER_DIR = ".airut/container"


# ── SandboxTaskResult ──────────────────────────────────────────────────

EventCallback = Callable[[StreamEvent], None]


@dataclass(frozen=True)
class SandboxTaskResult:
    """Result of a sandbox task execution.

    Returned by ``run_in_sandbox()`` with everything needed for the
    caller to deliver the result through a channel adapter.
    """

    outcome: Outcome
    conversation_id: str
    response_text: str
    """Claude's response or error message."""

    usage_stats: UsageStats | None
    layout: ConversationLayout
    """Conversation layout for outbox file access."""

    is_error: bool


# ── Helpers ────────────────────────────────────────────────────────────


def _make_todo_callback(
    tracker: TaskTracker,
    task_id: str,
    plan_streamer: PlanStreamer | None = None,
) -> Callable[[StreamEvent], None]:
    """Build an on_event callback that captures TodoWrite events.

    Updates the dashboard tracker and optionally forwards the full
    todo list to a plan streamer for real-time channel display.

    Args:
        tracker: Task tracker to update.
        task_id: Task ID to update todos for.
        plan_streamer: Optional plan streamer to forward todo
            updates to the user's channel in real time.

    Returns:
        Callback suitable for ``task.execute(on_event=...)``.
    """
    status_map = {s.value: s for s in TodoStatus}

    def on_event(event: StreamEvent) -> None:
        for block in event.content_blocks:
            if not isinstance(block, ToolUseBlock):
                continue

            if block.tool_name == "TodoWrite":
                raw = block.tool_input.get("todos")
                if isinstance(raw, list):
                    items = [
                        TodoItem(
                            content=t.get("content", ""),
                            status=status_map.get(
                                t.get("status", ""),
                                TodoStatus.PENDING,
                            ),
                            active_form=t.get(
                                "activeForm",
                                t.get("content", ""),
                            ),
                        )
                        for t in raw
                        if isinstance(t, dict)
                    ]
                    tracker.update_todos(task_id, items)
                    if plan_streamer is not None:
                        plan_streamer.update(items)

    return on_event


def build_recovery_prompt(
    last_response: str | None,
    channel_context: str,
    user_message: str,
) -> str:
    """Build a prompt for a new session after context compaction failure.

    When a conversation hits the context compaction boundary and can no
    longer be resumed, we start a fresh session with context about what
    happened.

    Args:
        last_response: The last successful response from the agent,
            or None.
        channel_context: The channel context header (channel mode
            instructions).
        user_message: The user's current message that triggered the
            error.

    Returns:
        Prompt string for the new session.
    """
    parts = [channel_context, ""]

    parts.append(
        "IMPORTANT: The previous conversation session could not be "
        "resumed due to context length limits (context compaction "
        "boundary). This is a fresh session, but the workspace may "
        "contain ongoing work from the previous session."
    )

    if last_response:
        # Truncate to avoid making the recovery prompt itself too long
        truncated = last_response[:3000]
        if len(last_response) > 3000:
            truncated += "\n\n[...truncated]"
        parts.append(
            f"\nYour last reply to the user was:\n---\n{truncated}\n---"
        )

    parts.append(
        "\nBe upfront with the user about the context loss. If the "
        "conversation state is unclear, ask for clarification. Check "
        "the workspace (git status, recent files) to understand any "
        "ongoing work."
    )

    parts.append(f"\nThe user's message:\n{user_message}")

    return "\n".join(parts)


def _build_image(
    service: GatewayService,
    mirror: GitMirrorCache,
    container_dir: str = _DEFAULT_CONTAINER_DIR,
) -> str:
    """Build or reuse container image from git mirror.

    Args:
        service: Parent service with sandbox.
        mirror: Git mirror cache.
        container_dir: Path to container directory in the repo
            (default: ``.airut/container``).

    Returns:
        Image tag for container execution.
    """
    # Read all files from the container directory
    try:
        filenames = mirror.list_directory(container_dir)
    except Exception as e:
        from airut.sandbox import ImageBuildError

        raise ImageBuildError(
            f"Failed to list {container_dir} from mirror: {e}"
        )

    dockerfile_content: bytes | None = None
    context_files: dict[str, bytes] = {}

    for filename in filenames:
        file_path = f"{container_dir}/{filename}"
        try:
            content = mirror.read_file(file_path)
        except Exception as e:
            from airut.sandbox import ImageBuildError

            raise ImageBuildError(
                f"Failed to read {file_path} from mirror: {e}"
            )

        if filename == "Dockerfile":
            dockerfile_content = content
        else:
            context_files[filename] = content

    if dockerfile_content is None:
        from airut.sandbox import ImageBuildError

        raise ImageBuildError(f"No Dockerfile found in {container_dir}")

    return service.sandbox.ensure_image(dockerfile_content, context_files)


def _build_reply_summary(
    result: ExecutionResult,
    *,
    request_text: str,
    response_text: str,
    is_error: bool = False,
) -> ReplySummary:
    """Build a ReplySummary from an ExecutionResult.

    Uses the scalar fields on ExecutionResult directly.

    Args:
        result: ExecutionResult from sandbox execution.
        request_text: The prompt text sent to Claude.
        response_text: Claude's response text (or error message).
        is_error: Whether this reply represents an error.

    Returns:
        ReplySummary ready for ConversationStore.
    """
    from datetime import datetime

    return ReplySummary(
        session_id=result.session_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        duration_ms=result.duration_ms,
        total_cost_usd=result.total_cost_usd,
        num_turns=result.num_turns,
        is_error=is_error or result.is_error,
        usage=result.usage,
        request_text=request_text,
        response_text=response_text,
    )


# ── Shared sandbox execution core ─────────────────────────────────────


def run_in_sandbox(
    service: GatewayService,
    repo_handler: RepoHandler,
    *,
    prompt: str,
    task_id: str,
    model: str,
    effort: str | None,
    conversation_id: str | None = None,
    on_event: EventCallback | None = None,
    channel_context: str = "",
    user_body: str = "",
) -> SandboxTaskResult:
    """Execute a prompt in the sandbox and return the result.

    If ``conversation_id`` is None, creates a new conversation
    (mirror update, workspace checkout).  If provided, the
    conversation must already be initialized — no mirror update
    or workspace checkout is performed.

    Handles: conversation creation (when ``conversation_id`` is
    None), image build, mount assembly, env/secrets, network
    sandbox, Claude binary, task creation, execution,
    prompt-too-long / session-corrupted recovery, and reply
    recording.

    Does NOT handle: acknowledgments, plan streaming, attachments,
    channel context construction, or response delivery.

    Args:
        service: Parent service for shared resources.
        repo_handler: Repo handler that owns this task.
        prompt: The full prompt to send to Claude (including any
            channel context header).
        task_id: Task ID for dashboard tracking.
        model: Model identifier (e.g. "opus", "sonnet").
        effort: Effort level override, or None for default.
        conversation_id: Existing conversation ID, or None to
            create a new conversation.
        on_event: Optional streaming event callback (for TodoWrite
            capture, plan streaming, etc.).
        channel_context: Channel context header portion of the
            prompt, used to construct a recovery prompt on
            session corruption.
        user_body: User message portion of the prompt, used to
            construct a recovery prompt on session corruption.

    Returns:
        SandboxTaskResult with outcome, response, usage, and
        layout.

    Raises:
        GitCloneError: If workspace initialization fails.
    """
    repo_id = repo_handler.config.repo_id
    conv_mgr = repo_handler.conversation_manager
    is_new = conversation_id is None

    # ── Conversation initialization (only when not provided) ──

    if is_new:
        logger.info("Repo '%s': creating new conversation", repo_id)
        logger.info(
            "Repo '%s': updating git mirror before creating conversation...",
            repo_id,
        )
        conv_mgr.mirror.update_mirror()
        conversation_id, _ = conv_mgr.initialize_new()
        logger.info(
            "Repo '%s': created conversation %s",
            repo_id,
            conversation_id,
        )
        service.tracker.set_conversation_id(task_id, conversation_id)

    # Register conversation-to-repo mapping
    assert conversation_id is not None
    service._conv_repo_map[conversation_id] = repo_id

    # ── Task environment and conversation store ──

    repo_cfg = repo_handler.config
    task_env, replacement_map = repo_cfg.build_task_env()
    resource_limits = repo_cfg.resource_limits

    conversation_dir = conv_mgr.get_conversation_dir(conversation_id)
    conversation_store = ConversationStore(conversation_dir)

    if is_new:
        conversation_store.set_model(conversation_id, model)
        conversation_store.set_effort(conversation_id, effort)
        service.tracker.set_task_model(task_id, model)
        service.tracker.set_reply_index(task_id, 0)
    else:
        # When called from process_message, these tracker calls
        # are redundant (process_message already set them).  They
        # are kept here so that non-process_message callers
        # (scheduled tasks) don't need to duplicate tracker setup.
        service.tracker.set_task_model(task_id, model)
        conv_meta = conversation_store.load()
        reply_count = len(conv_meta.replies) if conv_meta else 0
        service.tracker.set_reply_index(task_id, reply_count)

    # ── Layout, image, mounts, env ──

    layout = create_conversation_layout(conversation_dir)
    prepare_conversation(layout)

    image_tag = _build_image(service, conv_mgr.mirror, repo_cfg.container_path)

    mounts = [
        Mount(layout.workspace, "/workspace"),
        Mount(layout.inbox, "/inbox"),
        Mount(layout.outbox, "/outbox"),
        Mount(layout.storage, "/storage"),
    ]

    env = ContainerEnv(variables=task_env)

    # ── Network sandbox ──

    network_sandbox: NetworkSandboxConfig | None = None
    if not repo_cfg.network_sandbox_enabled:
        logger.warning("Repo '%s': network sandbox disabled", repo_id)
        if replacement_map:
            logger.warning(
                "Repo '%s': network sandbox is disabled but "
                "masked secrets are configured. Masked secrets "
                "require the proxy — they will not work without "
                "the sandbox.",
                repo_id,
            )
    if repo_cfg.network_sandbox_enabled:
        try:
            allowlist_data = conv_mgr.mirror.read_file(
                ".airut/network-allowlist.yaml"
            )
            allowlist = parse_allowlist_yaml(allowlist_data)
        except Exception as e:
            from airut.sandbox import ProxyError

            raise ProxyError(f"Failed to read/parse allowlist: {e}") from e

        replacements = _convert_replacement_map(replacement_map)
        network_sandbox = NetworkSandboxConfig(
            allowlist=allowlist,
            replacements=replacements,
        )

    # ── Claude binary ──

    claude_binary_path = None
    if service.claude_binary_cache is not None:
        claude_version = repo_cfg.claude_version
        try:
            binary_path, resolved_version = service.claude_binary_cache.ensure(
                claude_version
            )
            claude_binary_path = binary_path
            logger.info(
                "Repo '%s': using Claude binary %s",
                repo_id,
                resolved_version,
            )
        except ClaudeBinaryError as e:
            logger.error(
                "Repo '%s': failed to fetch Claude binary: %s",
                repo_id,
                e,
            )
            raise

    # ── Create and execute sandbox task ──

    task = service.sandbox.create_task(
        execution_context_id=conversation_id,
        image_tag=image_tag,
        mounts=mounts,
        env=env,
        execution_context_dir=conversation_dir,
        network_log_path=(
            conversation_dir / NETWORK_LOG_FILENAME
            if network_sandbox is not None
            else None
        ),
        network_sandbox=network_sandbox,
        resource_limits=resource_limits,
        claude_binary_path=claude_binary_path,
    )

    service.register_active_task(conversation_id, task)

    conversation_store.set_pending_request(conversation_id, prompt)

    task.event_log.start_new_reply()

    logger.info(
        "Repo '%s': executing Claude Code (model=%s, effort=%s)"
        " for conversation %s",
        repo_id,
        model,
        effort,
        conversation_id,
    )

    session_id = conversation_store.get_session_id_for_resume()
    if session_id:
        logger.info(
            "Repo '%s': resuming Claude session %s for conversation %s",
            repo_id,
            session_id,
            conversation_id,
        )

    try:
        result = asyncio.run(
            task.execute(
                prompt,
                session_id=session_id,
                model=model,
                effort=effort,
                on_event=on_event,
            )
        )
    finally:
        service.unregister_active_task(conversation_id)

    # ── Unresumable session recovery ──

    is_unresumable = result.outcome in (
        Outcome.PROMPT_TOO_LONG,
        Outcome.SESSION_CORRUPTED,
    )
    if is_unresumable and session_id is not None:
        reason = (
            "prompt too long"
            if result.outcome == Outcome.PROMPT_TOO_LONG
            else "session corrupted (API 4xx)"
        )
        logger.warning(
            "Repo '%s': %s for conversation %s, retrying with fresh session",
            repo_id,
            reason,
            conversation_id,
        )

        last_response = conversation_store.get_last_successful_response()
        recovery_prompt = build_recovery_prompt(
            last_response, channel_context, user_body
        )

        task = service.sandbox.create_task(
            execution_context_id=conversation_id,
            image_tag=image_tag,
            mounts=mounts,
            env=env,
            execution_context_dir=conversation_dir,
            network_log_path=(
                conversation_dir / NETWORK_LOG_FILENAME
                if network_sandbox is not None
                else None
            ),
            network_sandbox=network_sandbox,
            resource_limits=resource_limits,
        )

        conversation_store.set_pending_request(conversation_id, recovery_prompt)

        task.event_log.start_new_reply()

        service.register_active_task(conversation_id, task)
        try:
            result = asyncio.run(
                task.execute(
                    recovery_prompt,
                    session_id=None,
                    model=model,
                    on_event=on_event,
                )
            )
            prompt = recovery_prompt
        finally:
            service.unregister_active_task(conversation_id)

    # ── Build result ──

    if result.outcome == Outcome.SUCCESS:
        response_body = result.response_text
        is_subscription = bool(
            task_env.get("CLAUDE_CODE_OAUTH_TOKEN")
        ) and not bool(task_env.get("ANTHROPIC_API_KEY"))
        usage_stats = UsageStats(
            total_cost_usd=result.total_cost_usd
            if result.total_cost_usd > 0
            else None,
            web_search_requests=result.web_search_count,
            web_fetch_requests=result.web_fetch_count,
            is_subscription=is_subscription,
        )
        logger.info(
            "Repo '%s': execution successful for conversation %s",
            repo_id,
            conversation_id,
        )

        reply = _build_reply_summary(
            result,
            request_text=prompt,
            response_text=response_body,
        )
        conversation_store.add_reply(conversation_id, reply)

        return SandboxTaskResult(
            outcome=result.outcome,
            conversation_id=conversation_id,
            response_text=response_body,
            usage_stats=usage_stats,
            layout=layout,
            is_error=False,
        )

    elif result.outcome == Outcome.TIMEOUT:
        timeout_val = resource_limits.timeout
        if timeout_val is not None:
            interrupted = (
                f"The task was interrupted after {timeout_val} seconds."
            )
        else:
            interrupted = "The task was interrupted."
        error_msg = (
            f"{interrupted} "
            "Work done so far has been saved.\n\n"
            "Reply to resume \u2014 you can ask about progress "
            "or request next steps."
        )
        reply = _build_reply_summary(
            result,
            request_text=prompt,
            response_text=error_msg,
            is_error=True,
        )
        conversation_store.add_reply(conversation_id, reply)

        return SandboxTaskResult(
            outcome=result.outcome,
            conversation_id=conversation_id,
            response_text=error_msg,
            usage_stats=None,
            layout=layout,
            is_error=True,
        )

    else:
        response_body = (
            "An error occurred while processing your message. "
            "To retry, send your message again."
        )
        if result.error_summary:
            response_body += (
                f"\n\nClaude output:\n```\n{result.error_summary}\n```"
            )
        logger.error(
            "Repo '%s': execution failed for conversation %s: %s",
            repo_id,
            conversation_id,
            result.outcome.value,
        )
        reply = _build_reply_summary(
            result,
            request_text=prompt,
            response_text=response_body,
            is_error=True,
        )
        conversation_store.add_reply(conversation_id, reply)

        return SandboxTaskResult(
            outcome=result.outcome,
            conversation_id=conversation_id,
            response_text=response_body,
            usage_stats=None,
            layout=layout,
            is_error=True,
        )


# ── Channel-facing wrapper ─────────────────────────────────────────────


def process_message(
    service: GatewayService,
    parsed: ParsedMessage,
    task_id: str,
    repo_handler: RepoHandler,
    adapter: ChannelAdapter,
) -> tuple[CompletionReason, str | None]:
    """Process a parsed message from any channel.

    Args:
        service: Parent service for shared resources.
        parsed: Parsed message from the channel adapter.
        task_id: Task ID for dashboard tracking.
        repo_handler: Repo handler that owns this message.
        adapter: Channel adapter for sending replies.

    Returns:
        Tuple of (CompletionReason, conversation_id).
    """
    repo_id = repo_handler.config.repo_id
    conv_id = parsed.conversation_id
    conv_mgr = repo_handler.conversation_manager
    is_new = not conv_mgr.exists(conv_id) if conv_id else True

    logger.info(
        "Repo '%s': processing message from %s",
        repo_id,
        parsed.sender,
    )

    if not parsed.body.strip():
        # For new conversations with a subject line the subject
        # is part of channel_context and may carry the full
        # request, so an empty body is acceptable.
        if not parsed.subject:
            logger.warning("Repo '%s': empty message body", repo_id)
            adapter.send_error(
                parsed,
                None,
                "Your message appears to be empty. "
                "Please send a new message with instructions.",
            )
            return CompletionReason.EXECUTION_FAILED, None

    conversation_store: ConversationStore | None = None
    plan_streamer: PlanStreamer | None = None
    prompt = parsed.body

    try:
        # ── Conversation management ──

        if is_new:
            logger.info("Repo '%s': creating new conversation", repo_id)
            logger.info(
                "Repo '%s': updating git mirror before creating "
                "conversation...",
                repo_id,
            )
            conv_mgr.mirror.update_mirror()
            conv_id, repo_path = conv_mgr.initialize_new()
            logger.info(
                "Repo '%s': created conversation %s",
                repo_id,
                conv_id,
            )

            service.tracker.set_conversation_id(task_id, conv_id)
        else:
            logger.info(
                "Repo '%s': resuming conversation %s",
                repo_id,
                conv_id,
            )
            assert conv_id is not None
            logger.info(
                "Repo '%s': updating git mirror before resuming...",
                repo_id,
            )
            conv_mgr.mirror.update_mirror()
            conv_mgr.resume_existing(conv_id)

        # Register conversation-to-repo mapping
        assert conv_id is not None
        service._conv_repo_map[conv_id] = repo_id

        # ── Model and effort ──

        repo_cfg = repo_handler.config

        if is_new:
            model = parsed.model_hint or repo_cfg.model
            effort = repo_cfg.effort
            logger.info(
                "Repo '%s': using model=%s, effort=%s for new "
                "conversation %s (model_hint=%s)",
                repo_id,
                model,
                effort,
                conv_id,
                parsed.model_hint,
            )

            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            conversation_store = ConversationStore(conversation_dir)
            conversation_store.set_model(conv_id, model)
            conversation_store.set_effort(conv_id, effort)
            service.tracker.set_task_model(task_id, model)
            service.tracker.set_reply_index(task_id, 0)
        else:
            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            conversation_store = ConversationStore(conversation_dir)
            model = conversation_store.get_model() or repo_cfg.model
            effort = conversation_store.get_effort() or repo_cfg.effort
            if parsed.model_hint and parsed.model_hint != model:
                logger.warning(
                    "Repo '%s': ignoring model=%s in resumed "
                    "conversation %s (using stored model=%s)",
                    repo_id,
                    parsed.model_hint,
                    conv_id,
                    model,
                )
            service.tracker.set_task_model(task_id, model)
            conv_meta = conversation_store.load()
            reply_count = len(conv_meta.replies) if conv_meta else 0
            service.tracker.set_reply_index(task_id, reply_count)

        # ── Acknowledgment ──

        if is_new:
            dashboard_url = service.global_config.dashboard_base_url
            adapter.send_acknowledgment(parsed, conv_id, model, dashboard_url)

        # ── Layout and attachments ──

        layout = create_conversation_layout(conversation_dir)
        prepare_conversation(layout)

        filenames = adapter.save_attachments(parsed, layout.inbox)
        channel_context = parsed.channel_context
        if filenames:
            parsed.attachments = filenames
            logger.info(
                "Repo '%s': saved %d attachments: %s",
                repo_id,
                len(filenames),
                ", ".join(filenames),
            )
            inbox_note = (
                " The user has attached files to their message"
                ", which I have saved to /inbox/: "
                f"{', '.join(filenames)}."
            )
            channel_context += inbox_note

        # ── Build prompt ──

        prompt = f"{channel_context}\n\n{parsed.body}"

        # ── Execute in sandbox ──

        plan_streamer = adapter.create_plan_streamer(parsed)
        todo_callback = _make_todo_callback(
            service.tracker, task_id, plan_streamer
        )

        sandbox_result = run_in_sandbox(
            service,
            repo_handler,
            prompt=prompt,
            task_id=task_id,
            model=model,
            effort=effort,
            conversation_id=conv_id,
            on_event=todo_callback,
            channel_context=channel_context,
            user_body=parsed.body,
        )

        conv_id = sandbox_result.conversation_id

        # ── Finalize and deliver ──

        if plan_streamer is not None:
            plan_streamer.finalize()

        if sandbox_result.outcome == Outcome.SUCCESS:
            outbox_files = (
                list(sandbox_result.layout.outbox.iterdir())
                if sandbox_result.layout.outbox.exists()
                else []
            )
            usage_footer = (
                sandbox_result.usage_stats.format_summary()
                if sandbox_result.usage_stats
                and sandbox_result.usage_stats.has_any()
                else ""
            )
            adapter.send_reply(
                parsed,
                conv_id,
                sandbox_result.response_text,
                usage_footer,
                outbox_files,
            )
        elif sandbox_result.outcome == Outcome.TIMEOUT:
            adapter.send_error(parsed, conv_id, sandbox_result.response_text)
            return CompletionReason.TIMEOUT, conv_id
        else:
            outbox_files = (
                list(sandbox_result.layout.outbox.iterdir())
                if sandbox_result.layout.outbox.exists()
                else []
            )
            adapter.send_reply(
                parsed,
                conv_id,
                sandbox_result.response_text,
                "",
                outbox_files,
            )

        logger.info(
            "Repo '%s': sent reply to %s for conversation %s",
            repo_id,
            parsed.sender,
            conv_id,
        )
        if sandbox_result.outcome == Outcome.SUCCESS:
            return CompletionReason.SUCCESS, conv_id
        return CompletionReason.EXECUTION_FAILED, conv_id

    except GitCloneError as e:
        logger.exception(
            "Repo '%s': failed to initialize conversation: %s",
            repo_id,
            e,
        )
        error_msg = (
            "An error occurred while processing your message: "
            "unable to create workspace. "
            "To retry, send your message again.\n\n"
            f"`{e}`"
        )
        adapter.send_error(parsed, conv_id, error_msg)
        return CompletionReason.INTERNAL_ERROR, None
    except ClaudeBinaryError as e:
        logger.error(
            "Repo '%s': failed to fetch Claude binary: %s",
            repo_id,
            e,
        )
        adapter.send_error(
            parsed,
            conv_id,
            "Failed to fetch Claude binary. Please try again later.",
        )
        return CompletionReason.EXECUTION_FAILED, conv_id
    except ChannelSendError as e:
        if plan_streamer is not None:
            plan_streamer.finalize()
        logger.error(
            "Repo '%s': channel send error for conversation %s: %s",
            repo_id,
            conv_id,
            e,
        )
        return CompletionReason.CHANNEL_ERROR, conv_id
    except Exception as e:
        if plan_streamer is not None:
            plan_streamer.finalize()
        logger.exception(
            "Repo '%s': unexpected error processing message: %s",
            repo_id,
            e,
        )
        error_msg = (
            "An error occurred while processing your message."
            " To retry, send your message again.\n\n"
            f"`{type(e).__name__}: {e}`"
        )
        adapter.send_error(parsed, conv_id, error_msg)
        if conv_id and conversation_store:
            try:
                from datetime import datetime

                from airut.claude_output.types import Usage

                reply = ReplySummary(
                    session_id="",
                    timestamp=datetime.now(tz=UTC).isoformat(),
                    duration_ms=0,
                    total_cost_usd=0.0,
                    num_turns=0,
                    is_error=True,
                    usage=Usage(),
                    request_text=prompt,
                    response_text=error_msg,
                )
                conversation_store.add_reply(conv_id, reply)
            except Exception as persist_err:
                logger.warning(
                    "Failed to persist error to conversation: %s",
                    persist_err,
                )
        return CompletionReason.INTERNAL_ERROR, conv_id


def _convert_replacement_map(
    replacement_map: ReplacementMap,
) -> SecretReplacements:
    """Convert gateway ReplacementMap to sandbox types.

    Args:
        replacement_map: Gateway-produced replacement map.

    Returns:
        SecretReplacements for the sandbox.
    """
    from airut.gateway.config import (
        GitHubAppEntry,
        ReplacementEntry,
        SigningCredentialEntry,
    )
    from airut.sandbox.secrets import (
        SecretReplacements,
        _GitHubAppEntry,
        _ReplacementEntry,
        _SigningCredentialEntry,
    )

    internal_map: dict[
        str,
        _ReplacementEntry | _SigningCredentialEntry | _GitHubAppEntry,
    ] = {}

    for surrogate, entry in replacement_map.items():
        if isinstance(entry, ReplacementEntry):
            internal_map[surrogate] = _ReplacementEntry(
                real_value=entry.real_value,
                scopes=entry.scopes,
                headers=entry.headers,
                allow_foreign_credentials=(entry.allow_foreign_credentials),
            )
        elif isinstance(entry, SigningCredentialEntry):
            internal_map[surrogate] = _SigningCredentialEntry(
                access_key_id=entry.access_key_id,
                secret_access_key=entry.secret_access_key,
                session_token=entry.session_token,
                surrogate_session_token=(entry.surrogate_session_token),
                scopes=entry.scopes,
            )
        elif isinstance(entry, GitHubAppEntry):
            internal_map[surrogate] = _GitHubAppEntry(
                app_id=entry.app_id,
                private_key=entry.private_key,
                installation_id=entry.installation_id,
                base_url=entry.base_url,
                scopes=entry.scopes,
                allow_foreign_credentials=(entry.allow_foreign_credentials),
                permissions=entry.permissions,
                repositories=entry.repositories,
            )

    return SecretReplacements(_map=internal_map)
