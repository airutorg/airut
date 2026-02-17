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
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import TYPE_CHECKING

from airut.allowlist import parse_allowlist_yaml
from airut.claude_output import (
    extract_error_summary,
    extract_result_summary,
    extract_session_id,
)
from airut.claude_output.types import StreamEvent, ToolUseBlock
from airut.conversation import (
    ConversationStore,
    ReplySummary,
    create_conversation_layout,
    prepare_conversation,
)
from airut.dashboard.tracker import TaskTracker, TodoItem, TodoStatus
from airut.gateway.channel import ChannelAdapter, ParsedMessage
from airut.gateway.config import ReplacementMap, RepoConfig
from airut.gateway.conversation import GitCloneError
from airut.gateway.service.usage_stats import extract_usage_stats
from airut.sandbox import (
    ContainerEnv,
    Mount,
    NetworkSandboxConfig,
    Outcome,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from airut.gateway.service.gateway import GatewayService
    from airut.gateway.service.repo_handler import RepoHandler
    from airut.sandbox.secrets import SecretReplacements

logger = logging.getLogger(__name__)


_REPO_DOCKERFILE_PATH = ".airut/container/Dockerfile"
_REPO_CONTAINER_DIR = ".airut/container"


def _make_todo_callback(
    tracker: TaskTracker, conversation_id: str
) -> Callable[[StreamEvent], None]:
    """Build an on_event callback that captures TodoWrite events.

    Args:
        tracker: Task tracker to update.
        conversation_id: Conversation ID to update todos for.

    Returns:
        Callback suitable for ``task.execute(on_event=...)``.
    """
    status_map = {s.value: s for s in TodoStatus}

    def on_event(event: StreamEvent) -> None:
        for block in event.content_blocks:
            if (
                isinstance(block, ToolUseBlock)
                and block.tool_name == "TodoWrite"
            ):
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
                    tracker.update_todos(conversation_id, items)

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
        last_response: The last successful response from the agent, or None.
        channel_context: The channel context header (channel mode instructions).
        user_message: The user's current message that triggered the error.

    Returns:
        Prompt string for the new session.
    """
    parts = [channel_context, ""]

    parts.append(
        "IMPORTANT: The previous conversation session could not be resumed "
        "due to context length limits (context compaction boundary). "
        "This is a fresh session, but the workspace may contain ongoing work "
        "from the previous session."
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
        "conversation state is unclear, ask for clarification. Check the "
        "workspace (git status, recent files) to understand any ongoing work."
    )

    parts.append(f"\nThe user's message:\n{user_message}")

    return "\n".join(parts)


def _build_image(
    service: GatewayService,
    mirror: object,
) -> str:
    """Build or reuse container image from git mirror.

    Args:
        service: Parent service with sandbox.
        mirror: Git mirror cache.

    Returns:
        Image tag for container execution.
    """
    # Read all files from .airut/container/ directory
    try:
        filenames = mirror.list_directory(_REPO_CONTAINER_DIR)  # type: ignore[union-attr]
    except Exception as e:
        from airut.sandbox import ImageBuildError

        raise ImageBuildError(
            f"Failed to list {_REPO_CONTAINER_DIR} from mirror: {e}"
        )

    dockerfile_content: bytes | None = None
    context_files: dict[str, bytes] = {}

    for filename in filenames:
        file_path = f"{_REPO_CONTAINER_DIR}/{filename}"
        try:
            content = mirror.read_file(file_path)  # type: ignore[union-attr]
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

        raise ImageBuildError(f"No Dockerfile found in {_REPO_CONTAINER_DIR}")

    return service.sandbox.ensure_image(dockerfile_content, context_files)


def _build_reply_summary(
    result: object,
    *,
    request_text: str,
    response_text: str,
    is_error: bool = False,
) -> ReplySummary:
    """Build a ReplySummary from an ExecutionResult.

    Extracts session_id, cost, usage, and timing from the result's events
    and packages them into a ReplySummary for conversation.json.

    Args:
        result: ExecutionResult from sandbox execution.
        request_text: The prompt text sent to Claude.
        response_text: Claude's response text (or error message).
        is_error: Whether this reply represents an error.

    Returns:
        ReplySummary ready for ConversationStore.
    """
    from datetime import datetime

    from airut.claude_output.types import Usage
    from airut.sandbox.types import ExecutionResult

    assert isinstance(result, ExecutionResult)

    session_id = extract_session_id(result.events) or ""
    summary = extract_result_summary(result.events)

    if summary is not None:
        return ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=summary.duration_ms,
            total_cost_usd=summary.total_cost_usd,
            num_turns=summary.num_turns,
            is_error=is_error or summary.is_error,
            usage=summary.usage,
            request_text=request_text,
            response_text=response_text,
        )
    else:
        # No result event (e.g., timeout, crash) — use fallback values
        return ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=result.duration_ms,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=is_error,
            usage=Usage(),
            request_text=request_text,
            response_text=response_text,
        )


def process_message(
    service: GatewayService,
    parsed: ParsedMessage,
    task_id: str,
    repo_handler: RepoHandler,
    adapter: ChannelAdapter,
) -> tuple[bool, str | None]:
    """Process a parsed message from any channel.

    Args:
        service: Parent service for shared resources.
        parsed: Parsed message from the channel adapter.
        task_id: Task ID for dashboard tracking.
        repo_handler: Repo handler that owns this message.
        adapter: Channel adapter for sending replies.

    Returns:
        Tuple of (success, conversation_id).
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
        logger.warning("Repo '%s': empty message body", repo_id)
        adapter.send_error(
            parsed,
            None,
            "Your message appears to be empty. "
            "Please send a new message with instructions.",
        )
        return False, None

    conversation_store: ConversationStore | None = None
    prompt = parsed.body

    try:
        # Manage conversation
        if is_new:
            logger.info("Repo '%s': creating new conversation", repo_id)
            logger.info(
                "Repo '%s': updating git mirror before creating "
                "conversation...",
                repo_id,
            )
            conv_mgr.mirror.update_mirror()
            conv_id, repo_path = conv_mgr.initialize_new()
            logger.info("Repo '%s': created conversation %s", repo_id, conv_id)

            if conv_id != task_id:
                service.tracker.update_task_id(task_id, conv_id)
        else:
            logger.info("Repo '%s': resuming conversation %s", repo_id, conv_id)
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

        # Load repo config from git mirror
        repo_config, replacement_map = RepoConfig.from_mirror(
            conv_mgr.mirror,
            repo_handler.config.secrets,
            repo_handler.config.masked_secrets,
            repo_handler.config.signing_credentials,
            server_sandbox_enabled=repo_handler.config.network_sandbox_enabled,
        )

        if is_new:
            model = parsed.model_hint or repo_config.default_model
            logger.info(
                "Repo '%s': using model=%s for new conversation %s "
                "(requested=%s, default=%s)",
                repo_id,
                model,
                conv_id,
                parsed.model_hint,
                repo_config.default_model,
            )

            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            conversation_store = ConversationStore(conversation_dir)
            conversation_store.set_model(conv_id, model)
            service.tracker.set_task_model(conv_id, model)
        else:
            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            conversation_store = ConversationStore(conversation_dir)
            model = conversation_store.get_model() or repo_config.default_model
            if parsed.model_hint and parsed.model_hint != model:
                logger.warning(
                    "Repo '%s': ignoring model=%s in resumed "
                    "conversation %s (using stored model=%s)",
                    repo_id,
                    parsed.model_hint,
                    conv_id,
                    model,
                )
            service.tracker.set_task_model(conv_id, model)

        # Send acknowledgment only for first message
        if is_new:
            dashboard_url = service.global_config.dashboard_base_url
            adapter.send_acknowledgment(parsed, conv_id, model, dashboard_url)

        # Prepare session layout
        layout = create_conversation_layout(conversation_dir)
        prepare_conversation(layout)

        # Save attachments via the channel adapter now that inbox dir exists
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
                f" The user has attached files to their message, "
                f"which I have saved to /inbox/: {', '.join(filenames)}."
            )
            channel_context += inbox_note

        # Build prompt
        prompt = f"{channel_context}\n\n{parsed.body}"

        # Build or reuse container image
        image_tag = _build_image(service, conv_mgr.mirror)

        # Build mounts (sandbox manages claude/ internally)
        mounts = [
            Mount(layout.workspace, "/workspace"),
            Mount(layout.inbox, "/inbox"),
            Mount(layout.outbox, "/outbox"),
            Mount(layout.storage, "/storage"),
        ]

        # Build container environment
        env = ContainerEnv(variables=repo_config.container_env)

        # Build network sandbox config if enabled
        network_sandbox: NetworkSandboxConfig | None = None
        if repo_config.network_sandbox_enabled:
            try:
                allowlist_data = conv_mgr.mirror.read_file(
                    ".airut/network-allowlist.yaml"
                )
                allowlist = parse_allowlist_yaml(allowlist_data)
            except Exception as e:
                from airut.sandbox import ProxyError

                raise ProxyError(f"Failed to read/parse allowlist: {e}") from e

            # Convert gateway ReplacementMap to sandbox SecretReplacements
            replacements = _convert_replacement_map(replacement_map)
            network_sandbox = NetworkSandboxConfig(
                allowlist=allowlist,
                replacements=replacements,
            )

        # Create sandbox task
        task = service.sandbox.create_task(
            execution_context_id=conv_id,
            image_tag=image_tag,
            mounts=mounts,
            env=env,
            execution_context_dir=conversation_dir,
            network_log_dir=(
                conversation_dir if network_sandbox is not None else None
            ),
            network_sandbox=network_sandbox,
            timeout_seconds=repo_config.timeout,
        )

        # Register task for stop functionality
        service.register_active_task(conv_id, task)

        # Persist request text so dashboard can show it during execution
        conversation_store.set_pending_request(conv_id, prompt)

        # Start new reply delimiter in event log
        task.event_log.start_new_reply()

        logger.info(
            "Repo '%s': executing Claude Code (model=%s) for conversation %s",
            repo_id,
            model,
            conv_id,
        )

        # Get session ID for resumption
        session_id = conversation_store.get_session_id_for_resume()
        if session_id:
            logger.info(
                "Repo '%s': resuming Claude session %s for conversation %s",
                repo_id,
                session_id,
                conv_id,
            )

        todo_callback = _make_todo_callback(service.tracker, conv_id)

        try:
            result = task.execute(
                prompt,
                session_id=session_id,
                model=model,
                on_event=todo_callback,
            )
        finally:
            service.unregister_active_task(conv_id)

        # Handle unresumable session errors by retrying with a new session
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
                "Repo '%s': %s for conversation %s, "
                "retrying with fresh session",
                repo_id,
                reason,
                conv_id,
            )

            last_response = conversation_store.get_last_successful_response()
            recovery_prompt = build_recovery_prompt(
                last_response, channel_context, parsed.body
            )

            # Create new task for retry
            task = service.sandbox.create_task(
                execution_context_id=conv_id,
                image_tag=image_tag,
                mounts=mounts,
                env=env,
                execution_context_dir=conversation_dir,
                network_log_dir=(
                    conversation_dir if network_sandbox is not None else None
                ),
                network_sandbox=network_sandbox,
                timeout_seconds=repo_config.timeout,
            )

            # Persist recovery prompt for dashboard visibility
            conversation_store.set_pending_request(conv_id, recovery_prompt)

            # Start new reply delimiter for recovery attempt
            task.event_log.start_new_reply()

            service.register_active_task(conv_id, task)
            try:
                result = task.execute(
                    recovery_prompt,
                    session_id=None,
                    model=model,
                    on_event=todo_callback,
                )
                # Update prompt so conversation stores the recovery prompt
                prompt = recovery_prompt
            finally:
                service.unregister_active_task(conv_id)

        # Extract response and usage stats, record reply summary
        if result.outcome == Outcome.SUCCESS:
            response_body = result.response_text
            usage_stats = extract_usage_stats(
                result.events,
                is_subscription=bool(
                    repo_config.container_env.get("CLAUDE_CODE_OAUTH_TOKEN")
                ),
            )
            logger.info(
                "Repo '%s': execution successful for conversation %s",
                repo_id,
                conv_id,
            )

            reply = _build_reply_summary(
                result,
                request_text=prompt,
                response_text=response_body,
            )
            conversation_store.add_reply(conv_id, reply)

            # Collect outbox files for attachment
            outbox_files = (
                list(layout.outbox.iterdir()) if layout.outbox.exists() else []
            )
            usage_footer = (
                usage_stats.format_summary() if usage_stats.has_any() else ""
            )
            adapter.send_reply(
                parsed, conv_id, response_body, usage_footer, outbox_files
            )
        elif result.outcome == Outcome.TIMEOUT:
            error_msg = (
                f"The task was interrupted after "
                f"{repo_config.timeout} seconds. "
                "Work done so far has been saved.\n\n"
                "Reply to resume \u2014 you can ask about progress or "
                "request next steps."
            )
            adapter.send_error(parsed, conv_id, error_msg)
            reply = _build_reply_summary(
                result,
                request_text=prompt,
                response_text=error_msg,
                is_error=True,
            )
            conversation_store.add_reply(conv_id, reply)
            return False, conv_id
        else:
            response_body = (
                "An error occurred while processing your message. "
                "To retry, send your message again."
            )
            error_summary = extract_error_summary(result.events)
            if error_summary:
                response_body += (
                    f"\n\nClaude output:\n```\n{error_summary}\n```"
                )
            logger.error(
                "Repo '%s': execution failed for conversation %s: %s",
                repo_id,
                conv_id,
                result.outcome.value,
            )
            reply = _build_reply_summary(
                result,
                request_text=prompt,
                response_text=response_body,
                is_error=True,
            )
            conversation_store.add_reply(conv_id, reply)

            # Send error response with outbox files
            outbox_files = (
                list(layout.outbox.iterdir()) if layout.outbox.exists() else []
            )
            adapter.send_reply(parsed, conv_id, response_body, "", outbox_files)

        logger.info(
            "Repo '%s': sent reply to %s for conversation %s",
            repo_id,
            parsed.sender,
            conv_id,
        )
        return result.outcome == Outcome.SUCCESS, conv_id

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
        return False, None
    except Exception as e:
        logger.exception(
            "Repo '%s': unexpected error processing message: %s",
            repo_id,
            e,
        )
        error_msg = (
            "An error occurred while processing your message. "
            "To retry, send your message again.\n\n"
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
        return False, conv_id


def _convert_replacement_map(
    replacement_map: ReplacementMap,
) -> SecretReplacements:
    """Convert a gateway ReplacementMap to sandbox SecretReplacements.

    The gateway config module produces ReplacementMap with ReplacementEntry
    and SigningCredentialEntry objects. The sandbox needs SecretReplacements
    with its own internal types.

    Args:
        replacement_map: Gateway-produced replacement map.

    Returns:
        SecretReplacements for the sandbox.
    """
    from airut.gateway.config import (
        ReplacementEntry,
        SigningCredentialEntry,
    )
    from airut.sandbox.secrets import (
        SecretReplacements,
        _ReplacementEntry,
        _SigningCredentialEntry,
    )

    internal_map: dict[str, _ReplacementEntry | _SigningCredentialEntry] = {}

    for surrogate, entry in replacement_map.items():
        if isinstance(entry, ReplacementEntry):
            internal_map[surrogate] = _ReplacementEntry(
                real_value=entry.real_value,
                scopes=entry.scopes,
                headers=entry.headers,
            )
        elif isinstance(entry, SigningCredentialEntry):
            internal_map[surrogate] = _SigningCredentialEntry(
                access_key_id=entry.access_key_id,
                secret_access_key=entry.secret_access_key,
                session_token=entry.session_token,
                surrogate_session_token=entry.surrogate_session_token,
                scopes=entry.scopes,
            )

    return SecretReplacements(_map=internal_map)
