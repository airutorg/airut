# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Message processing logic for the gateway service.

This module handles:
- Processing individual email messages
- Managing conversation state and session resumption
- Executing Claude Code in containers
- Handling prompt-too-long recovery
"""

from __future__ import annotations

import logging
from email.message import Message
from typing import TYPE_CHECKING

from lib.container.conversation_layout import (
    create_conversation_layout,
    get_container_mounts,
    prepare_conversation,
)
from lib.container.executor import (
    ContainerTimeoutError,
    ExecutionResult,
    extract_error_summary,
)
from lib.container.session import SessionStore
from lib.gateway.config import RepoConfig
from lib.gateway.conversation import GitCloneError
from lib.gateway.parsing import (
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_model_from_address,
)
from lib.gateway.service.email_replies import (
    send_acknowledgment,
    send_error_reply,
    send_reply,
)
from lib.gateway.service.usage_stats import (
    extract_response_text,
    extract_usage_stats,
)


if TYPE_CHECKING:
    from lib.container.proxy import TaskProxy
    from lib.gateway.service.gateway import EmailGatewayService
    from lib.gateway.service.repo_handler import RepoHandler

logger = logging.getLogger(__name__)


def is_prompt_too_long_error(result: ExecutionResult) -> bool:
    """Check if an execution failure is a 'Prompt is too long' error.

    This error occurs when Claude's context window is exceeded after
    context compaction, making the session unresumable.

    Args:
        result: Execution result from Claude.

    Returns:
        True if the error is a prompt-too-long failure.
    """
    if result.success:
        return False
    # Claude outputs "Prompt is too long" to stdout when context is exceeded
    return "Prompt is too long" in result.stdout


def is_session_corrupted_error(result: ExecutionResult) -> bool:
    """Check if an execution failure is due to a corrupted/unresumable session.

    Detects API 4xx errors that indicate the session state is invalid and
    cannot be resumed. These include:
    - 400: invalid_request_error (e.g., mismatched tool_use_id/tool_result)
    - Other 4xx client errors from the Claude API

    When this occurs, the session_id must be cleared so the next attempt
    starts a fresh session rather than repeatedly hitting the same error.

    Args:
        result: Execution result from Claude.

    Returns:
        True if the error indicates a corrupted session.
    """
    if result.success:
        return False

    # Check both stdout and stderr for API error patterns.
    # Claude Code outputs "API Error: <status>" when an API call fails.
    combined = f"{result.stdout}\n{result.stderr}"
    if "API Error: 4" not in combined:
        return False

    # Only treat as corrupted session if this was a resumed session.
    # The error text alone is sufficient — we check session_id in the caller.
    return True


def build_recovery_prompt(
    last_response: str | None,
    email_context: str,
    user_message: str,
) -> str:
    """Build a prompt for a new session after context compaction failure.

    When a conversation hits the context compaction boundary and can no
    longer be resumed, we start a fresh session with context about what
    happened.

    Args:
        last_response: The last successful response from the agent, or None.
        email_context: The email context header (email mode instructions).
        user_message: The user's current message that triggered the error.

    Returns:
        Prompt string for the new session.
    """
    parts = [email_context, ""]

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


def process_message(
    service: EmailGatewayService,
    message: Message,
    task_id: str,
    repo_handler: RepoHandler,
) -> tuple[bool, str | None]:
    """Process a single email message.

    Args:
        service: Parent service for shared resources.
        message: Parsed email message.
        task_id: Task ID for dashboard tracking.
        repo_handler: Repo handler that owns this message.

    Returns:
        Tuple of (success, conversation_id).
    """
    sender = message.get("From", "")
    subject = decode_subject(message)
    message_id = message.get("Message-ID", "")
    to_address = message.get("To", "")
    repo_id = repo_handler.config.repo_id

    logger.info(
        "Repo '%s': processing message from %s: %s",
        repo_id,
        sender,
        subject[:50] + "..." if len(subject) > 50 else subject,
    )

    # Extract model from To address (e.g., airut+opus@domain.com)
    requested_model = extract_model_from_address(to_address)

    # Authentication: verify DMARC from trusted server
    authenticated_sender = repo_handler.authenticator.authenticate(message)
    if authenticated_sender is None:
        logger.warning(
            "Repo '%s': rejecting unauthenticated message from %s "
            "(Message-ID: %s)",
            repo_id,
            sender,
            message_id,
        )
        return False, None

    # Authorization: check sender is allowed
    if not repo_handler.authorizer.is_authorized(authenticated_sender):
        logger.warning(
            "Repo '%s': rejecting unauthorized message from %s "
            "(Message-ID: %s)",
            repo_id,
            sender,
            message_id,
        )
        return False, None

    # Extract conversation ID
    conv_id = extract_conversation_id(subject)
    conv_mgr = repo_handler.conversation_manager
    is_new = not conv_mgr.exists(conv_id) if conv_id else True

    # Extract body (HTML quotes stripped via strip_html_quotes in extract_body)
    clean_body = extract_body(message)

    if not clean_body.strip():
        logger.warning("Repo '%s': empty message body", repo_id)
        send_error_reply(
            repo_handler,
            message,
            "Your message appears to be empty. "
            "Please send a new message with instructions.",
        )
        return False, None

    session_store: SessionStore | None = None
    events_buffer: list[dict] = []
    prompt = clean_body

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
            repo_path = conv_mgr.resume_existing(conv_id)

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
            model = requested_model or repo_config.default_model
            logger.info(
                "Repo '%s': using model=%s for new conversation %s "
                "(requested=%s, default=%s)",
                repo_id,
                model,
                conv_id,
                requested_model,
                repo_config.default_model,
            )

            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            session_store = SessionStore(conversation_dir)
            session_store.set_model(conv_id, model)
            service.tracker.set_task_model(conv_id, model)
        else:
            conversation_dir = conv_mgr.get_conversation_dir(conv_id)
            session_store = SessionStore(conversation_dir)
            model = session_store.get_model() or repo_config.default_model
            if requested_model and requested_model != model:
                logger.warning(
                    "Repo '%s': ignoring model=%s in resumed "
                    "conversation %s (using stored model=%s)",
                    repo_id,
                    requested_model,
                    conv_id,
                    model,
                )
            service.tracker.set_task_model(conv_id, model)

        # Send acknowledgment only for first message
        if is_new:
            send_acknowledgment(
                repo_handler, message, conv_id, model, service.global_config
            )

        # Prepare session layout
        layout = create_conversation_layout(conversation_dir)
        prepare_conversation(layout)

        # Extract attachments
        filenames = extract_attachments(message, layout.inbox)
        if filenames:
            logger.info(
                "Repo '%s': saved %d attachments: %s",
                repo_id,
                len(filenames),
                ", ".join(filenames),
            )

        # Build prompt
        email_context = (
            "User is interacting with this session via email interface "
            "and will receive your last reply as email. "
            "After the reply, everything not in /workspace, /inbox, "
            "and /storage is reset. "
            "Markdown formatting is supported in your responses. "
            "To send files back to the user, place them in the "
            "/outbox/ directory root (no subdirectories). "
            "Use /storage to persist files across messages.\n\n"
            "IMPORTANT: AskUserQuestion and plan mode tools "
            "(EnterPlanMode/ExitPlanMode) do not work over email "
            "interface. If you need clarification, include questions in "
            "your response text and the user will reply via email."
        )

        if filenames:
            inbox_note = (
                f" The user has attached files to their email, "
                f"which I have saved to /inbox/: {', '.join(filenames)}."
            )
            email_context += inbox_note

        prompt = f"{email_context}\n\n{clean_body}"

        # Build or reuse container image
        image_tag = repo_handler.executor.ensure_image()

        # Get session ID for resumption
        session_id = session_store.get_session_id_for_resume()
        if session_id:
            logger.info(
                "Repo '%s': resuming Claude session %s for conversation %s",
                repo_id,
                session_id,
                conv_id,
            )

        logger.info(
            "Repo '%s': executing Claude Code (model=%s) for conversation %s",
            repo_id,
            model,
            conv_id,
        )

        # Streaming event callback
        events_buffer: list[dict] = []

        def on_event(event: dict) -> None:
            """Callback invoked for each streaming JSON event."""
            events_buffer.append(event)
            if conv_id:
                partial_output = {"events": events_buffer.copy()}
                if event.get("type") == "result":
                    partial_output["session_id"] = event.get("session_id", "")
                    partial_output["duration_ms"] = event.get("duration_ms", 0)
                    partial_output["total_cost_usd"] = event.get(
                        "total_cost_usd", 0.0
                    )
                    partial_output["num_turns"] = event.get("num_turns", 0)
                    partial_output["is_error"] = event.get("is_error", False)
                    partial_output["usage"] = event.get("usage", {})
                    partial_output["result"] = event.get("result", "")

                try:
                    session_store.update_or_add_reply(
                        conv_id,
                        partial_output,
                        request_text=prompt,
                        response_text="",
                    )
                except Exception as e:
                    logger.warning("Failed to update session file: %s", e)

        task_proxy: TaskProxy | None = None
        if repo_config.network_sandbox_enabled and conv_id:
            task_proxy = service.proxy_manager.start_task_proxy(
                conv_id,
                mirror=conv_mgr.mirror,
                conversation_dir=layout.conversation_dir,
                replacement_map=replacement_map,
            )

        try:
            result = repo_handler.executor.execute(
                session_git_repo=repo_path,
                prompt=prompt,
                mounts=get_container_mounts(layout),
                image_tag=image_tag,
                session_id=session_id,
                model=model,
                on_event=on_event,
                conversation_id=conv_id,
                task_proxy=task_proxy,
                container_env=repo_config.container_env,
                timeout_seconds=repo_config.timeout,
            )
        finally:
            if repo_config.network_sandbox_enabled and conv_id:
                service.proxy_manager.stop_task_proxy(conv_id)

        # Handle unresumable session errors by retrying with a new session.
        # This covers both "Prompt is too long" (context compaction boundary)
        # and API 4xx errors (corrupted session state, e.g., mismatched
        # tool_use_id/tool_result pairs).
        is_unresumable = is_prompt_too_long_error(
            result
        ) or is_session_corrupted_error(result)
        if is_unresumable and session_id is not None:
            reason = (
                "prompt too long"
                if is_prompt_too_long_error(result)
                else "session corrupted (API 4xx)"
            )
            logger.warning(
                "Repo '%s': %s for conversation %s, "
                "retrying with fresh session",
                repo_id,
                reason,
                conv_id,
            )

            last_response = session_store.get_last_successful_response()
            recovery_prompt = build_recovery_prompt(
                last_response, email_context, clean_body
            )

            # Reset events buffer for the retry
            events_buffer.clear()

            task_proxy = None
            if repo_config.network_sandbox_enabled and conv_id:
                task_proxy = service.proxy_manager.start_task_proxy(
                    conv_id,
                    mirror=conv_mgr.mirror,
                    conversation_dir=layout.conversation_dir,
                    replacement_map=replacement_map,
                )

            try:
                result = repo_handler.executor.execute(
                    session_git_repo=repo_path,
                    prompt=recovery_prompt,
                    mounts=get_container_mounts(layout),
                    image_tag=image_tag,
                    session_id=None,
                    model=model,
                    on_event=on_event,
                    conversation_id=conv_id,
                    task_proxy=task_proxy,
                    container_env=repo_config.container_env,
                    timeout_seconds=repo_config.timeout,
                )
                # Update prompt so session stores the recovery prompt
                prompt = recovery_prompt
            finally:
                if repo_config.network_sandbox_enabled and conv_id:
                    service.proxy_manager.stop_task_proxy(conv_id)

        # Extract response and usage stats
        if result.success:
            response_body = extract_response_text(result.output)
            usage_stats = extract_usage_stats(
                result.output,
                is_subscription=bool(
                    repo_config.container_env.get("CLAUDE_CODE_OAUTH_TOKEN")
                ),
            )
            logger.info(
                "Repo '%s': execution successful for conversation %s",
                repo_id,
                conv_id,
            )

            if result.output:
                session_store.update_or_add_reply(
                    conv_id,
                    result.output,
                    request_text=prompt,
                    response_text=response_body,
                )

            if usage_stats.has_any():
                stats_footer = usage_stats.format_summary()
                response_body = f"{response_body}\n\n*{stats_footer}*"
        else:
            response_body = (
                "An error occurred while processing your message. "
                "To retry, send your message again."
            )
            error_summary = extract_error_summary(result.stdout)
            if error_summary:
                response_body += (
                    f"\n\nClaude output:\n```\n{error_summary}\n```"
                )
            logger.error(
                "Repo '%s': execution failed for conversation %s: %s",
                repo_id,
                conv_id,
                result.error_message,
            )

            error_output = result.output or {
                "is_error": True,
                "events": events_buffer.copy(),
            }
            error_output.setdefault("is_error", True)
            session_store.update_or_add_reply(
                conv_id,
                error_output,
                request_text=prompt,
                response_text=response_body,
            )

        # Send reply
        assert conv_id is not None
        send_reply(repo_handler, message, conv_id, response_body)
        logger.info(
            "Repo '%s': sent reply to %s for conversation %s",
            repo_id,
            sender,
            conv_id,
        )
        return result.success, conv_id

    except ContainerTimeoutError as e:
        logger.error("Repo '%s': container execution timed out: %s", repo_id, e)
        error_msg = (
            f"The task was interrupted after {repo_config.timeout} seconds. "
            "Work done so far has been saved.\n\n"
            "Reply to resume — you can ask about progress or "
            "request next steps."
        )
        send_error_reply(repo_handler, message, error_msg)
        if conv_id and session_store:
            session_store.update_or_add_reply(
                conv_id,
                {"is_error": True, "events": events_buffer.copy()},
                request_text=prompt,
                response_text=error_msg,
            )
        return False, conv_id
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
        send_error_reply(repo_handler, message, error_msg)
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
        send_error_reply(repo_handler, message, error_msg)
        if conv_id and session_store:
            try:
                session_store.update_or_add_reply(
                    conv_id,
                    {"is_error": True, "events": events_buffer.copy()},
                    request_text=prompt,
                    response_text=error_msg,
                )
            except Exception as persist_err:
                logger.warning(
                    "Failed to persist error session: %s", persist_err
                )
        return False, conv_id
