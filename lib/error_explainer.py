# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Human-readable error explanations for user-facing contexts.

This module produces concise, actionable error messages for different
output contexts (email, dashboard).  When an Anthropic API key is
configured, it uses an LLM to summarize the error.  Otherwise, it falls
back to a fixed template that includes the error type and message but
omits raw tracebacks.
"""

from __future__ import annotations

import logging

import httpx


logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an error summarizer for Airut, an email gateway that runs \
Claude Code in isolated containers on behalf of users.  Users send \
tasks via email; Airut executes them and replies with results.

An error occurred while processing a user's message.  Produce a \
concise, actionable explanation suitable for including in a reply \
email.  The recipient may or may not be the system administrator.

Rules:
- Be concise: 2-4 sentences.
- Explain what went wrong in plain language.
- If possible, suggest what the user can try (retry, simplify the \
request, check configuration, etc.).
- Do NOT include raw tracebacks or stack traces.
- Do NOT say "the administrator has been notified" or similar.
- Do NOT include any greeting or sign-off.
- Write in first person plural ("we") or passive voice.\
"""

_API_BASE = "https://api.anthropic.com/v1"
_API_VERSION = "2023-06-01"
_TIMEOUT_SECONDS = 15


def explain_error(
    *,
    error: BaseException | None = None,
    error_message: str = "",
    traceback_str: str = "",
    context: str = "email",
    api_key: str | None = None,
    model: str = "claude-haiku-4-5",
) -> str:
    """Produce a human-readable error explanation.

    Args:
        error: The exception instance (if available).
        error_message: A plain error message string.
        traceback_str: Full traceback string (only sent to LLM, never
            included in fallback output).
        context: Output context.  Currently only ``"email"`` is
            supported; future contexts (e.g. ``"dashboard"``) may
            adjust formatting.
        api_key: Anthropic API key.  When ``None`` or empty, the
            fallback template is used.
        model: Anthropic model ID for summarization.

    Returns:
        A user-friendly error explanation string.
    """
    del context  # Reserved for future use

    # Build the raw error info for the LLM prompt
    raw_parts: list[str] = []
    if error is not None:
        raw_parts.append(f"Exception type: {type(error).__name__}")
        raw_parts.append(f"Exception message: {error}")
    if error_message:
        raw_parts.append(f"Error message: {error_message}")
    if traceback_str:
        raw_parts.append(f"Traceback:\n{traceback_str}")

    raw_info = "\n".join(raw_parts) if raw_parts else "Unknown error"

    if api_key:
        try:
            return _call_anthropic(api_key, model, raw_info)
        except Exception:
            logger.warning(
                "Service LLM call failed, using fallback error template",
                exc_info=True,
            )

    return _fallback_explanation(error, error_message)


def _call_anthropic(api_key: str, model: str, raw_info: str) -> str:
    """Call the Anthropic Messages API to summarize an error.

    Args:
        api_key: Anthropic API key.
        model: Model ID.
        raw_info: Raw error information to summarize.

    Returns:
        LLM-generated error summary.

    Raises:
        httpx.HTTPStatusError: On non-2xx responses.
        httpx.TimeoutException: On request timeout.
    """
    with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
        response = client.post(
            f"{_API_BASE}/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": _API_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 256,
                "system": _SYSTEM_PROMPT,
                "messages": [
                    {
                        "role": "user",
                        "content": raw_info,
                    }
                ],
            },
        )
        response.raise_for_status()

    data = response.json()
    content_blocks = data.get("content", [])
    texts = [
        block["text"] for block in content_blocks if block.get("type") == "text"
    ]
    return "\n".join(texts)


def _fallback_explanation(
    error: BaseException | None,
    error_message: str,
) -> str:
    """Build a fixed-template error explanation without LLM.

    Includes the error type and message but omits tracebacks.

    Args:
        error: The exception instance (if available).
        error_message: A plain error message string.

    Returns:
        A user-friendly error explanation string.
    """
    parts = ["An error occurred while processing your message."]

    detail = ""
    if error is not None:
        detail = f"{type(error).__name__}: {error}"
    elif error_message:
        detail = error_message

    if detail:
        parts.append(f"\nError: {detail}")

    parts.append("\nYou can retry your message or try a simpler request.")

    return "\n".join(parts)
