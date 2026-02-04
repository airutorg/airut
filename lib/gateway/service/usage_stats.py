# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Usage statistics extraction from Claude output.

This module handles:
- UsageStats dataclass for tracking costs and tool usage
- Response text extraction from Claude's streaming JSON output
- Usage statistics extraction from Claude output
"""

import logging
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class UsageStats:
    """Usage statistics extracted from Claude output.

    Attributes:
        total_cost_usd: Total cost in USD (if available).
        web_search_requests: Number of web search requests made.
        web_fetch_requests: Number of web fetch requests made.
        is_subscription: True if using Claude Pro/Max (OAuth token).
    """

    total_cost_usd: float | None = None
    web_search_requests: int = 0
    web_fetch_requests: int = 0
    is_subscription: bool = False

    def has_any(self) -> bool:
        """Return True if any usage stats are available."""
        return (
            (self.total_cost_usd is not None and not self.is_subscription)
            or self.web_search_requests > 0
            or self.web_fetch_requests > 0
        )

    def format_summary(self) -> str:
        """Format usage stats as a summary string for email footer.

        Note: Cost is excluded for subscription plans (Claude Pro/Max)
        since users pay a flat monthly fee, not per-request.

        Uses middle dot (·) as separator instead of pipe to avoid
        markdown table interpretation when rendered in email.
        """
        parts = []

        # Only show cost for API key users, not subscription plans
        if self.total_cost_usd is not None and not self.is_subscription:
            parts.append(f"Cost: ${self.total_cost_usd:.4f}")

        if self.web_search_requests > 0:
            parts.append(f"Web searches: {self.web_search_requests}")

        if self.web_fetch_requests > 0:
            parts.append(f"Web fetches: {self.web_fetch_requests}")

        # Use middle dot separator to avoid markdown table interpretation
        return " · ".join(parts)


def extract_response_text(output: dict | None) -> str:
    """Extract text from Claude's streaming JSON output.

    Args:
        output: Parsed streaming JSON from Claude.

    Returns:
        Extracted text content.
    """
    if not output:
        logger.warning("No output received from Claude")
        return "No output received from Claude."

    if not isinstance(output, dict):
        logger.error(
            "Output is not a dict, got %s: %s",
            type(output).__name__,
            output,
        )
        return f"Error: Invalid output type {type(output).__name__}"

    try:
        events = output.get("events", [])
        for event in reversed(events):
            if event.get("type") == "assistant":
                message = event.get("message", {})
                content = message.get("content", [])
                text_parts = [
                    block["text"]
                    for block in content
                    if block.get("type") == "text"
                ]
                if text_parts:
                    return "\n\n".join(text_parts)

        result = output.get("result")
        if result is None:
            logger.warning("No text found in events or result field")
            return "No output received from Claude."

        if isinstance(result, str):
            return result

        if isinstance(result, dict):
            content_blocks = result.get("content", [])
            text_parts = [
                block["text"]
                for block in content_blocks
                if block.get("type") == "text"
            ]
            return "\n\n".join(text_parts) if text_parts else "No text output."

        logger.warning("Unexpected result type: %s", type(result).__name__)
        return f"Error: Unexpected result type {type(result).__name__}"

    except (KeyError, TypeError, AttributeError) as e:
        logger.warning("Failed to extract text from output: %s", e)
        return "Error: Could not parse response."


def extract_usage_stats(
    output: dict | None,
    *,
    is_subscription: bool = False,
) -> UsageStats:
    """Extract usage statistics from Claude's streaming JSON output.

    Args:
        output: Parsed streaming JSON from Claude.
        is_subscription: Whether the user is on a subscription plan.

    Returns:
        UsageStats with extracted statistics.
    """
    stats = UsageStats(is_subscription=is_subscription)

    if not output or not isinstance(output, dict):
        return stats

    if "total_cost_usd" in output:
        try:
            stats.total_cost_usd = float(output["total_cost_usd"])
        except (ValueError, TypeError):
            pass

    events = output.get("events", [])
    for event in events:
        if not isinstance(event, dict):
            continue

        if event.get("type") != "assistant":
            continue

        message = event.get("message", {})
        if not isinstance(message, dict):
            continue

        content = message.get("content", [])
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict):
                continue

            if block.get("type") == "tool_use":
                tool_name = block.get("name", "")
                if tool_name == "WebSearch":
                    stats.web_search_requests += 1
                elif tool_name == "WebFetch":
                    stats.web_fetch_requests += 1

    return stats
