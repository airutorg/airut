# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Usage statistics for Claude output.

Provides the UsageStats dataclass for tracking costs and tool usage.
"""

from dataclasses import dataclass


@dataclass
class UsageStats:
    """Usage statistics extracted from Claude output.

    Attributes:
        total_cost_usd: Total cost in USD (if available).
        web_search_requests: Number of web search requests made.
        web_fetch_requests: Number of web fetch requests made.
        is_subscription: True if using Claude Pro/Max (OAuth without API key).
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
        """Format usage stats as a summary string for reply footer.

        Note: Cost is excluded for subscription plans (Claude Pro/Max)
        since users pay a flat monthly fee, not per-request.

        Uses middle dot (·) as separator instead of pipe to avoid
        markdown table interpretation when rendered in replies.
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
