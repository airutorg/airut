# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network log line rendering.

Provides functions that turn raw network-sandbox log lines into
styled HTML fragments.  Used by the SSE streaming code and by
handlers when rendering the initial page.
"""

import html
import re


# Pattern to extract status code from log lines: "ALLOWED GET ... -> 200"
_STATUS_CODE_PATTERN = re.compile(r"-> (\d{3})(?:\s|$)")

# Pattern to detect [dropped: N] suffix in log lines
_DROPPED_PATTERN = re.compile(r"\[dropped: (\d+)\]")


def _is_error_status(status_code: int) -> bool:
    """Check if status code indicates an error (not 2xx or 3xx)."""
    return status_code < 200 or status_code >= 400


def _extract_status_code(line: str) -> int | None:
    """Extract HTTP status code from a log line."""
    match = _STATUS_CODE_PATTERN.search(line)
    if match:
        return int(match.group(1))
    return None


def _highlight_status_code(escaped_line: str, status_code: int) -> str:
    """Wrap the status code in a highlight span."""
    # Status code is already escaped. The arrow -> becomes -&gt; after escaping.
    code_str = str(status_code)
    return escaped_line.replace(
        f"-&gt; {code_str}", f'-&gt; <span class="highlight">{code_str}</span>'
    )


def _highlight_blocked(escaped_line: str) -> str:
    """Wrap 'BLOCKED' in a highlight span."""
    return escaped_line.replace(
        "BLOCKED", '<span class="highlight">BLOCKED</span>', 1
    )


def _highlight_error_prefix(escaped_line: str) -> str:
    """Wrap 'ERROR' in a highlight span."""
    return escaped_line.replace(
        "ERROR", '<span class="highlight">ERROR</span>', 1
    )


def _highlight_stripped(escaped_line: str) -> str:
    """Wrap 'STRIPPED' in a highlight span."""
    return escaped_line.replace(
        "STRIPPED", '<span class="highlight">STRIPPED</span>', 1
    )


def _highlight_dropped(escaped_line: str) -> str:
    """Wrap [dropped: N] in a warning span."""
    return re.sub(
        r"\[dropped: (\d+)\]",
        r'<span class="dropped-tag">[dropped: \1]</span>',
        escaped_line,
    )


def render_network_log_line(line: str) -> str:
    """Render a single network log line with appropriate styling.

    Args:
        line: Raw log line (must not be empty).

    Returns:
        HTML string for the styled log line.

    Line types and their styling:
        - Task start headers (=== TASK START ...): blue
        - STRIPPED lines (foreign credential blocked): orange warning
        - BLOCKED requests: red with dark red background, BLOCKED in bold
        - ERROR lines (upstream failures): red with dark red background,
          ERROR in bold
        - ALLOWED requests with error status (4xx/5xx): orange with dark orange
          background, status code in bold
        - ALLOWED requests with [dropped: N]: green with warning tag
        - ALLOWED requests with success status (2xx/3xx): green
    """
    escaped = html.escape(line)

    if line.startswith("=== TASK START"):
        return f'<div class="log-line task-start">{escaped}</div>'
    elif line.startswith("STRIPPED"):
        highlighted = _highlight_stripped(escaped)
        return f'<div class="log-line stripped">{highlighted}</div>'
    elif line.startswith("BLOCKED"):
        highlighted = _highlight_blocked(escaped)
        return f'<div class="log-line blocked">{highlighted}</div>'
    elif line.startswith("ERROR"):
        highlighted = _highlight_error_prefix(escaped)
        return f'<div class="log-line conn-error">{highlighted}</div>'
    elif line.startswith("ALLOWED"):
        has_dropped = _DROPPED_PATTERN.search(line)
        status_code = _extract_status_code(line)
        if status_code is not None and _is_error_status(status_code):
            highlighted = _highlight_status_code(escaped, status_code)
            if has_dropped:
                highlighted = _highlight_dropped(highlighted)
            return f'<div class="log-line error">{highlighted}</div>'
        else:
            if has_dropped:
                highlighted = _highlight_dropped(escaped)
                return f'<div class="log-line allowed">{highlighted}</div>'
            return f'<div class="log-line allowed">{escaped}</div>'
    else:
        return f'<div class="log-line">{escaped}</div>'


def render_network_log_lines(log_content: str) -> str:
    """Render network log lines with appropriate styling.

    Args:
        log_content: Raw log file content.

    Returns:
        HTML string with styled log lines.
    """
    lines: list[str] = []
    for line in log_content.splitlines():
        if not line:
            continue
        lines.append(render_network_log_line(line))

    return "\n".join(lines)
